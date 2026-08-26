//! The HTTP/2 frame codec (RFC 9113 section 4): a pure, zero-copy parser and a
//! serializer for the 9-octet frame header and its payload. Like scanner.zig it
//! never owns or copies bytes - a parsed `Frame.payload` is a slice INTO the fed
//! buffer. It knows nothing about streams, HPACK, flow control, or Python; the
//! connection layer composes it. This boundary is what makes it independently
//! fuzzable.

const std = @import("std");
const constants = @import("constants.zig");

const FrameType = constants.FrameType;

/// The parsed 9-octet header. `stream_id` already has the reserved R bit masked
/// off (RFC 9113 4.1: "MUST be ignored when receiving").
pub const FrameHeader = struct {
    length: u24,
    ftype: u8,
    flags: u8,
    stream_id: u32,
};

/// A complete frame: its header plus a zero-copy slice of exactly `length`
/// payload octets that follow.
pub const Frame = struct {
    header: FrameHeader,
    payload: []const u8,
};

pub const FrameError = error{
    /// Fewer than a full frame (9 + length) is buffered; feed more.
    NeedData,
    /// A length violates a per-type fixed/minimum rule, or exceeds the locally
    /// advertised max frame size. Whether this is a stream or connection error
    /// is the connection layer's call (RFC 9113 4.2).
    FrameSizeError,
    /// A structural impossibility, e.g. padding >= payload (RFC 9113 6.1).
    ProtocolError,
    /// A payload too large to serialize (length exceeds the 24-bit field).
    TooLarge,
};

/// Parse the next frame at the start of `buf`. `max_frame_size` is the size WE
/// advertised; a frame claiming more is rejected before its payload is required,
/// so a peer cannot force us to buffer an oversized frame. The per-type
/// fixed/minimum length rule (checkLength) is enforced here too, so a caller
/// can never forget it; the connection layer still decides each FrameSizeError's
/// CLASS (stream vs connection). Returns NeedData when the full frame is not yet
/// buffered (the caller retries after feeding more). Does NOT advance anything -
/// the consumed length is 9 + header.length.
pub fn parse(buf: []const u8, max_frame_size: u32) FrameError!Frame {
    if (buf.len < constants.FRAME_HEADER_LEN) return error.NeedData;
    const header = parseHeader(buf[0..constants.FRAME_HEADER_LEN]);
    if (header.length > max_frame_size) return error.FrameSizeError;
    const total = constants.FRAME_HEADER_LEN + @as(usize, header.length);
    if (buf.len < total) return error.NeedData;
    try checkLength(header);
    return .{ .header = header, .payload = buf[constants.FRAME_HEADER_LEN..total] };
}

/// Decode the fixed 9-octet header. Length is a 24-bit big-endian integer; the
/// stream id is 31-bit big-endian with the top (reserved) bit masked off.
pub fn parseHeader(b: *const [9]u8) FrameHeader {
    const length: u24 = (@as(u24, b[0]) << 16) | (@as(u24, b[1]) << 8) | b[2];
    const raw_id = std.mem.readInt(u32, b[5..9], .big);
    return .{
        .length = length,
        .ftype = b[3],
        .flags = b[4],
        .stream_id = raw_id & 0x7FFF_FFFF,
    };
}

/// Strip a frame's padding (RFC 9113 6.1/6.2/6.6). When the PADDED flag is set
/// the first payload octet is Pad Length and that many trailing octets are
/// padding. An empty payload cannot hold the mandatory Pad Length octet, so it
/// is a FrameSizeError (RFC 9113 4.2). Pad Length >= the rest of the payload is
/// a PROTOCOL_ERROR (the underflow guard: the check precedes the subslice).
/// Returns the content slice with the pad-length octet and padding removed.
pub fn dePad(payload: []const u8, padded: bool) FrameError![]const u8 {
    if (!padded) return payload;
    if (payload.len == 0) return error.FrameSizeError;
    const pad_len = payload[0];
    const remaining = payload.len - 1;
    if (pad_len > remaining) return error.ProtocolError;
    return payload[1 .. payload.len - pad_len];
}

/// Extract a HEADERS frame's field-block fragment, accounting for the PADDED and
/// PRIORITY flags (RFC 9113 6.2). PRIORITY adds a mandatory 5-octet block
/// (exclusive bit + 31-bit stream dependency + 8-bit weight) that we parse past
/// but do not act on (priority is deprecated, RFC 9113 5.3.2). A payload too
/// short to hold the conditional mandatory fields is a FrameSizeError - the
/// bounds check that keeps later HPACK parsing from reading out of bounds.
pub fn headersFieldBlock(payload: []const u8, flags: u8) FrameError![]const u8 {
    var body = try dePad(payload, constants.Flags.has(flags, constants.Flags.padded));
    if (constants.Flags.has(flags, constants.Flags.priority)) {
        if (body.len < 5) return error.FrameSizeError;
        body = body[5..];
    }
    return body;
}

/// A PUSH_PROMISE frame's promised stream id and field-block fragment
/// (RFC 9113 6.6). After de-padding, the first 4 octets are R(1) + Promised
/// Stream ID(31); a payload too short for them is a FrameSizeError.
pub const PushPromise = struct { promised_id: u32, fragment: []const u8 };

pub fn pushPromiseFields(payload: []const u8, flags: u8) FrameError!PushPromise {
    const body = try dePad(payload, constants.Flags.has(flags, constants.Flags.padded));
    if (body.len < 4) return error.FrameSizeError;
    const raw = std.mem.readInt(u32, body[0..4], .big);
    return .{ .promised_id = raw & 0x7FFF_FFFF, .fragment = body[4..] };
}

/// Validate a frame's payload length against its type's fixed/minimum rule
/// (RFC 9113 section 6). The error CLASS (stream vs connection) is decided by the
/// connection layer; here we only flag that a rule was broken. Variable-length
/// types (DATA, HEADERS, PUSH_PROMISE, CONTINUATION, GOAWAY debug, unknown) have
/// no fixed rule and pass.
pub fn checkLength(header: FrameHeader) FrameError!void {
    const ftype: FrameType = @enumFromInt(header.ftype);
    const len = header.length;
    switch (ftype) {
        .priority => if (len != 5) return error.FrameSizeError,
        .rst_stream => if (len != 4) return error.FrameSizeError,
        .ping => if (len != 8) return error.FrameSizeError,
        .window_update => if (len != 4) return error.FrameSizeError,
        .settings => {
            if (constants.Flags.has(header.flags, constants.Flags.ack)) {
                if (len != 0) return error.FrameSizeError;
            } else if (len % 6 != 0) return error.FrameSizeError;
        },
        .goaway => if (len < 8) return error.FrameSizeError,
        else => {},
    }
}

/// Serialize a frame header into `out`. The payload is appended separately by
/// the caller (so a zero-copy payload slice needn't be concatenated first).
pub fn writeHeader(out: *std.ArrayList(u8), gpa: std.mem.Allocator, header: FrameHeader) !void {
    var buf: [9]u8 = undefined;
    buf[0] = @truncate(header.length >> 16);
    buf[1] = @truncate(header.length >> 8);
    buf[2] = @truncate(header.length);
    buf[3] = header.ftype;
    buf[4] = header.flags;
    std.mem.writeInt(u32, buf[5..9], header.stream_id & 0x7FFF_FFFF, .big);
    try out.appendSlice(gpa, &buf);
}

/// Serialize a full frame (header + payload) into `out`. A payload that does not
/// fit the 24-bit length field is rejected rather than truncated; the writer
/// layer is expected to split payloads to the peer's max frame size first.
pub fn write(out: *std.ArrayList(u8), gpa: std.mem.Allocator, ftype: FrameType, flags: u8, stream_id: u32, payload: []const u8) !void {
    if (payload.len > std.math.maxInt(u24)) return error.TooLarge;
    try out.ensureUnusedCapacity(gpa, 9 + payload.len);
    try writeHeader(out, gpa, .{
        .length = @intCast(payload.len),
        .ftype = @intFromEnum(ftype),
        .flags = flags,
        .stream_id = stream_id,
    });
    try out.appendSlice(gpa, payload);
}

const testing = std.testing;

test "parse decodes header fields and masks the R bit" {
    // length=8, type=PING(6), flags=ACK(1), stream_id=0 with R bit set.
    const bytes = [_]u8{ 0x00, 0x00, 0x08, 0x06, 0x01, 0x80, 0x00, 0x00, 0x00 } ++ [_]u8{0xAB} ** 8;
    const f = try parse(&bytes, constants.DEFAULT_FRAME_SIZE);
    try testing.expectEqual(@as(u24, 8), f.header.length);
    try testing.expectEqual(@as(u8, 6), f.header.ftype);
    try testing.expectEqual(@as(u8, 1), f.header.flags);
    try testing.expectEqual(@as(u32, 0), f.header.stream_id); // R bit masked off
    try testing.expectEqual(@as(usize, 8), f.payload.len);
}

test "parse decodes a 31-bit stream id with R bit set" {
    // stream_id = 0x7FFFFFFF, with the R bit also set -> 0xFFFFFFFF on the wire.
    const bytes = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };
    const f = try parse(&bytes, constants.DEFAULT_FRAME_SIZE);
    try testing.expectEqual(@as(u32, 0x7FFF_FFFF), f.header.stream_id);
}

test "parse needs the full header" {
    try testing.expectError(error.NeedData, parse(&[_]u8{ 0, 0, 0 }, constants.DEFAULT_FRAME_SIZE));
}

test "parse needs the full payload" {
    // Header says 4-octet payload but only 2 are present.
    const bytes = [_]u8{ 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB };
    try testing.expectError(error.NeedData, parse(&bytes, constants.DEFAULT_FRAME_SIZE));
}

test "parse rejects a frame larger than the advertised max before buffering" {
    // Length 16385 > default 16384; only the 9-byte header is present.
    const bytes = [_]u8{ 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    try testing.expectError(error.FrameSizeError, parse(&bytes, constants.DEFAULT_FRAME_SIZE));
}

test "parse returns a zero-copy payload sub-slice" {
    const bytes = [_]u8{ 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 'a', 'b', 'c' };
    const f = try parse(&bytes, constants.DEFAULT_FRAME_SIZE);
    try testing.expectEqual(@intFromPtr(&bytes[9]), @intFromPtr(f.payload.ptr));
    try testing.expectEqualStrings("abc", f.payload);
}

test "dePad strips pad length octet and padding" {
    // pad_len=2, content="hi", padding=00 00.
    const payload = [_]u8{ 0x02, 'h', 'i', 0x00, 0x00 };
    try testing.expectEqualStrings("hi", try dePad(&payload, true));
}

test "dePad with no padding flag is a no-op" {
    const payload = [_]u8{ 'd', 'a', 't', 'a' };
    try testing.expectEqualStrings("data", try dePad(&payload, false));
}

test "dePad rejects pad length >= total payload length (RFC 9113 6.1)" {
    // Payload length 2 (pad-length octet + 1 byte), pad_len = 2 >= 2 -> error.
    const payload = [_]u8{ 0x02, 0x00 };
    try testing.expectError(error.ProtocolError, dePad(&payload, true));
}

test "dePad accepts pad length one below total (zero content)" {
    // Payload length 2, pad_len = 1 < 2 -> empty content, the trailing octet is
    // padding. This is the exact valid boundary below the rejection above.
    const payload = [_]u8{ 0x01, 0x00 };
    try testing.expectEqualStrings("", try dePad(&payload, true));
}

test "dePad rejects an empty padded payload as a frame-size error" {
    // PADDED makes the Pad Length octet mandatory; a zero-length payload is too
    // small to carry it (RFC 9113 4.2 -> FRAME_SIZE_ERROR, not PROTOCOL_ERROR).
    try testing.expectError(error.FrameSizeError, dePad(&[_]u8{}, true));
}

test "parse enforces the per-type length rule" {
    // PING (type 6) must be 8 octets; a 7-octet PING fails at parse, so a caller
    // can never forget the length check.
    const bytes = [_]u8{ 0x00, 0x00, 0x07, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 } ++ [_]u8{0} ** 7;
    try testing.expectError(error.FrameSizeError, parse(&bytes, constants.DEFAULT_FRAME_SIZE));
}

test "headersFieldBlock handles plain, padded, and priority flags" {
    try testing.expectEqualStrings("hpack", try headersFieldBlock("hpack", 0));
    // PADDED: pad_len=1, fragment="ab", one padding octet.
    try testing.expectEqualStrings("ab", try headersFieldBlock(&[_]u8{ 0x01, 'a', 'b', 0x00 }, constants.Flags.padded));
    // PRIORITY: 5-octet block then the fragment.
    const pri = [_]u8{ 0x00, 0x00, 0x00, 0x01, 0x10 } ++ [_]u8{ 'h', 'i' };
    try testing.expectEqualStrings("hi", try headersFieldBlock(&pri, constants.Flags.priority));
}

test "headersFieldBlock rejects a payload too short for the priority block" {
    try testing.expectError(error.FrameSizeError, headersFieldBlock(&[_]u8{ 0, 0, 0, 1 }, constants.Flags.priority));
}

test "pushPromiseFields extracts the promised id and masks the R bit" {
    const payload = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFE } ++ [_]u8{ 'b', 'l' };
    const pp = try pushPromiseFields(&payload, 0);
    try testing.expectEqual(@as(u32, 0x7FFF_FFFE), pp.promised_id);
    try testing.expectEqualStrings("bl", pp.fragment);
}

test "pushPromiseFields rejects a payload too short for the promised id" {
    try testing.expectError(error.FrameSizeError, pushPromiseFields(&[_]u8{ 0, 0, 0 }, 0));
}

test "checkLength enforces fixed-size frames" {
    const ok: FrameHeader = .{ .length = 4, .ftype = 0x03, .flags = 0, .stream_id = 1 };
    try checkLength(ok); // RST_STREAM = 4
    const bad: FrameHeader = .{ .length = 5, .ftype = 0x03, .flags = 0, .stream_id = 1 };
    try testing.expectError(error.FrameSizeError, checkLength(bad));
}

test "checkLength enforces SETTINGS multiple-of-six and ACK-empty" {
    try checkLength(.{ .length = 12, .ftype = 0x04, .flags = 0, .stream_id = 0 });
    try testing.expectError(error.FrameSizeError, checkLength(.{ .length = 7, .ftype = 0x04, .flags = 0, .stream_id = 0 }));
    try checkLength(.{ .length = 0, .ftype = 0x04, .flags = 0x01, .stream_id = 0 }); // ACK empty
    try testing.expectError(error.FrameSizeError, checkLength(.{ .length = 6, .ftype = 0x04, .flags = 0x01, .stream_id = 0 }));
}

test "checkLength enforces GOAWAY minimum and PRIORITY exact" {
    try testing.expectError(error.FrameSizeError, checkLength(.{ .length = 7, .ftype = 0x07, .flags = 0, .stream_id = 0 }));
    try checkLength(.{ .length = 8, .ftype = 0x07, .flags = 0, .stream_id = 0 });
    try testing.expectError(error.FrameSizeError, checkLength(.{ .length = 4, .ftype = 0x02, .flags = 0, .stream_id = 1 }));
    try checkLength(.{ .length = 5, .ftype = 0x02, .flags = 0, .stream_id = 1 });
}

test "checkLength passes variable-length frames" {
    try checkLength(.{ .length = 12345, .ftype = 0x00, .flags = 0, .stream_id = 1 }); // DATA
    try checkLength(.{ .length = 999, .ftype = 0x01, .flags = 0, .stream_id = 1 }); // HEADERS
    try checkLength(.{ .length = 50000, .ftype = 0xFE, .flags = 0, .stream_id = 1 }); // unknown
}

fn writeFrameUnderAllocationFailure(gpa: std.mem.Allocator) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    write(&out, gpa, .data, 0, 1, &[_]u8{0xAA} ** 1024) catch |err| {
        try testing.expectEqual(@as(usize, 0), out.items.len);
        return err;
    };
    try testing.expectEqual(@as(usize, 9 + 1024), out.items.len);
}

test "frame writes are atomic on allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, writeFrameUnderAllocationFailure, .{});
}

test "write then parse round-trips" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try write(&out, testing.allocator, .data, constants.Flags.end_stream, 3, "payload");
    const f = try parse(out.items, constants.DEFAULT_FRAME_SIZE);
    try testing.expectEqual(FrameType.data, @as(FrameType, @enumFromInt(f.header.ftype)));
    try testing.expectEqual(@as(u8, constants.Flags.end_stream), f.header.flags);
    try testing.expectEqual(@as(u32, 3), f.header.stream_id);
    try testing.expectEqualStrings("payload", f.payload);
}

test "writeHeader masks the R bit out of the stream id" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try writeHeader(&out, testing.allocator, .{ .length = 0, .ftype = 0, .flags = 0, .stream_id = 0xFFFF_FFFF });
    const id = std.mem.readInt(u32, out.items[5..9], .big);
    try testing.expectEqual(@as(u32, 0x7FFF_FFFF), id);
}

/// Parse arbitrary bytes, then run every leaf check over the result. The only
/// acceptable outcomes are a FrameError or a frame whose zero-copy payload sits
/// within the input - never a panic, OOB read, or hang.
fn driveFrame(input: []const u8) void {
    const f = parse(input, constants.DEFAULT_FRAME_SIZE) catch return;
    std.debug.assert(f.payload.len == f.header.length);
    std.debug.assert(constants.FRAME_HEADER_LEN + f.payload.len <= input.len);
    const padded = constants.Flags.has(f.header.flags, constants.Flags.padded);
    _ = dePad(f.payload, padded) catch {};
    _ = headersFieldBlock(f.payload, f.header.flags) catch {};
    _ = pushPromiseFields(f.payload, f.header.flags) catch {};
}

test "fuzz: frame parsing never panics on adversarial inputs" {
    const seeds = [_][]const u8{
        "",
        &[_]u8{0} ** 9,
        &[_]u8{ 0x00, 0x00, 0x00, 0x06, 0x01, 0xFF, 0xFF, 0xFF, 0xFF }, // PING ACK, R set
        &[_]u8{ 0xFF, 0xFF, 0xFF, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01 }, // huge DATA length
        &([_]u8{ 0x00, 0x00, 0x05, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01 } ++ [_]u8{ 0xFF, 'a', 'b', 'c', 'd' }), // padded, pad>=remaining
    };
    for (seeds) |s| driveFrame(s);

    var prng = std.Random.DefaultPrng.init(0x6832667a7a);
    const rand = prng.random();
    var buf: [256]u8 = undefined;
    for (0..2000) |_| {
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        for (buf[0..len]) |*b| b.* = rand.int(u8);
        driveFrame(buf[0..len]);
    }
}
