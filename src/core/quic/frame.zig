//! The QUIC frame codec (RFC 9000 section 19): a pure, zero-copy parser over the
//! decrypted payload of a packet. A packet payload is a sequence of frames; this
//! decodes them one at a time. Like h2/frame.zig it never owns bytes - a parsed
//! frame's `data`/`token`/`reason` slices point INTO the fed payload - and it
//! knows nothing about crypto, streams, or flow control; the connection layer
//! composes it. That boundary is what makes it independently fuzzable.

const std = @import("std");
const varint = @import("varint.zig");
const constants = @import("constants.zig");

const FrameType = constants.FrameType;

pub const Error = error{
    /// The frame is truncated within the payload (a length/varint runs past the
    /// end). Inside a decrypted packet this is FRAME_ENCODING_ERROR, not NeedData
    /// - a packet is atomic, so there is no "feed more".
    Truncated,
    /// A structurally invalid frame: an unknown type, a reserved bit set, or a
    /// field that violates a frame-specific rule (RFC 9000 19).
    FrameEncodingError,
};

/// One decoded ACK range: `gap` unacked packets then `len`+1 acked (RFC 9000
/// 19.3). Kept as raw fields; the recovery layer folds them into its ack set.
pub const AckRange = struct {
    gap: u64,
    len: u64,
};

pub const EcnCounts = struct {
    ect0: u64,
    ect1: u64,
    ce: u64,
};

/// A parsed frame. A tagged union mirroring the RFC 9000 frame catalogue; the
/// variants the read path acts on carry their fields, and the many pure-signal
/// frames (PING, HANDSHAKE_DONE, ...) are bare tags.
pub const Frame = union(enum) {
    padding: usize, // a run of PADDING octets, collapsed to its count
    ping,
    ack: struct { largest: u64, delay: u64, first_range: u64, ranges: []const u8, ecn: ?EcnCounts = null }, // ranges left raw; decoded lazily
    reset_stream: struct { stream_id: u64, error_code: u64, final_size: u64 },
    stop_sending: struct { stream_id: u64, error_code: u64 },
    crypto: struct { offset: u64, data: []const u8 },
    new_token: struct { token: []const u8 },
    stream: struct { stream_id: u64, offset: u64, data: []const u8, fin: bool },
    max_data: u64,
    max_stream_data: struct { stream_id: u64, max: u64 },
    max_streams: struct { bidi: bool, max: u64 },
    data_blocked: u64,
    stream_data_blocked: struct { stream_id: u64, limit: u64 },
    streams_blocked: struct { bidi: bool, limit: u64 },
    new_connection_id: struct { seq: u64, retire_prior_to: u64, cid: []const u8, token: []const u8 },
    retire_connection_id: u64,
    path_challenge: [8]u8,
    path_response: [8]u8,
    connection_close: struct { app: bool, error_code: u64, frame_type: u64, reason: []const u8 },
    handshake_done,
};

/// A decoded frame plus how many octets it consumed, so the caller can advance.
pub const Decoded = struct {
    frame: Frame,
    len: usize,
};

const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn vint(self: *Cursor) Error!u64 {
        const d = varint.decode(self.buf[self.pos..]) catch return error.Truncated;
        self.pos += d.len;
        return d.value;
    }

    fn take(self: *Cursor, wire_len: u64) Error![]const u8 {
        const n = std.math.cast(usize, wire_len) orelse return error.Truncated;
        if (n > self.buf.len - self.pos) return error.Truncated;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }

    fn byte(self: *Cursor) Error!u8 {
        if (self.pos >= self.buf.len) return error.Truncated;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }
};

fn validateOffsetLen(offset: u64, len: u64) Error!void {
    const end = std.math.add(u64, offset, len) catch return error.FrameEncodingError;
    if (end > varint.MAX) return error.FrameEncodingError;
}

/// Decode the frame at the start of `buf`. PADDING runs are collapsed into one
/// `padding` frame so a packet full of padding does not yield thousands of
/// events. Returns Truncated if any field runs past the payload end.
pub fn decode(buf: []const u8) Error!Decoded {
    if (buf.len == 0) return error.Truncated;
    var cur = Cursor{ .buf = buf };
    const raw = try cur.vint();

    if (raw == @intFromEnum(FrameType.padding)) {
        while (cur.pos < buf.len and buf[cur.pos] == 0x00) cur.pos += 1;
        return .{ .frame = .{ .padding = cur.pos }, .len = cur.pos };
    }
    if (raw >= constants.STREAM_BASE and raw <= constants.STREAM_BASE + 0x07) {
        return decodeStream(&cur, raw);
    }

    const ftype: FrameType = @enumFromInt(raw);
    const frame: Frame = switch (ftype) {
        .ping => .ping,
        .ack, .ack_ecn => try decodeAck(&cur, ftype == .ack_ecn),
        .reset_stream => .{ .reset_stream = .{ .stream_id = try cur.vint(), .error_code = try cur.vint(), .final_size = try cur.vint() } },
        .stop_sending => .{ .stop_sending = .{ .stream_id = try cur.vint(), .error_code = try cur.vint() } },
        .crypto => blk: {
            const offset = try cur.vint();
            const dlen = try cur.vint();
            try validateOffsetLen(offset, dlen);
            break :blk .{ .crypto = .{ .offset = offset, .data = try cur.take(dlen) } };
        },
        .new_token => blk: {
            const tlen = try cur.vint();
            if (tlen == 0) return error.FrameEncodingError; // RFC 9000 19.7: token MUST NOT be empty
            break :blk .{ .new_token = .{ .token = try cur.take(tlen) } };
        },
        .max_data => .{ .max_data = try cur.vint() },
        .max_stream_data => .{ .max_stream_data = .{ .stream_id = try cur.vint(), .max = try cur.vint() } },
        .max_streams_bidi => .{ .max_streams = .{ .bidi = true, .max = try cur.vint() } },
        .max_streams_uni => .{ .max_streams = .{ .bidi = false, .max = try cur.vint() } },
        .data_blocked => .{ .data_blocked = try cur.vint() },
        .stream_data_blocked => .{ .stream_data_blocked = .{ .stream_id = try cur.vint(), .limit = try cur.vint() } },
        .streams_blocked_bidi => .{ .streams_blocked = .{ .bidi = true, .limit = try cur.vint() } },
        .streams_blocked_uni => .{ .streams_blocked = .{ .bidi = false, .limit = try cur.vint() } },
        .new_connection_id => try decodeNewCid(&cur),
        .retire_connection_id => .{ .retire_connection_id = try cur.vint() },
        .path_challenge => .{ .path_challenge = (try cur.take(8))[0..8].* },
        .path_response => .{ .path_response = (try cur.take(8))[0..8].* },
        .connection_close => try decodeClose(&cur, false),
        .connection_close_app => try decodeClose(&cur, true),
        .handshake_done => .handshake_done,
        .stream, .padding, _ => return error.FrameEncodingError,
    };
    return .{ .frame = frame, .len = cur.pos };
}

fn decodeStream(cur: *Cursor, raw: u64) Error!Decoded {
    const has_off = (raw & constants.STREAM_OFF) != 0;
    const has_len = (raw & constants.STREAM_LEN) != 0;
    const fin = (raw & constants.STREAM_FIN) != 0;
    const stream_id = try cur.vint();
    const offset = if (has_off) try cur.vint() else 0;
    const data = if (has_len) blk: {
        const dlen = try cur.vint();
        try validateOffsetLen(offset, dlen);
        break :blk try cur.take(dlen);
    } else cur.buf[cur.pos..]; // no length => the frame runs to the packet end
    if (!has_len) try validateOffsetLen(offset, @intCast(data.len));
    if (!has_len) cur.pos = cur.buf.len;
    return .{ .frame = .{ .stream = .{ .stream_id = stream_id, .offset = offset, .data = data, .fin = fin } }, .len = cur.pos };
}

fn decodeAck(cur: *Cursor, ecn: bool) Error!Frame {
    const largest = try cur.vint();
    const delay = try cur.vint();
    const range_count = try cur.vint();
    const first_range = try cur.vint();
    const ranges_start = cur.pos;
    var i: u64 = 0;
    while (i < range_count) : (i += 1) {
        _ = try cur.vint(); // gap
        _ = try cur.vint(); // ack range length
    }
    const ranges = cur.buf[ranges_start..cur.pos];
    var ecn_counts: ?EcnCounts = null;
    if (ecn) {
        ecn_counts = .{
            .ect0 = try cur.vint(),
            .ect1 = try cur.vint(),
            .ce = try cur.vint(),
        };
    }
    return .{ .ack = .{ .largest = largest, .delay = delay, .first_range = first_range, .ranges = ranges, .ecn = ecn_counts } };
}

fn decodeNewCid(cur: *Cursor) Error!Frame {
    const seq = try cur.vint();
    const retire_prior_to = try cur.vint();
    if (retire_prior_to > seq) return error.FrameEncodingError; // RFC 9000 19.15
    const cid_len = try cur.byte();
    if (cid_len == 0 or cid_len > constants.MAX_CID_LEN) return error.FrameEncodingError;
    const cid = try cur.take(cid_len);
    const token = try cur.take(16); // stateless reset token is exactly 16 octets
    return .{ .new_connection_id = .{ .seq = seq, .retire_prior_to = retire_prior_to, .cid = cid, .token = token } };
}

fn decodeClose(cur: *Cursor, app: bool) Error!Frame {
    const error_code = try cur.vint();
    const frame_type = if (app) 0 else try cur.vint();
    const rlen = try cur.vint();
    const reason = try cur.take(rlen);
    return .{ .connection_close = .{ .app = app, .error_code = error_code, .frame_type = frame_type, .reason = reason } };
}

// -- encode (the write side) -------------------------------------------------
//
// The inverse of `decode` for the frames an outbound packet carries: STREAM (the
// response bytes) and ACK (acknowledging the peer). Each appends to the caller's
// payload buffer; the connection layer seals and protects the assembled packet.

/// Append a STREAM frame (RFC 9000 19.8). The length is always written (LEN bit
/// set) so frames can be followed by others in the same packet; OFF is written
/// only for a nonzero offset. `fin` sets the FIN bit.
pub fn encodeStream(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    stream_id: u64,
    offset: u64,
    data: []const u8,
    fin: bool,
) !void {
    var ty: u64 = constants.STREAM_BASE | constants.STREAM_LEN;
    if (offset != 0) ty |= constants.STREAM_OFF;
    if (fin) ty |= constants.STREAM_FIN;
    try varint.append(out, gpa, ty);
    try varint.append(out, gpa, stream_id);
    if (offset != 0) try varint.append(out, gpa, offset);
    try varint.append(out, gpa, data.len);
    try out.appendSlice(gpa, data);
}

/// Append an ACK frame (RFC 9000 19.3) acknowledging `largest` and the
/// `first_range` packets below it, with no additional ranges (the common case:
/// one contiguous run). `delay` is the ack-delay varint.
pub fn encodeAck(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    largest: u64,
    delay: u64,
    first_range: u64,
) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.ack));
    try varint.append(out, gpa, largest);
    try varint.append(out, gpa, delay);
    try varint.append(out, gpa, 0); // ACK Range Count: no additional ranges
    try varint.append(out, gpa, first_range);
}

/// Append an ACK frame from a received-pn range set (RFC 9000 19.3): largest, delay,
/// the additional-range count, first_range, then each (gap, range_len) pair. This is
/// the accurate form - a peer with gaps in what it received needs every range.
pub fn encodeAckRanges(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    ranges: *const @import("ack_ranges.zig").AckRanges,
    delay: u64,
) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.ack));
    try varint.append(out, gpa, ranges.largest().?);
    try varint.append(out, gpa, delay);
    // The additional-range count is written after the extra pairs are sized; encode
    // the pairs into a scratch list, then emit the count + first_range + pairs.
    var extra: std.ArrayListUnmanaged(u8) = .empty;
    defer extra.deinit(gpa);
    const count = try ranges.encodeExtra(&extra, gpa);
    try varint.append(out, gpa, count);
    try varint.append(out, gpa, ranges.firstRange());
    try out.appendSlice(gpa, extra.items);
}

/// Append a MAX_DATA frame (RFC 9000 19.9): the new connection-wide limit on the
/// total stream data the peer may send.
pub fn encodeMaxData(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, max: u64) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.max_data));
    try varint.append(out, gpa, max);
}

/// Append a NEW_TOKEN frame (RFC 9000 19.7): an address-validation token a server
/// gives a client for a future connection.
pub fn encodeNewToken(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, token: []const u8) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.new_token));
    try varint.append(out, gpa, token.len);
    try out.appendSlice(gpa, token);
}

/// Append a MAX_STREAM_DATA frame (RFC 9000 19.10): the new limit on the data the
/// peer may send on `stream_id`.
pub fn encodeMaxStreamData(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, stream_id: u64, max: u64) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.max_stream_data));
    try varint.append(out, gpa, stream_id);
    try varint.append(out, gpa, max);
}

/// Append a MAX_STREAMS frame (RFC 9000 19.11): the new cap on the number of streams
/// of the given directionality the peer may open. `bidi` selects bidirectional.
pub fn encodeMaxStreams(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, bidi: bool, max: u64) !void {
    try varint.append(out, gpa, @intFromEnum(if (bidi) FrameType.max_streams_bidi else FrameType.max_streams_uni));
    try varint.append(out, gpa, max);
}

/// Append a DATA_BLOCKED frame (RFC 9000 19.12): our send side is blocked by the
/// peer's connection-level MAX_DATA limit.
pub fn encodeDataBlocked(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, limit: u64) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.data_blocked));
    try varint.append(out, gpa, limit);
}

/// Append a STREAM_DATA_BLOCKED frame (RFC 9000 19.13): our send side is blocked
/// by this stream's MAX_STREAM_DATA limit.
pub fn encodeStreamDataBlocked(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, stream_id: u64, limit: u64) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.stream_data_blocked));
    try varint.append(out, gpa, stream_id);
    try varint.append(out, gpa, limit);
}

/// Append a STREAMS_BLOCKED frame (RFC 9000 19.14): our stream creation is blocked
/// by the peer's MAX_STREAMS limit for the selected directionality.
pub fn encodeStreamsBlocked(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, bidi: bool, limit: u64) !void {
    try varint.append(out, gpa, @intFromEnum(if (bidi) FrameType.streams_blocked_bidi else FrameType.streams_blocked_uni));
    try varint.append(out, gpa, limit);
}

/// Append a NEW_CONNECTION_ID frame (RFC 9000 19.15). The stateless reset token is
/// exactly 16 octets.
pub fn encodeNewConnectionId(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, seq: u64, retire_prior_to: u64, cid: []const u8, token: [16]u8) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.new_connection_id));
    try varint.append(out, gpa, seq);
    try varint.append(out, gpa, retire_prior_to);
    try out.append(gpa, @intCast(cid.len));
    try out.appendSlice(gpa, cid);
    try out.appendSlice(gpa, &token);
}

/// Append a RETIRE_CONNECTION_ID frame (RFC 9000 19.16): the peer no longer uses
/// a locally-issued connection id with `seq`.
pub fn encodeRetireConnectionId(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, seq: u64) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.retire_connection_id));
    try varint.append(out, gpa, seq);
}

/// Append a RESET_STREAM frame (RFC 9000 19.4): abruptly terminate the sending part
/// of `stream_id` with `error_code`, declaring `final_size` as the total bytes sent.
pub fn encodeResetStream(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, stream_id: u64, error_code: u64, final_size: u64) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.reset_stream));
    try varint.append(out, gpa, stream_id);
    try varint.append(out, gpa, error_code);
    try varint.append(out, gpa, final_size);
}

/// Append a STOP_SENDING frame (RFC 9000 19.5): ask the peer to stop sending on
/// `stream_id` with `error_code` (the receiving part is no longer wanted).
pub fn encodeStopSending(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, stream_id: u64, error_code: u64) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.stop_sending));
    try varint.append(out, gpa, stream_id);
    try varint.append(out, gpa, error_code);
}

/// Append a CONNECTION_CLOSE frame (RFC 9000 19.19). `app` selects the application
/// variant (0x1d, no frame-type field) over the transport variant (0x1c); the
/// transport variant names the `frame_type` that triggered the error (0 if none).
pub fn encodeConnectionClose(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    app: bool,
    error_code: u64,
    frame_type: u64,
    reason: []const u8,
) !void {
    try varint.append(out, gpa, @intFromEnum(if (app) FrameType.connection_close_app else FrameType.connection_close));
    try varint.append(out, gpa, error_code);
    if (!app) try varint.append(out, gpa, frame_type); // transport variant only
    try varint.append(out, gpa, reason.len);
    try out.appendSlice(gpa, reason);
}

pub fn encodePathChallenge(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, data: [8]u8) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.path_challenge));
    try out.appendSlice(gpa, &data);
}

pub fn encodePathResponse(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, data: [8]u8) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.path_response));
    try out.appendSlice(gpa, &data);
}

/// Append a CRYPTO frame (RFC 9000 19.6): the handshake byte stream for one
/// packet-number space, carrying `data` at `offset`. Unlike STREAM there are no
/// flags and the length is always present.
pub fn encodeCrypto(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    offset: u64,
    data: []const u8,
) !void {
    try varint.append(out, gpa, @intFromEnum(FrameType.crypto));
    try varint.append(out, gpa, offset);
    try varint.append(out, gpa, data.len);
    try out.appendSlice(gpa, data);
}

/// Iterate the ranges of a parsed ACK frame. The recovery layer walks these to
/// learn which packet numbers the peer acknowledged.
pub fn ackRanges(ack_ranges: []const u8) AckRangeIterator {
    return .{ .buf = ack_ranges };
}

pub const AckRangeIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn next(self: *AckRangeIterator) ?AckRange {
        if (self.pos >= self.buf.len) return null;
        const gap = varint.decode(self.buf[self.pos..]) catch return null;
        self.pos += gap.len;
        const len = varint.decode(self.buf[self.pos..]) catch return null;
        self.pos += len.len;
        return .{ .gap = gap.value, .len = len.value };
    }
};

test "decode a PING frame" {
    const d = try decode(&.{0x01});
    try std.testing.expect(d.frame == .ping);
    try std.testing.expectEqual(@as(usize, 1), d.len);
}

test "PADDING collapses a run" {
    const d = try decode(&.{ 0x00, 0x00, 0x00, 0x01 });
    try std.testing.expectEqual(@as(usize, 3), d.frame.padding);
    try std.testing.expectEqual(@as(usize, 3), d.len);
}

test "PATH_CHALLENGE and PATH_RESPONSE round-trip" {
    const gpa = std.testing.allocator;
    const data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try encodePathChallenge(&out, gpa, data);
    try encodePathResponse(&out, gpa, data);

    const c = try decode(out.items);
    switch (c.frame) {
        .path_challenge => |got| try std.testing.expectEqualSlices(u8, &data, &got),
        else => return error.TestUnexpectedResult,
    }

    const r = try decode(out.items[c.len..]);
    switch (r.frame) {
        .path_response => |got| try std.testing.expectEqualSlices(u8, &data, &got),
        else => return error.TestUnexpectedResult,
    }
}

test "decode a STREAM frame with offset, length, and FIN" {
    // type 0x0f (OFF|LEN|FIN), id=4, off=8, len=3, "abc"
    const d = try decode(&.{ 0x0f, 0x04, 0x08, 0x03, 'a', 'b', 'c' });
    const s = d.frame.stream;
    try std.testing.expectEqual(@as(u64, 4), s.stream_id);
    try std.testing.expectEqual(@as(u64, 8), s.offset);
    try std.testing.expectEqualStrings("abc", s.data);
    try std.testing.expect(s.fin);
}

test "decode a STREAM frame without length runs to the end" {
    // type 0x08 (no OFF, no LEN, no FIN), id=0, then the rest is data
    const d = try decode(&.{ 0x08, 0x00, 'h', 'i' });
    const s = d.frame.stream;
    try std.testing.expectEqual(@as(u64, 0), s.offset);
    try std.testing.expectEqualStrings("hi", s.data);
    try std.testing.expect(!s.fin);
}

test "decode a CRYPTO frame" {
    const d = try decode(&.{ 0x06, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' });
    const cr = d.frame.crypto;
    try std.testing.expectEqual(@as(u64, 0), cr.offset);
    try std.testing.expectEqualStrings("hello", cr.data);
}

test "STREAM and CRYPTO offset plus length must fit the QUIC varint range" {
    const max = [_]u8{0xff} ** 8;
    const crypto_over = [_]u8{0x06} ++ max ++ [_]u8{ 0x01, 'x' };
    try std.testing.expectError(error.FrameEncodingError, decode(&crypto_over));

    const stream_over = [_]u8{ 0x0e, 0x00 } ++ max ++ [_]u8{ 0x01, 'x' };
    try std.testing.expectError(error.FrameEncodingError, decode(&stream_over));

    const stream_no_len_over = [_]u8{ 0x0c, 0x00 } ++ max ++ [_]u8{'x'};
    try std.testing.expectError(error.FrameEncodingError, decode(&stream_no_len_over));
}

test "decode an ACK frame and walk its ranges" {
    // largest=10, delay=0, range_count=1, first_range=2, [gap=1, len=3]
    const d = try decode(&.{ 0x02, 0x0a, 0x00, 0x01, 0x02, 0x01, 0x03 });
    const ack = d.frame.ack;
    try std.testing.expectEqual(@as(u64, 10), ack.largest);
    try std.testing.expectEqual(@as(u64, 2), ack.first_range);
    var it = ackRanges(ack.ranges);
    const r = it.next().?;
    try std.testing.expectEqual(@as(u64, 1), r.gap);
    try std.testing.expectEqual(@as(u64, 3), r.len);
    try std.testing.expect(it.next() == null);
}

test "decode an ACK_ECN frame retains ECN counts" {
    // largest=5, delay=0, range_count=0, first_range=0, ect0=7, ect1=0, ce=2.
    const d = try decode(&.{ 0x03, 0x05, 0x00, 0x00, 0x00, 0x07, 0x00, 0x02 });
    const ack = d.frame.ack;
    try std.testing.expectEqual(@as(u64, 5), ack.largest);
    try std.testing.expectEqual(@as(u64, 7), ack.ecn.?.ect0);
    try std.testing.expectEqual(@as(u64, 0), ack.ecn.?.ect1);
    try std.testing.expectEqual(@as(u64, 2), ack.ecn.?.ce);
}

test "decode MAX_STREAMS variants" {
    const bidi = try decode(&.{ 0x12, 0x3f }); // max = 63 (1-byte varint)
    try std.testing.expect(bidi.frame.max_streams.bidi);
    try std.testing.expectEqual(@as(u64, 63), bidi.frame.max_streams.max);
    try std.testing.expect(!(try decode(&.{ 0x13, 0x3f })).frame.max_streams.bidi);
}

test "decode a transport CONNECTION_CLOSE" {
    // error=0x0a (protocol_violation), frame_type=0, reason "no"
    const d = try decode(&.{ 0x1c, 0x0a, 0x00, 0x02, 'n', 'o' });
    const cc = d.frame.connection_close;
    try std.testing.expect(!cc.app);
    try std.testing.expectEqual(@as(u64, 0x0a), cc.error_code);
    try std.testing.expectEqualStrings("no", cc.reason);
}

test "truncated frame is rejected" {
    try std.testing.expectError(error.Truncated, decode(&.{0x06})); // CRYPTO with no offset
    try std.testing.expectError(error.Truncated, decode(&.{ 0x06, 0x00, 0x05, 'h' })); // claims 5, has 1
}

test "four-gibibyte wire lengths are truncated" {
    const huge = [_]u8{ 0xC0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectError(error.Truncated, decode(&([_]u8{ 0x06, 0x00 } ++ huge)));
    try std.testing.expectError(error.Truncated, decode(&([_]u8{0x07} ++ huge)));
    try std.testing.expectError(error.Truncated, decode(&([_]u8{ 0x0A, 0x00 } ++ huge)));
    try std.testing.expectError(error.Truncated, decode(&([_]u8{ 0x1C, 0x00, 0x00 } ++ huge)));
}

test "empty NEW_TOKEN is a frame encoding error" {
    try std.testing.expectError(error.FrameEncodingError, decode(&.{ 0x07, 0x00 }));
}

test "NEW_CONNECTION_ID with retire_prior_to past seq is rejected" {
    // seq=1, retire_prior_to=2 (invalid), ...
    try std.testing.expectError(error.FrameEncodingError, decode(&.{ 0x18, 0x01, 0x02 }));
}

test "encodeStream round-trips through decode" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try encodeStream(&out, gpa, 4, 8, "abc", true);
    const d = try decode(out.items);
    const s = d.frame.stream;
    try std.testing.expectEqual(@as(u64, 4), s.stream_id);
    try std.testing.expectEqual(@as(u64, 8), s.offset);
    try std.testing.expectEqualStrings("abc", s.data);
    try std.testing.expect(s.fin);
    try std.testing.expectEqual(out.items.len, d.len);
}

test "encodeStream omits the offset field when offset is zero" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try encodeStream(&out, gpa, 0, 0, "hi", false);
    // type 0x0a (BASE|LEN, no OFF, no FIN), id 0, len 2, "hi".
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x0a, 0x00, 0x02, 'h', 'i' }, out.items);
    const s = (try decode(out.items)).frame.stream;
    try std.testing.expectEqual(@as(u64, 0), s.offset);
    try std.testing.expect(!s.fin);
}

test "encodeAck round-trips through decode" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try encodeAck(&out, gpa, 10, 0, 2);
    const ack = (try decode(out.items)).frame.ack;
    try std.testing.expectEqual(@as(u64, 10), ack.largest);
    try std.testing.expectEqual(@as(u64, 2), ack.first_range);
    var it = ackRanges(ack.ranges);
    try std.testing.expect(it.next() == null); // no additional ranges
}

test "encodeCrypto round-trips through decode" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try encodeCrypto(&out, gpa, 64, "hello");
    const d = try decode(out.items);
    try std.testing.expectEqual(@as(u64, 64), d.frame.crypto.offset);
    try std.testing.expectEqualStrings("hello", d.frame.crypto.data);
    try std.testing.expectEqual(out.items.len, d.len);
}

test "encodeResetStream round-trips through decode" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try encodeResetStream(&out, gpa, 4, 0x010c, 42);
    const d = try decode(out.items);
    const r = d.frame.reset_stream;
    try std.testing.expectEqual(@as(u64, 4), r.stream_id);
    try std.testing.expectEqual(@as(u64, 0x010c), r.error_code);
    try std.testing.expectEqual(@as(u64, 42), r.final_size);
    try std.testing.expectEqual(out.items.len, d.len);
}

test "encodeMaxStreamData round-trips through decode" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try encodeMaxStreamData(&out, gpa, 8, 65536);
    const d = try decode(out.items);
    try std.testing.expectEqual(@as(u64, 8), d.frame.max_stream_data.stream_id);
    try std.testing.expectEqual(@as(u64, 65536), d.frame.max_stream_data.max);
    try std.testing.expectEqual(out.items.len, d.len);
}

test "encodeStopSending round-trips through decode" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try encodeStopSending(&out, gpa, 8, 0x010c);
    const d = try decode(out.items);
    const s = d.frame.stop_sending;
    try std.testing.expectEqual(@as(u64, 8), s.stream_id);
    try std.testing.expectEqual(@as(u64, 0x010c), s.error_code);
    try std.testing.expectEqual(out.items.len, d.len);
}

test "two encoded frames decode back to back in one payload" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try encodeAck(&out, gpa, 5, 0, 0);
    try encodeStream(&out, gpa, 0, 0, "ok", true);
    const first = try decode(out.items);
    try std.testing.expect(first.frame == .ack);
    const second = try decode(out.items[first.len..]);
    try std.testing.expectEqualStrings("ok", second.frame.stream.data);
    try std.testing.expect(second.frame.stream.fin);
}
