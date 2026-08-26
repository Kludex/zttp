//! The HTTP/3 frame codec (RFC 9114 section 7.1): the simplest framing in the
//! whole stack - a varint type, a varint length, then exactly that many payload
//! octets. HTTP/3 has no per-frame stream id (that is the QUIC stream's job) and
//! no flow control or PING (QUIC owns those), so what is left is DATA, HEADERS,
//! and a few control-stream frames. Pure and zero-copy: a parsed frame's payload
//! is a slice INTO the fed (already QUIC-ordered) stream bytes.

const std = @import("std");
const varint = @import("../quic/varint.zig");

/// HTTP/3 frame types (RFC 9114 7.2 and 11.2.1). Non-exhaustive: an unknown type
/// is not an error - it MUST be skipped (RFC 9114 9), so the connection layer
/// discards it by `Decoded.len`.
pub const FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0d,
    _,
};

pub const Error = error{
    /// The frame is not fully buffered yet (the type, length, or payload runs past
    /// the end). Unlike inside a QUIC packet, an HTTP/3 stream is a growing byte
    /// run, so this is a genuine "feed more", not a hard error.
    NeedData,
};

pub const Frame = struct {
    ftype: FrameType,
    /// The raw payload. For DATA this is body bytes; for HEADERS the QPACK field
    /// block; for SETTINGS/GOAWAY/etc. the type-specific encoding.
    payload: []const u8,
};

pub const Decoded = struct {
    frame: Frame,
    len: usize,
};

/// Parse the frame at the start of `buf`. Returns NeedData when the full frame is
/// not yet buffered. Does not advance; the consumed length is `Decoded.len`.
pub fn decode(buf: []const u8) Error!Decoded {
    const t = varint.decode(buf) catch return error.NeedData;
    const l = varint.decode(buf[t.len..]) catch return error.NeedData;
    const start = t.len + l.len;
    const length = std.math.cast(usize, l.value) orelse return error.NeedData;
    const end = std.math.add(usize, start, length) catch return error.NeedData;
    if (end > buf.len) return error.NeedData;
    return .{
        .frame = .{ .ftype = @enumFromInt(t.value), .payload = buf[start..end] },
        .len = end,
    };
}

/// Whether a known frame type is a reserved "grease" value (RFC 9114 7.2.8):
/// 0x1f * N + 0x21. These MUST be ignored on receipt.
pub fn isReserved(t: u64) bool {
    if (t < 0x21) return false;
    return (t - 0x21) % 0x1f == 0;
}

/// HTTP/2 frame type code points that have no HTTP/3 equivalent (RFC 9114
/// 7.2.8/11.2.1). These are different from grease values: receiving one is
/// H3_FRAME_UNEXPECTED, not "ignore unknown".
pub fn isReservedHttp2(t: FrameType) bool {
    return switch (@intFromEnum(t)) {
        0x02, 0x06, 0x08, 0x09 => true,
        else => false,
    };
}

/// Append a frame to a growing buffer (the writer side). Used by the H3 writer to
/// emit DATA/HEADERS/SETTINGS.
pub fn append(list: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, ftype: FrameType, payload: []const u8) !void {
    try varint.append(list, gpa, @intFromEnum(ftype));
    try varint.append(list, gpa, payload.len);
    try list.appendSlice(gpa, payload);
}

test "decode a DATA frame" {
    const d = try decode(&.{ 0x00, 0x03, 'a', 'b', 'c' });
    try std.testing.expectEqual(FrameType.data, d.frame.ftype);
    try std.testing.expectEqualStrings("abc", d.frame.payload);
    try std.testing.expectEqual(@as(usize, 5), d.len);
}

test "decode a HEADERS frame" {
    const d = try decode(&.{ 0x01, 0x02, 0xAA, 0xBB });
    try std.testing.expectEqual(FrameType.headers, d.frame.ftype);
    try std.testing.expectEqual(@as(usize, 2), d.frame.payload.len);
}

test "an unknown frame type parses and is skippable" {
    // type 0x21 (reserved), length 1, one octet.
    const d = try decode(&.{ 0x21, 0x01, 0xFF });
    try std.testing.expect(isReserved(@intFromEnum(d.frame.ftype)));
    try std.testing.expectEqual(@as(usize, 3), d.len);
}

test "a truncated frame needs more data" {
    try std.testing.expectError(error.NeedData, decode(&.{0x00})); // no length yet
    try std.testing.expectError(error.NeedData, decode(&.{ 0x00, 0x05, 'a' })); // claims 5, has 1
}

test "a four-gibibyte frame length needs more data" {
    const encoded = [_]u8{ 0x00, 0xC0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectError(error.NeedData, decode(&encoded));
}

test "append round-trips through decode" {
    const gpa = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    try append(&buf, gpa, .data, "hello");
    const d = try decode(buf.items);
    try std.testing.expectEqual(FrameType.data, d.frame.ftype);
    try std.testing.expectEqualStrings("hello", d.frame.payload);
}

test "isReserved matches the grease formula" {
    try std.testing.expect(isReserved(0x21));
    try std.testing.expect(isReserved(0x21 + 0x1f));
    try std.testing.expect(!isReserved(0x04)); // SETTINGS
}

test "HTTP/2-only frame type code points are reserved errors" {
    try std.testing.expect(isReservedHttp2(@enumFromInt(0x02)));
    try std.testing.expect(isReservedHttp2(@enumFromInt(0x06)));
    try std.testing.expect(isReservedHttp2(@enumFromInt(0x08)));
    try std.testing.expect(isReservedHttp2(@enumFromInt(0x09)));
    try std.testing.expect(!isReservedHttp2(.data));
    try std.testing.expect(!isReservedHttp2(@enumFromInt(0x21))); // grease is ignored
}
