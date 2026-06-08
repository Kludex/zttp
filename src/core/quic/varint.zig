//! QUIC's variable-length integer (RFC 9000 section 16). The two most-significant
//! bits of the first byte select the length - 1, 2, 4, or 8 octets - and the
//! remaining 6/14/30/62 bits are the big-endian value. It is the single most-used
//! primitive in the QUIC and HTTP/3 stacks: every frame field, packet number,
//! stream id, and length prefix is a varint. Pure and zero-copy like scanner.zig:
//! decoding borrows from the fed buffer and never allocates.

const std = @import("std");

/// The largest value a 62-bit varint can hold (2^62 - 1). A value above this
/// cannot be encoded and is rejected by `len`/`encode`.
pub const MAX: u64 = (1 << 62) - 1;

pub const Error = error{
    /// Fewer octets are buffered than the first byte's length prefix demands.
    NeedData,
    /// A value exceeds the 62-bit varint ceiling and cannot be serialized.
    TooLarge,
};

/// A decoded varint plus how many octets it consumed, so the caller can advance.
pub const Decoded = struct {
    value: u64,
    len: usize,
};

/// Decode the varint at the start of `buf`. Returns NeedData when the prefix
/// announces more octets than are buffered, so a caller can retry after feeding
/// more. Does not advance; the consumed length is in `Decoded.len`.
pub fn decode(buf: []const u8) Error!Decoded {
    if (buf.len == 0) return error.NeedData;
    const prefix = buf[0] >> 6;
    const n: usize = @as(usize, 1) << @intCast(prefix);
    if (buf.len < n) return error.NeedData;
    var value: u64 = buf[0] & 0x3F;
    for (buf[1..n]) |b| value = (value << 8) | b;
    return .{ .value = value, .len = n };
}

/// The number of octets a value encodes to, or TooLarge if it exceeds MAX. The
/// minimal encoding is always chosen (RFC 9000 16: an encoder SHOULD use the
/// fewest octets), so two encoders agree byte-for-byte.
pub fn len(value: u64) Error!usize {
    if (value <= 0x3F) return 1;
    if (value <= 0x3FFF) return 2;
    if (value <= 0x3FFF_FFFF) return 4;
    if (value <= MAX) return 8;
    return error.TooLarge;
}

/// Encode `value` into `out` and return the slice written. `out` must hold at
/// least `len(value)` octets; a caller sizes it with `len` first.
pub fn encode(out: []u8, value: u64) Error![]u8 {
    const n = try len(value);
    std.debug.assert(out.len >= n);
    const tag: u8 = switch (n) {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        8 => 0xC0,
        else => unreachable,
    };
    var v = value;
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        out[i] = @truncate(v);
        v >>= 8;
    }
    out[0] |= tag;
    return out[0..n];
}

/// Append `value` to a growing list. The connection/writer layers build packets
/// this way; it mirrors how the H2 writer appends to its scratch buffer.
pub fn append(list: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, value: u64) !void {
    var scratch: [8]u8 = undefined;
    const slice = try encode(&scratch, value);
    try list.appendSlice(gpa, slice);
}

test "decode the four lengths from RFC 9000 appendix A.1" {
    try std.testing.expectEqual(@as(u64, 151_288_809_941_952_652), (try decode(&.{ 0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C })).value);
    try std.testing.expectEqual(@as(u64, 494_878_333), (try decode(&.{ 0x9D, 0x7F, 0x3E, 0x7D })).value);
    try std.testing.expectEqual(@as(u64, 15_293), (try decode(&.{ 0x7B, 0xBD })).value);
    try std.testing.expectEqual(@as(u64, 37), (try decode(&.{0x25})).value);
    try std.testing.expectEqual(@as(u64, 37), (try decode(&.{ 0x40, 0x25 })).value);
}

test "decode reports the consumed length" {
    try std.testing.expectEqual(@as(usize, 1), (try decode(&.{0x25})).len);
    try std.testing.expectEqual(@as(usize, 8), (try decode(&.{ 0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C })).len);
}

test "decode needs the full announced length" {
    try std.testing.expectError(error.NeedData, decode(&.{}));
    try std.testing.expectError(error.NeedData, decode(&.{0xC0}));
    const two = [_]u8{ 0x40, 0x25 };
    try std.testing.expectError(error.NeedData, decode(two[0..1]));
}

test "len picks the minimal encoding" {
    try std.testing.expectEqual(@as(usize, 1), try len(0));
    try std.testing.expectEqual(@as(usize, 1), try len(0x3F));
    try std.testing.expectEqual(@as(usize, 2), try len(0x40));
    try std.testing.expectEqual(@as(usize, 2), try len(0x3FFF));
    try std.testing.expectEqual(@as(usize, 4), try len(0x4000));
    try std.testing.expectEqual(@as(usize, 8), try len(0x4000_0000));
    try std.testing.expectEqual(@as(usize, 8), try len(MAX));
    try std.testing.expectError(error.TooLarge, len(MAX + 1));
}

test "encode round-trips and is minimal" {
    var buf: [8]u8 = undefined;
    for ([_]u64{ 0, 37, 0x3F, 0x40, 15_293, 0x3FFF, 494_878_333, MAX }) |v| {
        const enc = try encode(&buf, v);
        const dec = try decode(enc);
        try std.testing.expectEqual(v, dec.value);
        try std.testing.expectEqual(try len(v), dec.len);
    }
}

test "encode matches the RFC appendix A.1 vectors" {
    var buf: [8]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{0x25}, try encode(&buf, 37));
    try std.testing.expectEqualSlices(u8, &.{ 0x7B, 0xBD }, try encode(&buf, 15_293));
    try std.testing.expectEqualSlices(u8, &.{ 0x9D, 0x7F, 0x3E, 0x7D }, try encode(&buf, 494_878_333));
    try std.testing.expectEqualSlices(u8, &.{ 0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C }, try encode(&buf, 151_288_809_941_952_652));
}

test "append writes onto a growing list" {
    const gpa = std.testing.allocator;
    var list: std.ArrayListUnmanaged(u8) = .empty;
    defer list.deinit(gpa);
    try append(&list, gpa, 37);
    try append(&list, gpa, 15_293);
    try std.testing.expectEqualSlices(u8, &.{ 0x25, 0x7B, 0xBD }, list.items);
}
