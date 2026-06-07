//! A stateless HPACK encoder (RFC 7541). It never uses the dynamic table - every
//! field is emitted as "literal without indexing", with the name replaced by a
//! static-table index when one matches exactly. No dynamic table means no encoder
//! bookkeeping and no compression-oracle (CRIME-style) risk; the small size cost
//! is irrelevant for a parser library. Output is raw (never Huffman) literals,
//! which any HPACK decoder accepts.

const std = @import("std");
const static_table = @import("static_table.zig");

const Header = @import("../../events.zig").Header;

/// Encode an HPACK integer with an `prefix`-bit prefix (RFC 7541 5.1). The high
/// `8 - prefix` bits of the first octet are supplied by the caller in `pattern`.
fn writeInteger(out: *std.ArrayList(u8), gpa: std.mem.Allocator, value: usize, prefix: u3, pattern: u8) !void {
    const max_prefix: usize = (@as(usize, 1) << prefix) - 1;
    if (value < max_prefix) {
        try out.append(gpa, pattern | @as(u8, @intCast(value)));
        return;
    }
    try out.append(gpa, pattern | @as(u8, @intCast(max_prefix)));
    var rem = value - max_prefix;
    while (rem >= 128) {
        try out.append(gpa, @as(u8, @intCast(rem & 0x7f)) | 0x80);
        rem >>= 7;
    }
    try out.append(gpa, @intCast(rem));
}

/// Encode a raw (non-Huffman) string literal: a 7-bit length prefix (H bit 0)
/// followed by the bytes.
fn writeString(out: *std.ArrayList(u8), gpa: std.mem.Allocator, s: []const u8) !void {
    try writeInteger(out, gpa, s.len, 7, 0x00);
    try out.appendSlice(gpa, s);
}

/// The static-table index whose NAME equals `name`, or 0 if none. Lowest index
/// wins (the canonical choice).
fn staticNameIndex(name: []const u8) usize {
    for (static_table.TABLE, 0..) |e, i| {
        if (std.mem.eql(u8, e.name, name)) return i + 1;
    }
    return 0;
}

/// Encode one header as "literal without indexing" (RFC 7541 6.2.2, prefix
/// `0000`). If the name matches a static entry, reference it by index; otherwise
/// emit the name as a literal.
pub fn encodeHeader(out: *std.ArrayList(u8), gpa: std.mem.Allocator, h: Header) !void {
    const idx = staticNameIndex(h.name);
    if (idx != 0) {
        try writeInteger(out, gpa, idx, 4, 0x00); // 0000 + 4-bit name index
    } else {
        try out.append(gpa, 0x00); // 0000 0000: literal name follows
        try writeString(out, gpa, h.name);
    }
    try writeString(out, gpa, h.value);
}

/// Encode a full header list into `out`.
pub fn encode(out: *std.ArrayList(u8), gpa: std.mem.Allocator, headers: []const Header) !void {
    for (headers) |h| try encodeHeader(out, gpa, h);
}

const testing = std.testing;

test "encode then decode round-trips a header list" {
    const decoder = @import("decoder.zig");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(testing.allocator);
    const headers = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = "x-custom", .value = "value" },
    };
    try encode(&block, testing.allocator, &headers);

    var d = decoder.Decoder.init(testing.allocator, 4096, 1 << 20);
    defer d.deinit();
    const out = try d.decodeBlock(block.items);
    try testing.expectEqual(@as(usize, 3), out.len);
    try testing.expectEqualStrings(":method", out[0].name);
    try testing.expectEqualStrings("GET", out[0].value);
    try testing.expectEqualStrings(":path", out[1].name);
    try testing.expectEqualStrings("/index.html", out[1].value);
    try testing.expectEqualStrings("x-custom", out[2].name);
    try testing.expectEqualStrings("value", out[2].value);
}

test "a static-name match uses the indexed name" {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(testing.allocator);
    // content-length is static index 28; emitted as 0x0? with a literal value.
    try encodeHeader(&block, testing.allocator, .{ .name = "content-length", .value = "5" });
    // First octet: literal without indexing (0000) + index 28 -> needs the
    // extension form (4-bit prefix max is 15), so 0x0F then the continuation.
    try testing.expect(block.items[0] & 0xF0 == 0x00);
}

test "writeInteger handles the multi-octet extension" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    // RFC 7541 C.1.1: encoding 1337 with a 5-bit prefix -> 31, 154, 10.
    try writeInteger(&out, testing.allocator, 1337, 5, 0x00);
    try testing.expectEqualSlices(u8, &[_]u8{ 31, 154, 10 }, out.items);
}

test "encode large header round-trips through the multi-octet length" {
    const decoder = @import("decoder.zig");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(testing.allocator);
    var big: [400]u8 = undefined;
    @memset(&big, 'a');
    try encodeHeader(&block, testing.allocator, .{ .name = "x-big", .value = &big });
    var d = decoder.Decoder.init(testing.allocator, 4096, 1 << 20);
    defer d.deinit();
    const out = try d.decodeBlock(block.items);
    try testing.expectEqualStrings(&big, out[0].value);
}
