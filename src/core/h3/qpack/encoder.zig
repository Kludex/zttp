//! A stateless QPACK encoder (RFC 9204 section 4). It never uses the dynamic
//! table - the field-section prefix is always Required Insert Count 0, Base 0 -
//! so there is no encoder bookkeeping and no compression-oracle (CRIME-style)
//! risk, mirroring the HPACK encoder. Each field line is emitted as the smallest
//! static-table form: an indexed line when the name AND value both match, a
//! literal with a static name reference when only the name matches, otherwise a
//! literal with a literal name. Values are raw (never Huffman), which any QPACK
//! decoder accepts.

const std = @import("std");
const static_table = @import("static_table.zig");

const Header = @import("../../events.zig").Header;

/// Encode a prefix integer (RFC 7541 5.1, shared with HPACK/QPACK). The high
/// `8 - prefix` bits of the first octet are supplied by the caller in `pattern`.
fn writeInteger(out: *std.ArrayList(u8), gpa: std.mem.Allocator, value: usize, prefix: u4, pattern: u8) !void {
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

/// Encode a raw (non-Huffman) string literal with a `prefix`-bit length. `pattern`
/// supplies the opcode bits above the length prefix (the H bit included, left 0).
fn writeString(out: *std.ArrayList(u8), gpa: std.mem.Allocator, prefix: u4, pattern: u8, s: []const u8) !void {
    try writeInteger(out, gpa, s.len, prefix, pattern);
    try out.appendSlice(gpa, s);
}

/// Encode one header line as its smallest static-table form (RFC 9204 4.5).
pub fn encodeHeader(out: *std.ArrayList(u8), gpa: std.mem.Allocator, h: Header) !void {
    if (static_table.nameValueIndex(h.name, h.value)) |idx| {
        // Indexed field line (4.5.2): 1Tiiiiii with T=1 (static), 6-bit index.
        try writeInteger(out, gpa, idx, 6, 0xC0);
        return;
    }
    if (static_table.nameIndex(h.name)) |idx| {
        // Literal with static name reference (4.5.4): 01NTiiii with N=0, T=1,
        // 4-bit name index, then the value (7-bit length prefix).
        try writeInteger(out, gpa, idx, 4, 0x50);
        try writeString(out, gpa, 7, 0x00, h.value);
        return;
    }
    // Literal with literal name (4.5.6): 001Nhiii with N=0, H=0, 3-bit name
    // length prefix, then the value (7-bit length prefix).
    try writeString(out, gpa, 3, 0x20, h.name);
    try writeString(out, gpa, 7, 0x00, h.value);
}

/// Encode a full field section: the prefix (RIC 0, Base 0) then every header.
pub fn encode(out: *std.ArrayList(u8), gpa: std.mem.Allocator, headers: []const Header) !void {
    try out.appendSlice(gpa, &.{ 0x00, 0x00 }); // Required Insert Count 0, Base 0
    for (headers) |h| try encodeHeader(out, gpa, h);
}

const testing = std.testing;

fn roundTrip(headers: []const Header) !void {
    const decoder = @import("decoder.zig");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(testing.allocator);
    try encode(&block, testing.allocator, headers);

    var d = decoder.Decoder.init(testing.allocator, 1 << 20);
    defer d.deinit();
    const out = try d.decode(block.items);
    try testing.expectEqual(headers.len, out.len);
    for (headers, out) |want, got| {
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqualStrings(want.value, got.value);
    }
}

test "an exact static name+value match is an indexed line" {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(testing.allocator);
    // :status 200 is static index 25; indexed line = 0xC0 | 25.
    try encode(&block, testing.allocator, &.{.{ .name = ":status", .value = "200" }});
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0xC0 | 25 }, block.items);
}

test "a static name match emits a literal with a name reference" {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(testing.allocator);
    // content-type's lowest index is 44; name ref = 0x50 | 12 (4-bit prefix max
    // is 15, so 44 needs the extension form). Easier to round-trip than pin bytes.
    try roundTrip(&.{.{ .name = "content-type", .value = "application/custom" }});
}

test "a fully novel header is a literal name and value" {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(testing.allocator);
    try encode(&block, testing.allocator, &.{.{ .name = "x-custom", .value = "v" }});
    // Literal name (001), len 8: the 3-bit length prefix maxes at 7, so 8 uses the
    // extension form -> 0x27 then continuation 0x01, the name, then 0x01 + "v".
    try testing.expectEqualSlices(u8, &([_]u8{ 0x00, 0x00, 0x27, 0x01 } ++ "x-custom".* ++ [_]u8{ 0x01, 'v' }), block.items);
}

test "encode then decode round-trips a response header list" {
    try roundTrip(&.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "x-custom", .value = "value" },
        .{ .name = "server", .value = "zttp" },
    });
}

test "a long value round-trips through the multi-octet length" {
    var big: [400]u8 = undefined;
    @memset(&big, 'a');
    try roundTrip(&.{.{ .name = "x-big", .value = &big }});
}

test "an empty header list encodes just the prefix" {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(testing.allocator);
    try encode(&block, testing.allocator, &.{});
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, block.items);
}
