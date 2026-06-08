//! The QPACK field-section decoder (RFC 9204 section 4): turns a HEADERS frame's
//! QPACK-encoded field block into (name, value) pairs. It handles the field-
//! section prefix and the four field-line representations - indexed, indexed with
//! post-base index, literal with name reference, and literal with literal name -
//! resolving static-table references and Huffman-decoded literals.
//!
//! Scope: the static table and literals, the complete read path when the dynamic
//! table is disabled (we advertise QPACK_MAX_TABLE_CAPACITY = 0, so a conformant
//! peer MUST NOT emit dynamic references or post-base indices). A nonzero Required
//! Insert Count is therefore a protocol error here; full dynamic-table support is
//! the follow-up. Decoded names/values are staged into an owned store so their
//! slices stay valid until the next decode, exactly like the HPACK decoder.

const std = @import("std");
const static_table = @import("static_table.zig");
const huffman = @import("../../h2/hpack/huffman.zig");

pub const Header = @import("../../events.zig").Header;

pub const Error = error{
    /// The block is truncated, an integer overflows, or a Huffman string is
    /// malformed (RFC 9204 4.1).
    DecompressionFailed,
    /// A representation referenced the dynamic table (or a nonzero Required Insert
    /// Count) while it is disabled here.
    DynamicReferenceUnsupported,
    /// A static-table index is out of range.
    BadIndex,
    OutOfMemory,
};

pub const Decoder = struct {
    gpa: std.mem.Allocator,
    headers: std.ArrayListUnmanaged(Header) = .empty,
    store: std.ArrayListUnmanaged(u8) = .empty,
    max_field_section_size: usize,

    pub fn init(gpa: std.mem.Allocator, max_field_section_size: usize) Decoder {
        return .{ .gpa = gpa, .max_field_section_size = max_field_section_size };
    }

    pub fn deinit(self: *Decoder) void {
        self.headers.deinit(self.gpa);
        self.store.deinit(self.gpa);
    }

    /// Decode one field section. The returned slice (and the slices inside it) are
    /// valid until the next `decode` call - the store is cleared at the start, so
    /// a caller must materialise anything it keeps, matching the core's discipline.
    pub fn decode(self: *Decoder, block: []const u8) Error![]const Header {
        self.headers.clearRetainingCapacity();
        self.store.clearRetainingCapacity();
        var p = Parser{ .buf = block };

        // Field-section prefix (RFC 9204 4.5.1): Required Insert Count, then Base.
        const ric = try p.integer(8);
        if (ric != 0) return error.DynamicReferenceUnsupported;
        if (p.pos >= block.len) return error.DecompressionFailed;
        // Sign bit + Delta Base; with RIC 0 the base is 0, so we just consume it.
        _ = try p.integer(7);

        var section_size: usize = 0;
        while (p.pos < block.len) {
            const b = p.buf[p.pos];
            if (b & 0x80 != 0) {
                try self.indexed(&p, &section_size);
            } else if (b & 0x40 != 0) {
                try self.literalNameRef(&p, &section_size);
            } else if (b & 0x20 != 0) {
                try self.literalLiteralName(&p, &section_size);
            } else {
                // 0x10 = indexed with post-base index, 0x00 = literal with post-base
                // name ref: both are dynamic-table-only (RFC 9204 4.5.4/4.5.6).
                return error.DynamicReferenceUnsupported;
            }
            if (section_size > self.max_field_section_size) return error.DecompressionFailed;
        }
        return self.headers.items;
    }

    fn indexed(self: *Decoder, p: *Parser, section_size: *usize) Error!void {
        // 1Tiiiiii: T must be 1 (static table); T=0 is a dynamic reference.
        if (p.buf[p.pos] & 0x40 == 0) return error.DynamicReferenceUnsupported;
        const index = try p.integer(6);
        const entry = static_table.get(index) orelse return error.BadIndex;
        try self.emit(entry.name, entry.value, section_size);
    }

    fn literalNameRef(self: *Decoder, p: *Parser, section_size: *usize) Error!void {
        // 01NTiiii: T must be 1 (static name reference).
        if (p.buf[p.pos] & 0x10 == 0) return error.DynamicReferenceUnsupported;
        const index = try p.integer(4);
        const entry = static_table.get(index) orelse return error.BadIndex;
        const value = try self.string(p, 7);
        try self.emit(entry.name, value, section_size);
    }

    fn literalLiteralName(self: *Decoder, p: *Parser, section_size: *usize) Error!void {
        // 001Nhiii: a 3-bit name-length prefix, then the value with a 7-bit prefix.
        const name = try self.string(p, 3);
        const value = try self.string(p, 7);
        try self.emit(name, value, section_size);
    }

    fn emit(self: *Decoder, name: []const u8, value: []const u8, section_size: *usize) Error!void {
        section_size.* += name.len + value.len + 32; // RFC 9204 4.1 size accounting
        self.headers.append(self.gpa, .{ .name = name, .value = value }) catch return error.OutOfMemory;
    }

    /// Decode a length-prefixed (optionally Huffman) string into the store and
    /// return the stored slice. `prefix` is the integer prefix width for the
    /// length; the high bit of the prefix byte is the Huffman flag.
    fn string(self: *Decoder, p: *Parser, prefix: u4) Error![]const u8 {
        if (p.pos >= p.buf.len) return error.DecompressionFailed;
        const huff = (p.buf[p.pos] & (@as(u8, 1) << @intCast(prefix))) != 0;
        const len = try p.integer(prefix);
        const raw = p.take(len) catch return error.DecompressionFailed;
        const start = self.store.items.len;
        if (huff) {
            const need = huffman.decodedLen(raw) catch return error.DecompressionFailed;
            self.store.appendNTimes(self.gpa, 0, need) catch return error.OutOfMemory;
            _ = huffman.decode(raw, self.store.items[start..]) catch return error.DecompressionFailed;
        } else {
            self.store.appendSlice(self.gpa, raw) catch return error.OutOfMemory;
        }
        return self.store.items[start..];
    }
};

const Parser = struct {
    buf: []const u8,
    pos: usize = 0,

    /// A QPACK/HPACK prefix integer (RFC 7541 5.1): `prefix` low bits of the first
    /// byte, then a base-128 continuation if they are all 1.
    fn integer(self: *Parser, prefix: u4) Error!u64 {
        if (self.pos >= self.buf.len) return error.DecompressionFailed;
        const max_prefix: u64 = (@as(u64, 1) << @as(u6, prefix)) - 1;
        var value: u64 = self.buf[self.pos] & max_prefix;
        self.pos += 1;
        if (value < max_prefix) return value;
        var shift: u6 = 0;
        while (true) {
            if (self.pos >= self.buf.len) return error.DecompressionFailed;
            const b = self.buf[self.pos];
            self.pos += 1;
            value += @as(u64, b & 0x7f) << shift;
            if (b & 0x80 == 0) break;
            shift += 7;
            if (shift > 62) return error.DecompressionFailed;
        }
        return value;
    }

    fn take(self: *Parser, n: u64) Error![]const u8 {
        if (self.pos + n > self.buf.len) return error.DecompressionFailed;
        const s = self.buf[self.pos .. self.pos + @as(usize, @intCast(n))];
        self.pos += @intCast(n);
        return s;
    }
};

const testing = std.testing;

test "decode an indexed static field" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    // prefix: RIC=0 (0x00), Base=0 (0x00); then 0xC0|17 = index 17 (:method GET).
    const block = [_]u8{ 0x00, 0x00, 0xC0 | 17 };
    const hs = try dec.decode(&block);
    try testing.expectEqual(@as(usize, 1), hs.len);
    try testing.expectEqualStrings(":method", hs[0].name);
    try testing.expectEqualStrings("GET", hs[0].value);
}

test "decode a literal with a static name reference (no Huffman)" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    // name index 0 (:authority) via 0x50|0 = 0x50 (01 N=0 T=1 0000); value "h" len 1.
    const block = [_]u8{ 0x00, 0x00, 0x50, 0x01, 'h' };
    const hs = try dec.decode(&block);
    try testing.expectEqualStrings(":authority", hs[0].name);
    try testing.expectEqualStrings("h", hs[0].value);
}

test "decode a literal name and literal value (no Huffman)" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    // 0x20 (001 N=0 H=0 len-prefix3): name len 3 "abc"; value len 1 "x".
    const block = [_]u8{ 0x00, 0x00, 0x20 | 3, 'a', 'b', 'c', 0x01, 'x' };
    const hs = try dec.decode(&block);
    try testing.expectEqualStrings("abc", hs[0].name);
    try testing.expectEqualStrings("x", hs[0].value);
}

test "a nonzero required insert count is unsupported" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    try testing.expectError(error.DynamicReferenceUnsupported, dec.decode(&.{ 0x01, 0x00 }));
}

test "a dynamic indexed reference is unsupported" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    // 0x80 = indexed, T=0 (dynamic).
    try testing.expectError(error.DynamicReferenceUnsupported, dec.decode(&.{ 0x00, 0x00, 0x80 }));
}

test "an out-of-range static index is rejected" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    // index 99 (past the 0-98 table): 0xC0|63 then continuation for 99.
    const block = [_]u8{ 0x00, 0x00, 0xFF, 36 }; // 63 + 36 = 99
    try testing.expectError(error.BadIndex, dec.decode(&block));
}
