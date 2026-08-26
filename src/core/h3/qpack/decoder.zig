//! The QPACK field-section decoder (RFC 9204 section 4): turns a HEADERS frame's
//! QPACK-encoded field block into (name, value) pairs. It handles the field-
//! section prefix and the four field-line representations - indexed, indexed with
//! post-base index, literal with name reference, and literal with literal name -
//! resolving static-table references and Huffman-decoded literals.
//!
//! Scope: static fields, literals, and dynamic-table entries already delivered on
//! the encoder stream. A header block whose Required Insert Count is ahead of the
//! encoder stream returns `error.Blocked`; the HTTP/3 connection stores and resumes
//! that block. Decoded names/values are staged into an owned store so their slices
//! stay valid until the next decode, exactly like the HPACK decoder.

const std = @import("std");
const static_table = @import("static_table.zig");
const huffman = @import("../../h2/hpack/huffman.zig");

pub const Header = @import("../../events.zig").Header;

pub const Error = error{
    /// The block is truncated, an integer overflows, or a Huffman string is
    /// malformed (RFC 9204 4.1).
    DecompressionFailed,
    /// An encoder-stream instruction is syntactically valid so far but incomplete.
    NeedData,
    /// A dynamic reference depends on encoder-stream instructions that have not
    /// arrived yet.
    Blocked,
    /// A static-table index is out of range.
    BadIndex,
    OutOfMemory,
};

// A name/value pair as offsets into `store`, not slices: the store is an
// ArrayList that may reallocate as later fields append to it, so a slice taken
// mid-decode can dangle. Offsets are stable; they are resolved into slices once,
// after the whole block is decoded and the store can no longer move.
const Span = struct { off: usize, len: usize };
const Field = struct { name: Span, value: Span };
const DynamicEntry = struct { name: []u8, value: []u8, size: usize, abs: u64 };
pub const EncoderProgress = struct { consumed: usize, inserts: u64 };

pub const Decoder = struct {
    gpa: std.mem.Allocator,
    headers: std.ArrayListUnmanaged(Header) = .empty,
    fields: std.ArrayListUnmanaged(Field) = .empty,
    store: std.ArrayListUnmanaged(u8) = .empty,
    dynamic: std.ArrayListUnmanaged(DynamicEntry) = .empty,
    dynamic_size: usize = 0,
    dynamic_capacity: usize = 0,
    max_dynamic_capacity: usize = 0,
    insert_count: u64 = 0,
    last_required_insert_count: u64 = 0,
    max_field_section_size: usize,

    pub fn init(gpa: std.mem.Allocator, max_field_section_size: usize) Decoder {
        return .{ .gpa = gpa, .max_field_section_size = max_field_section_size };
    }

    pub fn deinit(self: *Decoder) void {
        self.headers.deinit(self.gpa);
        self.fields.deinit(self.gpa);
        self.store.deinit(self.gpa);
        for (self.dynamic.items) |e| {
            self.gpa.free(e.name);
            self.gpa.free(e.value);
        }
        self.dynamic.deinit(self.gpa);
    }

    pub fn setMaxDynamicCapacity(self: *Decoder, cap: usize) void {
        self.max_dynamic_capacity = cap;
        if (self.dynamic_capacity > cap) {
            self.dynamic_capacity = cap;
            self.evictToCapacity();
        }
    }

    pub fn processEncoder(self: *Decoder, bytes: []const u8) Error!EncoderProgress {
        var p = Parser{ .buf = bytes };
        const before = self.insert_count;
        while (p.pos < bytes.len) {
            const start = p.pos;
            const b = p.buf[p.pos];
            if (b & 0x80 != 0) {
                self.encoderInsertNameRef(&p) catch |err| switch (err) {
                    error.NeedData => return .{ .consumed = start, .inserts = self.insert_count - before },
                    else => return err,
                };
            } else if (b & 0xC0 == 0x40) {
                self.encoderInsertLiteral(&p) catch |err| switch (err) {
                    error.NeedData => return .{ .consumed = start, .inserts = self.insert_count - before },
                    else => return err,
                };
            } else if (b & 0xE0 == 0x20) {
                const cap = p.integer(5) catch |err| switch (err) {
                    error.NeedData => return .{ .consumed = start, .inserts = self.insert_count - before },
                    else => return err,
                };
                if (cap > self.max_dynamic_capacity) return error.DecompressionFailed;
                self.dynamic_capacity = @intCast(cap);
                self.evictToCapacity();
            } else if (b & 0xE0 == 0x00) {
                const index = p.integer(5) catch |err| switch (err) {
                    error.NeedData => return .{ .consumed = start, .inserts = self.insert_count - before },
                    else => return err,
                };
                const e = self.dynamicRelative(index, self.insert_count) orelse return error.BadIndex;
                try self.insertDynamic(e.name, e.value);
            } else return error.DecompressionFailed;
        }
        return .{ .consumed = p.pos, .inserts = self.insert_count - before };
    }

    pub fn lastRequiredInsertCount(self: *const Decoder) u64 {
        return self.last_required_insert_count;
    }

    fn intern(self: *Decoder, bytes: []const u8) Error!Span {
        const off = self.store.items.len;
        self.store.appendSlice(self.gpa, bytes) catch return error.OutOfMemory;
        return .{ .off = off, .len = bytes.len };
    }

    /// Decode one field section. The returned slice (and the slices inside it) are
    /// valid until the next `decode` call - the store is cleared at the start, so
    /// a caller must materialise anything it keeps, matching the core's discipline.
    pub fn decode(self: *Decoder, block: []const u8) Error![]const Header {
        self.headers.clearRetainingCapacity();
        self.fields.clearRetainingCapacity();
        self.store.clearRetainingCapacity();
        self.last_required_insert_count = 0;
        var p = Parser{ .buf = block };

        // Field-section prefix (RFC 9204 4.5.1): Required Insert Count, then Base.
        const encoded_ric = try p.integer(8);
        if (p.pos >= block.len) return error.DecompressionFailed;
        const base_first = p.buf[p.pos];
        const sign = (base_first & 0x80) != 0;
        const delta = try p.integer(7);
        const ric = try self.requiredInsertCount(encoded_ric);
        if (ric > self.insert_count) return error.Blocked;
        self.last_required_insert_count = ric;
        const base = if (sign) blk: {
            const distance = std.math.add(u64, delta, 1) catch return error.DecompressionFailed;
            if (distance > ric) return error.DecompressionFailed;
            break :blk ric - distance;
        } else std.math.add(u64, ric, delta) catch return error.DecompressionFailed;

        var section_size: usize = 0;
        while (p.pos < block.len) {
            const b = p.buf[p.pos];
            if (b & 0x80 != 0) {
                try self.indexed(&p, base, &section_size);
            } else if (b & 0x40 != 0) {
                try self.literalNameRef(&p, base, &section_size);
            } else if (b & 0x20 != 0) {
                try self.literalLiteralName(&p, &section_size);
            } else if (b & 0x10 != 0) {
                try self.indexedPostBase(&p, base, &section_size);
            } else {
                try self.literalPostBaseNameRef(&p, base, &section_size);
            }
            if (section_size > self.max_field_section_size) return error.DecompressionFailed;
        }
        // The store can no longer move; resolve every offset pair into a slice.
        for (self.fields.items) |f| {
            self.headers.append(self.gpa, .{
                .name = self.store.items[f.name.off .. f.name.off + f.name.len],
                .value = self.store.items[f.value.off .. f.value.off + f.value.len],
            }) catch return error.OutOfMemory;
        }
        return self.headers.items;
    }

    fn indexed(self: *Decoder, p: *Parser, base: u64, section_size: *usize) Error!void {
        const is_static = (p.buf[p.pos] & 0x40) != 0;
        const index = try p.integer(6);
        if (is_static) {
            const entry = static_table.get(index) orelse return error.BadIndex;
            try self.emit(try self.intern(entry.name), try self.intern(entry.value), section_size);
        } else {
            const entry = self.dynamicRelative(index, base) orelse return error.BadIndex;
            try self.emit(try self.intern(entry.name), try self.intern(entry.value), section_size);
        }
    }

    fn literalNameRef(self: *Decoder, p: *Parser, base: u64, section_size: *usize) Error!void {
        const is_static = (p.buf[p.pos] & 0x10) != 0;
        const index = try p.integer(4);
        const name = if (is_static) blk: {
            const entry = static_table.get(index) orelse return error.BadIndex;
            break :blk try self.intern(entry.name);
        } else blk: {
            const entry = self.dynamicRelative(index, base) orelse return error.BadIndex;
            break :blk try self.intern(entry.name);
        };
        const value = try self.string(p, 7);
        try self.emit(name, value, section_size);
    }

    fn indexedPostBase(self: *Decoder, p: *Parser, base: u64, section_size: *usize) Error!void {
        const index = try p.integer(4);
        const entry = (try self.dynamicPostBase(index, base)) orelse return error.BadIndex;
        try self.emit(try self.intern(entry.name), try self.intern(entry.value), section_size);
    }

    fn literalPostBaseNameRef(self: *Decoder, p: *Parser, base: u64, section_size: *usize) Error!void {
        const index = try p.integer(3);
        const entry = (try self.dynamicPostBase(index, base)) orelse return error.BadIndex;
        const value = try self.string(p, 7);
        try self.emit(try self.intern(entry.name), value, section_size);
    }

    fn literalLiteralName(self: *Decoder, p: *Parser, section_size: *usize) Error!void {
        // 001Nhiii: a 3-bit name-length prefix, then the value with a 7-bit prefix.
        const name = try self.string(p, 3);
        const value = try self.string(p, 7);
        try self.emit(name, value, section_size);
    }

    fn emit(self: *Decoder, name: Span, value: Span, section_size: *usize) Error!void {
        // RFC 9204 4.1 size accounting. Checked so an attacker-influenced length cannot
        // wrap the running total in an unchecked (ReleaseFast) build.
        const field = std.math.add(usize, name.len, value.len) catch return error.DecompressionFailed;
        const charged = std.math.add(usize, field, 32) catch return error.DecompressionFailed;
        section_size.* = std.math.add(usize, section_size.*, charged) catch return error.DecompressionFailed;
        self.fields.append(self.gpa, .{ .name = name, .value = value }) catch return error.OutOfMemory;
    }

    fn encoderInsertNameRef(self: *Decoder, p: *Parser) Error!void {
        const is_static = (p.buf[p.pos] & 0x40) != 0;
        const index = try p.integer(6);
        const name = if (is_static) blk: {
            const entry = static_table.get(index) orelse return error.BadIndex;
            break :blk entry.name;
        } else blk: {
            const entry = self.dynamicRelative(index, self.insert_count) orelse return error.BadIndex;
            break :blk entry.name;
        };
        const value = try self.stringToOwned(p, 7);
        defer self.gpa.free(value);
        try self.insertDynamic(name, value);
    }

    fn encoderInsertLiteral(self: *Decoder, p: *Parser) Error!void {
        const name = try self.stringToOwned(p, 5);
        defer self.gpa.free(name);
        const value = try self.stringToOwned(p, 7);
        defer self.gpa.free(value);
        try self.insertDynamic(name, value);
    }

    fn insertDynamic(self: *Decoder, name: []const u8, value: []const u8) Error!void {
        const size = name.len + value.len + 32;
        if (size > self.dynamic_capacity) return error.DecompressionFailed;
        // The source may borrow the dynamic entry that eviction frees.
        const name_copy = self.gpa.dupe(u8, name) catch return error.OutOfMemory;
        errdefer self.gpa.free(name_copy);
        const value_copy = self.gpa.dupe(u8, value) catch return error.OutOfMemory;
        errdefer self.gpa.free(value_copy);
        self.evictUntilFits(size);
        self.dynamic.append(self.gpa, .{ .name = name_copy, .value = value_copy, .size = size, .abs = self.insert_count }) catch return error.OutOfMemory;
        self.dynamic_size += size;
        self.insert_count += 1;
    }

    fn evictUntilFits(self: *Decoder, need: usize) void {
        while (self.dynamic_size + need > self.dynamic_capacity and self.dynamic.items.len > 0) {
            self.evictOldest();
        }
    }

    fn evictToCapacity(self: *Decoder) void {
        while (self.dynamic_size > self.dynamic_capacity and self.dynamic.items.len > 0) self.evictOldest();
    }

    fn evictOldest(self: *Decoder) void {
        const e = self.dynamic.orderedRemove(0);
        self.dynamic_size -= e.size;
        self.gpa.free(e.name);
        self.gpa.free(e.value);
    }

    fn requiredInsertCount(self: *Decoder, encoded: u64) Error!u64 {
        if (encoded == 0) return 0;
        const max_entries: u64 = @intCast(self.maxDynamicEntries());
        if (max_entries == 0) return error.DecompressionFailed;
        const full_range = std.math.mul(u64, 2, max_entries) catch return error.DecompressionFailed;
        if (encoded > full_range) return error.DecompressionFailed;
        const max_value = std.math.add(u64, self.insert_count, max_entries) catch return error.DecompressionFailed;
        const max_wrapped = (max_value / full_range) * full_range;
        var ric = std.math.add(u64, max_wrapped, encoded - 1) catch return error.DecompressionFailed;
        if (ric > max_value) {
            if (ric <= full_range) return error.DecompressionFailed;
            ric -= full_range;
        }
        if (ric == 0) return error.DecompressionFailed;
        return ric;
    }

    fn maxDynamicEntries(self: *const Decoder) usize {
        return self.max_dynamic_capacity / 32;
    }

    fn dynamicRelative(self: *const Decoder, index: u64, base: u64) ?DynamicEntry {
        if (index >= base) return null;
        return self.dynamicAbsolute(base - index - 1);
    }

    fn dynamicPostBase(self: *const Decoder, index: u64, base: u64) Error!?DynamicEntry {
        const absolute = std.math.add(u64, base, index) catch return error.DecompressionFailed;
        return self.dynamicAbsolute(absolute);
    }

    fn dynamicAbsolute(self: *const Decoder, abs: u64) ?DynamicEntry {
        for (self.dynamic.items) |e| if (e.abs == abs) return e;
        return null;
    }

    /// Decode a length-prefixed (optionally Huffman) string into the store and
    /// return its (offset, len) span. `prefix` is the integer prefix width for the
    /// length; the high bit of the prefix byte is the Huffman flag. A span, not a
    /// slice, so a later append that reallocates the store cannot dangle it.
    fn string(self: *Decoder, p: *Parser, prefix: u4) Error!Span {
        if (p.pos >= p.buf.len) return error.NeedData;
        const huff = (p.buf[p.pos] & (@as(u8, 1) << @intCast(prefix))) != 0;
        const len = try p.integer(prefix);
        const raw = try p.take(len);
        const start = self.store.items.len;
        // A single field's string cannot legitimately exceed the whole field-section
        // budget, so reject an oversized one BEFORE growing the store. Otherwise a
        // peer could force an allocation past the advertised limit (up to the QUIC
        // flow-control window) before the per-field section-size check catches it.
        if (huff) {
            const need = huffman.decodedLen(raw) catch return error.DecompressionFailed;
            if (need > self.max_field_section_size) return error.DecompressionFailed;
            self.store.appendNTimes(self.gpa, 0, need) catch return error.OutOfMemory;
            _ = huffman.decode(raw, self.store.items[start..]) catch return error.DecompressionFailed;
        } else {
            if (raw.len > self.max_field_section_size) return error.DecompressionFailed;
            self.store.appendSlice(self.gpa, raw) catch return error.OutOfMemory;
        }
        return .{ .off = start, .len = self.store.items.len - start };
    }

    fn stringToOwned(self: *Decoder, p: *Parser, prefix: u4) Error![]u8 {
        if (p.pos >= p.buf.len) return error.NeedData;
        const huff = (p.buf[p.pos] & (@as(u8, 1) << @intCast(prefix))) != 0;
        const len = try p.integer(prefix);
        const raw = try p.take(len);
        if (huff) {
            const need = huffman.decodedLen(raw) catch return error.DecompressionFailed;
            const out = self.gpa.alloc(u8, need) catch return error.OutOfMemory;
            errdefer self.gpa.free(out);
            _ = huffman.decode(raw, out) catch return error.DecompressionFailed;
            return out;
        }
        return self.gpa.dupe(u8, raw) catch return error.OutOfMemory;
    }
};

const Parser = struct {
    buf: []const u8,
    pos: usize = 0,

    /// A QPACK/HPACK prefix integer (RFC 7541 5.1): `prefix` low bits of the first
    /// byte, then a base-128 continuation if they are all 1.
    fn integer(self: *Parser, prefix: u4) Error!u64 {
        if (self.pos >= self.buf.len) return error.NeedData;
        const max_prefix: u64 = (@as(u64, 1) << @as(u6, prefix)) - 1;
        var value: u64 = self.buf[self.pos] & max_prefix;
        self.pos += 1;
        if (value < max_prefix) return value;
        var shift: u32 = 0; // wide enough that `shift += 7` never overflows
        while (true) {
            if (self.pos >= self.buf.len) return error.NeedData;
            const b = self.buf[self.pos];
            self.pos += 1;
            // A shift of 64+ bits, or any result exceeding u64, is malformed: reject
            // before the shift/add can wrap (an unchecked u64 overflow traps in
            // ReleaseSafe). Mirrors the HPACK decoder's continuation handling.
            if (shift >= @bitSizeOf(u64)) return error.DecompressionFailed;
            const add = @as(u64, b & 0x7f);
            const shifted = std.math.shlExact(u64, add, @intCast(shift)) catch return error.DecompressionFailed;
            value = std.math.add(u64, value, shifted) catch return error.DecompressionFailed;
            if (b & 0x80 == 0) break;
            shift += 7;
        }
        return value;
    }

    fn take(self: *Parser, n: u64) Error![]const u8 {
        const len: usize = std.math.cast(usize, n) orelse return error.DecompressionFailed;
        if (len > self.buf.len - self.pos) return error.NeedData;
        const s = self.buf[self.pos .. self.pos + len];
        self.pos += len;
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

test "a value larger than the field-section limit is rejected before it is allocated" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 16); // advertise a 16-byte field-section cap
    defer dec.deinit();
    // :authority literal (0x50) with a 32-byte value: exceeds the cap on its own, so the
    // string decoder must reject it rather than grow the store to hold it.
    const block = [_]u8{ 0x00, 0x00, 0x50, 0x20 } ++ [_]u8{'x'} ** 32;
    try testing.expectError(error.DecompressionFailed, dec.decode(&block));
}

test "many literal fields stay valid across store growth (realloc regression)" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    // Several literal-name + literal-value fields, each appending to the store and
    // forcing it to grow/reallocate. Earlier fields' name/value slices must still
    // resolve correctly (they are offsets, resolved after the last append).
    var block: std.ArrayListUnmanaged(u8) = .empty;
    defer block.deinit(gpa);
    try block.appendSlice(gpa, &.{ 0x00, 0x00 }); // prefix
    // 6-char names: the literal-name 3-bit length prefix encodes 0-6 inline (7
    // would mean "continue"), so 6 keeps the length a single byte.
    const names = [_][]const u8{ "aaaaaa", "bbbbbb", "cccccc", "dddddd", "eeeeee" };
    for (names) |n| {
        try block.append(gpa, 0x20 | @as(u8, @intCast(n.len))); // literal name (001), len 6
        try block.appendSlice(gpa, n);
        try block.append(gpa, @intCast(n.len)); // value length (7-bit prefix, no Huffman)
        try block.appendSlice(gpa, n);
    }
    const hs = try dec.decode(block.items);
    try testing.expectEqual(@as(usize, 5), hs.len);
    for (hs, names) |h, n| {
        try testing.expectEqualStrings(n, h.name);
        try testing.expectEqualStrings(n, h.value);
    }
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

test "a header block blocks when its required insert count has not arrived" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    dec.setMaxDynamicCapacity(128);
    // Encoded RIC=2 means Required Insert Count=1 in the non-wrapped case.
    try testing.expectError(error.Blocked, dec.decode(&.{ 0x02, 0x00, 0x80 }));
}

test "required insert count reconstructs after modulo wraparound" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    dec.setMaxDynamicCapacity(100); // MaxEntries=3, FullRange=6.
    dec.insert_count = 10;

    // RFC 9204 4.5.1 example: with 10 inserts and a 100-byte table, encoded 4
    // reconstructs Required Insert Count 9.
    try testing.expectEqual(@as(u64, 9), try dec.requiredInsertCount(4));
    try testing.expectError(error.DecompressionFailed, dec.requiredInsertCount(7)); // > FullRange

    dec.insert_count = 0;
    try testing.expectError(error.DecompressionFailed, dec.requiredInsertCount(1)); // zero must encode as zero
}

test "a dynamic indexed reference without a matching entry is rejected" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    // 0x80 = indexed, T=0 (dynamic).
    try testing.expectError(error.BadIndex, dec.decode(&.{ 0x00, 0x00, 0x80 }));
}

test "decode a dynamic relative indexed field after encoder insert literal" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    dec.setMaxDynamicCapacity(128);

    // Encoder stream: Set Dynamic Table Capacity=128, then Insert With Literal
    // Name x=y. Capacity uses a 5-bit prefix: 31 + 97 = 128.
    const progress = try dec.processEncoder(&.{ 0x3f, 0x61, 0x41, 'x', 0x01, 'y' });
    try testing.expectEqual(@as(usize, 6), progress.consumed);
    try testing.expectEqual(@as(u64, 1), progress.inserts);

    // Header block: RIC=1, Base=1, indexed dynamic relative index 0.
    const hs = try dec.decode(&.{ 0x02, 0x00, 0x80 });
    try testing.expectEqual(@as(usize, 1), hs.len);
    try testing.expectEqualStrings("x", hs[0].name);
    try testing.expectEqualStrings("y", hs[0].value);
}

test "duplicate copies an entry before evicting it" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    dec.setMaxDynamicCapacity(34); // room for exactly one entry: 1 + 1 + 32

    // Insert a=b into a one-entry table, then duplicate index 0.
    const progress = try dec.processEncoder(&.{ 0x3f, 0x03, 0x41, 'a', 0x01, 'b', 0x00 });
    try testing.expectEqual(@as(usize, 7), progress.consumed);
    try testing.expectEqual(@as(u64, 2), progress.inserts);

    // The survivor is the duplicate; RIC=2, Base=2, dynamic relative index 0 -> a=b.
    const hs = try dec.decode(&.{ 0x01, 0x00, 0x80 });
    try testing.expectEqual(@as(usize, 1), hs.len);
    try testing.expectEqualStrings("a", hs[0].name);
    try testing.expectEqualStrings("b", hs[0].value);
}

test "encoder stream processing stops before an incomplete instruction" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    dec.setMaxDynamicCapacity(128);

    // A partial capacity integer is not malformed; nothing is consumed yet.
    try testing.expectEqual(@as(usize, 0), (try dec.processEncoder(&.{0x3f})).consumed);
    try testing.expectEqual(@as(usize, 2), (try dec.processEncoder(&.{ 0x3f, 0x61 })).consumed);

    // A complete capacity update followed by a partial insert consumes only the
    // capacity bytes. The caller leaves the insert prefix/name buffered.
    const partial = try dec.processEncoder(&.{ 0x3f, 0x61, 0x41, 'x' });
    try testing.expectEqual(@as(usize, 2), partial.consumed);
    try testing.expectEqual(@as(u64, 0), partial.inserts);
    const complete = try dec.processEncoder(&.{ 0x41, 'x', 0x01, 'y' });
    try testing.expectEqual(@as(usize, 4), complete.consumed);
    try testing.expectEqual(@as(u64, 1), complete.inserts);

    const hs = try dec.decode(&.{ 0x02, 0x00, 0x80 });
    try testing.expectEqualStrings("x", hs[0].name);
    try testing.expectEqualStrings("y", hs[0].value);
}

test "decode a dynamic post-base indexed field" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    dec.setMaxDynamicCapacity(128);

    const progress = try dec.processEncoder(&.{
        0x3f, 0x61, // Set Dynamic Table Capacity=128.
        0x41, 'a',
        0x01, '1',
        0x41, 'b',
        0x01, '2',
    });
    try testing.expectEqual(@as(usize, 10), progress.consumed);
    try testing.expectEqual(@as(u64, 2), progress.inserts);

    // RIC=2, Base=1 (sign=1, delta=0), post-base index 0 -> absolute index 1.
    const hs = try dec.decode(&.{ 0x03, 0x80, 0x10 });
    try testing.expectEqual(@as(usize, 1), hs.len);
    try testing.expectEqualStrings("b", hs[0].name);
    try testing.expectEqualStrings("2", hs[0].value);
}

test "field section base arithmetic rejects overflow" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    dec.setMaxDynamicCapacity(128);
    const max = [_]u8{0x80} ++ [_]u8{0xFF} ** 8 ++ [_]u8{0x01};

    try testing.expectError(error.DecompressionFailed, dec.decode(&([_]u8{ 0x00, 0xFF } ++ max)));

    dec.insert_count = 1;
    try testing.expectError(error.DecompressionFailed, dec.decode(&([_]u8{ 0x02, 0x7F } ++ max)));

    dec.insert_count = 0;
    try testing.expectError(error.DecompressionFailed, dec.decode(&([_]u8{ 0x00, 0x7F } ++ max ++ [_]u8{0x11})));
}

test "an out-of-range static index is rejected" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    // index 99 (past the 0-98 table): 0xC0|63 then continuation for 99.
    const block = [_]u8{ 0x00, 0x00, 0xFF, 36 }; // 63 + 36 = 99
    try testing.expectError(error.BadIndex, dec.decode(&block));
}

test "an integer whose continuation overflows is rejected, not crashed" {
    const gpa = testing.allocator;
    var dec = Decoder.init(gpa, 1 << 20);
    defer dec.deinit();
    // RIC=0, Base=0, then an indexed static field (0xC0|63 = prefix all-ones, so a
    // base-128 continuation follows) whose continuation never terminates the high
    // bit and accumulates past 2^64. The unchecked accumulation would trap in
    // ReleaseSafe; it must surface as a clean DecompressionFailed instead.
    const block = [_]u8{ 0x00, 0x00, 0xFF } ++ [_]u8{0xFF} ** 10;
    try testing.expectError(error.DecompressionFailed, dec.decode(&block));
}
