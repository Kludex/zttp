//! The HPACK decoder (RFC 7541): turns a reassembled field-block fragment into a
//! list of (name, value) headers. The dynamic table's bytes live in a decoder-
//! owned arena, never in the fed buffer, because Huffman decoding reconstructs
//! bytes that have no on-wire counterpart. Decoded headers point into either the
//! static table (static lifetime) or `out_store`.
//!
//! CRITICAL LIFETIME INVARIANT: `out_store` is cleared at the START of
//! decodeBlock, never the end. The connection layer decodes at most one block
//! per nextEvent and drains the events it produced before decoding the next
//! block, so a pushed-but-not-yet-drained Request's header slices stay valid
//! until the next decode actually begins. Clearing at the end would free them
//! while still referenced.

const std = @import("std");
const static_table = @import("static_table.zig");
const huffman = @import("huffman.zig");

/// The decoder emits the shared core Header so its output drops straight into
/// the event model with no conversion.
const Header = @import("../../events.zig").Header;

/// Per-entry overhead added to name+value length for dynamic-table accounting
/// (RFC 7541 4.1).
const ENTRY_OVERHEAD: usize = 32;

pub const HpackError = error{
    /// A malformed field block: bad index, bad integer, bad string, oversized
    /// dynamic-table-size-update, or invalid Huffman. Always connection-fatal.
    CompressionError,
    /// The decoded header list exceeded max_header_list_size (HPACK bomb guard).
    MessageTooLong,
    OutOfMemory,
};

const DynEntry = struct {
    name_off: usize,
    name_len: usize,
    value_off: usize,
    value_len: usize,
    size: usize,
};

/// A decoded header as offsets into `out_store`. Resolved to a `Header` (with
/// live slices) only after the whole block is decoded and `out_store` is stable.
const OutRange = struct { name_off: usize, name_len: usize, value_off: usize, value_len: usize };

/// A staged (offset, length) span within `out_store`.
const Span = struct { off: usize, len: usize };

pub const Decoder = struct {
    gpa: std.mem.Allocator,
    /// Backing bytes for dynamic-table entries (names + values), append-only
    /// within a generation; compacted on eviction.
    store: std.ArrayList(u8) = .empty,
    entries: std.ArrayList(DynEntry) = .empty, // newest at the end
    table_size: usize = 0, // current size in HPACK accounting units
    /// The cap WE advertise (SETTINGS_HEADER_TABLE_SIZE). A dynamic-table-size
    /// update may shrink the effective max below this but never above it.
    max_table_size: usize,
    /// The current effective cap: max_table_size, or smaller after a dynamic-
    /// table-size-update (RFC 7541 6.3). Drives eviction and insertion.
    effective_max: usize,
    /// Backing bytes for the CURRENT block's decoded names/values. EVERY emitted
    /// name/value is copied here (static, dynamic, or literal) so the resolved
    /// Header slices have one uniform, stable lifetime. Cleared at the start of
    /// each decodeBlock; the resolved slices are valid until the next call.
    out_store: std.ArrayList(u8) = .empty,
    out: std.ArrayList(OutRange) = .empty,
    /// Materialized Header slices for the current block (rebuilt from `out` once
    /// out_store is stable). The return value of decodeBlock.
    out_headers: std.ArrayList(Header) = .empty,
    /// Decoded-size cap for the current block (sum of name+value+overhead).
    max_header_list_size: usize,

    pub fn init(gpa: std.mem.Allocator, max_table_size: usize, max_header_list_size: usize) Decoder {
        return .{
            .gpa = gpa,
            .max_table_size = max_table_size,
            .effective_max = max_table_size,
            .max_header_list_size = max_header_list_size,
        };
    }

    pub fn deinit(self: *Decoder) void {
        self.store.deinit(self.gpa);
        self.entries.deinit(self.gpa);
        self.out_store.deinit(self.gpa);
        self.out.deinit(self.gpa);
        self.out_headers.deinit(self.gpa);
    }

    /// Decode a complete field block. The returned slice (and the bytes it points
    /// into) is valid until the NEXT decodeBlock call (see the lifetime invariant
    /// at the top of this file).
    pub fn decodeBlock(self: *Decoder, block: []const u8) HpackError![]const Header {
        self.out_store.clearRetainingCapacity();
        self.out.clearRetainingCapacity();
        self.out_headers.clearRetainingCapacity();
        var list_size: usize = 0;
        // A dynamic-table-size-update may only appear before any header field
        // representation in the block (RFC 7541 4.2); once a field is seen, an
        // update is a CompressionError.
        var fields_seen = false;

        var p = Parser{ .buf = block };
        while (!p.eof()) {
            const first = p.peek();
            if (first & 0x80 != 0) {
                // 1xxxxxxx: indexed header field (RFC 7541 6.1).
                const idx = try p.integer(7);
                try self.emitIndexed(idx, &list_size);
                fields_seen = true;
            } else if (first & 0x40 != 0) {
                // 01xxxxxx: literal with incremental indexing (6.2.1).
                try self.literal(&p, 6, true, &list_size);
                fields_seen = true;
            } else if (first & 0x20 != 0) {
                // 001xxxxx: dynamic table size update (6.3).
                if (fields_seen) return error.CompressionError;
                const new_size = try p.integer(5);
                if (new_size > self.max_table_size) return error.CompressionError;
                self.effective_max = new_size;
                try self.evictTo(new_size);
            } else {
                // 0000xxxx (never indexed, 6.2.3) or 0001xxxx (without indexing,
                // 6.2.2): both decode the same; neither touches the dynamic table.
                try self.literal(&p, 4, false, &list_size);
                fields_seen = true;
            }
        }
        // out_store is now stable; resolve every range to a live slice.
        try self.out_headers.ensureTotalCapacity(self.gpa, self.out.items.len);
        for (self.out.items) |r| {
            self.out_headers.appendAssumeCapacity(.{
                .name = self.out_store.items[r.name_off .. r.name_off + r.name_len],
                .value = self.out_store.items[r.value_off .. r.value_off + r.value_len],
            });
        }
        return self.out_headers.items;
    }

    /// Append bytes to out_store, returning their (offset, len) - the one place a
    /// decoded name/value is staged before resolution.
    fn stage(self: *Decoder, bytes: []const u8) HpackError!Span {
        const off = self.out_store.items.len;
        self.out_store.appendSlice(self.gpa, bytes) catch return error.OutOfMemory;
        return .{ .off = off, .len = bytes.len };
    }

    fn account(self: *Decoder, list_size: *usize, name_len: usize, value_len: usize) HpackError!void {
        const entry = std.math.add(usize, name_len, value_len) catch return error.MessageTooLong;
        const with_overhead = std.math.add(usize, entry, ENTRY_OVERHEAD) catch return error.MessageTooLong;
        list_size.* = std.math.add(usize, list_size.*, with_overhead) catch return error.MessageTooLong;
        if (list_size.* > self.max_header_list_size) return error.MessageTooLong;
    }

    /// An indexed header field: copy the resolved name+value into out_store and
    /// record the range.
    fn emitIndexed(self: *Decoder, index: usize, list_size: *usize) HpackError!void {
        const h = try self.resolveIndex(index);
        const n = try self.stage(h.name);
        const v = try self.stage(h.value);
        try self.account(list_size, n.len, v.len);
        try self.out.append(self.gpa, .{ .name_off = n.off, .name_len = n.len, .value_off = v.off, .value_len = v.len });
    }

    /// Resolve an index against the static then dynamic table. Returns slices
    /// into the static table or `store`; the caller MUST copy them into out_store
    /// before any mutation of `store` (eviction/insertion).
    fn resolveIndex(self: *Decoder, index: usize) HpackError!Header {
        if (index == 0) return error.CompressionError;
        if (static_table.lookup(index)) |e| return .{ .name = e.name, .value = e.value };
        const dyn_index = index - static_table.LENGTH; // 1-based into dynamic
        if (dyn_index == 0 or dyn_index > self.entries.items.len) return error.CompressionError;
        // Dynamic entries are newest-first by index: index 1 = most recent.
        const e = self.entries.items[self.entries.items.len - dyn_index];
        return .{
            .name = self.store.items[e.name_off .. e.name_off + e.name_len],
            .value = self.store.items[e.value_off .. e.value_off + e.value_len],
        };
    }

    /// Decode a literal representation: an indexed-or-literal name followed by a
    /// literal value. Both are staged into out_store FIRST, so the subsequent
    /// addDynamic (which may evict/compact `store`) can never read freed bytes -
    /// resolve-before-evict is structural, not incidental. `prefix` is the
    /// name-index prefix width (6 or 4); `index_it` adds the entry to the table.
    fn literal(self: *Decoder, p: *Parser, prefix: u4, index_it: bool, list_size: *usize) HpackError!void {
        const name_index = try p.integer(prefix);
        const n = if (name_index != 0) blk: {
            const h = try self.resolveIndex(name_index);
            break :blk try self.stage(h.name);
        } else try self.stageString(p);
        const v = try self.stageString(p);
        try self.account(list_size, n.len, v.len);
        try self.out.append(self.gpa, .{ .name_off = n.off, .name_len = n.len, .value_off = v.off, .value_len = v.len });
        if (index_it) {
            const name = self.out_store.items[n.off .. n.off + n.len];
            const value = self.out_store.items[v.off .. v.off + v.len];
            try self.addDynamic(name, value);
        }
    }

    /// Decode a length-prefixed string literal directly into out_store, returning
    /// its (offset, len). Handles the Huffman (H) bit.
    fn stageString(self: *Decoder, p: *Parser) HpackError!Span {
        if (p.eof()) return error.CompressionError;
        const huff = p.peek() & 0x80 != 0;
        const len = try p.integer(7);
        const raw = try p.take(len);
        if (!huff) return self.stage(raw);
        const out_len = huffman.decodedLen(raw) catch return error.CompressionError;
        const off = self.out_store.items.len;
        self.out_store.resize(self.gpa, off + out_len) catch return error.OutOfMemory;
        _ = huffman.decode(raw, self.out_store.items[off..]) catch return error.CompressionError;
        return .{ .off = off, .len = out_len };
    }

    /// Insert a new dynamic-table entry (RFC 7541 4.4). `name` and `value` point
    /// into out_store (the caller staged them first), so eviction compacting
    /// `store` cannot invalidate them. An entry larger than the effective max
    /// empties the table and is not inserted (it was still emitted).
    fn addDynamic(self: *Decoder, name: []const u8, value: []const u8) HpackError!void {
        const entry_size = name.len + value.len + ENTRY_OVERHEAD;
        if (entry_size > self.effective_max) {
            self.entries.clearRetainingCapacity();
            self.store.clearRetainingCapacity();
            self.table_size = 0;
            return;
        }
        try self.evictTo(self.effective_max - entry_size);
        // Reserve all capacity first so the appends below cannot fail partway and
        // leave orphaned bytes in `store` or a name without its entry.
        self.store.ensureUnusedCapacity(self.gpa, name.len + value.len) catch return error.OutOfMemory;
        self.entries.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
        const name_off = self.store.items.len;
        self.store.appendSliceAssumeCapacity(name);
        const value_off = self.store.items.len;
        self.store.appendSliceAssumeCapacity(value);
        self.entries.appendAssumeCapacity(.{
            .name_off = name_off,
            .name_len = name.len,
            .value_off = value_off,
            .value_len = value.len,
            .size = entry_size,
        });
        self.table_size += entry_size;
    }

    /// Evict oldest entries until table_size <= target. After eviction, compact
    /// `store` so offsets stay bounded (the surviving entries are rewritten to
    /// the front). Oldest entries are at the FRONT of `entries`. Returns
    /// OutOfMemory rather than leaving the table half-compacted.
    fn evictTo(self: *Decoder, target: usize) HpackError!void {
        if (self.table_size <= target) return;
        var keep_from: usize = 0;
        var freed: usize = 0;
        while (keep_from < self.entries.items.len and self.table_size - freed > target) {
            freed += self.entries.items[keep_from].size;
            keep_from += 1;
        }
        if (keep_from == 0) return;
        const survivors = self.entries.items[keep_from..];
        // Build a fresh store and rewrite offsets into a scratch buffer; commit
        // both (and the reduced table_size) only after everything succeeds, so an
        // OOM mid-compaction leaves the table exactly as it was.
        var new_store: std.ArrayList(u8) = .empty;
        errdefer new_store.deinit(self.gpa);
        const new_offsets = self.gpa.alloc([2]usize, survivors.len) catch return error.OutOfMemory;
        defer self.gpa.free(new_offsets);
        for (survivors, 0..) |e, i| {
            const nm = self.store.items[e.name_off .. e.name_off + e.name_len];
            const vl = self.store.items[e.value_off .. e.value_off + e.value_len];
            new_offsets[i][0] = new_store.items.len;
            new_store.appendSlice(self.gpa, nm) catch return error.OutOfMemory;
            new_offsets[i][1] = new_store.items.len;
            new_store.appendSlice(self.gpa, vl) catch return error.OutOfMemory;
        }
        // Past the last fallible step: commit.
        for (survivors, 0..) |*e, i| {
            e.name_off = new_offsets[i][0];
            e.value_off = new_offsets[i][1];
        }
        self.store.deinit(self.gpa);
        self.store = new_store;
        const n = survivors.len;
        std.mem.copyForwards(DynEntry, self.entries.items[0..n], survivors);
        self.entries.shrinkRetainingCapacity(n);
        self.table_size -= freed;
    }
};

/// A cursor over a field block with the two HPACK primitives: variable-length
/// integers (5.1) and the length read for strings (5.2). Bounds-checked: any
/// read past the end is a CompressionError.
const Parser = struct {
    buf: []const u8,
    pos: usize = 0,

    fn eof(self: *const Parser) bool {
        return self.pos >= self.buf.len;
    }

    fn peek(self: *const Parser) u8 {
        return self.buf[self.pos]; // callers guard with !eof()
    }

    fn take(self: *Parser, n: usize) HpackError![]const u8 {
        // Subtraction form: `self.pos + n` could wrap for a crafted huge n.
        if (n > self.buf.len - self.pos) return error.CompressionError;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }

    /// Decode an HPACK integer with an `prefix`-bit prefix (RFC 7541 5.1). The
    /// continuation is capped so a malicious encoding cannot loop or overflow.
    fn integer(self: *Parser, prefix: u4) HpackError!usize {
        if (self.eof()) return error.CompressionError;
        const max_prefix: usize = (@as(usize, 1) << prefix) - 1;
        var value: usize = self.buf[self.pos] & max_prefix;
        self.pos += 1;
        if (value < max_prefix) return value;
        var shift: u32 = 0; // wide enough that `shift += 7` never overflows
        while (true) {
            if (self.eof()) return error.CompressionError;
            const b = self.buf[self.pos];
            self.pos += 1;
            // A shift of 64+ bits, or any result exceeding usize, is malformed.
            if (shift >= @bitSizeOf(usize)) return error.CompressionError;
            const add = @as(usize, b & 0x7f);
            const shifted = std.math.shlExact(usize, add, @intCast(shift)) catch return error.CompressionError;
            value = std.math.add(usize, value, shifted) catch return error.CompressionError;
            if (b & 0x80 == 0) break;
            shift += 7;
        }
        return value;
    }
};

const testing = std.testing;

fn expectHeader(h: Header, name: []const u8, value: []const u8) !void {
    try testing.expectEqualStrings(name, h.name);
    try testing.expectEqualStrings(value, h.value);
}

test "decode RFC 7541 C.2.1 literal with incremental indexing" {
    // custom-key: custom-header
    const block = [_]u8{ 0x40, 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y', 0x0d, 'c', 'u', 's', 't', 'o', 'm', '-', 'h', 'e', 'a', 'd', 'e', 'r' };
    var d = Decoder.init(testing.allocator, 4096, 1 << 20);
    defer d.deinit();
    const out = try d.decodeBlock(&block);
    try testing.expectEqual(@as(usize, 1), out.len);
    try expectHeader(out[0], "custom-key", "custom-header");
    try testing.expectEqual(@as(usize, 1), d.entries.items.len); // it was indexed
}

test "decode RFC 7541 C.2.2 literal without indexing" {
    // :path: /sample/path
    const block = [_]u8{ 0x04, 0x0c, '/', 's', 'a', 'm', 'p', 'l', 'e', '/', 'p', 'a', 't', 'h' };
    var d = Decoder.init(testing.allocator, 4096, 1 << 20);
    defer d.deinit();
    const out = try d.decodeBlock(&block);
    try expectHeader(out[0], ":path", "/sample/path");
    try testing.expectEqual(@as(usize, 0), d.entries.items.len); // not indexed
}

test "decode RFC 7541 C.2.4 indexed header field" {
    // :method: GET (static index 2)
    const block = [_]u8{0x82};
    var d = Decoder.init(testing.allocator, 4096, 1 << 20);
    defer d.deinit();
    const out = try d.decodeBlock(&block);
    try expectHeader(out[0], ":method", "GET");
}

test "decode RFC 7541 C.3 request sequence with dynamic table" {
    var d = Decoder.init(testing.allocator, 4096, 1 << 20);
    defer d.deinit();
    // C.3.1
    const b1 = [_]u8{ 0x82, 0x86, 0x84, 0x41, 0x0f, 'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm' };
    const o1 = try d.decodeBlock(&b1);
    try testing.expectEqual(@as(usize, 4), o1.len);
    try expectHeader(o1[0], ":method", "GET");
    try expectHeader(o1[1], ":scheme", "http");
    try expectHeader(o1[2], ":path", "/");
    try expectHeader(o1[3], ":authority", "www.example.com");
    try testing.expectEqual(@as(usize, 1), d.entries.items.len);
    try testing.expectEqual(@as(usize, 57), d.table_size);
    // C.3.2: reuses the dynamic entry (index 62) and adds cache-control: no-cache
    const b2 = [_]u8{ 0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 'n', 'o', '-', 'c', 'a', 'c', 'h', 'e' };
    const o2 = try d.decodeBlock(&b2);
    try testing.expectEqual(@as(usize, 5), o2.len);
    try expectHeader(o2[3], ":authority", "www.example.com"); // 0xbe = index 62
    try expectHeader(o2[4], "cache-control", "no-cache");
    try testing.expectEqual(@as(usize, 2), d.entries.items.len);
}

test "decode C.4 Huffman-coded request" {
    var d = Decoder.init(testing.allocator, 4096, 1 << 20);
    defer d.deinit();
    // C.4.1: :authority www.example.com Huffman-encoded.
    const b1 = [_]u8{ 0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    const o1 = try d.decodeBlock(&b1);
    try expectHeader(o1[3], ":authority", "www.example.com");
}

test "oversized entry empties the table but still emits the header" {
    var d = Decoder.init(testing.allocator, 40, 1 << 20); // table fits one 34-byte entry
    defer d.deinit();
    // Seed a 34-byte entry (a: b).
    _ = try d.decodeBlock(&[_]u8{ 0x40, 0x01, 'a', 0x01, 'b' });
    try testing.expectEqual(@as(usize, 1), d.entries.items.len);
    // A literal-with-indexing whose size (5+4+32 = 41) exceeds the 40-byte max:
    // the table is emptied and the entry is NOT inserted, but the header is still
    // emitted (RFC 7541 4.4).
    const big = [_]u8{ 0x40, 0x05, 'b', 'i', 'g', 'g', 'y', 0x04, 'v', 'a', 'l', 's' };
    const out = try d.decodeBlock(&big);
    try expectHeader(out[0], "biggy", "vals");
    try testing.expectEqual(@as(usize, 0), d.entries.items.len);
    try testing.expectEqual(@as(usize, 0), d.table_size);
}

test "an indexed dynamic header survives a later insert that evicts it" {
    // A header that resolves through the dynamic table must not dangle when a
    // subsequent insert in the SAME block evicts/compacts the store.
    // With the offset-into-out_store design, the emitted bytes are copied before
    // any table mutation, so they stay valid.
    var d = Decoder.init(testing.allocator, 70, 1 << 20); // room for ~2 small entries
    defer d.deinit();
    // Seed entry index 62: "k": "v1" (size 35).
    _ = try d.decodeBlock(&[_]u8{ 0x40, 0x01, 'k', 0x02, 'v', '1' });
    // One block: reference index 62 (the dynamic entry), THEN add a new entry big
    // enough to evict it. The first header must still read "k"/"v1".
    const block = [_]u8{ 0xbe, 0x40, 0x01, 'm', 0x20 } ++ [_]u8{'z'} ** 32; // index 62, then m: zzz... (size 33+32)
    const out = try d.decodeBlock(&block);
    try expectHeader(out[0], "k", "v1"); // the evicted entry's bytes, still valid
    try testing.expectEqualStrings("m", out[1].name);
}

test "dynamic table size update to zero clears the table and blocks reinsertion" {
    var d = Decoder.init(testing.allocator, 4096, 1 << 20);
    defer d.deinit();
    _ = try d.decodeBlock(&[_]u8{ 0x40, 0x01, 'a', 0x01, 'b' });
    try testing.expectEqual(@as(usize, 1), d.entries.items.len);
    // 0x20 = dynamic-table-size-update to 0: clears the table; a following literal
    // with indexing cannot reinsert (its size exceeds the now-zero effective max).
    const block = [_]u8{ 0x20, 0x40, 0x01, 'c', 0x01, 'd' };
    _ = try d.decodeBlock(&block);
    try testing.expectEqual(@as(usize, 0), d.entries.items.len);
    try testing.expectEqual(@as(usize, 0), d.table_size);
}

test "dynamic table size update after a field is a compression error" {
    var d = Decoder.init(testing.allocator, 4096, 1 << 20);
    defer d.deinit();
    // An indexed field (0x82) followed by a size update (0x20) - illegal order.
    try testing.expectError(error.CompressionError, d.decodeBlock(&[_]u8{ 0x82, 0x20 }));
}

test "string length past the end is a compression error, not a panic" {
    var d = Decoder.init(testing.allocator, 4096, 1 << 20);
    defer d.deinit();
    // Literal with literal name, claimed name length 10 but only 2 bytes follow.
    try testing.expectError(error.CompressionError, d.decodeBlock(&[_]u8{ 0x00, 0x0a, 'a', 'b' }));
}

test "indexed zero is a compression error" {
    var d = Decoder.init(testing.allocator, 4096, 1 << 20);
    defer d.deinit();
    try testing.expectError(error.CompressionError, d.decodeBlock(&[_]u8{0x80}));
}

test "out_store survives across a second block decode until it begins" {
    // The lifetime invariant: hold block A's header slices, decode block B, and
    // assert A's bytes were not clobbered before B's decode cleared out_store.
    // Since decodeBlock clears out_store at its START, A's slices are valid right
    // up until the second decodeBlock call - which is exactly the contract.
    var d = Decoder.init(testing.allocator, 4096, 1 << 20);
    defer d.deinit();
    const a = [_]u8{ 0x40, 0x01, 'x', 0x03, 'a', 'a', 'a' };
    const out_a = try d.decodeBlock(&a);
    try expectHeader(out_a[0], "x", "aaa");
    // out_a is still valid here (before the next decode).
    try testing.expectEqualStrings("aaa", out_a[0].value);
}

test "max_header_list_size aborts mid-decode" {
    var d = Decoder.init(testing.allocator, 4096, 40); // one 34-byte entry fits, two don't
    defer d.deinit();
    const block = [_]u8{ 0x82, 0x82 }; // :method GET twice -> 2 * (7+3+32) ... first ok, second over
    try testing.expectError(error.MessageTooLong, d.decodeBlock(&block));
}

test "integer continuation overflow is rejected" {
    var d = Decoder.init(testing.allocator, 4096, 1 << 20);
    defer d.deinit();
    // Indexed field with a 7-bit prefix integer that never terminates / overflows.
    const block = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    try testing.expectError(error.CompressionError, d.decodeBlock(&block));
}

fn driveDecoder(input: []const u8) void {
    var d = Decoder.init(testing.allocator, 4096, 64 * 1024);
    defer d.deinit();
    _ = d.decodeBlock(input) catch {};
}

test "fuzz: hpack decode never panics on adversarial blocks" {
    const seeds = [_][]const u8{ "", &[_]u8{0x80}, &[_]u8{0xFF}, &[_]u8{ 0x40, 0xFF }, &[_]u8{ 0x20, 0xFF, 0xFF } };
    for (seeds) |s| driveDecoder(s);
    var prng = std.Random.DefaultPrng.init(0x6870_61636b);
    const rand = prng.random();
    var buf: [128]u8 = undefined;
    for (0..3000) |_| {
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        for (buf[0..len]) |*b| b.* = rand.int(u8);
        driveDecoder(buf[0..len]);
    }
}
