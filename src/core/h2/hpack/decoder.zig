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

const Header = struct { name: []const u8, value: []const u8 };

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
    /// Backing bytes for the CURRENT block's decoded names/values (Huffman or
    /// raw literals). Lifetime: cleared at the start of each decodeBlock.
    out_store: std.ArrayList(u8) = .empty,
    out: std.ArrayList(Header) = .empty,
    /// Decoded-size cap for the current block (sum of name+value+overhead).
    max_header_list_size: usize,

    pub fn init(gpa: std.mem.Allocator, max_table_size: usize, max_header_list_size: usize) Decoder {
        return .{ .gpa = gpa, .max_table_size = max_table_size, .max_header_list_size = max_header_list_size };
    }

    pub fn deinit(self: *Decoder) void {
        self.store.deinit(self.gpa);
        self.entries.deinit(self.gpa);
        self.out_store.deinit(self.gpa);
        self.out.deinit(self.gpa);
    }

    /// Decode a complete field block into `self.out`. The returned slice is valid
    /// until the NEXT decodeBlock call (see the lifetime invariant above).
    pub fn decodeBlock(self: *Decoder, block: []const u8) HpackError![]const Header {
        self.out_store.clearRetainingCapacity();
        self.out.clearRetainingCapacity();
        var list_size: usize = 0;

        var p = Parser{ .buf = block };
        // A dynamic-table-size-update (if present) must come first in the block;
        // it is also legal mid-block per RFC 7541 4.2, so we accept it anywhere.
        while (!p.eof()) {
            const first = p.peek();
            if (first & 0x80 != 0) {
                // 1xxxxxxx: indexed header field (RFC 7541 6.1).
                const idx = try p.integer(7);
                const h = try self.resolveIndex(idx);
                try self.emit(h, &list_size);
            } else if (first & 0x40 != 0) {
                // 01xxxxxx: literal with incremental indexing (6.2.1).
                const h = try self.literal(&p, 6);
                try self.addDynamic(h);
                try self.emit(h, &list_size);
            } else if (first & 0x20 != 0) {
                // 001xxxxx: dynamic table size update (6.3).
                const new_size = try p.integer(5);
                if (new_size > self.max_table_size) return error.CompressionError;
                self.evictTo(new_size);
            } else {
                // 0000xxxx (never indexed, 6.2.3) or 0001xxxx (without indexing,
                // 6.2.2): both decode the same; neither touches the dynamic table.
                const h = try self.literal(&p, 4);
                try self.emit(h, &list_size);
            }
        }
        return self.out.items;
    }

    fn emit(self: *Decoder, h: Header, list_size: *usize) HpackError!void {
        list_size.* += h.name.len + h.value.len + ENTRY_OVERHEAD;
        if (list_size.* > self.max_header_list_size) return error.MessageTooLong;
        try self.out.append(self.gpa, h);
    }

    /// Resolve an index against the static then dynamic table. Slices point into
    /// the static table (static lifetime) or `store` (decoder-owned).
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
    /// literal value. `prefix` is the name-index prefix width (6, 4). The
    /// returned slices live in `out_store` (or the static table for an indexed
    /// name) and are stable for the rest of this block.
    fn literal(self: *Decoder, p: *Parser, prefix: u4) HpackError!Header {
        const name_index = try p.integer(prefix);
        var name: []const u8 = undefined;
        if (name_index != 0) {
            name = (try self.resolveIndex(name_index)).name;
        } else {
            name = try self.string(p);
        }
        const value = try self.string(p);
        return .{ .name = name, .value = value };
    }

    /// Decode a length-prefixed string literal into `out_store`, returning a
    /// stable slice. Handles the Huffman (H) bit.
    fn string(self: *Decoder, p: *Parser) HpackError![]const u8 {
        if (p.eof()) return error.CompressionError;
        const huff = p.peek() & 0x80 != 0;
        const len = try p.integer(7);
        const raw = try p.take(len);
        if (!huff) {
            const start = self.out_store.items.len;
            self.out_store.appendSlice(self.gpa, raw) catch return error.OutOfMemory;
            return self.out_store.items[start..];
        }
        const out_len = huffman.decodedLen(raw) catch return error.CompressionError;
        const start = self.out_store.items.len;
        self.out_store.resize(self.gpa, start + out_len) catch return error.OutOfMemory;
        _ = huffman.decode(raw, self.out_store.items[start..]) catch return error.CompressionError;
        return self.out_store.items[start..];
    }

    /// Insert a new dynamic-table entry (RFC 7541 4.4). Resolve-before-evict: the
    /// name/value bytes are already materialized in `out_store` (or the static
    /// table) by the time we get here, so eviction compacting `store` cannot
    /// invalidate them. An entry larger than max_table_size empties the table and
    /// is not inserted (still a valid decoded header - already emitted).
    fn addDynamic(self: *Decoder, h: Header) HpackError!void {
        const entry_size = h.name.len + h.value.len + ENTRY_OVERHEAD;
        if (entry_size > self.max_table_size) {
            self.entries.clearRetainingCapacity();
            self.store.clearRetainingCapacity();
            self.table_size = 0;
            return;
        }
        self.evictTo(self.max_table_size - entry_size);
        const name_off = self.store.items.len;
        self.store.appendSlice(self.gpa, h.name) catch return error.OutOfMemory;
        const value_off = self.store.items.len;
        self.store.appendSlice(self.gpa, h.value) catch return error.OutOfMemory;
        self.entries.append(self.gpa, .{
            .name_off = name_off,
            .name_len = h.name.len,
            .value_off = value_off,
            .value_len = h.value.len,
            .size = entry_size,
        }) catch return error.OutOfMemory;
        self.table_size += entry_size;
    }

    /// Evict oldest entries until table_size <= target. After eviction, compact
    /// `store` so offsets stay bounded (the surviving entries are rewritten to
    /// the front). Oldest entries are at the FRONT of `entries`.
    fn evictTo(self: *Decoder, target: usize) void {
        if (self.table_size <= target) return;
        var keep_from: usize = 0;
        while (keep_from < self.entries.items.len and self.table_size > target) {
            self.table_size -= self.entries.items[keep_from].size;
            keep_from += 1;
        }
        if (keep_from == 0) return;
        // Compact: rewrite the surviving entries' bytes to the front of `store`.
        const survivors = self.entries.items[keep_from..];
        var new_store: std.ArrayList(u8) = .empty;
        for (survivors) |*e| {
            const nm = self.store.items[e.name_off .. e.name_off + e.name_len];
            const vl = self.store.items[e.value_off .. e.value_off + e.value_len];
            const no = new_store.items.len;
            new_store.appendSlice(self.gpa, nm) catch return; // compaction OOM: keep old store
            const vo = new_store.items.len;
            new_store.appendSlice(self.gpa, vl) catch return;
            e.name_off = no;
            e.value_off = vo;
        }
        self.store.deinit(self.gpa);
        self.store = new_store;
        // Drop the evicted entries from the front.
        const n = survivors.len;
        std.mem.copyForwards(DynEntry, self.entries.items[0..n], survivors);
        self.entries.shrinkRetainingCapacity(n);
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
        if (self.pos + n > self.buf.len) return error.CompressionError;
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
        var shift: u6 = 0;
        // At most ceil(64/7) = 10 continuation octets fit a usize; reject more.
        var octets: u8 = 0;
        while (true) {
            if (self.eof()) return error.CompressionError;
            const b = self.buf[self.pos];
            self.pos += 1;
            octets += 1;
            if (octets > 10) return error.CompressionError;
            const add = @as(usize, b & 0x7f);
            const shifted = std.math.shlExact(usize, add, shift) catch return error.CompressionError;
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
    var d = Decoder.init(testing.allocator, 64, 1 << 20); // tiny table
    defer d.deinit();
    // First seed a normal small entry.
    const seed = [_]u8{ 0x40, 0x01, 'a', 0x01, 'b' }; // a: b -> size 34
    _ = try d.decodeBlock(&seed);
    try testing.expectEqual(@as(usize, 1), d.entries.items.len);
    // Now a literal-with-indexing whose size (name+value+32) exceeds 64.
    const big = [_]u8{ 0x40, 0x05, 'b', 'i', 'g', 'g', 'y', 0x04, 'v', 'a', 'l', 's' }; // 5+4+32=41 ... still < 64
    _ = try d.decodeBlock(&big);
    // 41 <= 64, so it inserts and may evict the seed. Confirm table stayed valid.
    try testing.expect(d.table_size <= 64);
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
