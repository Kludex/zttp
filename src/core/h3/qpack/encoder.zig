//! QPACK field-section encoding (RFC 9204 section 4). The top-level `encode`
//! helper remains stateless and static/literal-only. `Encoder` adds a conservative
//! dynamic-table slice: it inserts selected regular headers on the encoder stream
//! and references them from the field block only when the peer advertised dynamic
//! table capacity and blocked-stream allowance.

const std = @import("std");
const static_table = @import("static_table.zig");

const Header = @import("../../events.zig").Header;
const decoder = @import("decoder.zig");

const DynamicEntry = struct { name: []u8, value: []u8, size: usize, abs: u64 };
const Outstanding = struct { stream_id: u64, required_insert_count: u64 };

/// Local cap on encoder dynamic-table bytes, independent of peer SETTINGS.
pub const max_dynamic_capacity: usize = 4096;
/// Local cap on field sections blocked on dynamic-table acknowledgments.
pub const max_blocked_streams: u64 = 16;

pub const Error = error{
    DecompressionFailed,
    NeedData,
    OutOfMemory,
};

pub const DecoderProgress = struct { consumed: usize };

/// Encode a prefix integer (RFC 7541 5.1, shared with HPACK/QPACK). The high
/// `8 - prefix` bits of the first octet are supplied by the caller in `pattern`.
fn writeInteger(out: *std.ArrayList(u8), gpa: std.mem.Allocator, value: u64, prefix: u4, pattern: u8) !void {
    const max_prefix: u64 = (@as(u64, 1) << @as(u6, prefix)) - 1;
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
    try writeInteger(out, gpa, @intCast(s.len), prefix, pattern);
    try out.appendSlice(gpa, s);
}

/// Encode one header line as its smallest static-table form (RFC 9204 4.5).
pub fn encodeHeader(out: *std.ArrayList(u8), gpa: std.mem.Allocator, h: Header) !void {
    if (static_table.nameValueIndex(h.name, h.value)) |idx| {
        // Indexed field line (4.5.2): 1Tiiiiii with T=1 (static), 6-bit index.
        try writeInteger(out, gpa, @intCast(idx), 6, 0xC0);
        return;
    }
    if (static_table.nameIndex(h.name)) |idx| {
        // Literal with static name reference (4.5.4): 01NTiiii with N=0, T=1,
        // 4-bit name index, then the value (7-bit length prefix).
        try writeInteger(out, gpa, @intCast(idx), 4, 0x50);
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

pub const Encoder = struct {
    gpa: std.mem.Allocator,
    dynamic: std.ArrayListUnmanaged(DynamicEntry) = .empty,
    outstanding: std.ArrayListUnmanaged(Outstanding) = .empty,
    dynamic_size: usize = 0,
    dynamic_capacity: usize = 0,
    insert_count: u64 = 0,
    known_received_count: u64 = 0,
    capacity_sent: bool = false,

    pub fn init(gpa: std.mem.Allocator) Encoder {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Encoder) void {
        for (self.dynamic.items) |e| {
            self.gpa.free(e.name);
            self.gpa.free(e.value);
        }
        self.dynamic.deinit(self.gpa);
        self.outstanding.deinit(self.gpa);
    }

    pub fn encodeFieldSection(
        self: *Encoder,
        field_block: *std.ArrayList(u8),
        encoder_stream: *std.ArrayList(u8),
        stream_id: u64,
        headers: []const Header,
        peer_capacity: u64,
        peer_blocked_streams: u64,
    ) !void {
        const advertised_capacity = std.math.cast(usize, peer_capacity) orelse std.math.maxInt(usize);
        const capacity = @min(advertised_capacity, max_dynamic_capacity);
        const blocked_streams = @min(peer_blocked_streams, max_blocked_streams);
        if (capacity == 0 or blocked_streams == 0) {
            try encode(field_block, self.gpa, headers);
            return;
        }
        const outstanding: u64 = @intCast(self.outstanding.items.len);
        if (outstanding >= blocked_streams) {
            try encode(field_block, self.gpa, headers);
            return;
        }

        var refs = try self.gpa.alloc(?u64, headers.len);
        defer self.gpa.free(refs);
        @memset(refs, null);
        var insert_refs = try self.gpa.alloc(bool, headers.len);
        defer self.gpa.free(insert_refs);
        @memset(insert_refs, false);

        var insert_size: usize = 0;
        var has_dynamic_ref = false;
        var reused_existing_ref = false;
        for (headers, 0..) |h, i| {
            if (!dynamicCandidate(h)) continue;
            if (self.findDynamic(h)) |abs| {
                refs[i] = abs;
                has_dynamic_ref = true;
                reused_existing_ref = true;
                continue;
            }
            const size = entrySize(h);
            if (size > capacity) continue;
            insert_size = std.math.add(usize, insert_size, size) catch {
                insert_size = capacity + 1;
                break;
            };
            refs[i] = 0; // selected; absolute index assigned during insertion.
            insert_refs[i] = true;
            has_dynamic_ref = true;
        }

        if (!has_dynamic_ref or insert_size > capacity) {
            try encode(field_block, self.gpa, headers);
            return;
        }

        if (reused_existing_ref and insert_size > 0 and self.dynamic_size + insert_size > capacity) {
            try encode(field_block, self.gpa, headers);
            return;
        }

        if (insert_size > 0) {
            if (!self.capacity_sent or self.dynamic_capacity != capacity) {
                try writeInteger(encoder_stream, self.gpa, @intCast(capacity), 5, 0x20);
                self.dynamic_capacity = capacity;
                self.capacity_sent = true;
            }
            self.evictUntilFits(insert_size);
            if (self.dynamic_size + insert_size > capacity) {
                try encode(field_block, self.gpa, headers);
                return;
            }
        }

        for (headers, 0..) |h, i| {
            if (!insert_refs[i]) continue;
            const abs = self.insert_count;
            try self.encodeInsert(encoder_stream, h);
            try self.insertDynamic(h);
            refs[i] = abs;
        }

        var ric: u64 = 0;
        for (refs) |ref| {
            if (ref) |abs| ric = @max(ric, abs + 1);
        }
        const max_entries = capacity / 32;
        const full_range = max_entries * 2;
        if (full_range == 0 or ric == 0) {
            try encode(field_block, self.gpa, headers);
            return;
        }
        const encoded_ric = (ric % full_range) + 1;
        try writeInteger(field_block, self.gpa, encoded_ric, 8, 0x00);
        try writeInteger(field_block, self.gpa, 0, 7, 0x00); // Base = Required Insert Count.

        for (headers, refs) |h, ref| {
            if (ref) |abs| {
                const relative = ric - abs - 1;
                try writeInteger(field_block, self.gpa, relative, 6, 0x80);
            } else {
                try encodeHeader(field_block, self.gpa, h);
            }
        }
        try self.outstanding.append(self.gpa, .{ .stream_id = stream_id, .required_insert_count = ric });
    }

    fn findDynamic(self: *const Encoder, h: Header) ?u64 {
        var i = self.dynamic.items.len;
        while (i > 0) {
            i -= 1;
            const e = self.dynamic.items[i];
            if (std.mem.eql(u8, e.name, h.name) and std.mem.eql(u8, e.value, h.value)) return e.abs;
        }
        return null;
    }

    pub fn processDecoder(self: *Encoder, bytes: []const u8) Error!DecoderProgress {
        var p = Parser{ .buf = bytes };
        while (p.pos < bytes.len) {
            const start = p.pos;
            const b = p.buf[p.pos];
            if (b & 0x80 != 0) {
                const stream_id = p.integer(7) catch |err| switch (err) {
                    error.NeedData => return .{ .consumed = start },
                    else => return err,
                };
                try self.ackSection(stream_id);
            } else if (b & 0x40 != 0) {
                const stream_id = p.integer(6) catch |err| switch (err) {
                    error.NeedData => return .{ .consumed = start },
                    else => return err,
                };
                try self.cancelStream(stream_id);
            } else {
                const increment = p.integer(6) catch |err| switch (err) {
                    error.NeedData => return .{ .consumed = start },
                    else => return err,
                };
                if (increment == 0) return error.DecompressionFailed;
                const next_known_received_count = std.math.add(u64, self.known_received_count, increment) catch return error.DecompressionFailed;
                if (next_known_received_count > self.insert_count) return error.DecompressionFailed;
                self.known_received_count = next_known_received_count;
                self.evictUntilFits(0);
            }
        }
        return .{ .consumed = p.pos };
    }

    fn encodeInsert(self: *Encoder, out: *std.ArrayList(u8), h: Header) !void {
        if (static_table.nameIndex(h.name)) |idx| {
            try writeInteger(out, self.gpa, @intCast(idx), 6, 0xC0);
            try writeString(out, self.gpa, 7, 0x00, h.value);
            return;
        }
        try writeString(out, self.gpa, 5, 0x40, h.name);
        try writeString(out, self.gpa, 7, 0x00, h.value);
    }

    fn insertDynamic(self: *Encoder, h: Header) !void {
        const name_copy = try self.gpa.dupe(u8, h.name);
        errdefer self.gpa.free(name_copy);
        const value_copy = try self.gpa.dupe(u8, h.value);
        errdefer self.gpa.free(value_copy);
        const size = entrySize(h);
        try self.dynamic.append(self.gpa, .{ .name = name_copy, .value = value_copy, .size = size, .abs = self.insert_count });
        self.dynamic_size += size;
        self.insert_count += 1;
    }

    fn ackSection(self: *Encoder, stream_id: u64) Error!void {
        for (self.outstanding.items, 0..) |o, i| {
            if (o.stream_id == stream_id) {
                self.known_received_count = @max(self.known_received_count, o.required_insert_count);
                _ = self.outstanding.orderedRemove(i);
                self.evictUntilFits(0);
                return;
            }
        }
        return error.DecompressionFailed;
    }

    fn cancelStream(self: *Encoder, stream_id: u64) Error!void {
        var found = false;
        var i: usize = 0;
        while (i < self.outstanding.items.len) {
            if (self.outstanding.items[i].stream_id == stream_id) {
                _ = self.outstanding.orderedRemove(i);
                found = true;
            } else {
                i += 1;
            }
        }
        if (!found) return error.DecompressionFailed;
        self.evictUntilFits(0);
    }

    fn evictUntilFits(self: *Encoder, need: usize) void {
        while (self.dynamic_size + need > self.dynamic_capacity and self.canEvictOldest()) {
            self.evictOldest();
        }
    }

    fn canEvictOldest(self: *const Encoder) bool {
        if (self.outstanding.items.len != 0) return false;
        if (self.dynamic.items.len == 0) return false;
        return self.dynamic.items[0].abs < self.known_received_count;
    }

    fn evictOldest(self: *Encoder) void {
        const e = self.dynamic.orderedRemove(0);
        self.dynamic_size -= e.size;
        self.gpa.free(e.name);
        self.gpa.free(e.value);
    }

    fn dynamicCandidate(h: Header) bool {
        return h.name.len > 0 and h.name[0] != ':' and static_table.nameValueIndex(h.name, h.value) == null;
    }

    fn entrySize(h: Header) usize {
        return h.name.len + h.value.len + 32;
    }
};

const Parser = struct {
    buf: []const u8,
    pos: usize = 0,

    fn integer(self: *Parser, prefix: u4) Error!u64 {
        if (self.pos >= self.buf.len) return error.NeedData;
        const max_prefix: u64 = (@as(u64, 1) << @as(u6, prefix)) - 1;
        var value: u64 = self.buf[self.pos] & max_prefix;
        self.pos += 1;
        if (value < max_prefix) return value;
        var shift: u32 = 0;
        while (true) {
            if (self.pos >= self.buf.len) return error.NeedData;
            const b = self.buf[self.pos];
            self.pos += 1;
            if (shift >= @bitSizeOf(u64)) return error.DecompressionFailed;
            const add = @as(u64, b & 0x7f);
            const shifted = std.math.shlExact(u64, add, @intCast(shift)) catch return error.DecompressionFailed;
            value = std.math.add(u64, value, shifted) catch return error.DecompressionFailed;
            if (b & 0x80 == 0) break;
            shift += 7;
        }
        return value;
    }
};

/// Decoder stream instruction (RFC 9204 4.4.1): acknowledge the earliest
/// unacknowledged dynamic field section on `stream_id`.
pub fn encodeSectionAcknowledgment(out: *std.ArrayList(u8), gpa: std.mem.Allocator, stream_id: u64) !void {
    try writeInteger(out, gpa, stream_id, 7, 0x80);
}

/// Decoder stream instruction (RFC 9204 4.4.2): cancel outstanding dynamic
/// references for an abandoned stream.
pub fn encodeStreamCancellation(out: *std.ArrayList(u8), gpa: std.mem.Allocator, stream_id: u64) !void {
    try writeInteger(out, gpa, stream_id, 6, 0x40);
}

/// Decoder stream instruction (RFC 9204 4.4.3): advance the encoder's Known
/// Received Count by `increment`. A zero increment is invalid on the wire.
pub fn encodeInsertCountIncrement(out: *std.ArrayList(u8), gpa: std.mem.Allocator, increment: u64) !void {
    if (increment == 0) return error.InvalidIncrement;
    try writeInteger(out, gpa, increment, 6, 0x00);
}

const testing = std.testing;

fn roundTrip(headers: []const Header) !void {
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

test "encode decoder stream instructions" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try encodeInsertCountIncrement(&out, testing.allocator, 1);
    try encodeSectionAcknowledgment(&out, testing.allocator, 0);
    try encodeStreamCancellation(&out, testing.allocator, 4);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x80, 0x40 | 4 }, out.items);
}

test "stateful encoder emits dynamic inserts and references" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(testing.allocator);
    var enc_stream: std.ArrayList(u8) = .empty;
    defer enc_stream.deinit(testing.allocator);

    try enc.encodeFieldSection(&block, &enc_stream, 0, &.{.{ .name = "x-dyn", .value = "v" }}, 128, 1);

    var dec = decoder.Decoder.init(testing.allocator, 1 << 20);
    defer dec.deinit();
    dec.setMaxDynamicCapacity(128);
    const progress = try dec.processEncoder(enc_stream.items);
    try testing.expectEqual(enc_stream.items.len, progress.consumed);
    const out = try dec.decode(block.items);
    try testing.expectEqual(@as(usize, 1), out.len);
    try testing.expectEqualStrings("x-dyn", out[0].name);
    try testing.expectEqualStrings("v", out[0].value);
}

test "stateful encoder reuses an exact dynamic entry" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();

    var block1: std.ArrayList(u8) = .empty;
    defer block1.deinit(testing.allocator);
    var enc_stream1: std.ArrayList(u8) = .empty;
    defer enc_stream1.deinit(testing.allocator);
    try enc.encodeFieldSection(&block1, &enc_stream1, 0, &.{.{ .name = "content-length", .value = "2" }}, 128, 4);
    try testing.expect(enc_stream1.items.len > 0);
    try testing.expectEqual(@as(u64, 1), enc.insert_count);

    var block2: std.ArrayList(u8) = .empty;
    defer block2.deinit(testing.allocator);
    var enc_stream2: std.ArrayList(u8) = .empty;
    defer enc_stream2.deinit(testing.allocator);
    try enc.encodeFieldSection(&block2, &enc_stream2, 4, &.{.{ .name = "content-length", .value = "2" }}, 128, 4);
    try testing.expectEqual(@as(usize, 0), enc_stream2.items.len);
    try testing.expectEqual(@as(u64, 1), enc.insert_count);
    try testing.expect(block2.items[0] != 0);

    var dec = decoder.Decoder.init(testing.allocator, 1 << 20);
    defer dec.deinit();
    dec.setMaxDynamicCapacity(128);
    const progress = try dec.processEncoder(enc_stream1.items);
    try testing.expectEqual(enc_stream1.items.len, progress.consumed);
    _ = try dec.decode(block1.items);
    const out = try dec.decode(block2.items);
    try testing.expectEqual(@as(usize, 1), out.len);
    try testing.expectEqualStrings("content-length", out[0].name);
    try testing.expectEqualStrings("2", out[0].value);
}

test "stateful encoder avoids evicting a reused entry in the same field section" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();

    var block1: std.ArrayList(u8) = .empty;
    defer block1.deinit(testing.allocator);
    var enc_stream1: std.ArrayList(u8) = .empty;
    defer enc_stream1.deinit(testing.allocator);
    try enc.encodeFieldSection(&block1, &enc_stream1, 0, &.{.{ .name = "x-a", .value = "v" }}, 64, 4);
    try testing.expect(enc_stream1.items.len > 0);
    try testing.expectEqual(@as(u64, 1), enc.insert_count);

    const ack = try enc.processDecoder(&.{ 0x01, 0x80 }); // Insert Count Increment(1), Section Ack(stream 0).
    try testing.expectEqual(@as(usize, 2), ack.consumed);
    try testing.expectEqual(@as(usize, 36), enc.dynamic_size);

    var block2: std.ArrayList(u8) = .empty;
    defer block2.deinit(testing.allocator);
    var enc_stream2: std.ArrayList(u8) = .empty;
    defer enc_stream2.deinit(testing.allocator);
    try enc.encodeFieldSection(&block2, &enc_stream2, 4, &.{
        .{ .name = "x-a", .value = "v" },
        .{ .name = "x-b", .value = "v" },
    }, 64, 4);

    try testing.expectEqual(@as(usize, 0), enc_stream2.items.len);
    try testing.expectEqual(@as(u64, 1), enc.insert_count);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, block2.items[0..2]);

    var dec = decoder.Decoder.init(testing.allocator, 1 << 20);
    defer dec.deinit();
    dec.setMaxDynamicCapacity(64);
    _ = try dec.processEncoder(enc_stream1.items);
    const out = try dec.decode(block2.items);
    try testing.expectEqual(@as(usize, 2), out.len);
    try testing.expectEqualStrings("x-a", out[0].name);
    try testing.expectEqualStrings("v", out[0].value);
    try testing.expectEqualStrings("x-b", out[1].name);
    try testing.expectEqualStrings("v", out[1].value);
}

test "peer settings cannot raise local encoder state limits" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();

    for (0..64) |index| {
        var value = [_]u8{'x'} ** 256;
        value[0] = @intCast('A' + index / 26);
        value[1] = @intCast('A' + index % 26);
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(testing.allocator);
        var encoder_stream: std.ArrayList(u8) = .empty;
        defer encoder_stream.deinit(testing.allocator);
        try enc.encodeFieldSection(
            &block,
            &encoder_stream,
            @intCast(index * 4),
            &.{.{ .name = "x-vary", .value = &value }},
            std.math.maxInt(u64),
            std.math.maxInt(u64),
        );
    }

    try testing.expectEqual(max_dynamic_capacity, enc.dynamic_capacity);
    try testing.expect(enc.dynamic_size <= max_dynamic_capacity);
    try testing.expect(@as(u64, @intCast(enc.outstanding.items.len)) <= max_blocked_streams);
}

test "decoder stream acknowledgements allow dynamic table reuse" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();

    var block1: std.ArrayList(u8) = .empty;
    defer block1.deinit(testing.allocator);
    var enc_stream1: std.ArrayList(u8) = .empty;
    defer enc_stream1.deinit(testing.allocator);
    try enc.encodeFieldSection(&block1, &enc_stream1, 0, &.{.{ .name = "x-a", .value = "v" }}, 64, 1);
    try testing.expect(enc_stream1.items.len > 0);
    try testing.expectEqual(@as(usize, 1), enc.outstanding.items.len);
    try testing.expectEqual(@as(usize, 36), enc.dynamic_size);

    var block2: std.ArrayList(u8) = .empty;
    defer block2.deinit(testing.allocator);
    var enc_stream2: std.ArrayList(u8) = .empty;
    defer enc_stream2.deinit(testing.allocator);
    try enc.encodeFieldSection(&block2, &enc_stream2, 4, &.{.{ .name = "x-b", .value = "v" }}, 64, 1);
    try testing.expectEqual(@as(usize, 0), enc_stream2.items.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, block2.items[0..2]);
    try testing.expectEqual(@as(usize, 1), enc.outstanding.items.len);

    const progress = try enc.processDecoder(&.{ 0x01, 0x80 }); // Insert Count Increment(1), Section Ack(stream 0).
    try testing.expectEqual(@as(usize, 2), progress.consumed);
    try testing.expectEqual(@as(u64, 1), enc.known_received_count);
    try testing.expectEqual(@as(usize, 0), enc.outstanding.items.len);
    try testing.expectEqual(@as(usize, 36), enc.dynamic_size);

    var block3: std.ArrayList(u8) = .empty;
    defer block3.deinit(testing.allocator);
    var enc_stream3: std.ArrayList(u8) = .empty;
    defer enc_stream3.deinit(testing.allocator);
    try enc.encodeFieldSection(&block3, &enc_stream3, 4, &.{.{ .name = "x-b", .value = "v" }}, 64, 1);
    try testing.expect(enc_stream3.items.len > 0);
    try testing.expect(block3.items[0] != 0);
}

test "section acknowledgement updates the known received count" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(testing.allocator);
    var enc_stream: std.ArrayList(u8) = .empty;
    defer enc_stream.deinit(testing.allocator);
    try enc.encodeFieldSection(&block, &enc_stream, 0, &.{.{ .name = "x-a", .value = "v" }}, 64, 1);
    try testing.expectEqual(@as(u64, 1), enc.insert_count);
    try testing.expectEqual(@as(u64, 0), enc.known_received_count);
    try testing.expectEqual(@as(usize, 1), enc.outstanding.items.len);

    const progress = try enc.processDecoder(&.{0x80}); // Section Ack(stream 0), no Insert Count Increment.
    try testing.expectEqual(@as(usize, 1), progress.consumed);
    try testing.expectEqual(@as(u64, 1), enc.known_received_count);
    try testing.expectEqual(@as(usize, 0), enc.outstanding.items.len);
    try testing.expectEqual(@as(usize, 36), enc.dynamic_size);
}

test "decoder stream processing stops before an incomplete instruction" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();

    try testing.expectEqual(@as(usize, 0), (try enc.processDecoder(&.{0x3f})).consumed);
    try testing.expectError(error.DecompressionFailed, enc.processDecoder(&.{0x00}));
}

test "invalid insert count increment leaves encoder state unchanged" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();

    enc.insert_count = 1;
    try testing.expectError(error.DecompressionFailed, enc.processDecoder(&.{0x02}));
    try testing.expectEqual(@as(u64, 0), enc.known_received_count);
}
