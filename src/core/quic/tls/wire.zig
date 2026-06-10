//! The big-endian length-prefixed reader/writer TLS 1.3 handshake messages are
//! built from (RFC 8446 3.4). The mirror of frame.zig's Cursor, but TLS lengths
//! are fixed-width u8/u16/u24 big-endian, not QUIC varints. Every slice a Reader
//! returns borrows from the fed buffer; the Writer appends into a caller list.
//!
//! `vector` is the crux: it returns a sub-Reader whose buf IS the carved slice,
//! so an inner length can never reach a sibling's bytes - length-confusion stops
//! being a check you can forget and becomes a structural property.

const std = @import("std");

pub const Error = error{
    /// A length field runs past the fed end. Inside a fully-buffered, contiguous
    /// handshake message this is fatal (the message boundary is atomic); the
    /// caller is responsible for not parsing until a whole message is buffered
    /// (see handshake.peek), so this never means "need more".
    Truncated,
    /// Structurally invalid: an inner length exceeds its outer vector, trailing
    /// bytes remain after a declared length, an illegal legacy field, a duplicate
    /// or malformed extension, or a TLS 1.3 downgrade signal.
    EncodingError,
};

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn byte(self: *Reader) Error!u8 {
        if (self.pos >= self.buf.len) return error.Truncated;
        defer self.pos += 1;
        return self.buf[self.pos];
    }

    pub fn readU16(self: *Reader) Error!u16 {
        const s = try self.take(2);
        return std.mem.readInt(u16, s[0..2], .big);
    }

    pub fn readU24(self: *Reader) Error!u32 {
        const s = try self.take(3);
        return (@as(u32, s[0]) << 16) | (@as(u32, s[1]) << 8) | s[2];
    }

    /// Take exactly `n` bytes, borrowing from buf. Overflow-safe: the bound is
    /// `n > remaining()` rather than `pos + n > len`, so an attacker-controlled
    /// u24 length (up to 16 MiB) can never wrap the addition.
    pub fn take(self: *Reader, n: usize) Error![]const u8 {
        if (n > self.remaining()) return error.Truncated;
        defer self.pos += n;
        return self.buf[self.pos .. self.pos + n];
    }

    /// Read an `Lbytes`-prefixed vector and return a sub-Reader scoped to exactly
    /// its bytes. The returned Reader cannot see past the vector, so any nested
    /// parse is clamped to its declared length by construction.
    pub fn vector(self: *Reader, comptime Lbytes: u2) Error!Reader {
        const n: usize = switch (Lbytes) {
            1 => try self.byte(),
            2 => try self.readU16(),
            3 => try self.readU24(),
            else => @compileError("vector length prefix is 1, 2, or 3 bytes"),
        };
        return .{ .buf = try self.take(n) };
    }

    pub fn remaining(self: *const Reader) usize {
        std.debug.assert(self.pos <= self.buf.len); // the one invariant take's safety rests on
        return self.buf.len - self.pos;
    }

    /// Trailing bytes after a declared length are an encoding error - the smuggling
    /// defense. Called after every vector whose container has no further fields.
    pub fn expectEnd(self: *const Reader) Error!void {
        if (self.remaining() != 0) return error.EncodingError;
    }
};

pub const Length = struct { at: usize, width: u2 };

pub const Writer = struct {
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,

    pub fn u8v(self: Writer, v: u8) !void {
        try self.out.append(self.gpa, v);
    }
    pub fn u16v(self: Writer, v: u16) !void {
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, v, .big);
        try self.out.appendSlice(self.gpa, &b);
    }
    pub fn bytes(self: Writer, b: []const u8) !void {
        try self.out.appendSlice(self.gpa, b);
    }

    /// Reserve an `Lbytes`-wide length placeholder; close() back-patches it.
    pub fn open(self: Writer, comptime Lbytes: u2) !Length {
        const at = self.out.items.len;
        try self.out.appendNTimes(self.gpa, 0, Lbytes);
        return .{ .at = at, .width = Lbytes };
    }

    /// Back-patch the placeholder with the byte count written since open(). A body
    /// too large for the prefix width is EncodingError, never a panicking @intCast.
    pub fn close(self: Writer, l: Length) Error!void {
        const body_len = self.out.items.len - l.at - l.width;
        const slot = self.out.items[l.at .. l.at + l.width];
        switch (l.width) {
            1 => {
                if (body_len > 0xFF) return error.EncodingError;
                slot[0] = @intCast(body_len);
            },
            2 => {
                if (body_len > 0xFFFF) return error.EncodingError;
                std.mem.writeInt(u16, slot[0..2], @intCast(body_len), .big);
            },
            3 => {
                if (body_len > 0xFF_FFFF) return error.EncodingError;
                slot[0] = @intCast(body_len >> 16);
                slot[1] = @truncate(body_len >> 8);
                slot[2] = @truncate(body_len);
            },
            else => unreachable,
        }
    }
};

const testing = std.testing;

test "vector returns a sub-reader clamped to its declared length" {
    var r = Reader{ .buf = &.{ 0x00, 0x03, 0xAA, 0xBB, 0xCC, 0xDD } }; // u16 len 3, then 3 bytes + 1 trailing
    var inner = try r.vector(2);
    try testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB, 0xCC }, inner.buf);
    try testing.expectEqual(@as(usize, 1), r.remaining()); // 0xDD untouched by inner
    try testing.expectError(error.Truncated, inner.take(4)); // cannot read past the carved slice
}

test "an inner length exceeding the buffer is Truncated, not a wild read" {
    var r = Reader{ .buf = &.{ 0x00, 0x10 } }; // u16 len 16 over a 0-byte body
    try testing.expectError(error.Truncated, r.vector(2));
}

test "expectEnd rejects trailing bytes" {
    var r = Reader{ .buf = &.{ 0x01, 0x02 } };
    _ = try r.byte();
    try testing.expectError(error.EncodingError, r.expectEnd());
}

test "open/close round-trips a u16 length and rejects oversize on width 1" {
    var list = std.ArrayListUnmanaged(u8).empty;
    defer list.deinit(testing.allocator);
    const w = Writer{ .out = &list, .gpa = testing.allocator };
    const l = try w.open(2);
    try w.bytes(&.{ 0xDE, 0xAD, 0xBE });
    try w.close(l);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x03, 0xDE, 0xAD, 0xBE }, list.items);

    var big = std.ArrayListUnmanaged(u8).empty;
    defer big.deinit(testing.allocator);
    const w2 = Writer{ .out = &big, .gpa = testing.allocator };
    const l2 = try w2.open(1);
    try w2.bytes(&[_]u8{0} ** 256); // 256 bytes cannot fit a u8 length
    try testing.expectError(error.EncodingError, w2.close(l2));
}
