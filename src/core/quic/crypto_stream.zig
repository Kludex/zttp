//! Per-encryption-level CRYPTO-frame reassembly (RFC 9001 4): one ordered byte run
//! assembled from possibly-reordered, possibly-overlapping CRYPTO frames in a single
//! packet-number space. Unlike a STREAM, CRYPTO has no flags and no final size, and
//! an overlap that carries DIFFERING bytes is a PROTOCOL_VIOLATION (RFC 9000 19.6),
//! not the benign retransmit a STREAM tolerates. `readable` yields the contiguous
//! prefix the TLS codec consumes via handshake.peek.
//!
//! The assembled prefix [0, contiguous) is kept resident in full and `consumed` is a
//! read cursor into it, so a conflicting retransmit of ALREADY-consumed bytes is
//! still caught (the bytes are still there to compare). A handshake is small and the
//! total buffered size is bounded, so retaining the prefix is cheap and removes the
//! blind spot a discard-on-consume design would have below the cursor.

const std = @import("std");

/// The most CRYPTO data one space will buffer before giving up (RFC 9000 reserves
/// CRYPTO_BUFFER_EXCEEDED, 0x0d, for exactly this). A TLS server flight and a
/// client flight both fit comfortably; a peer that exceeds it is abusive.
pub const MAX_BUFFERED: usize = 64 * 1024;

/// The most out-of-order fragments to hold, so a peer cannot force O(N^2) work and
/// N allocations by sending one byte per frame in reverse order.
pub const MAX_FRAGMENTS: usize = 256;

pub const Error = error{
    /// Overlapping CRYPTO frames disagreed on a byte (RFC 9000 19.6 / PROTOCOL_VIOLATION).
    CryptoConflict,
    /// Buffered CRYPTO exceeded MAX_BUFFERED or MAX_FRAGMENTS (RFC 9000 CRYPTO_BUFFER_EXCEEDED).
    CryptoBufferExceeded,
    OutOfMemory,
};

const Fragment = struct { offset: u64, data: []u8 };

pub const CryptoStream = struct {
    gpa: std.mem.Allocator,
    contiguous: u64 = 0, // bytes assembled in order from 0
    consumed: usize = 0, // read cursor into `ready`; how far the codec has advanced
    ready: std.ArrayListUnmanaged(u8) = .empty, // the full assembled prefix [0, contiguous)
    pending: std.ArrayListUnmanaged(Fragment) = .empty, // out-of-order fragments above contiguous

    pub fn init(gpa: std.mem.Allocator) CryptoStream {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *CryptoStream) void {
        for (self.pending.items) |f| self.gpa.free(f.data);
        self.pending.deinit(self.gpa);
        self.ready.deinit(self.gpa);
    }

    /// Accept one CRYPTO frame. Bytes already assembled are verified to match (a
    /// mismatch is CryptoConflict); the new in-order tail extends `ready` and may
    /// unlock buffered fragments; bytes ahead of the run are buffered, bounded.
    pub fn push(self: *CryptoStream, offset: u64, data: []const u8) Error!void {
        try self.verifyOverlap(offset, data);
        const end = std.math.add(u64, offset, data.len) catch return error.CryptoBufferExceeded;
        if (end <= self.contiguous) return; // wholly duplicate, verified equal above
        if (offset <= self.contiguous) {
            const skip: usize = @intCast(self.contiguous - offset);
            try self.appendReady(data[skip..]);
            self.contiguous = end;
            try self.drainPending();
        } else {
            try self.buffer(offset, data);
        }
    }

    /// The in-order bytes the codec has not yet consumed (a borrow valid until the
    /// next push/advance). The codec runs handshake.peek over this.
    pub fn readable(self: *const CryptoStream) []const u8 {
        return self.ready.items[self.consumed..];
    }

    /// Mark `n` readable bytes consumed once whole handshake messages are parsed.
    /// The bytes stay resident (for overlap checks); only the cursor moves.
    pub fn advance(self: *CryptoStream, n: usize) void {
        self.consumed = @min(self.consumed + n, self.ready.items.len);
    }

    fn appendReady(self: *CryptoStream, bytes: []const u8) Error!void {
        if (self.ready.items.len + bytes.len > MAX_BUFFERED) return error.CryptoBufferExceeded;
        self.ready.appendSlice(self.gpa, bytes) catch return error.OutOfMemory;
    }

    /// A conflicting retransmit is caught wherever it lands: against the full
    /// resident prefix [0, contiguous) and against every buffered fragment.
    fn verifyOverlap(self: *CryptoStream, offset: u64, data: []const u8) Error!void {
        const end = std.math.add(u64, offset, data.len) catch return error.CryptoBufferExceeded;
        const lo = offset; // the prefix starts at 0, so compare from the frame start
        const hi = @min(end, self.contiguous);
        if (lo < hi) {
            const ours = self.ready.items[@intCast(lo)..@intCast(hi)];
            const theirs = data[0..@as(usize, @intCast(hi - lo))];
            if (!std.mem.eql(u8, ours, theirs)) return error.CryptoConflict;
        }
        for (self.pending.items) |f| {
            const flo = @max(offset, f.offset);
            const fend = std.math.add(u64, f.offset, f.data.len) catch return error.CryptoBufferExceeded;
            const fhi = @min(end, fend);
            if (flo < fhi) {
                const a = f.data[@intCast(flo - f.offset)..@intCast(fhi - f.offset)];
                const b = data[@intCast(flo - offset)..@intCast(fhi - offset)];
                if (!std.mem.eql(u8, a, b)) return error.CryptoConflict;
            }
        }
    }

    fn buffer(self: *CryptoStream, offset: u64, data: []const u8) Error!void {
        if (self.pending.items.len >= MAX_FRAGMENTS) return error.CryptoBufferExceeded;
        if (self.bufferedBytes() + data.len > MAX_BUFFERED) return error.CryptoBufferExceeded;
        const copy = self.gpa.dupe(u8, data) catch return error.OutOfMemory;
        errdefer self.gpa.free(copy);
        var idx: usize = 0;
        while (idx < self.pending.items.len and self.pending.items[idx].offset < offset) idx += 1;
        self.pending.insert(self.gpa, idx, .{ .offset = offset, .data = copy }) catch return error.OutOfMemory;
    }

    fn bufferedBytes(self: *const CryptoStream) usize {
        var n: usize = self.ready.items.len;
        for (self.pending.items) |f| n += f.data.len;
        return n;
    }

    fn drainPending(self: *CryptoStream) Error!void {
        var progressed = true;
        while (progressed) {
            progressed = false;
            var i: usize = 0;
            while (i < self.pending.items.len) {
                const f = self.pending.items[i];
                const fend = std.math.add(u64, f.offset, f.data.len) catch return error.CryptoBufferExceeded;
                if (fend <= self.contiguous) {
                    self.gpa.free(f.data);
                    _ = self.pending.orderedRemove(i);
                    progressed = true;
                    continue;
                }
                if (f.offset <= self.contiguous) {
                    const skip: usize = @intCast(self.contiguous - f.offset);
                    try self.appendReady(f.data[skip..]);
                    self.contiguous = fend;
                    self.gpa.free(f.data);
                    _ = self.pending.orderedRemove(i);
                    progressed = true;
                    continue;
                }
                i += 1;
            }
        }
    }
};

const testing = std.testing;

test "in-order frames assemble into a readable prefix" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();
    try cs.push(0, "hello ");
    try cs.push(6, "world");
    try testing.expectEqualStrings("hello world", cs.readable());
    cs.advance(6);
    try testing.expectEqualStrings("world", cs.readable());
}

test "reordered frames reassemble; a gap holds back the prefix" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();
    try cs.push(6, "world"); // arrives first, buffered
    try testing.expectEqualStrings("", cs.readable()); // nothing in order yet
    try cs.push(0, "hello "); // unlocks the buffered tail
    try testing.expectEqualStrings("hello world", cs.readable());
}

test "an identical retransmit is a benign no-op" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();
    try cs.push(0, "abcdef");
    try cs.push(2, "cd"); // same bytes, fully inside the prefix
    try testing.expectEqualStrings("abcdef", cs.readable());
}

test "a conflicting overlap is a CryptoConflict, before and after consume" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();
    try cs.push(0, "abcdef");
    try testing.expectError(error.CryptoConflict, cs.push(2, "XX")); // [2,4) disagrees
    // Even after the codec consumes the bytes, a conflicting retransmit is caught
    // (the prefix stays resident).
    cs.advance(6);
    try testing.expectError(error.CryptoConflict, cs.push(0, "abXdef"));
}

test "a conflict against a buffered out-of-order fragment is caught" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();
    try cs.push(10, "world"); // buffered above the gap
    try testing.expectError(error.CryptoConflict, cs.push(12, "XX")); // disagrees with [12,14)
}

test "offset overflow is rejected before CRYPTO reassembly" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();
    try testing.expectError(error.CryptoBufferExceeded, cs.push(std.math.maxInt(u64), "x"));
}

test "buffering beyond MAX_BUFFERED is CryptoBufferExceeded" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();
    const big = [_]u8{0} ** 1024;
    var off: u64 = MAX_BUFFERED; // far ahead, never becomes contiguous
    var i: usize = 0;
    while (i < MAX_FRAGMENTS) : (i += 1) {
        cs.push(off, &big) catch |e| {
            try testing.expectEqual(error.CryptoBufferExceeded, e);
            return;
        };
        off += 4096;
    }
    return error.TestExpectedExceeded;
}
