//! The QUIC stream layer (RFC 9000 sections 2-3): stream-id typing and the recv
//! side that reassembles out-of-order STREAM frames into one ordered byte run. A
//! QUIC stream id encodes its initiator (client/server) and directionality
//! (bidi/uni) in its low two bits; everything above is the sequence number. The
//! recv buffer takes (offset, data, fin) fragments in any order and yields the
//! contiguous prefix the application can read. HTTP/3 sits directly on top of
//! this, pulling ordered bytes per stream.

const std = @import("std");

/// The four stream-id classes (RFC 9000 2.1), the low two bits of the id.
pub const StreamType = enum(u2) {
    client_bidi = 0x0,
    server_bidi = 0x1,
    client_uni = 0x2,
    server_uni = 0x3,

    pub fn of(id: u64) StreamType {
        return @enumFromInt(@as(u2, @truncate(id)));
    }

    pub fn isUni(self: StreamType) bool {
        return self == .client_uni or self == .server_uni;
    }

    pub fn isClientInitiated(self: StreamType) bool {
        return self == .client_bidi or self == .client_uni;
    }
};

/// The recv-side state machine (RFC 9000 3.2). We only need the states the read
/// path acts on: receiving, then size-known (a FIN arrived) and finally read once
/// the application has consumed everything.
pub const RecvState = enum {
    recv,
    size_known,
    data_read,
    reset_recvd,
};

pub const Error = error{
    /// Data arrived past the final size, or a second/conflicting FIN moved the
    /// final size (RFC 9000 4.5): FINAL_SIZE_ERROR.
    FinalSizeError,
    OutOfMemory,
};

/// One buffered fragment that has not yet been delivered in order.
const Fragment = struct {
    offset: u64,
    data: []u8, // owned copy; freed when consumed or on deinit
};

/// The receive half of one stream: an ordered byte run assembled from
/// possibly-reordered STREAM frames. `read_offset` is how far the application has
/// consumed; `contiguous` is how far an unbroken run extends from there.
pub const RecvStream = struct {
    gpa: std.mem.Allocator,
    state: RecvState = .recv,
    read_offset: u64 = 0,
    contiguous: u64 = 0,
    /// The largest byte offset ever received on this stream (may exceed
    /// `contiguous` when fragments arrive out of order). Connection-level flow
    /// control sums the growth of this across all streams.
    highest_received: u64 = 0,
    final_size: ?u64 = null,
    /// Out-of-order fragments above `contiguous`, kept sorted by offset.
    pending: std.ArrayListUnmanaged(Fragment) = .empty,
    /// The in-order, not-yet-read bytes [read_offset, contiguous).
    ready: std.ArrayListUnmanaged(u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) RecvStream {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *RecvStream) void {
        for (self.pending.items) |f| self.gpa.free(f.data);
        self.pending.deinit(self.gpa);
        self.ready.deinit(self.gpa);
    }

    /// Take a STREAM frame fragment. Bytes at or below `contiguous` extend the
    /// in-order run (and may unlock buffered fragments); bytes above it are
    /// buffered. A FIN fixes the final size. Returns how much the stream's highest
    /// received offset grew, which the connection charges against its window.
    pub fn push(self: *RecvStream, offset: u64, data: []const u8, fin: bool) Error!u64 {
        const end = offset + data.len;
        if (self.final_size) |fs| {
            if (end > fs) return error.FinalSizeError;
            if (fin and end != fs) return error.FinalSizeError;
        }
        const new_high = @max(self.highest_received, end);
        const delta = new_high - self.highest_received;
        self.highest_received = new_high;
        if (fin) {
            if (self.final_size) |fs| {
                if (fs != end) return error.FinalSizeError;
            } else self.final_size = end;
            if (self.state == .recv) self.state = .size_known;
        }

        if (end <= self.contiguous) return delta; // wholly duplicate

        if (offset <= self.contiguous) {
            const skip = self.contiguous - offset;
            try self.ready.appendSlice(self.gpa, data[skip..]);
            self.contiguous = end;
            try self.drainPending();
        } else {
            try self.buffer(offset, data);
        }
        return delta;
    }

    fn buffer(self: *RecvStream, offset: u64, data: []const u8) Error!void {
        const copy = try self.gpa.dupe(u8, data);
        errdefer self.gpa.free(copy);
        // Keep pending sorted by offset for an in-order drain.
        var idx: usize = 0;
        while (idx < self.pending.items.len and self.pending.items[idx].offset < offset) idx += 1;
        try self.pending.insert(self.gpa, idx, .{ .offset = offset, .data = copy });
    }

    fn drainPending(self: *RecvStream) Error!void {
        var progressed = true;
        while (progressed) {
            progressed = false;
            var i: usize = 0;
            while (i < self.pending.items.len) {
                const f = self.pending.items[i];
                const fend = f.offset + f.data.len;
                if (fend <= self.contiguous) {
                    self.gpa.free(f.data);
                    _ = self.pending.orderedRemove(i);
                    progressed = true;
                    continue;
                }
                if (f.offset <= self.contiguous) {
                    const skip = self.contiguous - f.offset;
                    try self.ready.appendSlice(self.gpa, f.data[skip..]);
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

    /// The in-order bytes available to read right now (a borrow valid until the
    /// next `consume`).
    pub fn readable(self: *const RecvStream) []const u8 {
        return self.ready.items;
    }

    /// Mark `n` readable bytes consumed, sliding the read offset. The transport
    /// uses this to know how much connection/stream flow-control credit to re-grant.
    pub fn consume(self: *RecvStream, n: usize) void {
        const take = @min(n, self.ready.items.len);
        self.read_offset += take;
        // Shift the remaining ready bytes down.
        const rest = self.ready.items.len - take;
        std.mem.copyForwards(u8, self.ready.items[0..rest], self.ready.items[take..]);
        self.ready.shrinkRetainingCapacity(rest);
        if (self.isFinished() and self.ready.items.len == 0) self.state = .data_read;
    }

    /// Has every byte through the final size been delivered into `ready`?
    pub fn isFinished(self: *const RecvStream) bool {
        return if (self.final_size) |fs| self.contiguous >= fs else false;
    }

    pub fn onReset(self: *RecvStream, final_size: u64) Error!void {
        if (self.final_size) |fs| {
            if (fs != final_size) return error.FinalSizeError;
        } else self.final_size = final_size;
        self.state = .reset_recvd;
    }
};

/// The send side of one stream: a retain buffer of all unacked bytes the
/// connection drains into STREAM frames, plus the bookkeeping to retransmit a
/// range whose packet was lost. One contiguous `buf` holds [base_offset, end);
/// the `sent` cursor splits already-framed bytes (left) from never-framed bytes
/// (right). Lost ranges are re-framed before new bytes (RFC 9002 13.3); acked
/// bytes are freed off the front. Mirrors RecvStream, but for the write direction.
pub const SendStream = struct {
    gpa: std.mem.Allocator,
    /// Every written, not-yet-acked byte: [base_offset, base_offset + buf.len).
    buf: std.ArrayListUnmanaged(u8) = .empty,
    /// Offset of buf.items[0]; everything below is acked and freed.
    base_offset: u64 = 0,
    /// Bytes in [base_offset, sent) have ridden a frame; [sent, end) are new. The
    /// cursor only moves forward (commit); a loss records a `lost` range instead.
    sent: u64 = 0,
    fin: bool = false, // the application finished writing; a FIN is owed at end()
    fin_sent: bool = false, // the FIN has ridden a frame
    fin_acked: bool = false, // the FIN has been acknowledged
    fin_lost: bool = false, // the FIN's packet was lost; it must ride again
    /// Byte spans below `sent` whose carrying packet was lost: re-framed first.
    /// Sorted by offset, non-overlapping.
    lost: std.ArrayListUnmanaged(Range) = .empty,
    /// Acked spans above `base_offset` not yet contiguous with it (out-of-order
    /// acks): held until the filling ack lets `base_offset` slide through them.
    /// Sorted, non-overlapping - the send-side mirror of RecvStream.pending.
    acked_gaps: std.ArrayListUnmanaged(Range) = .empty,

    const Range = struct { offset: u64, len: u64 };

    pub fn init(gpa: std.mem.Allocator) SendStream {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *SendStream) void {
        self.buf.deinit(self.gpa);
        self.lost.deinit(self.gpa);
        self.acked_gaps.deinit(self.gpa);
    }

    pub fn end(self: *const SendStream) u64 {
        return self.base_offset + self.buf.items.len;
    }

    /// Queue `data` and/or mark the stream finished. Writing after the stream is
    /// finished would exceed the final size (RFC 9000 4.5), so it is rejected.
    pub fn write(self: *SendStream, data: []const u8, fin: bool) Error!void {
        if (self.fin and (data.len != 0 or !fin)) return error.FinalSizeError;
        self.buf.appendSlice(self.gpa, data) catch return error.OutOfMemory;
        if (fin) self.fin = true;
    }

    /// Whether anything still needs to leave: a lost range, an owed FIN, or new
    /// bytes past the cursor.
    pub fn pending(self: *const SendStream) bool {
        if (self.lost.items.len > 0 or self.fin_lost) return true;
        if (self.sent < self.end()) return true;
        return self.finOwedAtEnd();
    }

    /// The next chunk to frame, capped at `max` bytes: a lost range first, then a
    /// lost FIN with no lost bytes, then new bytes. The data slice borrows from
    /// `buf` - valid until the next mutation, same as today's contract.
    pub const Chunk = struct { offset: u64, data: []const u8, fin: bool };
    pub fn peek(self: *const SendStream, max: usize) ?Chunk {
        if (max == 0) {
            if (self.finOwedAtEnd() and self.sent == self.end()) {
                return .{ .offset = self.end(), .data = &.{}, .fin = true };
            }
            return null;
        }
        // 1. Lost ranges first (resend lost data before new, RFC 9002 13.3).
        if (self.lost.items.len > 0) {
            const r = self.lost.items[0];
            const n: usize = @intCast(@min(@as(u64, max), r.len));
            const lo: usize = @intCast(r.offset - self.base_offset);
            const carries_fin = self.fin_lost and n == r.len and r.offset + r.len == self.end();
            return .{ .offset = r.offset, .data = self.buf.items[lo .. lo + n], .fin = carries_fin };
        }
        // 2. A lost FIN with no lost bytes left (a FIN-only retransmit).
        if (self.fin_lost and self.sent == self.end()) {
            return .{ .offset = self.end(), .data = &.{}, .fin = true };
        }
        // 3. New bytes after the cursor.
        const avail = self.end() - self.sent;
        const n: usize = @intCast(@min(@as(u64, max), avail));
        const carries_fin = self.finOwedAtEnd() and @as(u64, n) == avail;
        if (n == 0 and !carries_fin) return null;
        const lo: usize = @intCast(self.sent - self.base_offset);
        return .{ .offset = self.sent, .data = self.buf.items[lo .. lo + n], .fin = carries_fin };
    }

    fn finOwedAtEnd(self: *const SendStream) bool {
        return self.fin and !self.fin_acked and (!self.fin_sent or self.fin_lost);
    }

    /// Record that the chunk `peek` returned at `offset` (length `n`) has been
    /// framed. A lost-range chunk shrinks the front of `lost`; a new chunk advances
    /// the cursor. The offset disambiguates which path `peek` took.
    pub fn commit(self: *SendStream, offset: u64, n: usize, sent_fin: bool) void {
        if (self.lost.items.len > 0 and offset == self.lost.items[0].offset) {
            var r = &self.lost.items[0];
            r.offset += n;
            r.len -= n;
            if (r.len == 0) _ = self.lost.orderedRemove(0);
            if (sent_fin) self.fin_lost = false;
            return;
        }
        // A pure-FIN retransmit (no bytes, FIN owed) or new bytes after the cursor.
        self.sent += n;
        if (sent_fin) {
            self.fin_sent = true;
            self.fin_lost = false;
        }
    }

    /// A packet carrying [offset, offset+len) and possibly the FIN was lost. Record
    /// the still-unacked sub-range for retransmission. Idempotent and clipped to the
    /// unacked window, so an already-acked prefix is never re-queued.
    pub fn onLost(self: *SendStream, offset: u64, len: u64, fin: bool) Error!void {
        const lo = @max(offset, self.base_offset);
        const hi = offset + len;
        if (hi > lo) try self.insertLost(lo, hi - lo);
        if (fin and !self.fin_acked) self.fin_lost = true;
    }

    /// A packet carrying [offset, offset+len) and possibly the FIN was acked. Drop
    /// the span from any pending retransmit and free the now-contiguous prefix.
    pub fn onAck(self: *SendStream, offset: u64, len: u64, fin: bool) Error!void {
        const hi = offset + len;
        if (fin) {
            self.fin_acked = true;
            self.fin_lost = false;
        }
        try self.dropLost(offset, hi);
        if (hi <= self.base_offset) return; // wholly below the frontier; already freed
        if (offset <= self.base_offset) {
            self.slideBase(hi);
        } else {
            try self.insertAckedGap(offset, hi); // out of order: hold until the gap fills
        }
    }

    /// Slide `base_offset` up to `new_base`, freeing the prefix, then absorb any
    /// held acked gaps now made contiguous. `sent` never falls below `base_offset`.
    fn slideBase(self: *SendStream, new_base_in: u64) void {
        var new_base = new_base_in;
        var i: usize = 0;
        while (i < self.acked_gaps.items.len) {
            const g = self.acked_gaps.items[i];
            if (g.offset <= new_base) {
                new_base = @max(new_base, g.offset + g.len);
                _ = self.acked_gaps.orderedRemove(i);
                i = 0; // a merge can unlock an earlier-skipped gap; rescan
            } else i += 1;
        }
        const drop: usize = @intCast(new_base - self.base_offset);
        const keep = self.buf.items.len - drop;
        std.mem.copyForwards(u8, self.buf.items[0..keep], self.buf.items[drop..]);
        self.buf.shrinkRetainingCapacity(keep);
        self.base_offset = new_base;
        if (self.sent < self.base_offset) self.sent = self.base_offset;
    }

    fn insertLost(self: *SendStream, offset: u64, len: u64) Error!void {
        try self.insertRange(&self.lost, offset, len);
    }

    fn insertAckedGap(self: *SendStream, offset: u64, hi: u64) Error!void {
        try self.insertRange(&self.acked_gaps, offset, hi - offset);
    }

    /// Insert [offset, offset+len) into a sorted, non-overlapping range list,
    /// coalescing with any touching neighbour. An allocation failure propagates: a
    /// dropped retransmit or acked-gap record would silently strand bytes, so it is
    /// surfaced to the caller rather than swallowed.
    fn insertRange(self: *SendStream, list: *std.ArrayListUnmanaged(Range), offset: u64, len: u64) Error!void {
        var lo = offset;
        var hi = offset + len;
        var i: usize = 0;
        while (i < list.items.len) {
            const r = list.items[i];
            if (r.offset + r.len < lo) {
                i += 1; // entirely before; keep
            } else if (r.offset > hi) {
                break; // entirely after; insert here
            } else {
                lo = @min(lo, r.offset);
                hi = @max(hi, r.offset + r.len);
                _ = list.orderedRemove(i); // merged in; re-examine this index
            }
        }
        list.insert(self.gpa, i, .{ .offset = lo, .len = hi - lo }) catch return error.OutOfMemory;
    }

    /// Remove [lo, hi) from the pending retransmit list (it has been acked), keeping
    /// the remaining fragments. Intersection-based, so a span already absent is a
    /// no-op.
    fn dropLost(self: *SendStream, lo: u64, hi: u64) Error!void {
        var i: usize = 0;
        while (i < self.lost.items.len) {
            const r = self.lost.items[i];
            const rhi = r.offset + r.len;
            if (rhi <= lo or r.offset >= hi) {
                i += 1; // disjoint
                continue;
            }
            _ = self.lost.orderedRemove(i);
            if (r.offset < lo) try self.insertLost(r.offset, lo - r.offset); // left remainder
            if (rhi > hi) try self.insertLost(hi, rhi - hi); // right remainder
        }
    }
};

test "stream-id typing reads the low two bits" {
    try std.testing.expectEqual(StreamType.client_bidi, StreamType.of(0));
    try std.testing.expectEqual(StreamType.server_bidi, StreamType.of(1));
    try std.testing.expectEqual(StreamType.client_uni, StreamType.of(2));
    try std.testing.expectEqual(StreamType.server_uni, StreamType.of(3));
    try std.testing.expect(StreamType.of(7).isUni());
    try std.testing.expect(StreamType.of(8).isClientInitiated());
}

test "in-order fragments assemble" {
    const gpa = std.testing.allocator;
    var s = RecvStream.init(gpa);
    defer s.deinit();
    _ = try s.push(0, "hello ", false);
    _ = try s.push(6, "world", true);
    try std.testing.expectEqualStrings("hello world", s.readable());
    try std.testing.expect(s.isFinished());
}

test "out-of-order fragments are buffered then drained" {
    const gpa = std.testing.allocator;
    var s = RecvStream.init(gpa);
    defer s.deinit();
    _ = try s.push(6, "world", true); // arrives first, buffered
    try std.testing.expectEqualStrings("", s.readable());
    _ = try s.push(0, "hello ", false); // unlocks the buffered tail
    try std.testing.expectEqualStrings("hello world", s.readable());
    try std.testing.expect(s.isFinished());
}

test "overlapping and duplicate data is handled" {
    const gpa = std.testing.allocator;
    var s = RecvStream.init(gpa);
    defer s.deinit();
    _ = try s.push(0, "abcdef", false);
    _ = try s.push(3, "def", false); // wholly duplicate
    _ = try s.push(4, "efghij", false); // partial overlap, extends to 10
    try std.testing.expectEqualStrings("abcdefghij", s.readable());
}

test "consume slides the read offset" {
    const gpa = std.testing.allocator;
    var s = RecvStream.init(gpa);
    defer s.deinit();
    _ = try s.push(0, "abcdef", true);
    s.consume(3);
    try std.testing.expectEqualStrings("def", s.readable());
    try std.testing.expectEqual(@as(u64, 3), s.read_offset);
    s.consume(3);
    try std.testing.expectEqual(RecvState.data_read, s.state);
}

test "data past a known final size is a final-size error" {
    const gpa = std.testing.allocator;
    var s = RecvStream.init(gpa);
    defer s.deinit();
    _ = try s.push(0, "abc", true); // final size = 3
    try std.testing.expectError(error.FinalSizeError, s.push(3, "d", false));
}

test "a conflicting FIN offset is rejected" {
    const gpa = std.testing.allocator;
    var s = RecvStream.init(gpa);
    defer s.deinit();
    _ = try s.push(0, "abcde", true); // final size 5
    try std.testing.expectError(error.FinalSizeError, s.push(0, "abc", true)); // fin at 3
}

test "SendStream drains queued bytes in offset-ordered chunks" {
    const gpa = std.testing.allocator;
    var s = SendStream.init(gpa);
    defer s.deinit();
    try s.write("hello world", false);
    try std.testing.expect(s.pending());

    const c1 = s.peek(5).?; // capped at 5
    try std.testing.expectEqual(@as(u64, 0), c1.offset);
    try std.testing.expectEqualStrings("hello", c1.data);
    try std.testing.expect(!c1.fin);
    s.commit(c1.offset, c1.data.len, false);

    const c2 = s.peek(100).?;
    try std.testing.expectEqual(@as(u64, 5), c2.offset);
    try std.testing.expectEqualStrings(" world", c2.data);
    s.commit(c2.offset, c2.data.len, false);
    try std.testing.expect(!s.pending());
}

test "SendStream carries the FIN on the final chunk and forbids later writes" {
    const gpa = std.testing.allocator;
    var s = SendStream.init(gpa);
    defer s.deinit();
    try s.write("data", true); // bytes + FIN
    const c = s.peek(100).?;
    try std.testing.expect(c.fin);
    s.commit(c.offset, c.data.len, true);
    try std.testing.expect(!s.pending()); // FIN sent, nothing left

    // Writing after FIN would exceed the final size.
    try std.testing.expectError(error.FinalSizeError, s.write("x", false));
    // An empty, idempotent FIN write is allowed.
    try s.write("", true);
}

test "SendStream owes a FIN even with no bytes" {
    const gpa = std.testing.allocator;
    var s = SendStream.init(gpa);
    defer s.deinit();
    try s.write("", true); // pure FIN
    try std.testing.expect(s.pending());
    const c = s.peek(100).?;
    try std.testing.expectEqual(@as(usize, 0), c.data.len);
    try std.testing.expect(c.fin);
    s.commit(c.offset, 0, true);
    try std.testing.expect(!s.pending());
}

test "SendStream retains sent bytes until acked, then frees the prefix" {
    const gpa = std.testing.allocator;
    var s = SendStream.init(gpa);
    defer s.deinit();
    try s.write("abcdefghij", false);
    const c = s.peek(100).?;
    s.commit(c.offset, c.data.len, false);
    try std.testing.expect(!s.pending()); // all sent
    try std.testing.expectEqual(@as(usize, 10), s.buf.items.len); // but retained

    try s.onAck(0, 4, false); // first 4 bytes acked
    try std.testing.expectEqual(@as(u64, 4), s.base_offset);
    try std.testing.expectEqual(@as(usize, 6), s.buf.items.len); // prefix freed
    try s.onAck(4, 6, false);
    try std.testing.expectEqual(@as(usize, 0), s.buf.items.len); // fully freed
}

test "SendStream re-frames a lost range before new bytes" {
    const gpa = std.testing.allocator;
    var s = SendStream.init(gpa);
    defer s.deinit();
    try s.write("AAAA", false);
    const a = s.peek(100).?; // [0,4)
    s.commit(a.offset, a.data.len, false);
    try s.write("BBBB", false);
    const b = s.peek(100).?; // [4,8)
    s.commit(b.offset, b.data.len, false);

    try s.onLost(0, 4, false); // the first packet was lost
    try std.testing.expect(s.pending());
    const r = s.peek(100).?; // retransmit comes first
    try std.testing.expectEqual(@as(u64, 0), r.offset);
    try std.testing.expectEqualStrings("AAAA", r.data);
    s.commit(r.offset, r.data.len, false);
    try std.testing.expect(!s.pending()); // [4,8) was already sent; nothing new
}

test "SendStream frees out-of-order acks once the gap fills" {
    const gpa = std.testing.allocator;
    var s = SendStream.init(gpa);
    defer s.deinit();
    try s.write("0123456789", false);
    const c = s.peek(100).?;
    s.commit(c.offset, c.data.len, false);

    try s.onAck(5, 5, false); // ack the LATER half first (out of order)
    try std.testing.expectEqual(@as(u64, 0), s.base_offset); // cannot free yet
    try std.testing.expectEqual(@as(usize, 10), s.buf.items.len);
    try s.onAck(0, 5, false); // the filling ack lets base slide through the held gap
    try std.testing.expectEqual(@as(u64, 10), s.base_offset);
    try std.testing.expectEqual(@as(usize, 0), s.buf.items.len);
}

test "SendStream re-sends a lost FIN exactly once" {
    const gpa = std.testing.allocator;
    var s = SendStream.init(gpa);
    defer s.deinit();
    try s.write("hi", true);
    const c = s.peek(100).?; // "hi" + FIN
    try std.testing.expect(c.fin);
    s.commit(c.offset, c.data.len, true);

    try s.onLost(0, 2, true); // the FIN-carrying packet was lost
    try std.testing.expect(s.pending());
    const r = s.peek(100).?;
    try std.testing.expect(r.fin); // the FIN rides the resend
    try std.testing.expectEqualStrings("hi", r.data);
    s.commit(r.offset, r.data.len, true);
    try std.testing.expect(!s.pending()); // FIN owed exactly once
}
