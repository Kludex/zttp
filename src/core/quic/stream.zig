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

/// The send side of one stream: a queue of outbound bytes the connection drains
/// into STREAM frames. It tracks the offset of the next unsent byte and whether a
/// FIN is owed, mirroring RecvStream but for the write direction.
pub const SendStream = struct {
    gpa: std.mem.Allocator,
    /// Bytes queued but not yet framed (drained from the front as they are sent).
    unsent: std.ArrayListUnmanaged(u8) = .empty,
    /// The offset of the first byte still in `unsent` - what a STREAM frame for the
    /// next chunk carries.
    send_offset: u64 = 0,
    /// The application has finished writing; a FIN is owed on the last frame.
    fin: bool = false,
    /// The FIN has been emitted on a frame, so the stream is fully sent.
    fin_sent: bool = false,

    pub fn init(gpa: std.mem.Allocator) SendStream {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *SendStream) void {
        self.unsent.deinit(self.gpa);
    }

    /// Queue `data` to be sent and/or mark the stream finished. Writing after the
    /// stream has been finished (FIN owed or sent) would push bytes past the
    /// declared final size (RFC 9000 4.5), so it is rejected.
    pub fn write(self: *SendStream, data: []const u8, fin: bool) Error!void {
        if (self.fin and (data.len != 0 or !fin)) return error.FinalSizeError;
        self.unsent.appendSlice(self.gpa, data) catch return error.OutOfMemory;
        if (fin) self.fin = true;
    }

    /// Whether anything still needs to leave: buffered bytes, or an owed FIN.
    pub fn pending(self: *const SendStream) bool {
        return self.unsent.items.len > 0 or (self.fin and !self.fin_sent);
    }

    /// The next chunk to frame, capped at `max` bytes. Returns the offset, the
    /// chunk (a slice into `unsent`, valid until the next `commit`), and whether
    /// this chunk carries the FIN. Call `commit` once the chunk is framed.
    pub const Chunk = struct { offset: u64, data: []const u8, fin: bool };
    pub fn peek(self: *const SendStream, max: usize) ?Chunk {
        const n = @min(max, self.unsent.items.len);
        const carries_fin = self.fin and !self.fin_sent and n == self.unsent.items.len;
        if (n == 0 and !carries_fin) return null;
        return .{ .offset = self.send_offset, .data = self.unsent.items[0..n], .fin = carries_fin };
    }

    /// Drop the `n` bytes a framed chunk consumed and, if it carried the FIN, mark
    /// the FIN sent. `n` must be the length of the chunk returned by `peek`.
    pub fn commit(self: *SendStream, n: usize, sent_fin: bool) void {
        std.mem.copyForwards(u8, self.unsent.items[0 .. self.unsent.items.len - n], self.unsent.items[n..]);
        self.unsent.shrinkRetainingCapacity(self.unsent.items.len - n);
        self.send_offset += n;
        if (sent_fin) self.fin_sent = true;
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
    s.commit(c1.data.len, false);

    const c2 = s.peek(100).?;
    try std.testing.expectEqual(@as(u64, 5), c2.offset);
    try std.testing.expectEqualStrings(" world", c2.data);
    s.commit(c2.data.len, false);
    try std.testing.expect(!s.pending());
}

test "SendStream carries the FIN on the final chunk and forbids later writes" {
    const gpa = std.testing.allocator;
    var s = SendStream.init(gpa);
    defer s.deinit();
    try s.write("data", true); // bytes + FIN
    const c = s.peek(100).?;
    try std.testing.expect(c.fin);
    s.commit(c.data.len, true);
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
    s.commit(0, true);
    try std.testing.expect(!s.pending());
}
