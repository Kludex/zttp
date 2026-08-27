//! The set of packet numbers received in one space, as the ACK frame needs them
//! (RFC 9000 19.3): a descending list of contiguous ranges. A peer uses these to
//! learn exactly which packets arrived, so it can detect loss accurately; emitting
//! only the largest (as the first cut did) makes every gap look like a loss.

const std = @import("std");

/// One inclusive run of received packet numbers, [lo, hi].
const Range = struct { lo: u64, hi: u64 };

pub const AckRanges = struct {
    /// Ranges kept sorted DESCENDING by hi (ranges[0] holds the largest pn), each
    /// disjoint and non-adjacent. An ACK frame rarely needs more than a handful;
    /// the list is capped so a pathological gap pattern cannot grow it unbounded.
    ranges: std.ArrayListUnmanaged(Range) = .empty,
    ignore_below: u64 = 0,

    pub const MAX_RANGES: usize = 32;

    pub fn deinit(self: *AckRanges, gpa: std.mem.Allocator) void {
        self.ranges.deinit(gpa);
    }

    pub fn isEmpty(self: *const AckRanges) bool {
        return self.ranges.items.len == 0;
    }

    pub fn largest(self: *const AckRanges) ?u64 {
        return if (self.ranges.items.len == 0) null else self.ranges.items[0].hi;
    }

    /// Return whether `pn` is already recorded in a retained range.
    pub fn contains(self: *const AckRanges, pn: u64) bool {
        for (self.ranges.items) |range| {
            if (pn >= range.lo and pn <= range.hi) return true;
        }
        return false;
    }

    /// Return whether a packet was already recorded or is older than the bounded
    /// ACK history. Packets below a full range set cannot be distinguished from an
    /// evicted duplicate, so they are ignored rather than dispatched twice.
    pub fn shouldIgnore(self: *const AckRanges, pn: u64) bool {
        if (self.contains(pn)) return true;
        return pn < self.ignore_below;
    }

    /// Reserve any storage `add` will need for `pn` without recording it.
    pub fn ensureCanAdd(self: *AckRanges, gpa: std.mem.Allocator, pn: u64) !void {
        for (self.ranges.items) |range| {
            if (pn >= range.lo and pn <= range.hi) return;
            if (pn == range.hi + 1 or pn + 1 == range.lo) return;
        }
        if (self.ranges.items.len < MAX_RANGES) try self.ranges.ensureUnusedCapacity(gpa, 1);
    }

    /// Record that packet number `pn` was received. Extends or merges an existing
    /// range, or inserts a new one in descending order. If the list is at capacity
    /// the oldest (smallest) range is dropped - the peer will simply re-send those
    /// or they fall outside the ack window, which is acceptable.
    pub fn add(self: *AckRanges, gpa: std.mem.Allocator, pn: u64) !void {
        var i: usize = 0;
        while (i < self.ranges.items.len) : (i += 1) {
            const r = self.ranges.items[i];
            if (pn >= r.lo and pn <= r.hi) return; // already recorded
            if (pn == r.hi + 1) { // extends the top of this range
                self.ranges.items[i].hi = pn;
                self.mergeAround(i);
                return;
            }
            if (pn + 1 == r.lo) { // extends the bottom of this range
                self.ranges.items[i].lo = pn;
                self.mergeAround(i);
                return;
            }
            if (pn > r.hi) break; // belongs in a new range before index i (descending)
        }
        // Enforce the cap BEFORE inserting, so the list never grows past MAX_RANGES.
        // A new low range past the cap is simply dropped (it falls outside the ack
        // window the peer cares about); a new high range evicts the smallest first.
        if (self.ranges.items.len >= MAX_RANGES) {
            if (i >= MAX_RANGES) return; // would be the new smallest: drop it
            _ = self.ranges.pop(); // evict the current smallest to make room
        }
        try self.ranges.insert(gpa, i, .{ .lo = pn, .hi = pn });
        if (self.ranges.items.len == MAX_RANGES) {
            self.ignore_below = @max(self.ignore_below, self.ranges.items[MAX_RANGES - 1].lo);
        }
    }

    /// After growing range `i`, coalesce it with the neighbour it may now touch.
    fn mergeAround(self: *AckRanges, i: usize) void {
        // Merge with the range above (larger pns, index i-1).
        if (i > 0 and self.ranges.items[i].hi + 1 == self.ranges.items[i - 1].lo) {
            self.ranges.items[i - 1].lo = self.ranges.items[i].lo;
            _ = self.ranges.orderedRemove(i);
            return;
        }
        // Merge with the range below (smaller pns, index i+1).
        if (i + 1 < self.ranges.items.len and self.ranges.items[i + 1].hi + 1 == self.ranges.items[i].lo) {
            self.ranges.items[i].lo = self.ranges.items[i + 1].lo;
            _ = self.ranges.orderedRemove(i + 1);
        }
    }

    /// The ACK frame's first_range (RFC 9000 19.3): the count below `largest` that is
    /// contiguous, i.e. (hi - lo) of the top range.
    pub fn firstRange(self: *const AckRanges) u64 {
        return self.ranges.items[0].hi - self.ranges.items[0].lo;
    }

    /// Append the additional (gap, range_len) pairs after the first range, as raw
    /// varints, into `out` (RFC 9000 19.3). Returns how many pairs were written.
    pub fn encodeExtra(self: *const AckRanges, out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator) !usize {
        var count: usize = 0;
        var i: usize = 1;
        while (i < self.ranges.items.len) : (i += 1) {
            const prev_lo = self.ranges.items[i - 1].lo;
            const r = self.ranges.items[i];
            // gap = prev.lo - r.hi - 2; range_len = r.hi - r.lo (RFC 9000 19.3).
            try appendVarint(out, gpa, prev_lo - r.hi - 2);
            try appendVarint(out, gpa, r.hi - r.lo);
            count += 1;
        }
        return count;
    }
};

fn appendVarint(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, v: u64) !void {
    const varint = @import("varint.zig");
    try varint.append(out, gpa, v);
}

const testing = std.testing;

test "contiguous packets collapse to one range" {
    const gpa = testing.allocator;
    var a = AckRanges{};
    defer a.deinit(gpa);
    try a.add(gpa, 0);
    try a.add(gpa, 1);
    try a.add(gpa, 2);
    try testing.expectEqual(@as(u64, 2), a.largest().?);
    try testing.expectEqual(@as(u64, 2), a.firstRange()); // [0,2] -> first_range 2
    try testing.expectEqual(@as(usize, 1), a.ranges.items.len);
}

test "a gap produces two ranges and the right gap encoding" {
    const gpa = testing.allocator;
    var a = AckRanges{};
    defer a.deinit(gpa);
    try a.add(gpa, 0);
    try a.add(gpa, 1); // range [0,1]
    try a.add(gpa, 4);
    try a.add(gpa, 5); // range [4,5]; pn 2,3 missing
    try testing.expectEqual(@as(u64, 5), a.largest().?);
    try testing.expectEqual(@as(u64, 1), a.firstRange()); // [4,5]
    var extra: std.ArrayListUnmanaged(u8) = .empty;
    defer extra.deinit(gpa);
    const n = try a.encodeExtra(&extra, gpa);
    try testing.expectEqual(@as(usize, 1), n);
    // gap = prev.lo(4) - r.hi(1) - 2 = 1; range_len = hi(1)-lo(0) = 1.
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x01 }, extra.items);
}

test "out-of-order arrivals merge across a closing gap" {
    const gpa = testing.allocator;
    var a = AckRanges{};
    defer a.deinit(gpa);
    try a.add(gpa, 0);
    try a.add(gpa, 2); // [2,2] and [0,0]
    try testing.expectEqual(@as(usize, 2), a.ranges.items.len);
    try a.add(gpa, 1); // bridges them
    try testing.expectEqual(@as(usize, 1), a.ranges.items.len);
    try testing.expectEqual(@as(u64, 2), a.firstRange());
}

test "a duplicate pn is a no-op" {
    const gpa = testing.allocator;
    var a = AckRanges{};
    defer a.deinit(gpa);
    try a.add(gpa, 5);
    try a.add(gpa, 5);
    try testing.expectEqual(@as(usize, 1), a.ranges.items.len);
    try testing.expect(a.contains(5));
    try testing.expect(!a.contains(4));
}

test "packets older than full ACK history are ignored" {
    const gpa = testing.allocator;
    var a = AckRanges{};
    defer a.deinit(gpa);
    for (1..AckRanges.MAX_RANGES + 1) |index| try a.add(gpa, @intCast(index * 2));

    try testing.expect(a.shouldIgnore(2));
    try testing.expect(a.shouldIgnore(1));
    try testing.expect(!a.shouldIgnore(3));

    try a.add(gpa, (AckRanges.MAX_RANGES + 1) * 2);
    try a.add(gpa, 5);
    try testing.expectEqual(AckRanges.MAX_RANGES - 1, a.ranges.items.len);
    try testing.expect(a.shouldIgnore(2));
}
