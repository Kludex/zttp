//! QUIC loss detection and RTT estimation (RFC 9002 sections 5 and 6). It tracks
//! the packets sent in each number space, folds in ACK frames to learn what was
//! acknowledged, estimates the RTT, and decides which packets are lost (by the
//! packet-reordering threshold or the time threshold) and when the probe timeout
//! (PTO) should fire. It is sans-IO in the same sense the rest of the core is: it
//! takes a monotonic `now` (microseconds) from the caller and never reads a clock
//! itself, so it is fully deterministic and testable.

const std = @import("std");
const congestion = @import("congestion.zig");

/// RFC 9002 6.1.1 / 6.1.2 constants.
const PACKET_THRESHOLD: u64 = 3;
const TIME_THRESHOLD_NUM: u64 = 9; // 9/8 of max(srtt, latest_rtt)
const TIME_THRESHOLD_DEN: u64 = 8;
const GRANULARITY_US: u64 = 1000; // 1ms timer granularity
const INITIAL_RTT_US: u64 = 333_000; // RFC 9002 6.2.2 default: 333ms

/// One in-flight sent packet awaiting acknowledgement.
pub const SentPacket = struct {
    pn: u64,
    sent_time: u64, // microseconds
    size: u64, // congestion-controlled bytes (0 for ack-only packets)
    ack_eliciting: bool,
    in_flight: bool,
};

pub const RttEstimator = struct {
    latest: u64 = 0,
    smoothed: u64 = INITIAL_RTT_US,
    rttvar: u64 = INITIAL_RTT_US / 2,
    min_rtt: u64 = std.math.maxInt(u64),
    has_sample: bool = false,

    /// Fold in an RTT sample (RFC 9002 5.3). `ack_delay` is the peer-reported
    /// delay, clamped so it cannot drag the estimate below min_rtt.
    pub fn update(self: *RttEstimator, rtt: u64, ack_delay: u64) void {
        self.latest = rtt;
        self.min_rtt = @min(self.min_rtt, rtt);
        if (!self.has_sample) {
            self.smoothed = rtt;
            self.rttvar = rtt / 2;
            self.has_sample = true;
            return;
        }
        var adjusted = rtt;
        if (rtt >= self.min_rtt + ack_delay) adjusted = rtt - ack_delay;
        const var_sample = if (self.smoothed > adjusted) self.smoothed - adjusted else adjusted - self.smoothed;
        self.rttvar = (self.rttvar * 3 + var_sample) / 4;
        self.smoothed = (self.smoothed * 7 + adjusted) / 8;
    }

    /// The PTO base duration (RFC 9002 6.2.1): srtt + max(4*rttvar, granularity).
    pub fn pto(self: *const RttEstimator) u64 {
        return self.smoothed + @max(4 * self.rttvar, GRANULARITY_US);
    }
};

/// The result of folding in an ACK: which packets newly acked, and the loss the
/// caller should report to congestion control. The connection layer uses
/// `largest_acked_pn` to update the packet-number decoder window.
pub const AckOutcome = struct {
    newly_acked: u64,
    acked_bytes: u64,
    largest_newly_acked: ?u64,
};

/// Loss detection over one packet-number space.
pub const Space = struct {
    sent: std.ArrayListUnmanaged(SentPacket) = .empty,
    largest_acked: ?u64 = null,
    loss_time: ?u64 = null,
    /// The number of times the PTO has fired without progress (RFC 9002 6.2.1);
    /// the PTO backs off exponentially by this count.
    pto_count: u32 = 0,

    pub fn deinit(self: *Space, gpa: std.mem.Allocator) void {
        self.sent.deinit(gpa);
    }

    pub fn onSent(self: *Space, gpa: std.mem.Allocator, pkt: SentPacket) !void {
        try self.sent.append(gpa, pkt);
    }

    /// Apply an ACK (its largest, first-range, and the raw range bytes from the
    /// frame). Removes acked packets from the in-flight set, updates the RTT from
    /// the largest newly acked ack-eliciting packet, and returns what was acked.
    pub fn onAck(
        self: *Space,
        rtt: *RttEstimator,
        cc: *congestion.Controller,
        now: u64,
        largest: u64,
        ack_delay: u64,
        first_range: u64,
        ranges: anytype, // an iterator yielding {gap,len}
    ) !AckOutcome {
        var acked = AckSet{};
        acked.add(largest - first_range, largest);
        var smallest = largest - first_range;
        var it = ranges;
        while (it.next()) |r| {
            if (smallest < r.gap + 2) break; // malformed range; stop
            const next_largest = smallest - r.gap - 2;
            acked.add(next_largest - r.len, next_largest);
            smallest = next_largest - r.len;
        }

        var outcome = AckOutcome{ .newly_acked = 0, .acked_bytes = 0, .largest_newly_acked = null };
        var largest_acked_time: ?u64 = null;
        var largest_acked_elicits = false;

        var i: usize = 0;
        while (i < self.sent.items.len) {
            const p = self.sent.items[i];
            if (acked.contains(p.pn)) {
                outcome.newly_acked += 1;
                if (p.in_flight) {
                    outcome.acked_bytes += p.size;
                    cc.onAck(p.pn, p.size);
                }
                if (outcome.largest_newly_acked == null or p.pn > outcome.largest_newly_acked.?) {
                    outcome.largest_newly_acked = p.pn;
                    largest_acked_time = p.sent_time;
                    largest_acked_elicits = p.ack_eliciting;
                }
                _ = self.sent.swapRemove(i);
            } else i += 1;
        }

        if (outcome.largest_newly_acked) |ln| {
            self.largest_acked = if (self.largest_acked) |la| @max(la, ln) else ln;
            if (largest_acked_elicits) {
                if (largest_acked_time) |t| rtt.update(now - t, ack_delay);
            }
            self.pto_count = 0;
        }
        return outcome;
    }

    /// Detect lost packets (RFC 9002 6.1): a packet is lost if a later packet was
    /// acked and it is either more than PACKET_THRESHOLD behind the largest acked
    /// or older than the time threshold. Lost packets are removed and their bytes
    /// reported to congestion control. Returns how many were lost.
    pub fn detectLost(self: *Space, rtt: *const RttEstimator, cc: *congestion.Controller, now: u64) u64 {
        const largest = self.largest_acked orelse return 0;
        const threshold = @max(rtt.latest, rtt.smoothed) * TIME_THRESHOLD_NUM / TIME_THRESHOLD_DEN;
        self.loss_time = null;
        var lost: u64 = 0;
        var i: usize = 0;
        while (i < self.sent.items.len) {
            const p = self.sent.items[i];
            if (p.pn > largest) {
                i += 1;
                continue;
            }
            const by_packet = largest >= p.pn + PACKET_THRESHOLD;
            const by_time = now >= p.sent_time + threshold;
            if (by_packet or by_time) {
                if (p.in_flight) cc.onLost(p.pn, p.size);
                lost += 1;
                _ = self.sent.swapRemove(i);
            } else {
                const t = p.sent_time + threshold;
                self.loss_time = if (self.loss_time) |lt| @min(lt, t) else t;
                i += 1;
            }
        }
        return lost;
    }

    pub fn hasAckEliciting(self: *const Space) bool {
        for (self.sent.items) |p| {
            if (p.ack_eliciting) return true;
        }
        return false;
    }
};

/// A compact set of acknowledged packet-number ranges. ACK frames carry at most a
/// handful of ranges, so a small inline buffer is enough; this avoids allocating
/// per ack.
const AckSet = struct {
    ranges: [32]struct { lo: u64, hi: u64 } = undefined,
    n: usize = 0,

    fn add(self: *AckSet, lo: u64, hi: u64) void {
        if (self.n < self.ranges.len) {
            self.ranges[self.n] = .{ .lo = lo, .hi = hi };
            self.n += 1;
        }
    }

    fn contains(self: *const AckSet, pn: u64) bool {
        for (self.ranges[0..self.n]) |r| {
            if (pn >= r.lo and pn <= r.hi) return true;
        }
        return false;
    }
};

const EmptyRanges = struct {
    pub fn next(_: *EmptyRanges) ?struct { gap: u64, len: u64 } {
        return null;
    }
};

test "first RTT sample seeds the estimator" {
    var rtt = RttEstimator{};
    rtt.update(100_000, 0);
    try std.testing.expectEqual(@as(u64, 100_000), rtt.smoothed);
    try std.testing.expectEqual(@as(u64, 50_000), rtt.rttvar);
}

test "PTO is srtt plus four rttvar" {
    var rtt = RttEstimator{};
    rtt.update(100_000, 0);
    try std.testing.expectEqual(@as(u64, 100_000 + 4 * 50_000), rtt.pto());
}

test "ack removes the in-flight packet and updates RTT" {
    const gpa = std.testing.allocator;
    var space = Space{};
    defer space.deinit(gpa);
    var rtt = RttEstimator{};
    var cc = congestion.Controller.init(1200);
    cc.onSent(1200);
    try space.onSent(gpa, .{ .pn = 0, .sent_time = 1000, .size = 1200, .ack_eliciting = true, .in_flight = true });
    var ranges = EmptyRanges{};
    const out = try space.onAck(&rtt, &cc, 51_000, 0, 0, 0, &ranges);
    try std.testing.expectEqual(@as(u64, 1), out.newly_acked);
    try std.testing.expectEqual(@as(u64, 1200), out.acked_bytes);
    try std.testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);
    try std.testing.expectEqual(@as(u64, 50_000), rtt.latest); // 51000 - 1000
    try std.testing.expectEqual(@as(usize, 0), space.sent.items.len);
}

test "ack with multiple ranges" {
    const gpa = std.testing.allocator;
    var space = Space{};
    defer space.deinit(gpa);
    var rtt = RttEstimator{};
    var cc = congestion.Controller.init(1200);
    for (0..6) |pn| try space.onSent(gpa, .{ .pn = pn, .sent_time = 1000, .size = 100, .ack_eliciting = true, .in_flight = true });
    // largest=5, first_range=1 -> acks 4,5; then gap=0,len=1 -> acks 1,2
    const Ranges = struct {
        done: bool = false,
        pub fn next(self: *@This()) ?struct { gap: u64, len: u64 } {
            if (self.done) return null;
            self.done = true;
            return .{ .gap = 0, .len = 1 };
        }
    };
    var r = Ranges{};
    const out = try space.onAck(&rtt, &cc, 2000, 5, 0, 1, &r);
    try std.testing.expectEqual(@as(u64, 4), out.newly_acked); // 4,5,1,2
    try std.testing.expectEqual(@as(u64, 5), out.largest_newly_acked.?);
    try std.testing.expectEqual(@as(usize, 2), space.sent.items.len); // 0 and 3 remain
}

test "packet threshold declares an old packet lost" {
    const gpa = std.testing.allocator;
    var space = Space{};
    defer space.deinit(gpa);
    var rtt = RttEstimator{};
    rtt.update(50_000, 0);
    var cc = congestion.Controller.init(1200);
    // pn 0 is in flight; pn 4 gets acked -> 0 is > 3 behind -> lost.
    try space.onSent(gpa, .{ .pn = 0, .sent_time = 1000, .size = 1200, .ack_eliciting = true, .in_flight = true });
    try space.onSent(gpa, .{ .pn = 4, .sent_time = 1000, .size = 1200, .ack_eliciting = true, .in_flight = true });
    var ranges = EmptyRanges{};
    _ = try space.onAck(&rtt, &cc, 2000, 4, 0, 0, &ranges);
    const lost = space.detectLost(&rtt, &cc, 2000);
    try std.testing.expectEqual(@as(u64, 1), lost);
    try std.testing.expectEqual(@as(usize, 0), space.sent.items.len);
}
