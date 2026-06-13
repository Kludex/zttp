//! QUIC congestion control (RFC 9002 section 7): a NewReno controller that gates
//! how much in-flight data the sender allows. It is a pure accounting state
//! machine - it never times anything itself; the recovery layer tells it when a
//! packet was sent, acked, or lost, and it adjusts the window. Kept separate from
//! recovery so each is testable on its own.

const std = @import("std");

/// RFC 9002 7.2 constants. The initial window is min(10*max_datagram,
/// max(2*max_datagram, 14720)); with a 1200-octet datagram that is 12000.
const INITIAL_WINDOW_PACKETS: u64 = 10;
const MIN_WINDOW_PACKETS: u64 = 2;
const LOSS_REDUCTION_NUM: u64 = 1; // multiply cwnd by 1/2 on loss
const LOSS_REDUCTION_DEN: u64 = 2;

pub const Controller = struct {
    max_datagram_size: u64,
    congestion_window: u64,
    bytes_in_flight: u64 = 0,
    slow_start_threshold: u64 = std.math.maxInt(u64),
    /// The packet number that opened the current recovery period; an ack of a
    /// packet sent before it does not re-trigger a window cut (RFC 9002 7.3.2).
    recovery_start: ?u64 = null,

    pub fn init(max_datagram_size: u64) Controller {
        return .{
            .max_datagram_size = max_datagram_size,
            .congestion_window = INITIAL_WINDOW_PACKETS * max_datagram_size,
        };
    }

    /// May the sender put `bytes` more on the wire right now?
    pub fn canSend(self: *const Controller, bytes: u64) bool {
        return self.bytes_in_flight + bytes <= self.congestion_window;
    }

    pub fn available(self: *const Controller) u64 {
        return self.congestion_window -| self.bytes_in_flight;
    }

    fn inSlowStart(self: *const Controller) bool {
        return self.congestion_window < self.slow_start_threshold;
    }

    /// A congestion-controlled packet of `bytes` was sent.
    pub fn onSent(self: *Controller, bytes: u64) void {
        self.bytes_in_flight += bytes;
    }

    /// Remove bytes from the in-flight count WITHOUT treating them as acked (RFC
    /// 9002 A.4): used when a packet-number space is discarded, so the window does
    /// not grow for packets that were merely abandoned.
    pub fn onDiscard(self: *Controller, bytes: u64) void {
        self.bytes_in_flight -|= bytes;
    }

    /// A packet of `bytes` (sent as packet number `pn`) was newly acked.
    pub fn onAck(self: *Controller, pn: u64, bytes: u64) void {
        self.bytes_in_flight -|= bytes;
        // Do not grow the window for acks of packets from before the current
        // recovery period (RFC 9002 7.3.2).
        if (self.recovery_start) |start| {
            if (pn < start) return;
            self.recovery_start = null;
        }
        if (self.inSlowStart()) {
            self.congestion_window += bytes;
        } else {
            // Congestion avoidance: grow by max_datagram_size per cwnd acked.
            self.congestion_window += self.max_datagram_size * bytes / self.congestion_window;
        }
    }

    /// `bytes` of in-flight data (the packet numbered `largest_lost`) was declared
    /// lost. The window enters recovery and halves, once per recovery period.
    pub fn onLost(self: *Controller, largest_lost: u64, bytes: u64) void {
        self.bytes_in_flight -|= bytes;
        self.enterRecovery(largest_lost);
    }

    /// ECN-CE feedback is a congestion signal like loss (RFC 9002 7.3). ACK
    /// processing has already removed newly-acked bytes from flight, so this only
    /// enters recovery and reduces the window.
    pub fn onEcnCe(self: *Controller, largest_acked: u64) void {
        self.enterRecovery(largest_acked);
    }

    /// A persistent-congestion event (RFC 9002 7.6) collapses the window to the
    /// minimum - the network looks severely congested.
    pub fn onPersistentCongestion(self: *Controller) void {
        self.congestion_window = MIN_WINDOW_PACKETS * self.max_datagram_size;
        self.recovery_start = null;
    }

    fn enterRecovery(self: *Controller, pn: u64) void {
        if (self.recovery_start) |start| {
            if (pn < start) return; // already in recovery for a later packet
        }
        self.recovery_start = pn;
        self.slow_start_threshold = self.congestion_window * LOSS_REDUCTION_NUM / LOSS_REDUCTION_DEN;
        self.congestion_window = @max(self.slow_start_threshold, MIN_WINDOW_PACKETS * self.max_datagram_size);
    }
};

test "initial window is ten datagrams" {
    const cc = Controller.init(1200);
    try std.testing.expectEqual(@as(u64, 12000), cc.congestion_window);
    try std.testing.expect(cc.canSend(12000));
    try std.testing.expect(!cc.canSend(12001));
}

test "slow start grows by acked bytes" {
    var cc = Controller.init(1200);
    cc.onSent(1200);
    cc.onAck(0, 1200);
    try std.testing.expectEqual(@as(u64, 13200), cc.congestion_window);
    try std.testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);
}

test "loss halves the window and enters recovery" {
    var cc = Controller.init(1200);
    cc.onSent(1200);
    cc.onLost(0, 1200);
    try std.testing.expectEqual(@as(u64, 6000), cc.congestion_window); // 12000/2
    try std.testing.expect(cc.recovery_start != null);
}

test "ECN-CE halves the window without changing bytes in flight" {
    var cc = Controller.init(1200);
    cc.onSent(1200);
    cc.onEcnCe(0);
    try std.testing.expectEqual(@as(u64, 1200), cc.bytes_in_flight);
    try std.testing.expectEqual(@as(u64, 6000), cc.congestion_window);
    try std.testing.expect(cc.recovery_start != null);
}

test "acks from before recovery do not grow the window" {
    var cc = Controller.init(1200);
    cc.onLost(5, 1200); // recovery_start = 5, cwnd = 6000
    const after_loss = cc.congestion_window;
    cc.onAck(3, 1200); // pn 3 < 5: no growth, recovery stays
    try std.testing.expectEqual(after_loss, cc.congestion_window);
    try std.testing.expect(cc.recovery_start != null);
    cc.onAck(6, 1200); // pn 6 >= 5: exits recovery and grows
    try std.testing.expect(cc.congestion_window > after_loss);
    try std.testing.expect(cc.recovery_start == null);
}

test "persistent congestion collapses to the minimum" {
    var cc = Controller.init(1200);
    cc.onPersistentCongestion();
    try std.testing.expectEqual(@as(u64, 2400), cc.congestion_window);
}

test "available never underflows" {
    var cc = Controller.init(1200);
    cc.onSent(12000);
    try std.testing.expectEqual(@as(u64, 0), cc.available());
    cc.onSent(5000); // over the window (recovery edge cases can do this)
    try std.testing.expectEqual(@as(u64, 0), cc.available());
}
