//! QUIC flow control (RFC 9000 section 4 and 19.9-19.11): the credit accounting
//! that bounds how much a peer can make the receiver buffer. There are two
//! granularities - per-stream (MAX_STREAM_DATA) and per-connection (MAX_DATA) -
//! plus a concurrency cap on streams (MAX_STREAMS). Pure accounting state: it
//! grants and consumes credit and flags when a new limit should be advertised; it
//! sends nothing itself.

const std = @import("std");

/// One direction of a data flow-control window (used for both a stream's recv
/// window and the connection-wide window). The receiver consumes credit as bytes
/// arrive and re-grants it as the application reads, advertising a new MAX when
/// the window is over half consumed.
pub const Window = struct {
    /// The largest offset the peer is allowed to send (the advertised limit).
    limit: u64,
    /// The largest offset actually received so far.
    received: u64 = 0,
    /// How much the application has consumed; the floor the window slides above.
    consumed: u64 = 0,
    /// The window size to maintain; a new limit is `consumed + initial`.
    initial: u64,

    pub fn init(initial: u64) Window {
        return .{ .limit = initial, .initial = initial };
    }

    pub const Error = error{
        /// The peer sent data past the limit it was granted (RFC 9000 4.1):
        /// FLOW_CONTROL_ERROR.
        FlowControlError,
    };

    /// Record that data up to `offset` (exclusive) has been received. Rejects an
    /// offset beyond the advertised limit.
    pub fn onReceived(self: *Window, offset: u64) Error!void {
        if (offset > self.limit) return error.FlowControlError;
        self.received = @max(self.received, offset);
    }

    /// The application consumed up to `offset`; this slides the window.
    pub fn onConsumed(self: *Window, offset: u64) void {
        self.consumed = @max(self.consumed, offset);
    }

    /// Should a new MAX be advertised? True once more than half the window has
    /// been consumed since the last grant (RFC 9000 4.1 auto-tuning heuristic).
    pub fn shouldUpdate(self: *const Window) bool {
        return self.limit - self.consumed < self.initial / 2;
    }

    /// The limit a grant would advertise, without recording it - so the caller can
    /// build the frame first and only commit (grant) once the send cannot fail.
    pub fn nextLimit(self: *const Window) u64 {
        return self.consumed + self.initial;
    }

    /// The new limit to advertise, and the side effect of recording it.
    pub fn grant(self: *Window) u64 {
        self.limit = self.consumed + self.initial;
        return self.limit;
    }
};

/// The send side of a data window: how much we are allowed to send, bounded by
/// the peer's advertised MAX. Separate from `Window` because the roles differ -
/// here the limit is set by the peer and we track what we have sent.
pub const SendWindow = struct {
    limit: u64,
    sent: u64 = 0,

    pub fn init(limit: u64) SendWindow {
        return .{ .limit = limit };
    }

    /// How many more bytes may be sent right now.
    pub fn available(self: *const SendWindow) u64 {
        return self.limit -| self.sent;
    }

    pub fn onSent(self: *SendWindow, bytes: u64) void {
        self.sent += bytes;
    }

    /// The peer raised the limit (a MAX_DATA / MAX_STREAM_DATA frame). A limit can
    /// only grow; a lower value is ignored (RFC 9000 4.1).
    pub fn onMaxData(self: *SendWindow, new_limit: u64) void {
        self.limit = @max(self.limit, new_limit);
    }

    /// Set the initial limit from the peer's transport parameter (RFC 9000 7.4),
    /// before any MAX_DATA frame raises it. Unlike onMaxData this replaces, since
    /// the initial grant is authoritative (it may be lower than a placeholder).
    pub fn setInitial(self: *SendWindow, limit: u64) void {
        self.limit = limit;
    }

    pub fn blocked(self: *const SendWindow) bool {
        return self.available() == 0;
    }
};

/// The concurrency cap on streams a peer may open (RFC 9000 4.6, MAX_STREAMS).
/// Bidi and uni are tracked separately by the caller with two of these. It mirrors
/// `Window`: closed streams return credit so a steady stream of short-lived requests
/// is never starved without allowing more than `window` streams concurrently.
pub const StreamLimit = struct {
    /// The maximum stream count the peer may open (a count, not an id).
    max: u64,
    /// The highest stream count opened so far; the floor the cap slides above.
    opened: u64 = 0,
    /// The maximum number of peer streams allowed concurrently.
    window: u64,
    /// Peer streams that reached a terminal state and can be replaced.
    closed: u64 = 0,
    /// Closed-stream credit already included in an advertised limit.
    granted_closed: u64 = 0,

    pub fn init(max: u64) StreamLimit {
        return .{ .max = max, .window = max };
    }

    pub const Error = error{
        /// The peer opened more streams than allowed (RFC 9000 4.6):
        /// STREAM_LIMIT_ERROR.
        StreamLimitError,
    };

    /// A peer-initiated stream with this 0-based index was opened.
    pub fn onOpened(self: *StreamLimit, index: u64) Error!void {
        if (index >= self.max) return error.StreamLimitError;
        self.opened = @max(self.opened, index + 1);
    }

    /// A peer-initiated stream reached a terminal state.
    pub fn onClosed(self: *StreamLimit) void {
        self.closed += 1;
    }

    /// Should a higher cap be advertised? True once the headroom ahead of the highest
    /// opened stream falls below half the window (RFC 9000 4.6 auto-tuning). The half is
    /// rounded up so a window of 1 still trips after its single slot is used - an
    /// integer `window / 2` would be 0, a threshold unsigned headroom can never fall
    /// below, stranding a one-request-at-a-time server.
    pub fn shouldUpdate(self: *const StreamLimit) bool {
        return self.closed > self.granted_closed and self.max - self.opened < (self.window + 1) / 2;
    }

    /// Add newly closed-stream credit to the cumulative limit and return it.
    pub fn grant(self: *StreamLimit) u64 {
        self.max += self.closed - self.granted_closed;
        self.granted_closed = self.closed;
        return self.max;
    }

    /// The peer raised the maximum number of streams we may open. Like MAX_DATA,
    /// MAX_STREAMS can only increase the grant; smaller values are ignored.
    pub fn onMaxStreams(self: *StreamLimit, new_max: u64) void {
        self.max = @max(self.max, new_max);
    }
};

test "recv window rejects data past the limit" {
    var w = Window.init(100);
    try w.onReceived(80);
    try std.testing.expectError(error.FlowControlError, w.onReceived(101));
}

test "recv window auto-tunes after half consumed" {
    var w = Window.init(100);
    try std.testing.expect(!w.shouldUpdate());
    w.onConsumed(60);
    try std.testing.expect(w.shouldUpdate());
    // nextLimit previews the grant without committing it, so the caller can build the
    // frame first and only commit once the send cannot fail.
    try std.testing.expectEqual(@as(u64, 160), w.nextLimit());
    try std.testing.expectEqual(@as(u64, 100), w.limit); // unchanged by the preview
    try std.testing.expectEqual(@as(u64, 160), w.grant());
    try std.testing.expect(!w.shouldUpdate());
}

test "send window tracks available credit" {
    var s = SendWindow.init(100);
    try std.testing.expectEqual(@as(u64, 100), s.available());
    s.onSent(100);
    try std.testing.expect(s.blocked());
    s.onMaxData(150);
    try std.testing.expectEqual(@as(u64, 50), s.available());
}

test "send window ignores a smaller MAX" {
    var s = SendWindow.init(100);
    s.onMaxData(80);
    try std.testing.expectEqual(@as(u64, 100), s.limit);
}

test "stream limit rejects too many streams" {
    var l = StreamLimit.init(3);
    try l.onOpened(0);
    try l.onOpened(2);
    try std.testing.expectError(error.StreamLimitError, l.onOpened(3));
}

test "stream limit re-advertises closed capacity once headroom runs low" {
    var l = StreamLimit.init(4);
    try std.testing.expect(!l.shouldUpdate());
    try l.onOpened(0);
    try l.onOpened(1);
    try l.onOpened(2); // 3 of 4 opened: headroom 1 < window/2 (2)
    try std.testing.expect(!l.shouldUpdate());
    l.onClosed();
    try std.testing.expect(l.shouldUpdate());
    try std.testing.expectEqual(@as(u64, 5), l.grant());
    try std.testing.expect(!l.shouldUpdate());
    try l.onOpened(4); // the replacement stream is now permitted
}

test "a window of 1 grants a replacement after its stream closes" {
    var l = StreamLimit.init(1);
    try std.testing.expect(!l.shouldUpdate()); // nothing opened yet
    try l.onOpened(0); // the one allowed stream
    try std.testing.expect(!l.shouldUpdate());
    l.onClosed();
    try std.testing.expect(l.shouldUpdate());
    try std.testing.expectEqual(@as(u64, 2), l.grant());
    try l.onOpened(1); // the next stream is now permitted
}

test "stream limit ignores smaller MAX_STREAMS" {
    var l = StreamLimit.init(3);
    l.onMaxStreams(2);
    try std.testing.expectEqual(@as(u64, 3), l.max);
    l.onMaxStreams(4);
    try std.testing.expectEqual(@as(u64, 4), l.max);
}
