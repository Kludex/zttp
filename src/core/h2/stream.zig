//! The per-stream state machine and flow-control accounting (RFC 9113 5.1, 6.9).
//! A pure value struct the connection mutates - no buffers, no allocation. Its
//! job is to classify, for each (state, incoming frame), whether the frame is
//! allowed, a STREAM error, or a CONNECTION error, with the exact error code.
//! This is where the spec's subtle distinctions live (RST_STREAM-on-idle is a
//! connection error; DATA-on-half-closed is a stream error; etc).

const std = @import("std");
const constants = @import("constants.zig");

const ErrorCode = constants.ErrorCode;
const FrameType = constants.FrameType;

pub const State = enum {
    idle,
    reserved_local,
    reserved_remote,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

/// How the connection should react to a frame on this stream.
pub const Action = enum { ok, stream_error, connection_error };

pub const Transition = struct {
    action: Action,
    code: ErrorCode = .no_error,

    const ok: Transition = .{ .action = .ok };
    fn streamErr(code: ErrorCode) Transition {
        return .{ .action = .stream_error, .code = code };
    }
    fn connErr(code: ErrorCode) Transition {
        return .{ .action = .connection_error, .code = code };
    }
};

pub const Stream = struct {
    id: u32,
    state: State = .idle,
    /// Receive/send flow-control windows. i32 because INITIAL_WINDOW_SIZE
    /// reductions can drive a send window negative (RFC 9113 6.9.2); the overflow
    /// check against 2^31-1 is done in i64 by the caller before narrowing.
    recv_window: i32,
    send_window: i32,
    /// Receive bytes consumed on this stream since the last WINDOW_UPDATE we sent.
    recv_credit: u32 = 0,
    /// Declared Content-Length (if any) and bytes of DATA seen, for the
    /// h2->h1 smuggling guard (validated at END_STREAM).
    content_length: ?u64 = null,
    data_seen: u64 = 0,
    /// The response on this stream carries no body regardless of content-length
    /// (it answers a HEAD, or its status is 204/304), so the content-length vs
    /// data-seen check is skipped (RFC 9110 8.6).
    expects_bodyless: bool = false,
    headers_done: bool = false,
    end_stream_seen: bool = false,
    /// Outbound DATA the send window could not yet admit, parked here and drained
    /// as WINDOW_UPDATE credits arrive. `send_end_pending` records that END_STREAM
    /// is owed once the buffer empties (so an end_message on a blocked stream still
    /// closes it at the right point). Empty/false for streams that never send.
    send_pending: std.ArrayListUnmanaged(u8) = .empty,
    send_end_pending: bool = false,

    pub fn init(id: u32, recv_window: i32, send_window: i32) Stream {
        return .{ .id = id, .recv_window = recv_window, .send_window = send_window };
    }

    pub fn deinit(self: *Stream, gpa: std.mem.Allocator) void {
        self.send_pending.deinit(gpa);
    }

    /// Does this stream count toward MAX_CONCURRENT_STREAMS? Only open and the
    /// two half-closed states do (RFC 9113 5.1.2).
    pub fn countsTowardConcurrency(self: *const Stream) bool {
        return switch (self.state) {
            .open, .half_closed_local, .half_closed_remote => true,
            else => false,
        };
    }

    /// Classify a frame ARRIVING (from the peer) on this stream, given its type
    /// and whether it carries END_STREAM. Does NOT mutate; the caller applies the
    /// resulting transition with `recvApply` once it decides to proceed. This
    /// models the receive side (server reading requests, client reading
    /// responses).
    pub fn classifyRecv(self: *const Stream, ftype: FrameType, end_stream: bool) Transition {
        _ = end_stream;
        return switch (self.state) {
            .idle => switch (ftype) {
                // HEADERS opens the stream; PRIORITY is always tolerated.
                .headers => Transition.ok,
                .priority => Transition.ok,
                // RST_STREAM / WINDOW_UPDATE / DATA etc on an idle stream is a
                // connection error PROTOCOL_ERROR (RFC 9113 5.1).
                else => Transition.connErr(.protocol_error),
            },
            .open => switch (ftype) {
                .data, .headers, .window_update, .rst_stream, .priority => Transition.ok,
                else => Transition.ok, // unknown types are discarded by the caller
            },
            .half_closed_remote => switch (ftype) {
                // The peer may no longer send DATA/HEADERS; only flow/control.
                .window_update, .priority, .rst_stream => Transition.ok,
                .data, .headers => Transition.streamErr(.stream_closed),
                else => Transition.ok,
            },
            .half_closed_local => switch (ftype) {
                .data, .headers, .window_update, .rst_stream, .priority => Transition.ok,
                else => Transition.ok,
            },
            .closed => switch (ftype) {
                // After close, only PRIORITY is unconditionally fine; the grace
                // window for WINDOW_UPDATE/RST_STREAM is handled by the
                // connection (it knows whether the close was recent). Anything
                // else is treated as STREAM_CLOSED.
                .priority, .window_update, .rst_stream => Transition.ok,
                else => Transition.streamErr(.stream_closed),
            },
            // Reserved states only arise with server push, which is out of scope.
            .reserved_local, .reserved_remote => Transition.connErr(.protocol_error),
        };
    }

    /// Apply the state transition for a successfully-accepted received frame.
    pub fn recvApply(self: *Stream, ftype: FrameType, end_stream: bool) void {
        switch (ftype) {
            .headers => {
                if (self.state == .idle) self.state = .open;
                if (end_stream) self.halfCloseRemote();
            },
            .data => {
                if (end_stream) self.halfCloseRemote();
            },
            .rst_stream => self.state = .closed,
            else => {},
        }
    }

    fn halfCloseRemote(self: *Stream) void {
        self.end_stream_seen = true;
        self.state = switch (self.state) {
            .open => .half_closed_remote,
            .half_closed_local => .closed,
            else => self.state,
        };
    }

    /// Apply the local side sending a frame, mirroring recvApply for the send
    /// direction. END_STREAM half-closes locally: open -> half_closed_local,
    /// half_closed_remote -> closed.
    pub fn sendApply(self: *Stream, end_stream: bool) void {
        if (end_stream) self.state = switch (self.state) {
            .open => .half_closed_local,
            .half_closed_remote => .closed,
            else => self.state,
        };
    }

    /// Whether the stream has reached the fully-closed terminal state with no
    /// outbound send still owed - i.e. it can be evicted from the connection map.
    /// A half_closed_* stream is NOT done: it still counts toward concurrency and
    /// stays addressable until both directions finish.
    pub fn isFullyClosed(self: *const Stream) bool {
        return self.state == .closed and self.send_pending.items.len == 0 and !self.send_end_pending;
    }

    /// Account for inbound DATA against the receive window. Returns a transition:
    /// a window overrun is a connection FLOW_CONTROL_ERROR. `len` is the full
    /// frame payload length (including padding), which is what counts against the
    /// window (RFC 9113 6.9.1).
    pub fn debitRecvWindow(self: *Stream, len: u32) Transition {
        if (@as(i64, self.recv_window) - @as(i64, len) < 0) {
            return Transition.streamErr(.flow_control_error);
        }
        self.recv_window -= @intCast(len);
        return Transition.ok;
    }

    /// Refill the receive window by `len` (the data was just consumed) and record
    /// the same amount as credit to advertise back via WINDOW_UPDATE.
    pub fn creditRecvWindow(self: *Stream, len: u32) void {
        self.recv_window += @intCast(len);
        self.recv_credit +|= len;
    }

    /// Apply a WINDOW_UPDATE increment to the send window. A zero increment is a
    /// stream PROTOCOL_ERROR; exceeding 2^31-1 is a FLOW_CONTROL_ERROR. The sum
    /// is computed in i64 to detect the overflow before narrowing.
    pub fn creditSendWindow(self: *Stream, increment: u32) Transition {
        if (increment == 0) return Transition.streamErr(.protocol_error);
        const sum = @as(i64, self.send_window) + @as(i64, increment);
        if (sum > constants.MAX_WINDOW_SIZE) return Transition.streamErr(.flow_control_error);
        self.send_window = @intCast(sum);
        return Transition.ok;
    }

    /// Retroactively adjust the send window by an INITIAL_WINDOW_SIZE delta
    /// (RFC 9113 6.9.2). The window may go negative; only a positive result above
    /// 2^31-1 is an error (FLOW_CONTROL_ERROR).
    pub fn adjustSendWindow(self: *Stream, delta: i32) Transition {
        const sum = @as(i64, self.send_window) + @as(i64, delta);
        if (sum > constants.MAX_WINDOW_SIZE) return Transition.connErr(.flow_control_error);
        self.send_window = @intCast(sum);
        return Transition.ok;
    }

    /// Record DATA bytes for the Content-Length check.
    pub fn recordData(self: *Stream, len: u64) void {
        self.data_seen += len;
    }

    /// At END_STREAM, verify the body length matched a declared Content-Length.
    /// A mismatch is a STREAM error PROTOCOL_ERROR (h2->h1 smuggling guard).
    pub fn checkContentLength(self: *const Stream) Transition {
        if (self.expects_bodyless) {
            // A bodyless response may still declare a Content-Length that mirrors
            // the GET entity, but any actual DATA bytes are a violation.
            if (self.data_seen != 0) return Transition.streamErr(.protocol_error);
            return Transition.ok;
        }
        if (self.content_length) |cl| {
            if (cl != self.data_seen) return Transition.streamErr(.protocol_error);
        }
        return Transition.ok;
    }
};

const testing = std.testing;

test "idle stream accepts HEADERS and PRIORITY, rejects others as connection errors" {
    const s = Stream.init(1, 65535, 65535);
    try testing.expectEqual(Action.ok, s.classifyRecv(.headers, false).action);
    try testing.expectEqual(Action.ok, s.classifyRecv(.priority, false).action);
    const t = s.classifyRecv(.data, false);
    try testing.expectEqual(Action.connection_error, t.action);
    try testing.expectEqual(ErrorCode.protocol_error, t.code);
}

test "RST_STREAM on an idle stream is a connection error" {
    const s = Stream.init(1, 65535, 65535);
    const t = s.classifyRecv(.rst_stream, false);
    try testing.expectEqual(Action.connection_error, t.action);
    try testing.expectEqual(ErrorCode.protocol_error, t.code);
}

test "HEADERS with END_STREAM opens then half-closes the stream" {
    var s = Stream.init(1, 65535, 65535);
    s.recvApply(.headers, true);
    try testing.expectEqual(State.half_closed_remote, s.state);
    try testing.expect(s.end_stream_seen);
}

test "DATA on a half-closed-remote stream is a stream error STREAM_CLOSED" {
    var s = Stream.init(1, 65535, 65535);
    s.recvApply(.headers, true); // -> half_closed_remote
    const t = s.classifyRecv(.data, false);
    try testing.expectEqual(Action.stream_error, t.action);
    try testing.expectEqual(ErrorCode.stream_closed, t.code);
}

test "WINDOW_UPDATE is allowed on a half-closed-remote stream" {
    var s = Stream.init(1, 65535, 65535);
    s.recvApply(.headers, true);
    try testing.expectEqual(Action.ok, s.classifyRecv(.window_update, false).action);
}

test "RST_STREAM closes the stream" {
    var s = Stream.init(1, 65535, 65535);
    s.recvApply(.headers, false); // -> open
    s.recvApply(.rst_stream, false);
    try testing.expectEqual(State.closed, s.state);
}

test "concurrency counting follows the open/half-closed rule" {
    var s = Stream.init(1, 65535, 65535);
    try testing.expect(!s.countsTowardConcurrency()); // idle
    s.recvApply(.headers, false);
    try testing.expect(s.countsTowardConcurrency()); // open
    s.recvApply(.rst_stream, false);
    try testing.expect(!s.countsTowardConcurrency()); // closed
}

test "debitRecvWindow rejects an overrun" {
    var s = Stream.init(1, 10, 65535);
    try testing.expectEqual(Action.ok, s.debitRecvWindow(10).action);
    try testing.expectEqual(@as(i32, 0), s.recv_window);
    try testing.expectEqual(Action.stream_error, s.debitRecvWindow(1).action);
}

test "creditSendWindow rejects zero and overflow" {
    var s = Stream.init(1, 65535, 65535);
    try testing.expectEqual(ErrorCode.protocol_error, s.creditSendWindow(0).code);
    s.send_window = constants.MAX_WINDOW_SIZE - 1;
    try testing.expectEqual(ErrorCode.flow_control_error, s.creditSendWindow(2).code);
    try testing.expectEqual(Action.ok, s.creditSendWindow(1).action);
    try testing.expectEqual(constants.MAX_WINDOW_SIZE, s.send_window);
}

test "adjustSendWindow allows a negative result" {
    var s = Stream.init(1, 65535, 100);
    try testing.expectEqual(Action.ok, s.adjustSendWindow(-200).action);
    try testing.expectEqual(@as(i32, -100), s.send_window);
}

test "content-length mismatch at end of stream is a stream error" {
    var s = Stream.init(1, 65535, 65535);
    s.content_length = 5;
    s.recordData(3);
    const t = s.checkContentLength();
    try testing.expectEqual(Action.stream_error, t.action);
    try testing.expectEqual(ErrorCode.protocol_error, t.code);
    s.recordData(2);
    try testing.expectEqual(Action.ok, s.checkContentLength().action);
}
