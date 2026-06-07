//! The HTTP/2 connection orchestrator: the H2 analogue of reader.zig. It owns the
//! input buffer, the preface/SETTINGS phase machine, the HPACK decoder, both
//! settings directions, the stream map, the connection flow windows, and a
//! bounded pending-event ring. feed()/nextEvent() expose the same sans-IO pull
//! API as the H1 Reader; each emitted event carries its stream_id.
//!
//! DRAIN DISCIPLINE: nextEvent drains the pending ring fully before decoding the
//! next frame. One frame fans out into at most PENDING_CAP events. This keeps the
//! one-event-per-call contract and - together with the HPACK decoder clearing its
//! out_store at the start of each block - keeps a not-yet-drained Request's header
//! slices valid (see docs/architecture/http2-design.md).

const std = @import("std");
const constants = @import("constants.zig");
const frame_mod = @import("frame.zig");
const settings_mod = @import("settings.zig");
const stream_mod = @import("stream.zig");
const decoder_mod = @import("hpack/decoder.zig");
const events = @import("../events.zig");

const Event = events.Event;
const FrameType = constants.FrameType;
const ErrorCode = constants.ErrorCode;
const Flags = constants.Flags;
const Settings = settings_mod.Settings;
const Stream = stream_mod.Stream;
const Action = stream_mod.Action;

const COMPACT_THRESHOLD: usize = 64 * 1024;

/// Max events one frame can fan out into. A HEADERS(END_STREAM) yields Request +
/// EndOfMessage = 2; no decode path exceeds this. Sized with headroom.
const PENDING_CAP: usize = 4;

pub const Role = enum { server, client };

pub const Limits = struct {
    max_concurrent_streams: u32 = 128,
    max_header_list_size: u32 = 64 * 1024,
    header_table_size: u32 = constants.DEFAULT_HEADER_TABLE_SIZE,
    max_frame_size: u32 = constants.DEFAULT_FRAME_SIZE,
    max_buffer: usize = 8 * 1024 * 1024,
};

/// The error set the H2 engine raises. Mapped to RFC 9113 error codes for the
/// GOAWAY it emits before poisoning.
pub const H2Error = error{
    ProtocolError,
    FrameSizeError,
    CompressionError,
    FlowControlError,
    MessageTooLong,
    EnhanceYourCalm,
};

const Phase = enum {
    /// Server: waiting for the 24-byte client preface. Client: about to send its
    /// preface (no inbound preface to await).
    await_preface,
    /// Waiting for the peer's first frame, which MUST be SETTINGS.
    await_settings,
    /// Steady state.
    open,
    /// Poisoned by a connection error; every later call re-raises.
    failed,
};

pub const Connection = struct {
    gpa: std.mem.Allocator,
    role: Role,
    limits: Limits = .{},

    buf: std.ArrayList(u8) = .empty,
    consumed: usize = 0,

    phase: Phase = .await_preface,
    hpack: decoder_mod.Decoder,
    local_settings: Settings = .{},
    peer_settings: Settings = .{},
    streams: std.AutoHashMapUnmanaged(u32, Stream) = .empty,
    conn_recv_window: i32 = constants.DEFAULT_WINDOW_SIZE,
    conn_send_window: i32 = constants.DEFAULT_WINDOW_SIZE,
    highest_peer_id: u32 = 0,

    pending: [PENDING_CAP]Event = undefined,
    pending_len: usize = 0,
    pending_head: usize = 0,
    /// Owned scratch for a Settings event's params; valid until the next event is
    /// produced (the integrator copies what it needs synchronously, as for Data).
    settings_scratch: std.ArrayList(events.SettingPair) = .empty,

    failed_with: H2Error = error.ProtocolError,
    eof_seen: bool = false,

    pub fn init(gpa: std.mem.Allocator, role: Role) Connection {
        var c = Connection{
            .gpa = gpa,
            .role = role,
            .hpack = undefined,
        };
        c.hpack = decoder_mod.Decoder.init(gpa, c.limits.header_table_size, c.limits.max_header_list_size);
        if (role == .client) c.phase = .await_settings; // a client has no inbound preface
        return c;
    }

    pub fn deinit(self: *Connection) void {
        self.buf.deinit(self.gpa);
        self.streams.deinit(self.gpa);
        self.hpack.deinit();
        self.settings_scratch.deinit(self.gpa);
    }

    /// Append received bytes (empty slice signals EOF). Bounded by max_buffer.
    pub fn feed(self: *Connection, data: []const u8) H2Error!void {
        if (data.len == 0) {
            self.eof_seen = true;
            return;
        }
        if (self.limits.max_buffer != 0) {
            const unconsumed = self.buf.items.len - self.consumed;
            if (unconsumed + data.len > self.limits.max_buffer) return error.MessageTooLong;
        }
        self.buf.appendSlice(self.gpa, data) catch return error.MessageTooLong;
    }

    /// Produce the next event, or `.need_data`. A connection error poisons the
    /// engine: it is latched and re-raised on every later call (as H1 does).
    pub fn nextEvent(self: *Connection) H2Error!Event {
        if (self.phase == .failed) return self.failed_with;
        return self.dispatch() catch |e| {
            self.phase = .failed;
            self.failed_with = e;
            return e;
        };
    }

    fn dispatch(self: *Connection) H2Error!Event {
        // Drain any buffered events from the previous frame first.
        if (self.pending_len > 0) return self.popPending();

        if (self.consumed >= COMPACT_THRESHOLD and self.consumed * 2 >= self.buf.items.len) self.compact();

        if (self.phase == .await_preface) {
            switch (try self.consumePreface()) {
                .need_data => return .need_data,
                .ready => self.phase = .await_settings,
            }
        }

        // Decode frames until one produces an event or the buffer runs dry. A run
        // of no-event frames (SETTINGS-ACK, PRIORITY) is consumed in this loop
        // rather than via recursion, so it cannot overflow the stack.
        while (true) {
            switch (try self.readFrame()) {
                .need_data => return .need_data,
                .progressed => if (self.pending_len > 0) return self.popPending(),
            }
        }
    }

    const PrefaceResult = enum { need_data, ready };

    fn consumePreface(self: *Connection) H2Error!PrefaceResult {
        const region = self.avail();
        const magic = constants.CLIENT_PREFACE;
        if (region.len < magic.len) {
            // As far as we have, it must match the prefix; mismatch fails early.
            const n = region.len;
            if (!std.mem.eql(u8, region, magic[0..n])) return error.ProtocolError;
            return .need_data;
        }
        if (!std.mem.eql(u8, region[0..magic.len], magic)) return error.ProtocolError;
        self.consumed += magic.len;
        return .ready;
    }

    const FrameResult = enum { need_data, progressed };

    fn readFrame(self: *Connection) H2Error!FrameResult {
        const region = self.avail();
        const f = frame_mod.parse(region, self.limits.max_frame_size) catch |e| switch (e) {
            error.NeedData => {
                if (self.eof_seen and region.len == 0) return .need_data;
                return .need_data;
            },
            error.FrameSizeError => return error.FrameSizeError,
            error.ProtocolError => return error.ProtocolError,
            error.TooLarge => return error.ProtocolError,
        };
        const total = constants.FRAME_HEADER_LEN + @as(usize, f.header.length);

        // The first frame after the preface MUST be SETTINGS (RFC 9113 3.4).
        const ftype: FrameType = @enumFromInt(f.header.ftype);
        if (self.phase == .await_settings) {
            if (ftype != .settings) return error.ProtocolError;
            self.phase = .open;
        }

        try self.handleFrame(f, ftype);
        self.consumed += total;
        return .progressed;
    }

    fn handleFrame(self: *Connection, f: frame_mod.Frame, ftype: FrameType) H2Error!void {
        switch (ftype) {
            .settings => try self.handleSettings(f),
            .ping => try self.handlePing(f),
            .goaway => try self.handleGoaway(f),
            .window_update => try self.handleWindowUpdate(f),
            .data => try self.handleData(f),
            .rst_stream => try self.handleRstStream(f),
            .priority => {}, // deprecated; parsed by frame.checkLength, ignored
            // HEADERS / CONTINUATION / PUSH_PROMISE land in the next iteration.
            .headers, .continuation, .push_promise => return error.ProtocolError,
            else => {}, // unknown frame types are discarded (RFC 9113 4.1)
        }
    }

    fn handleSettings(self: *Connection, f: frame_mod.Frame) H2Error!void {
        if (f.header.stream_id != 0) return error.ProtocolError;
        if (Flags.has(f.header.flags, Flags.ack)) return; // our SETTINGS was ACKed; nothing to emit
        const delta = self.peer_settings.apply(f.payload) catch |e| switch (e) {
            error.ProtocolError => return error.ProtocolError,
            error.FlowControlError => return error.FlowControlError,
            error.FrameSizeError => return error.FrameSizeError,
        };
        if (delta) |d| try self.applyInitialWindowDelta(d);
        // Surface the peer's settings (id, value) pairs so the integrator can
        // react and knows an ACK is owed. The payload was already validated as a
        // multiple of 6 by frame.checkLength.
        self.settings_scratch.clearRetainingCapacity();
        var i: usize = 0;
        while (i < f.payload.len) : (i += 6) {
            const id = std.mem.readInt(u16, f.payload[i..][0..2], .big);
            const value = std.mem.readInt(u32, f.payload[i + 2 ..][0..4], .big);
            self.settings_scratch.append(self.gpa, .{ .id = id, .value = value }) catch return error.MessageTooLong;
        }
        self.push(.{ .settings = .{ .params = self.settings_scratch.items } });
    }

    fn applyInitialWindowDelta(self: *Connection, delta: i32) H2Error!void {
        var it = self.streams.valueIterator();
        while (it.next()) |s| {
            if (s.adjustSendWindow(delta).action == .connection_error) return error.FlowControlError;
        }
    }

    fn handlePing(self: *Connection, f: frame_mod.Frame) H2Error!void {
        if (f.header.stream_id != 0) return error.ProtocolError;
        var data: [8]u8 = undefined;
        @memcpy(&data, f.payload[0..8]);
        self.push(.{ .ping = .{ .ack = Flags.has(f.header.flags, Flags.ack), .opaque_data = data } });
    }

    fn handleGoaway(self: *Connection, f: frame_mod.Frame) H2Error!void {
        if (f.header.stream_id != 0) return error.ProtocolError;
        const last_id = std.mem.readInt(u32, f.payload[0..4], .big) & 0x7FFF_FFFF;
        const code = std.mem.readInt(u32, f.payload[4..8], .big);
        self.push(.{ .goaway = .{ .last_stream_id = last_id, .error_code = code, .debug = f.payload[8..] } });
    }

    fn handleWindowUpdate(self: *Connection, f: frame_mod.Frame) H2Error!void {
        const increment = std.mem.readInt(u32, f.payload[0..4], .big) & 0x7FFF_FFFF;
        if (f.header.stream_id == 0) {
            // Connection-level: a zero increment or an overflow is a CONNECTION
            // error (RFC 9113 6.9 / 6.9.1).
            if (increment == 0) return error.ProtocolError;
            const sum = @as(i64, self.conn_send_window) + @as(i64, increment);
            if (sum > constants.MAX_WINDOW_SIZE) return error.FlowControlError;
            self.conn_send_window = @intCast(sum);
            self.push(.{ .window_update = .{ .stream_id = 0, .increment = increment } });
            return;
        }
        const s = self.streams.getPtr(f.header.stream_id) orelse {
            // No live stream: an id never opened (> highest seen) is idle, which
            // is a connection PROTOCOL_ERROR; an id at/below the high-water mark
            // is closed, and a stray WINDOW_UPDATE in its wake is ignored.
            if (self.isIdle(f.header.stream_id)) return error.ProtocolError;
            return;
        };
        // A stream-level violation (zero increment or window overflow) resets the
        // stream; we do NOT also emit a window_update for the rejected frame.
        const t = s.creditSendWindow(increment);
        switch (t.action) {
            .ok => self.push(.{ .window_update = .{ .stream_id = f.header.stream_id, .increment = increment } }),
            .stream_error => self.push(.{ .rst_stream = .{ .stream_id = f.header.stream_id, .error_code = @intFromEnum(t.code) } }),
            .connection_error => return error.FlowControlError,
        }
    }

    /// Is `id` a peer-initiated stream that has never been opened (idle)? An id
    /// above the highest one we have seen open is idle; at/below is closed.
    fn isIdle(self: *const Connection, id: u32) bool {
        return id > self.highest_peer_id;
    }

    fn handleData(self: *Connection, f: frame_mod.Frame) H2Error!void {
        if (f.header.stream_id == 0) return error.ProtocolError;
        const end_stream = Flags.has(f.header.flags, Flags.end_stream);
        const content = frame_mod.dePad(f.payload, Flags.has(f.header.flags, Flags.padded)) catch |e| switch (e) {
            error.ProtocolError => return error.ProtocolError,
            error.FrameSizeError => return error.FrameSizeError,
            else => return error.ProtocolError,
        };
        // Connection-window accounting against the FULL frame payload length.
        if (@as(i64, self.conn_recv_window) - @as(i64, f.header.length) < 0) return error.FlowControlError;
        self.conn_recv_window -= @intCast(f.header.length);

        const s = self.streams.getPtr(f.header.stream_id) orelse return error.ProtocolError;
        const classify = s.classifyRecv(.data, end_stream);
        switch (classify.action) {
            .ok => {},
            .stream_error => {
                self.push(.{ .rst_stream = .{ .stream_id = f.header.stream_id, .error_code = @intFromEnum(classify.code) } });
                return;
            },
            .connection_error => return error.ProtocolError,
        }
        const wt = s.debitRecvWindow(f.header.length);
        if (wt.action == .stream_error) {
            self.push(.{ .rst_stream = .{ .stream_id = f.header.stream_id, .error_code = @intFromEnum(ErrorCode.flow_control_error) } });
            return;
        }
        s.recordData(content.len);
        if (content.len > 0) self.push(.{ .data = .{ .data = content, .stream_id = f.header.stream_id } });
        s.recvApply(.data, end_stream);
        if (end_stream) {
            if (s.checkContentLength().action == .stream_error) {
                self.push(.{ .rst_stream = .{ .stream_id = f.header.stream_id, .error_code = @intFromEnum(ErrorCode.protocol_error) } });
                return;
            }
            self.push(.{ .end_of_message = .{ .stream_id = f.header.stream_id } });
        }
    }

    fn handleRstStream(self: *Connection, f: frame_mod.Frame) H2Error!void {
        if (f.header.stream_id == 0) return error.ProtocolError;
        const code = std.mem.readInt(u32, f.payload[0..4], .big);
        const s = self.streams.getPtr(f.header.stream_id) orelse return error.ProtocolError; // RST on idle
        s.recvApply(.rst_stream, false);
        self.push(.{ .rst_stream = .{ .stream_id = f.header.stream_id, .error_code = code } });
    }

    /// Test/connection helper to open a stream (the HEADERS path will do this in
    /// the next iteration; exposed so the DATA path can be exercised meanwhile).
    pub fn openStreamForTest(self: *Connection, id: u32) !void {
        try self.streams.put(self.gpa, id, Stream.init(id, self.local_settings.initial_window_size, self.peer_settings.initial_window_size));
        var s = self.streams.getPtr(id).?;
        s.recvApply(.headers, false);
        if (id > self.highest_peer_id) self.highest_peer_id = id;
    }

    fn push(self: *Connection, ev: Event) void {
        std.debug.assert(self.pending_len < PENDING_CAP);
        const slot = (self.pending_head + self.pending_len) % PENDING_CAP;
        self.pending[slot] = ev;
        self.pending_len += 1;
    }

    fn popPending(self: *Connection) Event {
        const ev = self.pending[self.pending_head];
        self.pending_head = (self.pending_head + 1) % PENDING_CAP;
        self.pending_len -= 1;
        return ev;
    }

    fn avail(self: *Connection) []const u8 {
        return self.buf.items[self.consumed..];
    }

    fn compact(self: *Connection) void {
        if (self.consumed == 0) return;
        const rest = self.buf.items.len - self.consumed;
        std.mem.copyForwards(u8, self.buf.items[0..rest], self.buf.items[self.consumed..]);
        self.buf.shrinkRetainingCapacity(rest);
        self.consumed = 0;
    }
};

const testing = std.testing;

fn frameBytes(out: *std.ArrayList(u8), ftype: FrameType, flags: u8, stream_id: u32, payload: []const u8) !void {
    try frame_mod.write(out, testing.allocator, ftype, flags, stream_id, payload);
}

test "server consumes the preface then a SETTINGS frame" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    try input.appendSlice(testing.allocator, constants.CLIENT_PREFACE);
    try frameBytes(&input, .settings, 0, 0, &.{}); // empty SETTINGS
    try c.feed(input.items);
    const ev = try c.nextEvent();
    try testing.expectEqual(std.meta.Tag(Event).settings, std.meta.activeTag(ev));
    try testing.expectEqual(Event.need_data, try c.nextEvent());
}

test "a non-SETTINGS first frame is a protocol error" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    try input.appendSlice(testing.allocator, constants.CLIENT_PREFACE);
    try frameBytes(&input, .ping, 0, 0, &[_]u8{0} ** 8);
    try c.feed(input.items);
    try testing.expectError(error.ProtocolError, c.nextEvent());
    // Poisoned: re-raises.
    try testing.expectError(error.ProtocolError, c.nextEvent());
}

test "a bad preface fails early" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    try c.feed("NOT-THE-PREFACE-AT-ALL!!!");
    try testing.expectError(error.ProtocolError, c.nextEvent());
}

test "DATA on an open stream yields a Data then EndOfMessage with the stream id" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    try input.appendSlice(testing.allocator, constants.CLIENT_PREFACE);
    try frameBytes(&input, .settings, 0, 0, &.{});
    try frameBytes(&input, .data, Flags.end_stream, 1, "hello");
    try c.feed(input.items);
    try c.openStreamForTest(1);
    try testing.expectEqual(std.meta.Tag(Event).settings, std.meta.activeTag(try c.nextEvent()));
    const d = try c.nextEvent();
    try testing.expectEqual(@as(u32, 1), d.data.stream_id);
    try testing.expectEqualStrings("hello", d.data.data);
    const eom = try c.nextEvent();
    try testing.expectEqual(@as(u32, 1), eom.end_of_message.stream_id);
    try testing.expectEqual(Event.need_data, try c.nextEvent());
}

test "partial frame resumes across feeds" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    try input.appendSlice(testing.allocator, constants.CLIENT_PREFACE);
    try frameBytes(&input, .settings, 0, 0, &.{});
    const split = input.items.len - 1;
    try c.feed(input.items[0..split]);
    try testing.expectEqual(Event.need_data, try c.nextEvent());
    try c.feed(input.items[split..]);
    try testing.expectEqual(std.meta.Tag(Event).settings, std.meta.activeTag(try c.nextEvent()));
}

fn handshook(c: *Connection, extra: []const u8) !void {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    try input.appendSlice(testing.allocator, constants.CLIENT_PREFACE);
    try frameBytes(&input, .settings, 0, 0, &.{});
    try input.appendSlice(testing.allocator, extra);
    try c.feed(input.items);
    try testing.expectEqual(std.meta.Tag(Event).settings, std.meta.activeTag(try c.nextEvent()));
}

test "WINDOW_UPDATE on an idle stream is a connection error" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var wu: std.ArrayList(u8) = .empty;
    defer wu.deinit(testing.allocator);
    try frameBytes(&wu, .window_update, 0, 7, &[_]u8{ 0x00, 0x00, 0x00, 0x10 }); // stream 7, never opened
    try handshook(&c, wu.items);
    try testing.expectError(error.ProtocolError, c.nextEvent());
}

test "WINDOW_UPDATE with a zero increment on an open stream resets it, no window_update event" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var wu: std.ArrayList(u8) = .empty;
    defer wu.deinit(testing.allocator);
    try frameBytes(&wu, .window_update, 0, 1, &[_]u8{ 0x00, 0x00, 0x00, 0x00 }); // zero increment
    try handshook(&c, wu.items);
    try c.openStreamForTest(1);
    const ev = try c.nextEvent();
    try testing.expectEqual(@as(u32, 1), ev.rst_stream.stream_id);
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.protocol_error)), ev.rst_stream.error_code);
    try testing.expectEqual(Event.need_data, try c.nextEvent());
}

test "a long run of no-event frames does not overflow the stack" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    try input.appendSlice(testing.allocator, constants.CLIENT_PREFACE);
    try frameBytes(&input, .settings, 0, 0, &.{});
    // Thousands of PRIORITY frames (no event each) then a PING (an event).
    var k: usize = 0;
    while (k < 5000) : (k += 1) {
        try frameBytes(&input, .priority, 0, 1, &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00 });
    }
    try frameBytes(&input, .ping, 0, 0, &[_]u8{0} ** 8);
    try c.feed(input.items);
    try testing.expectEqual(std.meta.Tag(Event).settings, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(std.meta.Tag(Event).ping, std.meta.activeTag(try c.nextEvent()));
}

fn driveConnection(input: []const u8) void {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    c.limits.max_buffer = 1 << 20;
    c.feed(input) catch return;
    for (0..input.len + 8) |_| {
        const ev = c.nextEvent() catch break;
        if (ev == .need_data or ev == .connection_closed) break;
    }
}

test "fuzz: connection never panics on adversarial frames" {
    const seeds = [_][]const u8{
        "",
        constants.CLIENT_PREFACE,
        constants.CLIENT_PREFACE ++ [_]u8{ 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 },
    };
    for (seeds) |s| driveConnection(s);
    var prng = std.Random.DefaultPrng.init(0x636f_6e6e);
    const rand = prng.random();
    var buf: [256]u8 = undefined;
    for (0..3000) |_| {
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        for (buf[0..len]) |*b| b.* = rand.int(u8);
        driveConnection(buf[0..len]);
    }
}
