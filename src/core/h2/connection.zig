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
//! slices valid (see docs/architecture/overview.md).

const std = @import("std");
const constants = @import("constants.zig");
const frame_mod = @import("frame.zig");
const settings_mod = @import("settings.zig");
const stream_mod = @import("stream.zig");
const decoder_mod = @import("hpack/decoder.zig");
const writer_mod = @import("writer.zig");
const events = @import("../events.zig");
const ascii = @import("../ascii.zig");
const fields = @import("fields.zig");

const Event = events.H2Event;
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
    /// Caps on an open field block (HEADERS + its CONTINUATIONs), defending
    /// against the CONTINUATION flood (CVE-2024-27316).
    max_field_block_bytes: usize = 64 * 1024,
    max_continuation_frames: u32 = 16,
    /// Total streams ever opened on one connection and total resets the peer may
    /// drive, defending against rapid-reset churn (CVE-2023-44487). Defaults are
    /// generous multiples of max_concurrent_streams; exceeding either trips
    /// EnhanceYourCalm (-> GOAWAY).
    max_streams: u64 = 4096,
    max_stream_resets: u64 = 256,
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
    /// Connection-level receive bytes consumed since the last WINDOW_UPDATE we sent.
    /// The window is refilled immediately on consume (the core surfaces DATA at
    /// once), and this accumulates what to advertise back, flushed by a threshold.
    conn_recv_credit: u32 = 0,
    highest_peer_id: u32 = 0,
    /// High-water of the client's own opened ids (highest_peer_id's local analogue),
    /// so a response for a reset stream is recognized as closed, not a new stream.
    highest_local_id: u32 = 0,
    /// Rapid-reset churn budgets: total streams ever opened and total resets.
    /// These count streams that no longer exist (evicted), so unlike the live
    /// concurrency count they are real state, not derivable from the map.
    streams_opened: u64 = 0,
    stream_resets: u64 = 0,

    pending: [PENDING_CAP]Event = undefined,
    pending_len: usize = 0,
    pending_head: usize = 0,
    /// Owned scratch for a Settings event's params; valid until the next event is
    /// produced (the integrator copies what it needs synchronously, as for Data).
    settings_scratch: std.ArrayList(events.SettingPair) = .empty,
    /// Scratch list of stream ids to evict after a flushSendable pass, so the map
    /// is never mutated while its iterator is live.
    evict_scratch: std.ArrayList(u32) = .empty,

    /// The single open field block (RFC 9113 4.3): once HEADERS without
    /// END_HEADERS opens it, the very next frame must be CONTINUATION on this
    /// stream. Only one block may be open across the whole connection, so this is
    /// connection-level state, not per-stream. null = no block open.
    fb_stream: ?u32 = null,
    fb_end_stream: bool = false, // END_STREAM carried by the opening HEADERS
    fb_is_trailer: bool = false, // a second HEADERS block on an open stream
    fb_refused: bool = false, // over the concurrency cap: decode for HPACK sync, then discard
    fb_ignored: bool = false, // a response for a client stream we already reset: decode for HPACK sync, surface nothing
    fb_buf: std.ArrayList(u8) = .empty, // accumulated fragment bytes
    fb_frames: u32 = 0, // CONTINUATION frame count (flood guard)
    /// Storage for a collapsed request/response: the regular header list and a
    /// byte scratch for synthesized values (e.g. the host from :authority). Both
    /// are stable until the next HEADERS decode, mirroring the HPACK out_store
    /// lifetime contract.
    req_headers: std.ArrayList(events.Header) = .empty,
    req_scratch: std.ArrayList(u8) = .empty,

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
        var it = self.streams.valueIterator();
        while (it.next()) |s| s.deinit(self.gpa);
        self.streams.deinit(self.gpa);
        self.hpack.deinit();
        self.settings_scratch.deinit(self.gpa);
        self.evict_scratch.deinit(self.gpa);
        self.fb_buf.deinit(self.gpa);
        self.req_headers.deinit(self.gpa);
        self.req_scratch.deinit(self.gpa);
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
        // Contiguity (RFC 9113 4.3): while a field block is open, the ONLY legal
        // frame is a CONTINUATION on the same stream. Anything else - any type,
        // any stream - is a connection PROTOCOL_ERROR.
        if (self.fb_stream) |open_id| {
            if (ftype != .continuation or f.header.stream_id != open_id) return error.ProtocolError;
            return self.handleContinuation(f);
        }
        switch (ftype) {
            .settings => try self.handleSettings(f),
            .ping => try self.handlePing(f),
            .goaway => try self.handleGoaway(f),
            .window_update => try self.handleWindowUpdate(f),
            .data => try self.handleData(f),
            .rst_stream => try self.handleRstStream(f),
            .headers => try self.handleHeaders(f),
            .priority => {}, // deprecated; parsed by frame.checkLength, ignored
            // A CONTINUATION with no open block is a protocol error (4.3); server
            // push is out of scope so PUSH_PROMISE is rejected.
            .continuation, .push_promise => return error.ProtocolError,
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
    /// Idle = never opened by either side; at/below either high-water is closed.
    fn isIdle(self: *const Connection, id: u32) bool {
        return id > self.highest_peer_id and id > self.highest_local_id;
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

        const s = self.streams.getPtr(f.header.stream_id) orelse {
            // No live stream: an idle id (never opened) is a connection error;
            // a closed/evicted id is a stream error STREAM_CLOSED (RFC 9113 5.1,
            // mirroring stream.classifyRecv's .closed branch).
            if (self.isIdle(f.header.stream_id)) return error.ProtocolError;
            self.push(.{ .rst_stream = .{ .stream_id = f.header.stream_id, .error_code = @intFromEnum(ErrorCode.stream_closed) } });
            return;
        };
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
        // Refill the receive windows immediately (the data is surfaced now) and
        // accumulate the consumed length to advertise back via WINDOW_UPDATE.
        self.conn_recv_window += @intCast(f.header.length);
        self.conn_recv_credit +|= f.header.length;
        s.creditRecvWindow(f.header.length);
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
        const s = self.streams.getPtr(f.header.stream_id) orelse {
            // RST on a never-opened (idle) stream is a connection error; on a
            // closed/forgotten stream it is tolerated and dropped.
            if (self.isIdle(f.header.stream_id)) return error.ProtocolError;
            return;
        };
        s.recvApply(.rst_stream, false);
        self.evictStream(f.header.stream_id);
        try self.chargeReset();
        self.push(.{ .rst_stream = .{ .stream_id = f.header.stream_id, .error_code = code } });
    }

    // -- HEADERS / CONTINUATION reassembly -----------------------------------

    fn handleHeaders(self: *Connection, f: frame_mod.Frame) H2Error!void {
        if (f.header.stream_id == 0) return error.ProtocolError;
        const id = f.header.stream_id;
        const fragment = frame_mod.headersFieldBlock(f.payload, f.header.flags) catch |e| switch (e) {
            error.FrameSizeError => return error.FrameSizeError,
            error.ProtocolError => return error.ProtocolError,
            else => return error.ProtocolError,
        };

        const existing = self.streams.getPtr(id);
        var is_trailer = false;
        var refused = false;
        var ignored = false;
        if (existing) |s| {
            // A second HEADERS block is a trailer ONLY while the stream is still
            // open (body not yet ended). A HEADERS after the peer's END_STREAM
            // (half-closed-remote) or on a closed stream is a protocol error.
            const client_reading = self.role == .client and (s.state == .open or s.state == .half_closed_local);
            if (s.headers_done and s.state == .open) {
                is_trailer = true;
            } else if (client_reading and !s.headers_done) {
                // A client reading a response head: the stream is open, or
                // half_closed_local once the client finished sending its request.
                // An interim (1xx) head may already have arrived; accept the next.
            } else {
                return error.ProtocolError;
            }
        } else if (self.role == .client) {
            // A client reads a response on a stream it opened (odd id, 5.1.1). An id
            // at/below the local high-water but gone from the map was already reset:
            // decode for HPACK sync but surface nothing. A new id opens its stream.
            if (id % 2 == 0) return error.ProtocolError;
            if (id <= self.highest_local_id) {
                ignored = true;
            } else {
                try self.openPeerStream(id);
            }
        } else {
            // A new request stream. Its id must be odd and exceed the highest peer
            // id (5.1.1: parity + monotonicity).
            if (id % 2 == 0 or id <= self.highest_peer_id) return error.ProtocolError;
            // Over the concurrency cap: still HPACK-decode the block to keep the
            // connection-global dynamic table in sync, but refuse the request
            // (RST_STREAM REFUSED_STREAM) and never surface it. No stream record
            // is inserted, so the map cannot grow under a refused-stream flood.
            refused = self.liveStreamCount() >= self.limits.max_concurrent_streams;
            if (!refused) {
                try self.openPeerStream(id);
            }
            self.highest_peer_id = id;
        }

        self.fb_stream = id;
        self.fb_end_stream = Flags.has(f.header.flags, Flags.end_stream);
        self.fb_is_trailer = is_trailer;
        self.fb_refused = refused;
        self.fb_ignored = ignored;
        self.fb_frames = 0;
        self.fb_buf.clearRetainingCapacity();
        self.fb_buf.appendSlice(self.gpa, fragment) catch return error.MessageTooLong;
        if (self.fb_buf.items.len > self.limits.max_field_block_bytes) return error.EnhanceYourCalm;

        if (Flags.has(f.header.flags, Flags.end_headers)) try self.completeFieldBlock();
    }

    fn handleContinuation(self: *Connection, f: frame_mod.Frame) H2Error!void {
        if (self.fb_frames == self.limits.max_continuation_frames) return error.EnhanceYourCalm;
        self.fb_frames += 1;
        self.fb_buf.appendSlice(self.gpa, f.payload) catch return error.MessageTooLong;
        if (self.fb_buf.items.len > self.limits.max_field_block_bytes) return error.EnhanceYourCalm;
        if (Flags.has(f.header.flags, Flags.end_headers)) try self.completeFieldBlock();
    }

    /// The field block is complete: HPACK-decode it (always, to keep the dynamic
    /// table in sync), collapse pseudo-headers into a Request, validate, and emit.
    /// A malformed message is a STREAM error (RST_STREAM) - the connection and the
    /// HPACK table survive (RFC 9113 8.1.1).
    fn completeFieldBlock(self: *Connection) H2Error!void {
        const id = self.fb_stream.?;
        const end_stream = self.fb_end_stream;
        const is_trailer = self.fb_is_trailer;
        const refused = self.fb_refused;
        const ignored = self.fb_ignored;
        self.fb_stream = null;

        // Always decode (even when refused/malformed) to keep the dynamic table
        // in sync; a decode failure is connection-fatal COMPRESSION_ERROR.
        const headers = self.hpack.decodeBlock(self.fb_buf.items) catch |e| switch (e) {
            error.CompressionError => return error.CompressionError,
            error.MessageTooLong => return error.MessageTooLong,
            error.OutOfMemory => return error.MessageTooLong,
        };

        if (ignored) {
            // Response for an already-reset stream: decoded for HPACK sync, dropped.
            return;
        }

        if (refused) {
            // Decoded for HPACK sync; the request is not surfaced and no stream
            // record exists, so nothing to close.
            self.push(.{ .rst_stream = .{ .stream_id = id, .error_code = @intFromEnum(ErrorCode.refused_stream) } });
            return;
        }

        const s = self.streams.getPtr(id).?;
        if (is_trailer) {
            // Trailers: a second HEADERS block; must carry END_STREAM (8.1) and
            // must not contain pseudo-headers or otherwise-invalid fields.
            if (!end_stream or !validTrailers(headers)) {
                try self.resetStream(s, id, .protocol_error);
                return;
            }
            s.recvApply(.headers, true);
            self.push(.{ .end_of_message = .{ .trailers = headers, .stream_id = id } });
            return;
        }

        if (self.role == .client) {
            // Collapse the response pseudo-header (:status) + regular fields.
            const resp = self.collapseResponse(headers, id) catch |e| switch (e) {
                error.Malformed => {
                    try self.resetStream(s, id, .protocol_error);
                    return;
                },
                error.OutOfMemory => return error.MessageTooLong,
            };
            // A 1xx interim response is informational: it carries no body and the
            // stream stays open for the final response (RFC 9110 15.2). It must
            // therefore NOT end the stream - an interim with END_STREAM would leave
            // the receive side closed waiting for a final response that can never
            // arrive, so it is malformed and resets the stream.
            if (resp.event.status_code >= 100 and resp.event.status_code < 200) {
                if (end_stream) {
                    try self.resetStream(s, id, .protocol_error);
                    return;
                }
                self.push(.{ .response = resp.event });
                return;
            }
            s.headers_done = true;
            if (resp.content_length) |cl| s.content_length = cl;
            // 204/304 responses carry no body regardless of content-length.
            if (resp.event.status_code == 204 or resp.event.status_code == 304) s.expects_bodyless = true;
            self.push(.{ .response = resp.event });
            if (end_stream) {
                s.recvApply(.headers, true); // open -> half_closed_remote
                self.push(.{ .end_of_message = .{ .stream_id = id } });
            }
            return;
        }

        // Collapse pseudo-headers into the request line + regular headers.
        const req = self.collapseRequest(headers, id) catch |e| switch (e) {
            error.Malformed => {
                try self.resetStream(s, id, .protocol_error);
                return;
            },
            error.OutOfMemory => return error.MessageTooLong,
        };
        s.headers_done = true;
        if (req.content_length) |cl| s.content_length = cl;
        self.push(.{ .request = req.event });
        if (end_stream) {
            s.recvApply(.headers, true); // open -> half_closed_remote
            self.push(.{ .end_of_message = .{ .stream_id = id } });
        }
    }

    /// Reset a stream for a stream error: emit RST_STREAM, move its state to
    /// closed, and evict it. A locally-driven reset still counts as churn.
    fn resetStream(self: *Connection, s: *Stream, id: u32, code: ErrorCode) H2Error!void {
        s.recvApply(.rst_stream, false); // -> closed
        self.evictStream(id);
        try self.chargeReset();
        self.push(.{ .rst_stream = .{ .stream_id = id, .error_code = @intFromEnum(code) } });
    }

    const CollapseError = error{ Malformed, OutOfMemory };
    const Collapsed = struct { event: events.Request, content_length: ?u64 };

    /// Map HTTP/2 pseudo-headers + regular fields to a zttp Request (RFC 9113 8).
    /// :method->method, :path->target, :authority->a synthesized lowercase host
    /// header. Enforces: pseudo-headers precede regular fields; exactly one each
    /// of :method/:scheme/:path; no response pseudo-header; lowercase names; no
    /// connection-specific fields; TE only "trailers". Slices point into the HPACK
    /// out_store (valid until the next decode) or req_scratch (owned, stable).
    fn collapseRequest(self: *Connection, headers: []const events.Header, id: u32) CollapseError!Collapsed {
        self.req_headers.clearRetainingCapacity();
        self.req_scratch.clearRetainingCapacity();
        var method: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var scheme: ?[]const u8 = null;
        var authority: ?[]const u8 = null;
        var content_length: ?u64 = null;
        var seen_regular = false;

        for (headers) |h| {
            if (h.name.len == 0) return error.Malformed;
            if (!fields.validValue(h.value)) return error.Malformed; // CR/LF/NUL/control in value
            if (h.name[0] == ':') {
                if (seen_regular) return error.Malformed; // pseudo after regular
                if (eql(h.name, ":method")) {
                    if (method != null) return error.Malformed;
                    method = h.value;
                } else if (eql(h.name, ":path")) {
                    if (path != null) return error.Malformed;
                    path = h.value;
                } else if (eql(h.name, ":scheme")) {
                    if (scheme != null) return error.Malformed;
                    scheme = h.value;
                } else if (eql(h.name, ":authority")) {
                    if (authority != null) return error.Malformed;
                    authority = h.value;
                } else {
                    return error.Malformed; // unknown or response pseudo-header
                }
                continue;
            }
            seen_regular = true;
            if (!fields.isValidFieldName(h.name)) return error.Malformed; // uppercase / non-token byte
            if (fields.isConnectionSpecific(h.name)) return error.Malformed;
            if (eql(h.name, "te") and !eql(h.value, "trailers")) return error.Malformed;
            if (eql(h.name, "content-length")) {
                const cl = ascii.parseDecimal(u64, h.value) orelse return error.Malformed;
                // A repeated content-length is malformed unless it agrees (RFC 9110).
                if (content_length) |prev| {
                    if (prev != cl) return error.Malformed;
                } else content_length = cl;
            }
            self.req_headers.append(self.gpa, h) catch return error.OutOfMemory;
        }

        if (method == null or path == null or scheme == null) return error.Malformed;
        const target = path.?;
        // RFC 9113 8.3.1: :path must be non-empty for http/https (the empty/CONNECT
        // and asterisk-form carve-outs are *, which is non-empty, so this is enough).
        if (target.len == 0) return error.Malformed;
        const q = std.mem.indexOfScalar(u8, target, '?');
        const req_path = if (q) |i| target[0..i] else target;
        const req_query = if (q) |i| target[i + 1 ..] else target[target.len..];
        // Synthesize a host header from :authority (copied into req_scratch).
        if (authority) |a| {
            const start = self.req_scratch.items.len;
            self.req_scratch.appendSlice(self.gpa, a) catch return error.OutOfMemory;
            const host_val = self.req_scratch.items[start..];
            self.req_headers.append(self.gpa, .{ .name = "host", .value = host_val }) catch return error.OutOfMemory;
        }

        return .{
            .event = .{
                .method = method.?,
                .target = target,
                .path = req_path,
                .query = req_query,
                .http_version = "2",
                .headers = self.req_headers.items,
                .stream_id = id,
            },
            .content_length = content_length,
        };
    }

    const CollapsedResponse = struct { event: events.Response, content_length: ?u64 };

    /// Map HTTP/2 response pseudo-headers + regular fields to a zttp Response
    /// (RFC 9113 8.3.2). The only valid pseudo-header is :status (a 3-digit code);
    /// request pseudo-headers (:method/:path/:scheme/:authority) are malformed in a
    /// response. Same field-validity rules as a request: pseudo precede regular,
    /// lowercase names, no connection-specific fields. The reason phrase does not
    /// exist in HTTP/2, so it is empty. Slices point into the HPACK out_store.
    fn collapseResponse(self: *Connection, headers: []const events.Header, id: u32) CollapseError!CollapsedResponse {
        self.req_headers.clearRetainingCapacity();
        var status: ?u16 = null;
        var content_length: ?u64 = null;
        var seen_regular = false;

        for (headers) |h| {
            if (h.name.len == 0) return error.Malformed;
            if (h.name[0] == ':') {
                if (seen_regular) return error.Malformed; // pseudo after regular
                if (!eql(h.name, ":status")) return error.Malformed; // request pseudo or unknown
                // :status is digit-checked below, so it cannot carry a control byte.
                if (status != null) return error.Malformed;
                if (h.value.len != 3) return error.Malformed;
                var code: u16 = 0;
                for (h.value) |d| {
                    if (d < '0' or d > '9') return error.Malformed;
                    code = code * 10 + (d - '0');
                }
                // Only the defined status classes (1xx-5xx) are valid; 000-099 and
                // 600-999 are impossible codes (RFC 9110 15).
                if (code < 100 or code > 599) return error.Malformed;
                status = code;
                continue;
            }
            seen_regular = true;
            if (!fields.isValidFieldName(h.name)) return error.Malformed;
            if (!fields.validValue(h.value)) return error.Malformed; // CR/LF/NUL/control in value
            if (fields.isConnectionSpecific(h.name)) return error.Malformed;
            if (eql(h.name, "content-length")) {
                const cl = ascii.parseDecimal(u64, h.value) orelse return error.Malformed;
                if (content_length) |prev| {
                    if (prev != cl) return error.Malformed;
                } else content_length = cl;
            }
            self.req_headers.append(self.gpa, h) catch return error.OutOfMemory;
        }

        if (status == null) return error.Malformed;
        return .{
            .event = .{
                .status_code = status.?,
                .reason = "",
                .http_version = "2",
                .headers = self.req_headers.items,
                .stream_id = id,
            },
            .content_length = content_length,
        };
    }

    // -- Send side: flow-controlled DATA ------------------------------------
    //
    // The window state already lives here (conn_send_window, per-stream
    // send_window, credited by WINDOW_UPDATE and SETTINGS), so the send gate
    // lives here too rather than being mirrored into the Writer. The Writer stays
    // a stateless framer: this code decides how many bytes may leave now and hands
    // each chunk to writer.writeDataFrame. Bytes the window cannot yet admit are
    // parked in the stream's send_pending and drained by flushSendable when a
    // WINDOW_UPDATE or SETTINGS credit arrives. The caller owns the Writer (the
    // adapter pairs them), so it is passed in rather than stored.

    /// Ensure a stream entry exists for an outgoing message. A client opens the
    /// stream by sending; the read side has no entry until then. The send window
    /// is seeded from the peer's INITIAL_WINDOW_SIZE (what the peer will accept).
    pub fn registerSendStream(self: *Connection, id: u32) error{OutOfMemory}!void {
        if (id > self.highest_local_id) self.highest_local_id = id;
        if (self.streams.getPtr(id) != null) return;
        self.openStream(id) catch return error.OutOfMemory;
    }

    /// Mark that the response on `id` will carry no body (the request method is
    /// HEAD), so the content-length vs data-seen check is skipped when it ends.
    /// Call after registerSendStream. A no-op on an unknown id.
    pub fn markBodylessRequest(self: *Connection, id: u32) void {
        if (self.streams.getPtr(id)) |s| s.expects_bodyless = true;
    }

    /// Account for a locally-initiated RST_STREAM: the stream is terminally closed,
    /// so drop it from the map (the caller serializes the RST_STREAM frame itself).
    /// A no-op on an unknown id.
    pub fn localReset(self: *Connection, id: u32) void {
        self.evictStream(id);
    }

    /// The highest peer-initiated stream id seen so far - the natural last-stream-id
    /// for a GOAWAY (everything above it was never processed).
    pub fn lastPeerStreamId(self: *const Connection) u32 {
        return self.highest_peer_id;
    }

    /// Queue outbound body bytes on `id`, emitting as much as the connection and
    /// stream send windows (and the peer's max frame) allow, parking the rest.
    pub fn sendStreamData(self: *Connection, writer: *writer_mod.Writer, id: u32, data: []const u8, end_stream: bool) writer_mod.WriteError!void {
        try self.registerSendStream(id);
        const s = self.streams.getPtr(id).?;
        if (data.len != 0) s.send_pending.appendSlice(self.gpa, data) catch return error.OutOfMemory;
        if (end_stream) s.send_end_pending = true;
        try self.flushStream(writer, id);
    }

    /// Drain parked DATA on every stream the windows now permit. Call after a
    /// WINDOW_UPDATE or an INITIAL_WINDOW_SIZE change credits a send window.
    /// Flushing mutates only each stream's own fields and the writer (never the
    /// map's shape), so iterating value pointers in place is safe.
    /// Emit WINDOW_UPDATE frames to advertise the receive credit accumulated as
    /// DATA was consumed, so the peer's send window never drains to a stall. A
    /// connection-level update (stream 0) plus one per stream that has consumed
    /// at least `threshold` bytes; the connection update fires on the same
    /// threshold against its own accumulator. Auto-replenish to full is the
    /// pragmatic default for a core that surfaces DATA immediately.
    pub fn flushRecvWindows(self: *Connection, writer: *writer_mod.Writer) writer_mod.WriteError!void {
        const threshold: u32 = @intCast(@divTrunc(constants.DEFAULT_WINDOW_SIZE, 2));
        if (self.conn_recv_credit >= threshold) {
            try writer.sendWindowUpdate(0, self.conn_recv_credit);
            self.conn_recv_credit = 0;
        }
        var it = self.streams.valueIterator();
        while (it.next()) |strm| {
            if (strm.recv_credit >= threshold) {
                try writer.sendWindowUpdate(strm.id, strm.recv_credit);
                strm.recv_credit = 0;
            }
        }
    }

    pub fn flushSendable(self: *Connection, writer: *writer_mod.Writer) writer_mod.WriteError!void {
        // Flush every stream, then evict the ones that fully closed in a SEPARATE
        // pass. Removing entries while the value iterator is live would be fragile
        // (it happens to work only because the hash map tombstones rather than
        // back-shifts on remove), so the eviction ids are collected first.
        self.evict_scratch.clearRetainingCapacity();
        var it = self.streams.iterator();
        while (it.next()) |e| {
            try self.flushStreamPtr(writer, e.value_ptr);
            const st = e.value_ptr;
            if (st.isFullyClosed()) {
                self.evict_scratch.append(self.gpa, e.key_ptr.*) catch return error.OutOfMemory;
            }
        }
        for (self.evict_scratch.items) |id| self.evictStream(id);
    }

    fn flushStream(self: *Connection, writer: *writer_mod.Writer, id: u32) writer_mod.WriteError!void {
        const s = self.streams.getPtr(id) orelse return;
        try self.flushStreamPtr(writer, s);
        self.maybeEvictDone(id);
    }

    fn flushStreamPtr(self: *Connection, writer: *writer_mod.Writer, s: *Stream) writer_mod.WriteError!void {
        const id = s.id;
        const max_frame = writer.peerMaxFrame();
        var off: usize = 0;
        while (off < s.send_pending.items.len) {
            const stream_room: i64 = s.send_window;
            const conn_room: i64 = self.conn_send_window;
            const room = @min(stream_room, conn_room);
            if (room <= 0) break; // window closed; the rest stays parked
            const remaining = s.send_pending.items.len - off;
            const chunk: usize = @intCast(@min(@min(room, @as(i64, max_frame)), @as(i64, @intCast(remaining))));
            const last = off + chunk == s.send_pending.items.len;
            const end = last and s.send_end_pending;
            try writer.writeDataFrame(id, s.send_pending.items[off .. off + chunk], end);
            s.send_window -= @intCast(chunk);
            self.conn_send_window -= @intCast(chunk);
            off += chunk;
            if (end) {
                s.send_end_pending = false;
                s.sendApply(true);
            }
        }
        // Drop the bytes we emitted; keep what the window could not admit.
        if (off > 0) {
            const rest = s.send_pending.items.len - off;
            std.mem.copyForwards(u8, s.send_pending.items[0..rest], s.send_pending.items[off..]);
            s.send_pending.shrinkRetainingCapacity(rest);
        }
        // A bodyless end (END_STREAM with no buffered bytes left) still needs an
        // empty DATA frame to close the stream.
        if (s.send_pending.items.len == 0 and s.send_end_pending) {
            try writer.writeDataFrame(id, &.{}, true);
            s.send_end_pending = false;
            s.sendApply(true);
        }
    }

    /// Whether any stream still has parked outbound bytes (or an owed END_STREAM)
    /// that the send window has not yet admitted. The adapter exposes this so the
    /// integrator knows a flush is pending once more credit arrives.
    pub fn hasPendingSend(self: *Connection) bool {
        var it = self.streams.valueIterator();
        while (it.next()) |s| {
            if (s.send_pending.items.len != 0 or s.send_end_pending) return true;
        }
        return false;
    }

    /// Insert a stream and move it idle->open. Maintains the live counter and the
    /// total-streams churn cap (CVE-2023-44487). Every counted insertion goes
    /// through here so live_streams and streams_opened stay exact.
    /// Insert a stream and move it idle->open. The single insertion point; the
    /// trusted send path and the peer-driven read path both route through it. The
    /// total-streams churn cap is enforced only on the peer path (openPeerStream),
    /// never here - the local app is not the adversary, so a client/server opening
    /// many streams to send is not abuse.
    fn openStream(self: *Connection, id: u32) H2Error!void {
        self.streams.put(self.gpa, id, Stream.init(id, self.local_settings.initial_window_size, self.peer_settings.initial_window_size)) catch return error.MessageTooLong;
        self.streams.getPtr(id).?.recvApply(.headers, false); // idle -> open
    }

    /// Open a PEER-initiated stream, enforcing the total-streams churn cap
    /// (CVE-2023-44487) that bounds how many streams one peer may ever open.
    fn openPeerStream(self: *Connection, id: u32) H2Error!void {
        if (self.limits.max_streams != 0 and self.streams_opened >= self.limits.max_streams) return error.EnhanceYourCalm;
        try self.openStream(id);
        self.streams_opened += 1;
    }

    /// Remove a stream from the map. Safe to call on a closed entry: the null path
    /// in handleData/handleWindowUpdate/handleRstStream classifies an evicted
    /// (id <= highest_peer_id) stream as closed, not idle.
    fn evictStream(self: *Connection, id: u32) void {
        if (self.streams.fetchRemove(id)) |kv| {
            var s = kv.value;
            s.deinit(self.gpa);
        }
    }

    /// Streams currently counting toward MAX_CONCURRENT_STREAMS (open or
    /// half-closed). Derived from the map rather than cached: the map is bounded by
    /// max_concurrent_streams plus a few in-flight, so the scan is cheap and there
    /// is no counter to drift out of sync.
    fn liveStreamCount(self: *Connection) u32 {
        var n: u32 = 0;
        var it = self.streams.valueIterator();
        while (it.next()) |s| {
            if (s.countsTowardConcurrency()) n += 1;
        }
        return n;
    }

    /// Evict a stream that has reached the fully-closed terminal state with no
    /// outbound send still owed. A half_closed_remote stream is NOT evicted here:
    /// it still counts toward MAX_CONCURRENT_STREAMS and must stay addressable for
    /// a late RST_STREAM/WINDOW_UPDATE until the local side finishes the response
    /// (RFC 9113 5.1). The connection-error/memory bound for streams that never
    /// finish comes from max_concurrent_streams and the churn caps, not eviction.
    fn maybeEvictDone(self: *Connection, id: u32) void {
        const s = self.streams.getPtr(id) orelse return;
        if (s.isFullyClosed()) self.evictStream(id);
    }

    /// Charge one stream reset against the churn budget (CVE-2023-44487).
    fn chargeReset(self: *Connection) H2Error!void {
        self.stream_resets += 1;
        if (self.limits.max_stream_resets != 0 and self.stream_resets > self.limits.max_stream_resets) return error.EnhanceYourCalm;
    }

    /// Open a stream as if a HEADERS had arrived - used by tests that exercise the
    /// DATA path without driving a full HEADERS block.
    pub fn openStreamForTest(self: *Connection, id: u32) !void {
        try self.openStream(id);
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

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Trailers (RFC 9113 8.1): no pseudo-header may appear, and every name must be
/// a valid lowercase field name. Connection-specific fields are likewise barred.
fn validTrailers(headers: []const events.Header) bool {
    for (headers) |h| {
        if (h.name.len == 0 or h.name[0] == ':') return false;
        if (!fields.isValidFieldName(h.name)) return false;
        if (!fields.validValue(h.value)) return false;
        if (fields.isConnectionSpecific(h.name)) return false;
    }
    return true;
}

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

// RFC 7541 C.3.1: an HPACK block for :method GET, :scheme http, :path /,
// :authority www.example.com.
const GET_BLOCK = [_]u8{ 0x82, 0x86, 0x84, 0x41, 0x0f } ++ "www.example.com".*;

test "HEADERS with END_STREAM yields a Request then EndOfMessage" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &GET_BLOCK);
    try handshook(&c, hdr.items);
    const req = try c.nextEvent();
    try testing.expectEqual(@as(u32, 1), req.request.stream_id);
    try testing.expectEqualStrings("GET", req.request.method);
    try testing.expectEqualStrings("/", req.request.target);
    try testing.expectEqualStrings("2", req.request.http_version);
    // :authority became a synthesized host header.
    try testing.expectEqualStrings("host", req.request.headers[req.request.headers.len - 1].name);
    try testing.expectEqualStrings("www.example.com", req.request.headers[req.request.headers.len - 1].value);
    const eom = try c.nextEvent();
    try testing.expectEqual(@as(u32, 1), eom.end_of_message.stream_id);
}

test "HEADERS split across a CONTINUATION reassembles to one Request" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    // First half of the block in HEADERS (no END_HEADERS), rest in CONTINUATION.
    try frameBytes(&frames, .headers, Flags.end_stream, 1, GET_BLOCK[0..3]);
    try frameBytes(&frames, .continuation, Flags.end_headers, 1, GET_BLOCK[3..]);
    try handshook(&c, frames.items);
    const req = try c.nextEvent();
    try testing.expectEqualStrings("GET", req.request.method);
    try testing.expectEqual(std.meta.Tag(Event).end_of_message, std.meta.activeTag(try c.nextEvent()));
}

test "an interleaved frame during an open field block is a connection error" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try frameBytes(&frames, .headers, 0, 1, GET_BLOCK[0..3]); // no END_HEADERS
    try frameBytes(&frames, .ping, 0, 0, &[_]u8{0} ** 8); // illegal: not a CONTINUATION
    try handshook(&c, frames.items);
    try testing.expectError(error.ProtocolError, c.nextEvent());
}

test "a CONTINUATION flood trips the cap" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    c.limits.max_continuation_frames = 4;
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try frameBytes(&frames, .headers, 0, 1, GET_BLOCK[0..1]);
    var k: usize = 0;
    while (k < 6) : (k += 1) try frameBytes(&frames, .continuation, 0, 1, &[_]u8{}); // never END_HEADERS
    try handshook(&c, frames.items);
    try testing.expectError(error.EnhanceYourCalm, c.nextEvent());
}

test "an uppercase header name makes the request malformed (stream reset)" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    // :method GET, :scheme http, :path /, then a literal "Bad: x" with an
    // uppercase name (literal-without-indexing, literal name).
    const block = [_]u8{ 0x82, 0x86, 0x84, 0x00, 0x03, 'B', 'a', 'd', 0x01, 'x' };
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &block);
    try handshook(&c, hdr.items);
    const ev = try c.nextEvent();
    try testing.expectEqual(@as(u32, 1), ev.rst_stream.stream_id);
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.protocol_error)), ev.rst_stream.error_code);
}

test "an even-numbered request stream id is a connection error" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 2, &GET_BLOCK);
    try handshook(&c, hdr.items);
    try testing.expectError(error.ProtocolError, c.nextEvent());
}

test "a field name with a space byte is malformed" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    // :method GET, :scheme http, :path /, then literal "ba d: x" (space in name).
    const block = [_]u8{ 0x82, 0x86, 0x84, 0x00, 0x04, 'b', 'a', ' ', 'd', 0x01, 'x' };
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &block);
    try handshook(&c, hdr.items);
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent()));
}

test "conflicting duplicate content-length is malformed" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    // :method GET, :scheme http, :path /, content-length: 1, content-length: 2.
    const block = [_]u8{ 0x82, 0x86, 0x84, 0x00, 0x0e } ++ "content-length".* ++ [_]u8{ 0x01, '1', 0x00, 0x0e } ++ "content-length".* ++ [_]u8{ 0x01, '2' };
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &block);
    try handshook(&c, hdr.items);
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent()));
}

test "a malformed request closes the stream so later DATA does not reopen it" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    const bad = [_]u8{ 0x82, 0x86, 0x84, 0x00, 0x03, 'B', 'a', 'd', 0x01, 'x' }; // uppercase name
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try frameBytes(&frames, .headers, Flags.end_headers, 1, &bad); // no END_STREAM
    try frameBytes(&frames, .data, Flags.end_stream, 1, "x"); // DATA on the reset stream
    try handshook(&c, frames.items);
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent()));
    // The stream is closed; DATA on it is a stream error, not a Data event.
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent()));
}

test "over the concurrency cap, a request is refused not surfaced" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    c.limits.max_concurrent_streams = 1;
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    // Stream 1 opens (no END_STREAM, so it stays open and counts). Stream 3 is
    // over the cap of 1 -> refused.
    try frameBytes(&frames, .headers, Flags.end_headers, 1, &GET_BLOCK);
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 3, &GET_BLOCK);
    try handshook(&c, frames.items);
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent())); // stream 1
    const refused = try c.nextEvent();
    try testing.expectEqual(@as(u32, 3), refused.rst_stream.stream_id);
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.refused_stream)), refused.rst_stream.error_code);
    // The refused stream left no record, so only stream 1 is tracked.
    try testing.expectEqual(@as(u32, 1), c.liveStreamCount());
}

// A client's inbound handshake is just the server's SETTINGS - no preface to
// consume - so it differs from the server `handshook` helper.
fn clientHandshook(c: *Connection, extra: []const u8) !void {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    try frameBytes(&input, .settings, 0, 0, &.{});
    try input.appendSlice(testing.allocator, extra);
    try c.feed(input.items);
    try testing.expectEqual(std.meta.Tag(Event).settings, std.meta.activeTag(try c.nextEvent()));
}

// HPACK static index 8 is exactly ":status: 200", so a one-byte indexed field
// (0x80 | 8) is a complete response head.
const STATUS_200_BLOCK = [_]u8{0x88};

test "client reads a HEADERS response with END_STREAM" {
    var c = Connection.init(testing.allocator, .client);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 1, &STATUS_200_BLOCK);
    try clientHandshook(&c, frames.items);
    const resp = try c.nextEvent();
    try testing.expectEqual(std.meta.Tag(Event).response, std.meta.activeTag(resp));
    try testing.expectEqual(@as(u16, 200), resp.response.status_code);
    try testing.expectEqual(@as(u32, 1), resp.response.stream_id);
    try testing.expectEqualStrings("2", resp.response.http_version);
    try testing.expectEqual(std.meta.Tag(Event).end_of_message, std.meta.activeTag(try c.nextEvent()));
}

test "client reads a response head then a DATA body" {
    var c = Connection.init(testing.allocator, .client);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try frameBytes(&frames, .headers, Flags.end_headers, 1, &STATUS_200_BLOCK); // open, no END_STREAM
    try frameBytes(&frames, .data, Flags.end_stream, 1, "hi");
    try clientHandshook(&c, frames.items);
    try testing.expectEqual(@as(u16, 200), (try c.nextEvent()).response.status_code);
    const d = try c.nextEvent();
    try testing.expectEqualStrings("hi", d.data.data);
    try testing.expectEqual(std.meta.Tag(Event).end_of_message, std.meta.activeTag(try c.nextEvent()));
}

test "client reads a 1xx interim response then the final response" {
    var c = Connection.init(testing.allocator, .client);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    // A literal ":status: 100" (no static-table code for interim responses):
    // literal-name(len 7) ":status", value(len 3) "100".
    const interim = [_]u8{ 0x00, 0x07 } ++ ":status".* ++ [_]u8{0x03} ++ "100".*;
    try frameBytes(&frames, .headers, Flags.end_headers, 1, &interim);
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 1, &STATUS_200_BLOCK);
    try clientHandshook(&c, frames.items);
    try testing.expectEqual(@as(u16, 100), (try c.nextEvent()).response.status_code);
    try testing.expectEqual(@as(u16, 200), (try c.nextEvent()).response.status_code);
    try testing.expectEqual(std.meta.Tag(Event).end_of_message, std.meta.activeTag(try c.nextEvent()));
}

test "a request pseudo-header in a response resets the stream" {
    var c = Connection.init(testing.allocator, .client);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    // :method GET (static index 2 = 0x82) is illegal in a response.
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 1, &[_]u8{0x82});
    try clientHandshook(&c, frames.items);
    const ev = try c.nextEvent();
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(ev));
}

test "a response for a client-reset stream is ignored, not surfaced or re-opened" {
    var c = Connection.init(testing.allocator, .client);
    defer c.deinit();
    try c.registerSendStream(1);
    c.localReset(1);
    try testing.expectEqual(@as(usize, 0), c.streams.count());
    // An in-flight response for the reset stream must surface no response/data.
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try frameBytes(&frames, .headers, Flags.end_headers, 1, &STATUS_200_BLOCK);
    try frameBytes(&frames, .data, Flags.end_stream, 1, "hi");
    try clientHandshook(&c, frames.items);
    while (true) {
        const ev = try c.nextEvent();
        if (ev == .need_data) break;
        try testing.expect(ev != .response and ev != .data);
    }
    try testing.expectEqual(@as(usize, 0), c.streams.count()); // not re-opened
}

test "an even response stream id is a connection error for a client" {
    var c = Connection.init(testing.allocator, .client);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 2, &STATUS_200_BLOCK);
    try clientHandshook(&c, frames.items);
    try testing.expectError(error.ProtocolError, c.nextEvent());
}

test "an out-of-range :status resets the stream" {
    var c = Connection.init(testing.allocator, .client);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    // A literal ":status: 700" - a code outside the 100-599 range.
    const bad = [_]u8{ 0x00, 0x07 } ++ ":status".* ++ [_]u8{0x03} ++ "700".*;
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 1, &bad);
    try clientHandshook(&c, frames.items);
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent()));
}

test "a 1xx response with END_STREAM resets the stream" {
    var c = Connection.init(testing.allocator, .client);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    // A literal ":status: 100" that illegally ends the stream.
    const interim = [_]u8{ 0x00, 0x07 } ++ ":status".* ++ [_]u8{0x03} ++ "100".*;
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 1, &interim);
    try clientHandshook(&c, frames.items);
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent()));
}

test "HEADERS after END_STREAM (not a trailer) is a connection error" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 1, &GET_BLOCK); // ends the stream
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 1, &GET_BLOCK); // illegal second HEADERS
    try handshook(&c, frames.items);
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(std.meta.Tag(Event).end_of_message, std.meta.activeTag(try c.nextEvent()));
    try testing.expectError(error.ProtocolError, c.nextEvent());
}

test "valid trailers flow into EndOfMessage.trailers" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try frameBytes(&frames, .headers, Flags.end_headers, 1, &GET_BLOCK); // open, no END_STREAM
    try frameBytes(&frames, .data, 0, 1, "body");
    // Trailer block: a single literal "x-checksum: abc" (literal name+value).
    const trailer = [_]u8{ 0x00, 0x0a } ++ "x-checksum".* ++ [_]u8{0x03} ++ "abc".*;
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 1, &trailer);
    try handshook(&c, frames.items);
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(std.meta.Tag(Event).data, std.meta.activeTag(try c.nextEvent()));
    const eom = try c.nextEvent();
    try testing.expectEqual(@as(usize, 1), eom.end_of_message.trailers.len);
    try testing.expectEqualStrings("x-checksum", eom.end_of_message.trailers[0].name);
}

test "a pseudo-header in trailers is rejected" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try frameBytes(&frames, .headers, Flags.end_headers, 1, &GET_BLOCK);
    try frameBytes(&frames, .data, 0, 1, "body");
    // Trailer with an illegal pseudo-header ":x: y".
    const trailer = [_]u8{ 0x00, 0x02 } ++ ":x".* ++ [_]u8{0x01} ++ "y".*;
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 1, &trailer);
    try handshook(&c, frames.items);
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(std.meta.Tag(Event).data, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent()));
}

test "a CR in a regular header value resets the stream" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    // :method GET, :scheme http, :path /, then literal "x-evil: a\rb".
    const block = [_]u8{ 0x82, 0x86, 0x84, 0x00, 0x06 } ++ "x-evil".* ++ [_]u8{ 0x03, 'a', 0x0D, 'b' };
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &block);
    try handshook(&c, hdr.items);
    const ev = try c.nextEvent();
    try testing.expectEqual(@as(u32, 1), ev.rst_stream.stream_id);
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.protocol_error)), ev.rst_stream.error_code);
}

test "an LF in a regular header value resets the stream" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    const block = [_]u8{ 0x82, 0x86, 0x84, 0x00, 0x06 } ++ "x-evil".* ++ [_]u8{ 0x03, 'a', 0x0A, 'b' };
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &block);
    try handshook(&c, hdr.items);
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent()));
}

test "a NUL in a regular header value resets the stream" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    const block = [_]u8{ 0x82, 0x86, 0x84, 0x00, 0x06 } ++ "x-evil".* ++ [_]u8{ 0x03, 'a', 0x00, 'b' };
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &block);
    try handshook(&c, hdr.items);
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent()));
}

test "a CRLF in :path resets the stream" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    // :method GET, :scheme http, then a literal :path value "/\r\n".
    const block = [_]u8{ 0x82, 0x86, 0x00, 0x05 } ++ ":path".* ++ [_]u8{ 0x03, '/', 0x0D, 0x0A };
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &block);
    try handshook(&c, hdr.items);
    const ev = try c.nextEvent();
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(ev));
}

test "a CRLF in :authority resets the stream" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    // :method GET, :scheme http, :path /, then a literal :authority "evil\r\n".
    const block = [_]u8{ 0x82, 0x86, 0x84, 0x00, 0x0a } ++ ":authority".* ++ [_]u8{ 0x06, 'e', 'v', 'i', 'l', 0x0D, 0x0A };
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &block);
    try handshook(&c, hdr.items);
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent()));
}

test "a control byte in a trailer value resets the stream" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try frameBytes(&frames, .headers, Flags.end_headers, 1, &GET_BLOCK); // open, no END_STREAM
    try frameBytes(&frames, .data, 0, 1, "body");
    // Trailer "x-checksum: a\x00b" - a NUL in the value.
    const trailer = [_]u8{ 0x00, 0x0a } ++ "x-checksum".* ++ [_]u8{ 0x03, 'a', 0x00, 'b' };
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 1, &trailer);
    try handshook(&c, frames.items);
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(std.meta.Tag(Event).data, std.meta.activeTag(try c.nextEvent()));
    const ev = try c.nextEvent();
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(ev));
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.protocol_error)), ev.rst_stream.error_code);
}

test "an empty :path is malformed and resets the stream" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    // :method GET, :scheme http, then a literal :path with an empty value.
    const block = [_]u8{ 0x82, 0x86, 0x00, 0x05 } ++ ":path".* ++ [_]u8{0x00};
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &block);
    try handshook(&c, hdr.items);
    const ev = try c.nextEvent();
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(ev));
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.protocol_error)), ev.rst_stream.error_code);
}

test "an obs-text value (0x80-0xFF) is accepted" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    // A full GET request plus a literal "x-obs: \x80\xFF" (obs-text, legal).
    const block = GET_BLOCK ++ [_]u8{ 0x00, 0x05 } ++ "x-obs".* ++ [_]u8{ 0x02, 0x80, 0xFF };
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &block);
    try handshook(&c, hdr.items);
    const req = try c.nextEvent();
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(req));
    try testing.expectEqualStrings("x-obs", req.request.headers[0].name);
    try testing.expectEqualStrings(&[_]u8{ 0x80, 0xFF }, req.request.headers[0].value);
}

test "a trailing-whitespace value resets the stream (RFC 9113 8.2.1)" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    // :method GET, :scheme http, :path /, then literal "x-test: val " (trailing SP).
    const block = [_]u8{ 0x82, 0x86, 0x84, 0x00, 0x06 } ++ "x-test".* ++ [_]u8{ 0x04, 'v', 'a', 'l', ' ' };
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &block);
    try handshook(&c, hdr.items);
    const ev = try c.nextEvent();
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(ev));
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.protocol_error)), ev.rst_stream.error_code);
}

test "a leading-whitespace value resets the stream (RFC 9113 8.2.1)" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    // literal "x-test: \tval" (leading HTAB).
    const block = [_]u8{ 0x82, 0x86, 0x84, 0x00, 0x06 } ++ "x-test".* ++ [_]u8{ 0x04, 0x09, 'v', 'a', 'l' };
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &block);
    try handshook(&c, hdr.items);
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent()));
}

test "an inner-whitespace value is accepted (only edge OWS is rejected)" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    // literal "x-test: a b" - an inner SP is legal (e.g. media-type parameters).
    const block = GET_BLOCK ++ [_]u8{ 0x00, 0x06 } ++ "x-test".* ++ [_]u8{ 0x03, 'a', ' ', 'b' };
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &block);
    try handshook(&c, hdr.items);
    const req = try c.nextEvent();
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(req));
    try testing.expectEqualStrings("a b", req.request.headers[0].value);
}

test "rapid open+RST churn keeps the stream map and live counter bounded" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    // Open-then-RST 100 streams on increasing odd ids. Each pair must leave zero
    // residue: no map entry, no live count.
    var id: u32 = 1;
    var k: usize = 0;
    while (k < 100) : (k += 1) {
        try frameBytes(&frames, .headers, Flags.end_headers, id, &GET_BLOCK); // open, no END_STREAM
        try frameBytes(&frames, .rst_stream, 0, id, &[_]u8{ 0x00, 0x00, 0x00, 0x08 }); // CANCEL
        id += 2;
    }
    try handshook(&c, frames.items);
    var seen: usize = 0;
    while (true) {
        const ev = try c.nextEvent();
        if (ev == .need_data) break;
        seen += 1;
    }
    try testing.expect(seen >= 100); // at least the 100 rst_stream echoes surfaced
    try testing.expectEqual(@as(usize, 0), c.streams.count());
    try testing.expectEqual(@as(u32, 0), c.liveStreamCount());
}

test "a late WINDOW_UPDATE or RST on an evicted closed stream is tolerated" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    // Open stream 1, RST it (evicts), then send a stray WINDOW_UPDATE and a stray
    // RST on the now-evicted id 1 (<= highest_peer_id, so closed not idle).
    try frameBytes(&frames, .headers, Flags.end_headers, 1, &GET_BLOCK);
    try frameBytes(&frames, .rst_stream, 0, 1, &[_]u8{ 0x00, 0x00, 0x00, 0x08 });
    try frameBytes(&frames, .window_update, 0, 1, &[_]u8{ 0x00, 0x00, 0x00, 0x10 });
    try frameBytes(&frames, .rst_stream, 0, 1, &[_]u8{ 0x00, 0x00, 0x00, 0x08 });
    try handshook(&c, frames.items);
    // The opening HEADERS surfaces the request; then the RST echo; then the strays
    // after eviction are dropped.
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(Event.need_data, try c.nextEvent());
    try testing.expectEqual(@as(u32, 0), c.liveStreamCount());
}

test "DATA on an evicted closed stream is a stream error STREAM_CLOSED" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try frameBytes(&frames, .headers, Flags.end_headers, 1, &GET_BLOCK); // open
    try frameBytes(&frames, .rst_stream, 0, 1, &[_]u8{ 0x00, 0x00, 0x00, 0x08 }); // evicts
    try frameBytes(&frames, .data, Flags.end_stream, 1, "x"); // DATA on the evicted id
    try handshook(&c, frames.items);
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent())); // the opening request
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent())); // the RST echo
    const stale = try c.nextEvent();
    try testing.expectEqual(@as(u32, 1), stale.rst_stream.stream_id);
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.stream_closed)), stale.rst_stream.error_code);
}

test "the live-stream count matches reality across read-completion and reset" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    // Stream 1: a complete request (END_STREAM) lingers in half_closed_remote and
    // still counts until the app responds.
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 1, &GET_BLOCK);
    // Stream 3: open, no END_STREAM -> still receiving -> counts.
    try frameBytes(&frames, .headers, Flags.end_headers, 3, &GET_BLOCK);
    try handshook(&c, frames.items);
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent())); // 1 request
    try testing.expectEqual(std.meta.Tag(Event).end_of_message, std.meta.activeTag(try c.nextEvent())); // 1 eom
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent())); // 3 request
    try testing.expectEqual(Event.need_data, try c.nextEvent());
    // Both count: stream 1 (half_closed_remote, awaiting response) and stream 3 (open).
    try testing.expectEqual(@as(u32, 2), c.liveStreamCount());
    try testing.expectEqual(@as(usize, 2), c.streams.count());
    // Now RST stream 3: it is evicted; stream 1 still lingers awaiting its response.
    var more: std.ArrayList(u8) = .empty;
    defer more.deinit(testing.allocator);
    try frameBytes(&more, .rst_stream, 0, 3, &[_]u8{ 0x00, 0x00, 0x00, 0x08 });
    try c.feed(more.items);
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(@as(u32, 1), c.liveStreamCount());
    try testing.expectEqual(@as(usize, 1), c.streams.count());
}

test "a reset-churn flood trips EnhanceYourCalm" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    c.limits.max_stream_resets = 3;
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    // Four open+RST cycles; the 4th reset exceeds the budget of 3.
    var id: u32 = 1;
    var k: usize = 0;
    while (k < 4) : (k += 1) {
        try frameBytes(&frames, .headers, Flags.end_headers, id, &GET_BLOCK);
        try frameBytes(&frames, .rst_stream, 0, id, &[_]u8{ 0x00, 0x00, 0x00, 0x08 });
        id += 2;
    }
    try handshook(&c, frames.items);
    var tripped = false;
    for (0..64) |_| {
        const ev = c.nextEvent() catch |e| {
            try testing.expectEqual(error.EnhanceYourCalm, e);
            tripped = true;
            break;
        };
        if (ev == .need_data) break;
    }
    try testing.expect(tripped);
}

test "opening more than max_streams trips EnhanceYourCalm" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    c.limits.max_streams = 2;
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    // Three opens (no END_STREAM); the 3rd open exceeds the cap of 2.
    try frameBytes(&frames, .headers, Flags.end_headers, 1, &GET_BLOCK);
    try frameBytes(&frames, .headers, Flags.end_headers, 3, &GET_BLOCK);
    try frameBytes(&frames, .headers, Flags.end_headers, 5, &GET_BLOCK);
    try handshook(&c, frames.items);
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent())); // stream 1
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent())); // stream 3
    try testing.expectError(error.EnhanceYourCalm, c.nextEvent()); // stream 5 over the cap
}

test "half-closed-remote requests count toward concurrency until the response finishes" {
    // A completed request the app has not yet responded to lingers in
    // half_closed_remote and counts toward MAX_CONCURRENT_STREAMS (RFC 9113 5.1.2),
    // so a flood of bodyless requests is refused past the cap rather than all
    // surfaced. (This is the inverse of the earlier eager-eviction bug.)
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    c.limits.max_concurrent_streams = 4;
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    try input.appendSlice(testing.allocator, constants.CLIENT_PREFACE);
    try frameBytes(&input, .settings, 0, 0, &.{});
    var id: u32 = 1;
    var k: usize = 0;
    while (k < 10) : (k += 1) {
        try frameBytes(&input, .headers, Flags.end_headers | Flags.end_stream, id, &GET_BLOCK);
        id += 2;
    }
    try c.feed(input.items);
    try testing.expectEqual(std.meta.Tag(Event).settings, std.meta.activeTag(try c.nextEvent()));
    var requests: usize = 0;
    var refusals: usize = 0;
    while (true) {
        const ev = try c.nextEvent();
        switch (ev) {
            .need_data => break,
            .request => requests += 1,
            .rst_stream => refusals += 1,
            else => {},
        }
    }
    // The first 4 are surfaced; the rest are refused (REFUSED_STREAM) because the
    // half-closed-remote streams still occupy concurrency slots.
    try testing.expectEqual(@as(usize, 4), requests);
    try testing.expectEqual(@as(usize, 6), refusals);
    try testing.expectEqual(@as(u32, 4), c.liveStreamCount());
}

test "a request+response cycle returns the live-stream count to zero" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var w = writer_mod.Writer.init(testing.allocator, .server);
    defer w.deinit();
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    // A complete request (END_STREAM): the recv side ends, but the stream lingers
    // in half_closed_remote and still counts toward concurrency until the local
    // side finishes the response (RFC 9113 5.1).
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &GET_BLOCK);
    try handshook(&c, hdr.items);
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(std.meta.Tag(Event).end_of_message, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(Event.need_data, try c.nextEvent());
    try testing.expectEqual(@as(u32, 1), c.liveStreamCount()); // still awaiting the response
    // The app responds: register the send, then a body with END_STREAM. Once the
    // response drains the stream reaches .closed and is evicted - back to zero.
    try w.sendResponse(1, 200, &.{}, false);
    try c.sendStreamData(&w, 1, "hi", true);
    try testing.expectEqual(@as(u32, 0), c.liveStreamCount());
    try testing.expectEqual(@as(usize, 0), c.streams.count());
}

test "many request+response cycles do not leak the concurrency budget" {
    // Regression: a re-created response stream must drain to eviction, or every
    // cycle leaks one live_streams and the connection refuses requests past 128.
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var w = writer_mod.Writer.init(testing.allocator, .server);
    defer w.deinit();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    try input.appendSlice(testing.allocator, constants.CLIENT_PREFACE);
    try frameBytes(&input, .settings, 0, 0, &.{});
    try c.feed(input.items);
    try testing.expectEqual(std.meta.Tag(Event).settings, std.meta.activeTag(try c.nextEvent()));
    var id: u32 = 1;
    var k: usize = 0;
    while (k < 300) : (k += 1) {
        var hdr: std.ArrayList(u8) = .empty;
        defer hdr.deinit(testing.allocator);
        try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, id, &GET_BLOCK);
        try c.feed(hdr.items);
        try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent()));
        try testing.expectEqual(std.meta.Tag(Event).end_of_message, std.meta.activeTag(try c.nextEvent()));
        try testing.expectEqual(Event.need_data, try c.nextEvent());
        try w.sendResponse(id, 200, &.{}, false);
        try c.sendStreamData(&w, id, "ok", true);
        try testing.expectEqual(@as(u32, 0), c.liveStreamCount()); // never accumulates
        id += 2;
    }
    try testing.expectEqual(@as(usize, 0), c.streams.count());
}

test "late DATA after a response is registered is a stream error STREAM_CLOSED" {
    // The re-created response stream is half_closed_remote, so a peer sending DATA
    // after its own END_STREAM is rejected, not silently reopened (smuggling guard).
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var w = writer_mod.Writer.init(testing.allocator, .server);
    defer w.deinit();
    var hdr: std.ArrayList(u8) = .empty;
    defer hdr.deinit(testing.allocator);
    try frameBytes(&hdr, .headers, Flags.end_headers | Flags.end_stream, 1, &GET_BLOCK);
    try handshook(&c, hdr.items);
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(std.meta.Tag(Event).end_of_message, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(Event.need_data, try c.nextEvent());
    try w.sendResponse(1, 200, &.{}, false); // register the response (re-creates stream 1 half_closed_remote)
    try c.registerSendStream(1);
    // The peer sends DATA on stream 1 after it already ended: STREAM_CLOSED.
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(testing.allocator);
    try frameBytes(&data, .data, 0, 1, "evil");
    try c.feed(data.items);
    const ev = try c.nextEvent();
    try testing.expectEqual(std.meta.Tag(Event).rst_stream, std.meta.activeTag(ev));
    try testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.stream_closed)), ev.rst_stream.error_code);
}

test "a WINDOW_UPDATE on a half-closed-remote stream awaiting its response is honored" {
    // The P1 case: a completed request awaiting a response stays addressable - a
    // WINDOW_UPDATE for it must be applied, not dropped as a forgotten stream.
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try frameBytes(&frames, .headers, Flags.end_headers | Flags.end_stream, 1, &GET_BLOCK);
    try frameBytes(&frames, .window_update, 0, 1, &[_]u8{ 0x00, 0x00, 0x00, 0x10 });
    try handshook(&c, frames.items);
    try testing.expectEqual(std.meta.Tag(Event).request, std.meta.activeTag(try c.nextEvent()));
    try testing.expectEqual(std.meta.Tag(Event).end_of_message, std.meta.activeTag(try c.nextEvent()));
    // The stream is still present, so the WINDOW_UPDATE is surfaced (not dropped).
    const wu = try c.nextEvent();
    try testing.expectEqual(@as(u32, 1), wu.window_update.stream_id);
    try testing.expectEqual(@as(u32, 0x10), wu.window_update.increment);
}

test "fuzz: H2 connection never panics on adversarial frame streams" {
    const seeds = [_][]const u8{
        &[_]u8{ 0x00, 0x00, 0x03, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, 0x82, 0x86, 0x84 }, // HEADERS GET
        &[_]u8{ 0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08 }, // RST_STREAM
        &([_]u8{ 0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 } ++ [_]u8{0} ** 8), // PING
        &[_]u8{ 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 'h', 'e', 'l', 'l', 'o' }, // DATA END_STREAM
        &[_]u8{ 0xff, 0xff, 0xff, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01 }, // over-long HEADERS length
        &[_]u8{ 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7f, 0xff, 0xff, 0xff }, // WINDOW_UPDATE
    };
    var rng = std.Random.DefaultPrng.init(0xC0FFEE);
    const r = rng.random();
    var k: usize = 0;
    while (k < 2000) : (k += 1) {
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(testing.allocator);
        try input.appendSlice(testing.allocator, constants.CLIENT_PREFACE);
        try frameBytes(&input, .settings, 0, 0, &.{});
        const n = r.intRangeAtMost(usize, 1, 6);
        var j: usize = 0;
        while (j < n) : (j += 1) {
            const seed = try testing.allocator.dupe(u8, seeds[r.intRangeLessThan(usize, 0, seeds.len)]);
            defer testing.allocator.free(seed);
            if (seed.len != 0 and r.boolean()) seed[r.intRangeLessThan(usize, 0, seed.len)] = r.int(u8);
            try input.appendSlice(testing.allocator, seed);
        }
        var c = Connection.init(testing.allocator, .server);
        defer c.deinit();
        c.limits.max_buffer = 1 << 20;
        c.feed(input.items) catch continue;
        var iter: usize = 0;
        while (iter < input.items.len + 16) : (iter += 1) {
            const ev = c.nextEvent() catch break;
            if (ev == .need_data) break;
        }
    }
}

test "consumed DATA refills the receive window and accrues credit to advertise" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var w = writer_mod.Writer.init(testing.allocator, .server);
    defer w.deinit();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    try input.appendSlice(testing.allocator, constants.CLIENT_PREFACE);
    try frameBytes(&input, .settings, 0, 0, &.{});
    try frameBytes(&input, .headers, Flags.end_headers, 1, &GET_BLOCK); // open, no END_STREAM
    // Three DATA frames totaling 48000 bytes, past the half-window threshold.
    const chunk = [_]u8{'x'} ** 16000;
    var k: usize = 0;
    while (k < 3) : (k += 1) try frameBytes(&input, .data, 0, 1, &chunk);
    try c.feed(input.items);
    while (true) {
        const ev = try c.nextEvent();
        if (ev == .need_data) break;
    }
    // The window was refilled on consume, so it never dropped below the start.
    try testing.expectEqual(constants.DEFAULT_WINDOW_SIZE, c.conn_recv_window);
    try testing.expectEqual(@as(u32, 48000), c.conn_recv_credit);
    try testing.expectEqual(@as(u32, 48000), c.streams.getPtr(1).?.recv_credit);
    // Flushing emits WINDOW_UPDATEs and clears the accumulators.
    try c.flushRecvWindows(&w);
    try testing.expectEqual(@as(u32, 0), c.conn_recv_credit);
    try testing.expectEqual(@as(u32, 0), c.streams.getPtr(1).?.recv_credit);
}

test "a small body stays under the window-update threshold" {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    var w = writer_mod.Writer.init(testing.allocator, .server);
    defer w.deinit();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    try input.appendSlice(testing.allocator, constants.CLIENT_PREFACE);
    try frameBytes(&input, .settings, 0, 0, &.{});
    try frameBytes(&input, .headers, Flags.end_headers, 1, &GET_BLOCK);
    try frameBytes(&input, .data, Flags.end_stream, 1, "hello");
    try c.feed(input.items);
    while (true) {
        const ev = try c.nextEvent();
        if (ev == .need_data) break;
    }
    const before = w.pending().len;
    try c.flushRecvWindows(&w); // below threshold -> nothing emitted
    try testing.expectEqual(before, w.pending().len);
}

fn driveConnection(input: []const u8) void {
    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    c.limits.max_buffer = 1 << 20;
    c.feed(input) catch return;
    for (0..input.len + 8) |_| {
        const ev = c.nextEvent() catch break;
        if (ev == .need_data) break;
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
