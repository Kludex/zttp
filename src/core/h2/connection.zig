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
const events = @import("../events.zig");
const tables = @import("../tables.zig");

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

    /// The single open field block (RFC 9113 4.3): once HEADERS without
    /// END_HEADERS opens it, the very next frame must be CONTINUATION on this
    /// stream. Only one block may be open across the whole connection, so this is
    /// connection-level state, not per-stream. null = no block open.
    fb_stream: ?u32 = null,
    fb_end_stream: bool = false, // END_STREAM carried by the opening HEADERS
    fb_is_trailer: bool = false, // a second HEADERS block on an open stream
    fb_refused: bool = false, // over the concurrency cap: decode for HPACK sync, then discard
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
        self.streams.deinit(self.gpa);
        self.hpack.deinit();
        self.settings_scratch.deinit(self.gpa);
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
        const s = self.streams.getPtr(f.header.stream_id) orelse {
            // RST on a never-opened (idle) stream is a connection error; on a
            // closed/forgotten stream it is tolerated and dropped.
            if (self.isIdle(f.header.stream_id)) return error.ProtocolError;
            return;
        };
        s.recvApply(.rst_stream, false);
        self.push(.{ .rst_stream = .{ .stream_id = f.header.stream_id, .error_code = code } });
    }

    // -- HEADERS / CONTINUATION reassembly -----------------------------------

    fn handleHeaders(self: *Connection, f: frame_mod.Frame) H2Error!void {
        if (f.header.stream_id == 0) return error.ProtocolError;
        if (self.role != .server) return error.ProtocolError; // client HEADERS read = response; later
        const id = f.header.stream_id;
        const fragment = frame_mod.headersFieldBlock(f.payload, f.header.flags) catch |e| switch (e) {
            error.FrameSizeError => return error.FrameSizeError,
            error.ProtocolError => return error.ProtocolError,
            else => return error.ProtocolError,
        };

        const existing = self.streams.getPtr(id);
        var is_trailer = false;
        var refused = false;
        if (existing) |s| {
            // A second HEADERS block is a trailer ONLY while the stream is still
            // open (body not yet ended). A HEADERS after the peer's END_STREAM
            // (half-closed-remote) or on a closed stream is a protocol error.
            if (s.headers_done and s.state == .open) {
                is_trailer = true;
            } else {
                return error.ProtocolError;
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
                self.streams.put(self.gpa, id, Stream.init(id, self.local_settings.initial_window_size, self.peer_settings.initial_window_size)) catch return error.MessageTooLong;
                self.streams.getPtr(id).?.recvApply(.headers, false); // idle -> open
            }
            self.highest_peer_id = id;
        }

        self.fb_stream = id;
        self.fb_end_stream = Flags.has(f.header.flags, Flags.end_stream);
        self.fb_is_trailer = is_trailer;
        self.fb_refused = refused;
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
        self.fb_stream = null; // block closed

        // Always decode (even when refused/malformed) to keep the dynamic table
        // in sync; a decode failure is connection-fatal COMPRESSION_ERROR.
        const headers = self.hpack.decodeBlock(self.fb_buf.items) catch |e| switch (e) {
            error.CompressionError => return error.CompressionError,
            error.MessageTooLong => return error.MessageTooLong,
            error.OutOfMemory => return error.MessageTooLong,
        };

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
                self.resetStream(s, id, .protocol_error);
                return;
            }
            s.recvApply(.headers, true);
            self.push(.{ .end_of_message = .{ .trailers = headers, .stream_id = id } });
            return;
        }

        // Collapse pseudo-headers into the request line + regular headers.
        const req = self.collapseRequest(headers, id) catch |e| switch (e) {
            error.Malformed => {
                self.resetStream(s, id, .protocol_error);
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

    /// Reset a stream for a stream error: emit RST_STREAM and move its state to
    /// closed so later frames on it are no longer treated as open.
    fn resetStream(self: *Connection, s: *Stream, id: u32, code: ErrorCode) void {
        s.recvApply(.rst_stream, false); // -> closed
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
            if (!isValidFieldName(h.name)) return error.Malformed; // uppercase / non-token byte
            if (isConnectionSpecific(h.name)) return error.Malformed;
            if (eql(h.name, "te") and !eql(h.value, "trailers")) return error.Malformed;
            if (eql(h.name, "content-length")) {
                const cl = parseU64(h.value) orelse return error.Malformed;
                // A repeated content-length is malformed unless it agrees (RFC 9110).
                if (content_length) |prev| {
                    if (prev != cl) return error.Malformed;
                } else content_length = cl;
            }
            self.req_headers.append(self.gpa, h) catch return error.OutOfMemory;
        }

        if (method == null or path == null or scheme == null) return error.Malformed;
        const target = path.?;
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

    fn liveStreamCount(self: *Connection) u32 {
        var n: u32 = 0;
        var it = self.streams.valueIterator();
        while (it.next()) |s| {
            if (s.countsTowardConcurrency()) n += 1;
        }
        return n;
    }

    /// Open a stream as if a HEADERS had arrived - used by tests that exercise the
    /// DATA path without driving a full HEADERS block.
    pub fn openStreamForTest(self: *Connection, id: u32) !void {
        try self.streams.put(self.gpa, id, Stream.init(id, self.local_settings.initial_window_size, self.peer_settings.initial_window_size));
        self.streams.getPtr(id).?.recvApply(.headers, false);
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

/// A valid HTTP/2 field name: a non-empty RFC 9110 token (so no SP, NUL, ':',
/// or other separators) with no uppercase ASCII (RFC 9113 8.2.1). `:` is
/// excluded here, so this is only applied to regular (non-pseudo) names.
fn isValidFieldName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |ch| {
        if (ch >= 'A' and ch <= 'Z') return false;
        if (!tables.is_tchar[ch]) return false;
    }
    return true;
}

/// Trailers (RFC 9113 8.1): no pseudo-header may appear, and every name must be
/// a valid lowercase field name. Connection-specific fields are likewise barred.
fn validTrailers(headers: []const events.Header) bool {
    for (headers) |h| {
        if (h.name.len == 0 or h.name[0] == ':') return false;
        if (!isValidFieldName(h.name)) return false;
        if (isConnectionSpecific(h.name)) return false;
    }
    return true;
}

/// The connection-specific fields forbidden in HTTP/2 (RFC 9113 8.2.2).
fn isConnectionSpecific(name: []const u8) bool {
    const forbidden = [_][]const u8{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" };
    for (forbidden) |f| {
        if (eql(name, f)) return true;
    }
    return false;
}

fn parseU64(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    var v: u64 = 0;
    for (s) |ch| {
        if (ch < '0' or ch > '9') return null;
        v = std.math.mul(u64, v, 10) catch return null;
        v = std.math.add(u64, v, ch - '0') catch return null;
    }
    return v;
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
