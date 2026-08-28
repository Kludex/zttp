//! The HTTP/3 connection orchestrator (RFC 9114): sits on top of the QUIC
//! transport and turns the ordered bytes of each request stream into the shared
//! Request / Data / EndOfMessage events. It classifies streams (the control stream
//! carries SETTINGS; bidirectional streams carry requests), parses HTTP/3 frames,
//! QPACK-decodes a HEADERS block into a Request - collapsing the pseudo-headers
//! (:method -> method, :path -> target, :authority -> a synthesized host) exactly
//! as the HTTP/2 layer does - and drains events through a flat, arrival-ordered
//! queue, one per `nextEvent`, so HTTP/3 reaches the same pull API as H1 and H2.
//!
//! It is driven by the QUIC connection: `pump` reads whatever ordered bytes the
//! transport has for each known request stream and advances the per-stream parse.

const std = @import("std");
const ascii = @import("../ascii.zig");
const events = @import("../events.zig");
const fields = @import("../fields.zig");
const quic_conn = @import("../quic/connection.zig");
const quic_frame = @import("../quic/frame.zig");
const quic_stream = @import("../quic/stream.zig");
const varint = @import("../quic/varint.zig");
const h3_frame = @import("frame.zig");
const h3_stream = @import("stream.zig");
const h3_error = @import("error.zig");
const qpack = @import("qpack/decoder.zig");
const qpack_enc = @import("qpack/encoder.zig");

const Header = events.Header;
const H3Event = events.H3Event;

pub const Error = error{
    /// A connection-fatal HTTP/3 error (RFC 9114 7): the connection is closed.
    H3Error,
    /// Internal signal: a QPACK field section is waiting for more encoder-stream
    /// inserts and has been stored on the stream for later retry.
    Blocked,
    /// The integrator must drain queued events before pumping more transport data.
    EventQueueFull,
    OutOfMemory,
};

/// Resource limits for one HTTP/3 connection.
pub const Limits = struct {
    /// Require the integrator to drain before the next pump batch once this many events are waiting.
    max_pending_events: usize = 1024,
};

const MsgState = enum { idle, headers_done, trailers_done, done, rejected };
const BlockedSection = enum { initial, trailers };

fn StreamOutcome(comptime T: type) type {
    return union(enum) {
        value: T,
        rejected: h3_error.ErrorCode,
    };
}

const RequestStream = struct {
    state: MsgState = .idle,
    /// The declared message body length (RFC 9114 4.1.2), or null if no
    /// Content-Length was sent. Reconciled against the DATA bytes at the FIN.
    content_length: ?u64 = null,
    body_received: u64 = 0,
    /// DATA payload bytes parsed but not yet acknowledged by the application.
    body_unconsumed: u64 = 0,
    /// Responses to HEAD, 204, and 304 carry no body regardless of Content-Length.
    expects_bodyless: bool = false,
    /// Client-side only: responses to a locally-sent HEAD request carry no body
    /// regardless of status or Content-Length.
    head_response: bool = false,
    /// Whether a peer-reset event has already been emitted for this stream, so a
    /// re-pump (if the stream could not yet be dropped) does not re-fire it.
    rst_emitted: bool = false,
    /// Whether the current field section referenced the QPACK dynamic table and has
    /// not yet been acknowledged or cancelled on our decoder stream.
    qpack_section_pending: bool = false,
    /// Complete QPACK field block for a HEADERS frame whose Required Insert Count is
    /// ahead of the encoder stream. Owned by this stream state until resumed/dropped.
    blocked_headers: ?[]u8 = null,
    blocked_section: BlockedSection = .initial,
    trailers: ?[]Header = null,
    /// The initial HEADERS frame was also the final bytes on this request
    /// stream, so the Request event already represented message completion.
    head_ended_stream: bool = false,

    fn deinit(self: *RequestStream, gpa: std.mem.Allocator) void {
        if (self.blocked_headers) |b| gpa.free(b);
        self.blocked_headers = null;
        self.clearTrailers(gpa);
    }

    fn clearTrailers(self: *RequestStream, gpa: std.mem.Allocator) void {
        if (self.trailers) |ts| {
            for (ts) |t| {
                gpa.free(t.name);
                gpa.free(t.value);
            }
            gpa.free(ts);
        }
        self.trailers = null;
    }
};

const CollapsedResponse = struct {
    event: events.Response,
    content_length: ?u64,
};

/// Outbound (response) state per stream, so the send API cannot serialize invalid
/// HTTP/3: DATA before HEADERS, a second HEADERS, or a write after the FIN.
const SendState = enum { idle, headers_sent, fin_sent };

/// Per inbound unidirectional stream. `utype` is null until the leading type-prefix
/// varint has fully arrived (it may straddle datagrams). `settings_seen` tracks the
/// control stream's "SETTINGS first, exactly once" rule (RFC 9114 6.2.1).
const UniStream = struct {
    utype: ?h3_stream.UniStreamType = null,
    settings_seen: bool = false,
};

/// The largest field section (header block) we will decode, advertised to the peer
/// as SETTINGS_MAX_FIELD_SECTION_SIZE so it does not send a larger one.
const MAX_FIELD_SECTION_SIZE: u64 = 1 << 16;
/// Decoder dynamic-table capacity we advertise to the peer. Keeping this modest
/// limits per-connection QPACK state while still allowing dynamic references.
const QPACK_MAX_TABLE_CAPACITY = qpack_enc.max_dynamic_capacity;
const QPACK_BLOCKED_STREAMS = qpack_enc.max_blocked_streams;

pub const Connection = struct {
    gpa: std.mem.Allocator,
    qc: *quic_conn.Connection,
    limits: Limits,
    streams: std.AutoHashMapUnmanaged(u64, RequestStream) = .empty,
    send_state: std.AutoHashMapUnmanaged(u64, SendState) = .empty,
    send_content_length: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    send_body_sent: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    /// Request streams whose response must not carry DATA or trailers: inbound HEAD
    /// requests, plus responses we locally serialize as 204/304.
    send_bodyless: std.AutoHashMapUnmanaged(u64, void) = .empty,
    next_request_stream_id: u64 = 0,
    qpack_dec: qpack.Decoder,
    qpack_enc_state: qpack_enc.Encoder,
    queue: std.ArrayListUnmanaged(H3Event) = .empty,
    qpos: usize = 0,
    /// Owned copies of the strings each queued event borrows; freed when the queue
    /// is reset. QPACK's decode store is reused per call, so we materialise here.
    arena: std.heap.ArenaAllocator,
    /// Whether our control stream (type + SETTINGS) has been opened (RFC 9114
    /// 6.2.1). The control stream is opened once, before any response.
    control_sent: bool = false,
    /// Whether our QPACK decoder stream has been opened. It carries decoder
    /// instructions acknowledging dynamic table state received from the peer.
    qpack_decoder_sent: bool = false,
    /// Whether our QPACK encoder stream has been opened. It carries dynamic-table
    /// insertions for field sections we encode with dynamic references.
    qpack_encoder_sent: bool = false,
    /// Per inbound unidirectional stream: its decoded type, once enough bytes have
    /// arrived to read the type-prefix varint (it may span datagrams).
    uni_streams: std.AutoHashMapUnmanaged(u64, UniStream) = .empty,
    /// The peer's control-stream id, set when its type prefix is read. A second
    /// control stream is a connection error (RFC 9114 6.2.1).
    control_recv_id: ?u64 = null,
    /// The peer's QPACK streams, set when their type prefixes are read. A peer gets
    /// one encoder stream and one decoder stream; duplicates are connection errors.
    qpack_encoder_recv_id: ?u64 = null,
    qpack_decoder_recv_id: ?u64 = null,
    /// The peer's SETTINGS, once its (mandatory, first-on-the-control-stream) frame
    /// has been parsed (RFC 9114 7.2.4). Null until then; a request that arrives
    /// first is H3_MISSING_SETTINGS.
    peer_settings: ?h3_stream.Settings = null,
    /// The id of the last GOAWAY we sent (RFC 9114 5.2), or null if none. A later
    /// GOAWAY may only lower it, so this gates monotonicity.
    goaway_sent: ?u64 = null,
    /// The id of a GOAWAY received from the peer, or null. A second GOAWAY may only
    /// lower it (a higher id is H3_ID_ERROR).
    goaway_recv: ?u64 = null,
    /// Largest MAX_PUSH_ID received from a client. Null means push is not allowed.
    /// We still do not initiate pushes, but RFC 9114 requires rejecting decreases.
    max_push_id_recv: ?u64 = null,
    pub fn init(gpa: std.mem.Allocator, qc: *quic_conn.Connection) Connection {
        return initWithLimits(gpa, qc, .{});
    }

    /// Initialize a connection with explicit resource limits.
    pub fn initWithLimits(gpa: std.mem.Allocator, qc: *quic_conn.Connection, limits: Limits) Connection {
        var dec = qpack.Decoder.init(gpa, MAX_FIELD_SECTION_SIZE);
        dec.setMaxDynamicCapacity(QPACK_MAX_TABLE_CAPACITY);
        return .{
            .gpa = gpa,
            .qc = qc,
            .limits = limits,
            .qpack_dec = dec,
            .qpack_enc_state = qpack_enc.Encoder.init(gpa),
            .arena = std.heap.ArenaAllocator.init(gpa),
        };
    }

    pub fn deinit(self: *Connection) void {
        var stream_it = self.streams.valueIterator();
        while (stream_it.next()) |rs| rs.deinit(self.gpa);
        self.streams.deinit(self.gpa);
        self.send_state.deinit(self.gpa);
        self.send_content_length.deinit(self.gpa);
        self.send_body_sent.deinit(self.gpa);
        self.send_bodyless.deinit(self.gpa);
        self.uni_streams.deinit(self.gpa);
        self.qpack_dec.deinit();
        self.qpack_enc_state.deinit();
        self.queue.deinit(self.gpa);
        self.arena.deinit();
    }

    /// Fail the connection with an HTTP/3 error: queue a CONNECTION_CLOSE carrying the
    /// specific application error code (RFC 9114 8.1) so the peer learns which rule
    /// broke, then surface error.H3Error to the caller. `close` is idempotent, so a
    /// second failure does not overwrite the first. The integrator drains the close
    /// via data_to_send.
    fn fail(self: *Connection, code: h3_error.ErrorCode, reason: []const u8) Error {
        self.qc.close(true, @intFromEnum(code), reason) catch {};
        return error.H3Error;
    }

    fn removeStreamState(self: *Connection, id: u64) void {
        if (self.streams.getPtr(id)) |rs| rs.deinit(self.gpa);
        _ = self.streams.remove(id);
    }

    fn releaseStreamCredit(self: *Connection, id: u64, rs: *RequestStream) void {
        self.qc.releaseStreamCredit(id);
        rs.body_unconsumed = 0;
    }

    /// Reset request stream `id` with `code` and drop its state: RESET_STREAM the
    /// response, STOP_SENDING the request, drain and reclaim. Used both for a
    /// malformed request and a request covered by our GOAWAY.
    fn rejectStream(self: *Connection, id: u64, code: h3_error.ErrorCode) Error!void {
        if (self.streams.getPtr(id)) |rs| try self.cancelQpackSectionIfPending(id, rs);
        _ = self.send_bodyless.remove(id);
        self.qc.resetStream(id, @intFromEnum(code)) catch return error.H3Error;
        self.qc.stopSending(id, @intFromEnum(code)) catch return error.H3Error;
        if (self.streams.getPtr(id)) |rs| self.releaseStreamCredit(id, rs);
        const pending = self.qc.streamData(id).len;
        if (pending > 0) self.qc.consumeStream(id, pending);
        // Drop the stream if the transport can (recv terminal); otherwise mark it
        // .rejected so a later pump quarantines it (drains, no more events) rather than
        // re-parsing a stream we already reset, which could surface a spurious request.
        if (self.qc.dropStream(id)) {
            self.removeStreamState(id);
        } else if (self.streams.getPtr(id)) |rs| {
            rs.state = .rejected;
        }
    }

    /// Open our unidirectional control stream and send SETTINGS as its first frame
    /// (RFC 9114 6.2.1, 7.2.4). A conformant peer treats the absence of our SETTINGS
    /// as H3_MISSING_SETTINGS and may refuse to send requests, so this must precede
    /// any response. Idempotent: the control stream is opened at most once. The
    /// stream-type byte (0x00) prefixes the SETTINGS frame on the same stream.
    pub fn initiateControl(self: *Connection) Error!void {
        if (self.control_sent) return;
        var settings: std.ArrayListUnmanaged(u8) = .empty;
        defer settings.deinit(self.gpa);
        // SETTINGS_MAX_FIELD_SECTION_SIZE = our decode cap. QPACK capacity advertises
        // how much dynamic table state our decoder is prepared to keep.
        varint.append(&settings, self.gpa, @intFromEnum(h3_stream.SettingId.qpack_max_table_capacity)) catch return error.OutOfMemory;
        varint.append(&settings, self.gpa, @as(u64, QPACK_MAX_TABLE_CAPACITY)) catch return error.OutOfMemory;
        varint.append(&settings, self.gpa, @intFromEnum(h3_stream.SettingId.qpack_blocked_streams)) catch return error.OutOfMemory;
        varint.append(&settings, self.gpa, QPACK_BLOCKED_STREAMS) catch return error.OutOfMemory;
        varint.append(&settings, self.gpa, @intFromEnum(h3_stream.SettingId.max_field_section_size)) catch return error.OutOfMemory;
        varint.append(&settings, self.gpa, MAX_FIELD_SECTION_SIZE) catch return error.OutOfMemory;

        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(self.gpa);
        out.append(self.gpa, @intFromEnum(h3_stream.UniStreamType.control)) catch return error.OutOfMemory;
        h3_frame.append(&out, self.gpa, .settings, settings.items) catch return error.OutOfMemory;
        try self.streamSend(self.controlStreamId(), out.items, false);
        self.control_sent = true;
    }

    /// Begin a graceful shutdown: send a GOAWAY on the control stream (RFC 9114 5.2).
    /// Servers announce the first client request stream they will NOT process; clients
    /// announce the first push ID they will NOT accept. The control stream is opened
    /// first if needed. A later GOAWAY may only lower the id (a higher one is
    /// rejected), so a shutdown can narrow but never widen what we promise to handle.
    pub fn shutdown(self: *Connection, stream_id: u64) Error!void {
        // A server's GOAWAY id names a client request stream; a client's GOAWAY id
        // names a push ID. Validate BEFORE any side effect (opening the control
        // stream), so a bad id is a clean rejection.
        if (stream_id > varint.MAX) return error.H3Error;
        if (self.qc.role == .server and quic_stream.StreamType.of(stream_id) != .client_bidi) return error.H3Error;
        if (self.goaway_sent) |prev| if (stream_id > prev) return error.H3Error;
        try self.initiateControl();
        var payload: std.ArrayListUnmanaged(u8) = .empty;
        defer payload.deinit(self.gpa);
        varint.append(&payload, self.gpa, stream_id) catch return error.OutOfMemory;
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(self.gpa);
        h3_frame.append(&out, self.gpa, .goaway, payload.items) catch return error.OutOfMemory;
        try self.streamSend(self.controlStreamId(), out.items, false);
        self.goaway_sent = stream_id;
    }

    /// The first locally-initiated unidirectional stream id (RFC 9000 2.1). A
    /// client's control stream is 2; a server's control stream is 3.
    fn controlStreamId(self: *const Connection) u64 {
        return if (self.qc.role == .client) 2 else 3;
    }

    fn qpackDecoderStreamId(self: *const Connection) u64 {
        return if (self.qc.role == .client) 6 else 7;
    }

    fn qpackEncoderStreamId(self: *const Connection) u64 {
        return if (self.qc.role == .client) 10 else 11;
    }

    /// Advance only the streams changed by the datagram the transport just handled.
    pub fn pumpStreams(self: *Connection, ids: []const u64) Error!void {
        if (self.eventQueueFull()) return error.EventQueueFull;
        try self.pumpStreamSnapshot(ids);
    }

    /// Advance every stream the transport currently knows about.
    pub fn pumpAll(self: *Connection) Error!void {
        if (self.eventQueueFull()) return error.EventQueueFull;
        var stack_ids: [64]u64 = undefined;
        const count = self.qc.streamCount();
        if (count <= stack_ids.len) {
            const n = self.qc.streamIds(&stack_ids);
            try self.pumpStreamSnapshot(stack_ids[0..n]);
            return;
        }

        const ids = self.gpa.alloc(u64, count) catch return error.OutOfMemory;
        defer self.gpa.free(ids);
        const n = self.qc.streamIds(ids);
        try self.pumpStreamSnapshot(ids[0..n]);
    }

    fn pumpStreamSnapshot(self: *Connection, ids: []const u64) Error!void {
        // SETTINGS lives on the peer's control stream. Process inbound uni streams
        // first so a datagram carrying both SETTINGS and a request is accepted, but
        // a request/response stream that arrives before peer SETTINGS is still
        // H3_MISSING_SETTINGS (RFC 9114 6.2.1, 7.2.4).
        for (ids) |id| {
            if (self.isInboundUni(id)) try self.pump(id);
        }
        if (self.peer_settings == null) {
            for (ids) |id| {
                if (!self.isInboundRequestStream(id)) continue;
                if (self.qc.streamData(id).len > 0 or self.qc.streamFinished(id)) {
                    return self.fail(.missing_settings, "request stream arrived before peer SETTINGS");
                }
            }
        }
        for (ids) |id| {
            if (!self.isInboundUni(id)) try self.pump(id);
        }
    }

    fn isInboundUni(self: *const Connection, id: u64) bool {
        return switch (self.qc.role) {
            .server => quic_stream.StreamType.of(id) == .client_uni,
            .client => quic_stream.StreamType.of(id) == .server_uni,
        };
    }

    fn isInboundRequestStream(_: *const Connection, id: u64) bool {
        return quic_stream.StreamType.of(id) == .client_bidi;
    }

    fn pump(self: *Connection, id: u64) Error!void {
        switch (self.qc.role) {
            .server => switch (quic_stream.StreamType.of(id)) {
                .client_bidi => try self.pumpRequest(id),
                .client_uni => try self.pumpUni(id),
                else => {}, // server-initiated streams are ours; nothing to read here
            },
            .client => switch (quic_stream.StreamType.of(id)) {
                .client_bidi => try self.pumpResponse(id),
                .server_uni => try self.pumpUni(id),
                else => {}, // client-initiated uni streams are ours; server bidi is unused by H3
            },
        }
    }

    fn pumpRequest(self: *Connection, id: u64) Error!void {
        // After we send a GOAWAY (RFC 9114 5.2) we have promised not to process a
        // request stream at or above the advertised id, so a racing or non-compliant
        // peer that opens one gets no Request event - its bytes are drained (so flow
        // control is re-granted and the stream is reclaimed) but never surfaced. The
        // client retries such requests on a fresh connection. A stream we already
        // began before the GOAWAY is left to complete (it is below the id, or already
        // tracked).
        if (self.goaway_sent) |limit| {
            // Exempt only a stream we have actually begun processing (a Request was
            // surfaced, so its state left .idle). A merely pre-tracked idle
            // placeholder - created when a partial HEADERS frame arrived but no
            // Request was emitted yet - must still be rejected: otherwise a peer
            // could send a HEADERS fragment on a high stream id, wait for the
            // GOAWAY, then complete it and slip a request past the advertised limit.
            const already_processing = if (self.streams.getPtr(id)) |rs| rs.state != .idle else false;
            if (id >= limit and !already_processing) {
                // We promised not to process this request (RFC 9114 5.2): reject it
                // with H3_REQUEST_REJECTED so the client knows it may safely retry on a
                // fresh connection, rather than silently dropping it.
                try self.rejectStream(id, .request_rejected);
                return;
            }
        }
        // Don't recreate H3 state for a stream the transport no longer has (retired
        // after completion/reset): a late frame for it is already ignored there, and
        // recreating an idle entry here would resurrect it on the H3 map.
        if (!self.streams.contains(id) and !self.qc.hasStream(id)) return;
        const gop = self.streams.getOrPut(self.gpa, id) catch return error.OutOfMemory;
        if (!gop.found_existing) gop.value_ptr.* = .{};
        const rs = gop.value_ptr;

        // A stream we already rejected (reset) but could not yet drop: drain any
        // further bytes the peer sent and reclaim it once terminal, but never parse
        // them - it must produce no more events.
        if (rs.state == .rejected) {
            const pending = self.qc.streamData(id).len;
            const finished = self.qc.streamFinished(id) or self.qc.streamReset(id);
            if (pending > 0 or finished) self.qc.consumeStream(id, pending);
            if (finished and self.qc.dropStream(id)) self.removeStreamState(id);
            return;
        }

        if (rs.blocked_headers != null) {
            if (self.qc.streamReset(id) and !rs.rst_emitted) {
                try self.cancelQpackSectionIfPending(id, rs);
                self.releaseStreamCredit(id, rs);
                try self.push(.{ .rst_stream = .{ .stream_id = id, .error_code = self.qc.streamResetCode(id) orelse 0 } });
                rs.rst_emitted = true;
            }
            if (self.qc.streamReset(id) and self.qc.dropStream(id)) self.removeStreamState(id);
            return;
        }

        // Parse from the start of the ordered bytes the transport currently holds:
        // every fully-decoded frame is consumed (removed from the QUIC stream)
        // before this returns, so the next pump always begins at offset 0 with the
        // not-yet-consumed tail (a partial frame plus any newer bytes). Tracking a
        // persistent offset here would desync once the transport slides the buffer.
        const ready = self.qc.streamData(id);
        var consumed_total: usize = 0;
        var credited_total: usize = 0;
        while (consumed_total < ready.len) {
            const rest = ready[consumed_total..];
            const d = h3_frame.decode(rest) catch break; // NeedData: wait for more
            const frame_ends_stream = self.qc.streamFinished(id) and consumed_total + d.len == ready.len;
            switch (try self.onFrame(id, rs, d.frame, frame_ends_stream)) {
                .value => {},
                .rejected => |code| return self.rejectStream(id, code), // rs dangles after the drop inside
            }
            consumed_total += d.len;
            credited_total += if (d.frame.ftype == .data) d.len - d.frame.payload.len else d.len;
            if (rs.blocked_headers != null) break;
        }
        if (self.qc.streamFinished(id) and rs.blocked_headers == null and consumed_total < ready.len) {
            return self.fail(.frame_error, "stream ended with a truncated HTTP/3 frame");
        }
        if (self.qc.streamFinished(id) and !self.qc.streamReset(id) and rs.blocked_headers == null and rs.state == .idle) {
            return self.rejectStream(id, .request_incomplete);
        }
        if (self.qc.streamFinished(id) and (rs.state == .headers_done or rs.state == .trailers_done)) {
            // Fewer body bytes than the declared Content-Length is malformed (RFC
            // 9114 4.1.2); the over-count is caught per-DATA above.
            if (rs.content_length) |cl| if (rs.body_received != cl) return self.rejectStream(id, .message_error);
            if (!rs.head_ended_stream) {
                const trailers = try self.materializeTrailers(rs);
                try self.push(.{ .end_of_message = .{ .trailers = trailers, .stream_id = id } });
            }
            rs.state = .done;
        }
        // Consume BEFORE dropping: consuming the last byte of a finished stream is
        // what moves its receive state to terminal, which dropStream then reclaims.
        // A FIN-only completion (the FIN arrived as a zero-length STREAM frame) still
        // needs the consume, or the stream never reaches terminal and cannot be dropped.
        if (consumed_total > 0 or (self.qc.streamFinished(id) and rs.state == .done)) {
            self.qc.advanceStream(id, consumed_total);
            self.qc.creditStream(id, credited_total);
        }
        // A peer RESET_STREAM cancels the request: surface it as an event (with the
        // peer's error code) once, before the stream is dropped, so the integrator is
        // not left waiting on a request that silently vanished. The flag guards against
        // a re-fire if the stream cannot be dropped yet (e.g. an allocator failure).
        if (self.qc.streamReset(id) and !rs.rst_emitted) {
            try self.cancelQpackSectionIfPending(id, rs);
            self.releaseStreamCredit(id, rs);
            try self.push(.{ .rst_stream = .{ .stream_id = id, .error_code = self.qc.streamResetCode(id) orelse 0 } });
            rs.rst_emitted = true;
        }
        // Drop the per-stream state on both layers once the request is fully
        // delivered (EOM) OR the peer reset the stream, so an open-then-reset storm
        // cannot grow the maps (the memory half of the Rapid-Reset class). The QUIC
        // send half is retained until its bytes are acked, so a still-in-flight
        // response is not freed from under recovery.
        if ((rs.state == .done and rs.body_unconsumed == 0) or self.qc.streamReset(id)) {
            if (self.qc.dropStream(id)) self.removeStreamState(id); // rs dangles after this
        }
    }

    fn pumpResponse(self: *Connection, id: u64) Error!void {
        if (!self.streams.contains(id) and !self.qc.hasStream(id)) return;
        const gop = self.streams.getOrPut(self.gpa, id) catch return error.OutOfMemory;
        if (!gop.found_existing) gop.value_ptr.* = .{};
        const rs = gop.value_ptr;

        if (rs.state == .rejected) {
            const pending = self.qc.streamData(id).len;
            const finished = self.qc.streamFinished(id) or self.qc.streamReset(id);
            if (pending > 0 or finished) self.qc.consumeStream(id, pending);
            if (finished and self.qc.dropStream(id)) self.removeStreamState(id);
            return;
        }

        if (rs.blocked_headers != null) {
            if (self.qc.streamReset(id) and !rs.rst_emitted) {
                try self.cancelQpackSectionIfPending(id, rs);
                self.releaseStreamCredit(id, rs);
                try self.push(.{ .rst_stream = .{ .stream_id = id, .error_code = self.qc.streamResetCode(id) orelse 0 } });
                rs.rst_emitted = true;
            }
            if (self.qc.streamReset(id) and self.qc.dropStream(id)) self.removeStreamState(id);
            return;
        }

        const ready = self.qc.streamData(id);
        var consumed_total: usize = 0;
        var credited_total: usize = 0;
        while (consumed_total < ready.len) {
            const rest = ready[consumed_total..];
            const d = h3_frame.decode(rest) catch break;
            switch (try self.onResponseFrame(id, rs, d.frame)) {
                .value => {},
                .rejected => |code| return self.rejectStream(id, code),
            }
            consumed_total += d.len;
            credited_total += if (d.frame.ftype == .data) d.len - d.frame.payload.len else d.len;
            if (rs.blocked_headers != null) break;
        }
        if (self.qc.streamFinished(id) and rs.blocked_headers == null and consumed_total < ready.len) {
            return self.fail(.frame_error, "stream ended with a truncated HTTP/3 frame");
        }
        if (self.qc.streamFinished(id) and rs.blocked_headers == null and rs.state != .done) {
            if (rs.state != .headers_done and rs.state != .trailers_done) return self.rejectStream(id, .message_error);
            if (!rs.expects_bodyless) {
                if (rs.content_length) |cl| if (rs.body_received != cl) return self.rejectStream(id, .message_error);
            }
            const trailers = try self.materializeTrailers(rs);
            try self.push(.{ .end_of_message = .{ .trailers = trailers, .stream_id = id } });
            rs.state = .done;
        }
        // Consume the completion even when it carried no new frame bytes (a FIN-only
        // STREAM frame): consuming is what advances the recv side to its terminal
        // state, so dropStream below reclaims a finished stream instead of leaving it
        // for pumpAll to revisit on every datagram.
        if (consumed_total > 0 or (self.qc.streamFinished(id) and rs.state == .done)) {
            self.qc.advanceStream(id, consumed_total);
            self.qc.creditStream(id, credited_total);
        }
        if (self.qc.streamReset(id) and !rs.rst_emitted) {
            try self.cancelQpackSectionIfPending(id, rs);
            self.releaseStreamCredit(id, rs);
            try self.push(.{ .rst_stream = .{ .stream_id = id, .error_code = self.qc.streamResetCode(id) orelse 0 } });
            rs.rst_emitted = true;
        }
        if ((rs.state == .done and rs.body_unconsumed == 0) or self.qc.streamReset(id)) {
            if (self.qc.dropStream(id)) self.removeStreamState(id);
        }
    }

    /// Advance an inbound unidirectional stream (RFC 9114 6.2). The first varint is
    /// the stream type; the control stream carries frames, QPACK streams carry
    /// encoder/decoder instructions, push is rejected because it is never enabled,
    /// and an unknown type is abandoned. The type-prefix read tolerates a varint
    /// that straddles datagrams (it stays unconsumed until complete).
    fn pumpUni(self: *Connection, id: u64) Error!void {
        const us = self.uni_streams.getOrPut(self.gpa, id) catch return error.OutOfMemory;
        if (!us.found_existing) us.value_ptr.* = .{};
        const u = us.value_ptr;
        const ready = self.qc.streamData(id);
        var consumed: usize = 0;

        if (u.utype == null) {
            const d = h3_stream.decodeUniType(ready) orelse {
                // The type varint is not all here yet. If the stream is already
                // finished/reset without ever sending a type, it is an abandoned
                // empty uni stream - reclaim it so a flood of them cannot grow the
                // maps (the type stays unknown, so it is never the control stream).
                if (self.qc.streamFinished(id) or self.qc.streamReset(id)) {
                    self.qc.consumeStream(id, 0);
                    if (self.qc.dropStream(id)) _ = self.uni_streams.remove(id);
                }
                return;
            };
            u.utype = d.utype;
            consumed += d.len;
            if (d.utype == .control) {
                if (self.control_recv_id != null) return self.fail(.stream_creation_error, "a second control stream");
                self.control_recv_id = id;
            } else if (d.utype == .qpack_encoder) {
                if (self.qpack_encoder_recv_id != null) return self.fail(.stream_creation_error, "a second QPACK encoder stream");
                self.qpack_encoder_recv_id = id;
            } else if (d.utype == .qpack_decoder) {
                if (self.qpack_decoder_recv_id != null) return self.fail(.stream_creation_error, "a second QPACK decoder stream");
                self.qpack_decoder_recv_id = id;
            } else if (d.utype == .push and self.qc.role == .server) {
                return self.fail(.stream_creation_error, "client opened a push stream");
            }
        }

        switch (u.utype.?) {
            .control => {
                // Frames on the control stream (SETTINGS, and later GOAWAY); the
                // ordering rules live in onControlFrame.
                while (consumed < ready.len) {
                    const d = h3_frame.decode(ready[consumed..]) catch break; // need more
                    try self.onControlFrame(u, d.frame);
                    consumed += d.len;
                }
            },
            .qpack_encoder => {
                const progress = self.qpack_dec.processEncoder(ready[consumed..]) catch return self.fail(.qpack_encoder_stream_error, "bad QPACK encoder stream");
                consumed += progress.consumed;
                if (progress.inserts > 0) {
                    try self.sendQpackInsertCountIncrement(progress.inserts);
                    try self.resumeBlockedStreams();
                }
            },
            .qpack_decoder => {
                const progress = self.qpack_enc_state.processDecoder(ready[consumed..]) catch return self.fail(.qpack_decoder_stream_error, "bad QPACK decoder stream");
                consumed += progress.consumed;
            },
            .push => {
                const push_id = varint.decode(ready[consumed..]) catch {
                    if (self.qc.streamFinished(id)) return self.fail(.frame_error, "truncated push stream header");
                    if (self.qc.streamReset(id)) {
                        self.qc.consumeStream(id, ready.len);
                        if (self.qc.dropStream(id)) _ = self.uni_streams.remove(id);
                        return;
                    }
                    if (consumed > 0) self.qc.consumeStream(id, consumed);
                    return;
                };
                _ = push_id;
                return self.fail(.id_error, "server push is not enabled");
            },
            // An unknown unidirectional stream type MUST be abandoned (RFC 9114 6.2);
            // drain it rather than letting its bytes accrete.
            _ => consumed = ready.len,
        }
        const finished = self.qc.streamFinished(id) or self.qc.streamReset(id);
        if (u.utype.? == .control and self.qc.streamFinished(id) and consumed < ready.len) {
            return self.fail(.frame_error, "control stream ended with a truncated HTTP/3 frame");
        }
        if (self.qc.streamFinished(id) and consumed < ready.len) {
            switch (u.utype.?) {
                .qpack_encoder => return self.fail(.qpack_encoder_stream_error, "QPACK encoder stream ended with a truncated instruction"),
                .qpack_decoder => return self.fail(.qpack_decoder_stream_error, "QPACK decoder stream ended with a truncated instruction"),
                else => {},
            }
        }
        // Control and QPACK streams are critical: closing them (FIN or reset) is a
        // connection error. For control, this also prevents a peer from closing
        // before its mandatory SETTINGS frame.
        if (isCriticalUniStream(u.utype.?) and finished) return self.fail(.closed_critical_stream, "critical unidirectional stream was closed");
        // Reclaim any other finished/reset ignored uni stream so a peer cannot grow
        // the maps by opening-and-finishing many of them. Consume even zero bytes: a
        // bare FIN in its own frame leaves nothing new to consume, but the consume is
        // what flips the recv state to terminal so dropStream can reclaim it.
        const ignored_done = u.utype.? != .control and finished;
        if (consumed > 0 or ignored_done) self.qc.consumeStream(id, consumed);
        if (ignored_done) {
            if (self.qc.dropStream(id)) _ = self.uni_streams.remove(id);
        }
    }

    fn isCriticalUniStream(utype: h3_stream.UniStreamType) bool {
        return switch (utype) {
            .control, .qpack_encoder, .qpack_decoder => true,
            else => false,
        };
    }

    /// A frame on the control stream (RFC 9114 7.2.4, 6.2.1). The first frame MUST be
    /// SETTINGS, exactly once; DATA/HEADERS are never legal here. The parsed SETTINGS
    /// are applied (the peer's max field-section size bounds what we send; an
    /// unparsable or duplicate-id SETTINGS is a connection error).
    fn onControlFrame(self: *Connection, u: *UniStream, f: h3_frame.Frame) Error!void {
        if (h3_frame.isReservedHttp2(f.ftype)) return self.fail(.frame_unexpected, "HTTP/2-only frame type");
        if (f.ftype == .settings) {
            if (u.settings_seen) return self.fail(.frame_unexpected, "second SETTINGS");
            const s = h3_stream.parseSettings(f.payload) catch return self.fail(.settings_error, "malformed SETTINGS");
            const params = self.settingsEventParams(f.payload) catch return self.fail(.settings_error, "malformed SETTINGS");
            u.settings_seen = true;
            self.peer_settings = s;
            try self.push(.{ .settings = .{ .params = params } });
            return;
        }
        // Any other frame (GOAWAY, MAX_PUSH_ID, grease) before SETTINGS means the
        // first frame was not SETTINGS - missing_settings (RFC 9114 6.2.1).
        if (!u.settings_seen) return self.fail(.missing_settings, "control stream did not begin with SETTINGS");
        if (f.ftype == .data or f.ftype == .headers or f.ftype == .push_promise) return self.fail(.frame_unexpected, "frame not allowed on the control stream");
        if (f.ftype == .goaway) {
            const d = varint.decode(f.payload) catch return self.fail(.frame_error, "malformed GOAWAY");
            if (d.len != f.payload.len) return self.fail(.frame_error, "GOAWAY has trailing bytes");
            // A peer's GOAWAY id may only decrease (RFC 9114 5.2); a higher one is an
            // H3_ID_ERROR. The id names the largest push id / response stream the peer
            // will accept - it never grows.
            if (self.qc.role == .client and quic_stream.StreamType.of(d.value) != .client_bidi) return self.fail(.id_error, "server GOAWAY id is not a client request stream");
            if (self.goaway_recv) |prev| if (d.value > prev) return self.fail(.id_error, "GOAWAY id increased");
            self.goaway_recv = d.value;
            try self.push(.{ .goaway = .{ .last_stream_id = d.value, .error_code = 0 } });
        }
        if (f.ftype == .max_push_id) {
            const d = varint.decode(f.payload) catch return self.fail(.frame_error, "malformed MAX_PUSH_ID");
            if (d.len != f.payload.len) return self.fail(.frame_error, "MAX_PUSH_ID has trailing bytes");
            if (self.qc.role == .client) return self.fail(.frame_unexpected, "server sent MAX_PUSH_ID");
            if (self.max_push_id_recv) |prev| if (d.value < prev) return self.fail(.id_error, "MAX_PUSH_ID decreased");
            self.max_push_id_recv = d.value;
            return;
        }
        if (f.ftype == .cancel_push) {
            const d = varint.decode(f.payload) catch return self.fail(.frame_error, "malformed CANCEL_PUSH");
            if (d.len != f.payload.len) return self.fail(.frame_error, "CANCEL_PUSH has trailing bytes");
            // Push is disabled in this implementation: no push id can have been
            // promised, so a cancellation can only reference an invalid push id.
            return self.fail(.id_error, "CANCEL_PUSH for an unpromised push");
        }
        // Grease/unknown frames after SETTINGS are ignored.
    }

    fn settingsEventParams(self: *Connection, payload: []const u8) Error![]const events.SettingPair {
        var params: std.ArrayListUnmanaged(events.SettingPair) = .empty;
        const a = self.arena.allocator();
        var pos: usize = 0;
        while (pos < payload.len) {
            const id = varint.decode(payload[pos..]) catch return error.H3Error;
            pos += id.len;
            const value = varint.decode(payload[pos..]) catch return error.H3Error;
            pos += value.len;
            params.append(a, .{ .id = id.value, .value = value.value }) catch return error.OutOfMemory;
        }
        return params.items;
    }

    fn sendQpackDecoderInstruction(self: *Connection, payload: []const u8) Error!void {
        try self.initiateControl();
        if (payload.len == 0) return;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.gpa);
        if (!self.qpack_decoder_sent) {
            out.append(self.gpa, @intFromEnum(h3_stream.UniStreamType.qpack_decoder)) catch return error.OutOfMemory;
            self.qpack_decoder_sent = true;
        }
        out.appendSlice(self.gpa, payload) catch return error.OutOfMemory;
        try self.streamSend(self.qpackDecoderStreamId(), out.items, false);
    }

    fn sendQpackEncoderInstruction(self: *Connection, payload: []const u8) Error!void {
        try self.initiateControl();
        if (payload.len == 0) return;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.gpa);
        if (!self.qpack_encoder_sent) {
            out.append(self.gpa, @intFromEnum(h3_stream.UniStreamType.qpack_encoder)) catch return error.OutOfMemory;
            self.qpack_encoder_sent = true;
        }
        out.appendSlice(self.gpa, payload) catch return error.OutOfMemory;
        try self.streamSend(self.qpackEncoderStreamId(), out.items, false);
    }

    fn encodeFieldSection(self: *Connection, out: *std.ArrayList(u8), stream_id: u64, headers: []const Header) Error!void {
        var encoder_stream: std.ArrayList(u8) = .empty;
        defer encoder_stream.deinit(self.gpa);
        const settings = self.peer_settings orelse h3_stream.Settings{};
        const section_size = fieldSectionSize(headers) catch return error.H3Error;
        if (section_size > settings.max_field_section_size) return error.H3Error;
        self.qpack_enc_state.encodeFieldSection(
            out,
            &encoder_stream,
            stream_id,
            headers,
            settings.qpack_max_table_capacity,
            settings.qpack_blocked_streams,
        ) catch return error.OutOfMemory;
        if (encoder_stream.items.len > 0) try self.sendQpackEncoderInstruction(encoder_stream.items);
    }

    fn sendQpackSectionAcknowledgment(self: *Connection, stream_id: u64) Error!void {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.gpa);
        qpack_enc.encodeSectionAcknowledgment(&payload, self.gpa, stream_id) catch return error.OutOfMemory;
        try self.sendQpackDecoderInstruction(payload.items);
    }

    fn sendQpackInsertCountIncrement(self: *Connection, increment: u64) Error!void {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.gpa);
        qpack_enc.encodeInsertCountIncrement(&payload, self.gpa, increment) catch return error.OutOfMemory;
        try self.sendQpackDecoderInstruction(payload.items);
    }

    fn sendQpackStreamCancellation(self: *Connection, stream_id: u64) Error!void {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.gpa);
        qpack_enc.encodeStreamCancellation(&payload, self.gpa, stream_id) catch return error.OutOfMemory;
        try self.sendQpackDecoderInstruction(payload.items);
    }

    fn onQpackDecodeError(self: *Connection, err: qpack.Error) Error {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.Blocked => error.Blocked,
            else => self.fail(.qpack_decompression_failed, "bad QPACK field section"),
        };
    }

    fn markQpackSectionIfDynamic(self: *Connection, rs: *RequestStream) void {
        if (self.qpack_dec.lastRequiredInsertCount() != 0) rs.qpack_section_pending = true;
    }

    fn acknowledgeQpackSectionIfPending(self: *Connection, stream_id: u64, rs: *RequestStream) Error!void {
        if (!rs.qpack_section_pending) return;
        try self.sendQpackSectionAcknowledgment(stream_id);
        rs.qpack_section_pending = false;
    }

    fn cancelQpackSectionIfPending(self: *Connection, stream_id: u64, rs: *RequestStream) Error!void {
        if (!rs.qpack_section_pending) return;
        try self.sendQpackStreamCancellation(stream_id);
        rs.qpack_section_pending = false;
    }

    fn blockedStreamCount(self: *Connection) u64 {
        var n: u64 = 0;
        var it = self.streams.valueIterator();
        while (it.next()) |rs| {
            if (rs.blocked_headers != null) n += 1;
        }
        return n;
    }

    fn blockHeaders(self: *Connection, rs: *RequestStream, block: []const u8, section: BlockedSection) Error!void {
        if (rs.blocked_headers != null) return;
        if (self.blockedStreamCount() >= QPACK_BLOCKED_STREAMS) return self.fail(.qpack_decompression_failed, "too many blocked QPACK streams");
        rs.blocked_headers = self.gpa.dupe(u8, block) catch return error.OutOfMemory;
        rs.blocked_section = section;
        rs.qpack_section_pending = true;
    }

    fn clearBlockedHeaders(self: *Connection, rs: *RequestStream) void {
        if (rs.blocked_headers) |b| self.gpa.free(b);
        rs.blocked_headers = null;
        rs.blocked_section = .initial;
    }

    fn resumeBlockedStreams(self: *Connection) Error!void {
        var ids: [64]u64 = undefined;
        var n: usize = 0;
        var it = self.streams.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.blocked_headers == null) continue;
            if (n == ids.len) break;
            ids[n] = e.key_ptr.*;
            n += 1;
        }
        for (ids[0..n]) |id| {
            const resumed = try self.resumeBlockedStream(id);
            if (resumed) try self.pump(id);
        }
    }

    fn resumeBlockedStream(self: *Connection, id: u64) Error!bool {
        const rs = self.streams.getPtr(id) orelse return false;
        const block = rs.blocked_headers orelse return false;

        switch (self.qc.role) {
            .server => {
                if (quic_stream.StreamType.of(id) != .client_bidi) return false;
                if (rs.blocked_section == .trailers) {
                    const outcome = self.decodeTrailers(id, block, rs) catch |e| switch (e) {
                        error.Blocked => return false,
                        else => return e,
                    };
                    switch (outcome) {
                        .value => {},
                        .rejected => |code| {
                            try self.rejectStream(id, code);
                            return false;
                        },
                    }
                    self.clearBlockedHeaders(rs);
                    rs.state = .trailers_done;
                    return true;
                }
                const outcome = self.decodeRequest(id, block, rs) catch |e| switch (e) {
                    error.Blocked => return false,
                    else => return e,
                };
                var req = switch (outcome) {
                    .value => |request| request,
                    .rejected => |code| {
                        try self.rejectStream(id, code);
                        return false;
                    },
                };
                self.clearBlockedHeaders(rs);
                // A QPACK-blocked request whose headers only just unblocked is still
                // an idle pre-tracked stream at this point. If we have advertised a
                // GOAWAY at or below its id, we promised not to process it (RFC 9114
                // 5.2) - reject here too, or this resume path would surface it past
                // the limit, bypassing the guard in pumpRequest. Trailers are not
                // checked: they belong to a request already being processed.
                if (self.goaway_sent) |limit| {
                    if (id >= limit) {
                        try self.rejectStream(id, .request_rejected);
                        return false;
                    }
                }
                const end_stream = self.qc.streamFinished(id) and self.qc.streamData(id).len == 0;
                if (end_stream) {
                    if (rs.content_length) |cl| if (cl != 0) {
                        try self.rejectStream(id, .message_error);
                        return false;
                    };
                    req.end_stream = true;
                    rs.head_ended_stream = true;
                }
                try self.push(.{ .request = req });
                rs.state = .headers_done;
                return true;
            },
            .client => {
                if (quic_stream.StreamType.of(id) != .client_bidi) return false;
                if (rs.blocked_section == .trailers) {
                    const outcome = self.decodeTrailers(id, block, rs) catch |e| switch (e) {
                        error.Blocked => return false,
                        else => return e,
                    };
                    switch (outcome) {
                        .value => {},
                        .rejected => |code| {
                            try self.rejectStream(id, code);
                            return false;
                        },
                    }
                    self.clearBlockedHeaders(rs);
                    rs.state = .trailers_done;
                    return true;
                }
                const outcome = self.decodeResponse(id, block, rs) catch |e| switch (e) {
                    error.Blocked => return false,
                    else => return e,
                };
                const resp = switch (outcome) {
                    .value => |response| response,
                    .rejected => |code| {
                        try self.rejectStream(id, code);
                        return false;
                    },
                };
                self.clearBlockedHeaders(rs);
                try self.push(.{ .response = resp.event });
                if (resp.event.status_code >= 100 and resp.event.status_code < 200) return true;
                rs.state = .headers_done;
                rs.content_length = resp.content_length;
                rs.expects_bodyless = rs.head_response or resp.event.status_code == 204 or resp.event.status_code == 304;
                return true;
            },
        }
    }

    fn onFrame(
        self: *Connection,
        id: u64,
        rs: *RequestStream,
        f: h3_frame.Frame,
        frame_ends_stream: bool,
    ) Error!StreamOutcome(void) {
        if (h3_frame.isReservedHttp2(f.ftype)) return self.fail(.frame_unexpected, "HTTP/2-only frame type");
        switch (f.ftype) {
            .headers => {
                if (rs.state == .idle) {
                    const outcome = self.decodeRequest(id, f.payload, rs) catch |e| switch (e) {
                        error.Blocked => {
                            try self.blockHeaders(rs, f.payload, .initial);
                            return .{ .value = {} };
                        },
                        else => return e,
                    };
                    var req = switch (outcome) {
                        .value => |request| request,
                        .rejected => |code| return .{ .rejected = code },
                    };
                    if (frame_ends_stream) {
                        if (rs.content_length) |cl| if (cl != 0) return .{ .rejected = .message_error };
                        req.end_stream = true;
                        rs.head_ended_stream = true;
                    }
                    try self.push(.{ .request = req });
                    rs.state = .headers_done;
                } else if (rs.state == .headers_done) {
                    const outcome = self.decodeTrailers(id, f.payload, rs) catch |e| switch (e) {
                        error.Blocked => {
                            try self.blockHeaders(rs, f.payload, .trailers);
                            return .{ .value = {} };
                        },
                        else => return e,
                    };
                    switch (outcome) {
                        .value => {},
                        .rejected => |code| return .{ .rejected = code },
                    }
                    rs.state = .trailers_done;
                } else return .{ .rejected = .message_error };
            },
            .data => {
                if (rs.state != .headers_done) return self.fail(.frame_unexpected, "DATA before HEADERS"); // RFC 9114 4.1
                const body_received = std.math.add(u64, rs.body_received, f.payload.len) catch
                    return .{ .rejected = .message_error };
                // More body than the declared Content-Length is malformed (RFC 9114 4.1.2).
                if (rs.content_length) |cl| if (body_received > cl) return .{ .rejected = .message_error };
                const body = try self.dupe(f.payload);
                try self.push(.{ .data = .{ .data = body, .stream_id = id } });
                rs.body_received = body_received;
                rs.body_unconsumed += f.payload.len;
            },
            // Control-stream frames are not allowed on a request stream (RFC 9114
            // 7.1): H3_FRAME_UNEXPECTED.
            .cancel_push, .settings, .push_promise, .goaway, .max_push_id => return self.fail(.frame_unexpected, "control frame on a request stream"),
            // Any other (unknown) frame type, grease or not, MUST be ignored on
            // receipt (RFC 9114 9). The frame is already fully buffered, so the pump
            // loop skips it by Decoded.len.
            else => {},
        }
        return .{ .value = {} };
    }

    fn onResponseFrame(self: *Connection, id: u64, rs: *RequestStream, f: h3_frame.Frame) Error!StreamOutcome(void) {
        if (h3_frame.isReservedHttp2(f.ftype)) return self.fail(.frame_unexpected, "HTTP/2-only frame type");
        switch (f.ftype) {
            .headers => {
                if (rs.state == .idle) {
                    const outcome = self.decodeResponse(id, f.payload, rs) catch |e| switch (e) {
                        error.Blocked => {
                            try self.blockHeaders(rs, f.payload, .initial);
                            return .{ .value = {} };
                        },
                        else => return e,
                    };
                    const resp = switch (outcome) {
                        .value => |response| response,
                        .rejected => |code| return .{ .rejected = code },
                    };
                    try self.push(.{ .response = resp.event });
                    if (resp.event.status_code >= 100 and resp.event.status_code < 200) {
                        return .{ .value = {} }; // informational response; final response HEADERS still follow
                    }
                    rs.state = .headers_done;
                    rs.content_length = resp.content_length;
                    rs.expects_bodyless = rs.head_response or resp.event.status_code == 204 or resp.event.status_code == 304;
                } else if (rs.state == .headers_done) {
                    if (rs.expects_bodyless) return .{ .rejected = .message_error };
                    const outcome = self.decodeTrailers(id, f.payload, rs) catch |e| switch (e) {
                        error.Blocked => {
                            try self.blockHeaders(rs, f.payload, .trailers);
                            return .{ .value = {} };
                        },
                        else => return e,
                    };
                    switch (outcome) {
                        .value => {},
                        .rejected => |code| return .{ .rejected = code },
                    }
                    rs.state = .trailers_done;
                } else return .{ .rejected = .message_error };
            },
            .data => {
                if (rs.state != .headers_done) return self.fail(.frame_unexpected, "DATA before response HEADERS");
                if (rs.expects_bodyless and f.payload.len > 0) return .{ .rejected = .message_error };
                const body_received = std.math.add(u64, rs.body_received, f.payload.len) catch
                    return .{ .rejected = .message_error };
                if (rs.content_length) |cl| if (body_received > cl) return .{ .rejected = .message_error };
                if (f.payload.len > 0) {
                    const body = try self.dupe(f.payload);
                    try self.push(.{ .data = .{ .data = body, .stream_id = id } });
                }
                rs.body_received = body_received;
                rs.body_unconsumed += f.payload.len;
            },
            .push_promise => {
                _ = varint.decode(f.payload) catch return self.fail(.frame_error, "malformed PUSH_PROMISE");
                return self.fail(.id_error, "PUSH_PROMISE for disabled push");
            },
            .cancel_push, .settings, .goaway, .max_push_id => return self.fail(.frame_unexpected, "control frame on a response stream"),
            else => {},
        }
        return .{ .value = {} };
    }

    /// Collapse a QPACK-decoded field section into a Request, pulling the four
    /// pseudo-headers into the shared shape and keeping the rest as headers.
    fn decodeRequest(self: *Connection, id: u64, block: []const u8, rs: *RequestStream) Error!StreamOutcome(events.Request) {
        // A malformed QPACK block is connection-fatal QPACK_DECOMPRESSION_FAILED;
        // HTTP field violations below are stream-level message errors.
        const decoded = self.qpack_dec.decode(block) catch |err| return self.onQpackDecodeError(err);
        self.markQpackSectionIfDynamic(rs);
        var method: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var authority: ?[]const u8 = null;
        var scheme: ?[]const u8 = null;
        var host: ?[]const u8 = null;
        var regular: std.ArrayListUnmanaged(Header) = .empty;
        defer regular.deinit(self.gpa);
        var seen_regular = false;

        for (decoded) |h| {
            if (h.name.len > 0 and h.name[0] == ':') {
                if (seen_regular) return .{ .rejected = .message_error }; // pseudo after regular (RFC 9114 4.3)
                // A pseudo-header value is validated like any other (no CR/LF/NUL/
                // control), so a :authority carrying CR/LF cannot be synthesized into
                // a `host` header and split a downgraded HTTP/1.1 request line.
                if (!fields.validValue(h.value)) return .{ .rejected = .message_error };
                // A request pseudo-header appears at most once (RFC 9114 4.3.1 ->
                // RFC 9113 8.3); a duplicate is malformed.
                const slot = if (eql(h.name, ":method")) &method else if (eql(h.name, ":path")) &path else if (eql(h.name, ":authority")) &authority else if (eql(h.name, ":scheme")) &scheme else return .{ .rejected = .message_error };
                if (slot.* != null) return .{ .rejected = .message_error };
                slot.* = h.value;
            } else {
                seen_regular = true;
                // RFC 9114 4.2 inherits the HTTP/2 field rules: lowercase token
                // names, no connection-specific fields, and TE only "trailers".
                if (!fields.isValidFieldName(h.name)) return .{ .rejected = .message_error };
                if (!fields.validValue(h.value)) return .{ .rejected = .message_error };
                if (fields.isConnectionSpecific(h.name)) return .{ .rejected = .message_error };
                if (eql(h.name, "te") and !eql(h.value, "trailers")) return .{ .rejected = .message_error };
                if (eql(h.name, "host")) {
                    if (host) |prev| {
                        if (!eql(prev, h.value)) return .{ .rejected = .message_error };
                    } else host = h.value;
                    continue;
                }
                if (eql(h.name, "content-length")) {
                    const cl = ascii.parseDecimal(u64, h.value) orelse return .{ .rejected = .message_error };
                    // A repeated Content-Length is malformed unless it agrees (RFC 9110).
                    if (rs.content_length) |prev| {
                        if (prev != cl) return .{ .rejected = .message_error };
                    } else rs.content_length = cl;
                }
                regular.append(self.gpa, h) catch return error.OutOfMemory;
            }
        }
        const method_v = method orelse return .{ .rejected = .message_error };
        if (!fields.isValidToken(method_v)) return .{ .rejected = .message_error };
        if (authority) |auth| {
            if (auth.len == 0 or std.mem.indexOfAny(u8, auth, " \t") != null) return .{ .rejected = .message_error };
        }
        if (eql(method_v, "HEAD")) self.send_bodyless.put(self.gpa, id, {}) catch return error.OutOfMemory;
        const target_v = if (eql(method_v, "CONNECT")) blk: {
            if (path != null or scheme != null) return .{ .rejected = .message_error };
            const auth = authority orelse return .{ .rejected = .message_error };
            if (auth.len == 0) return .{ .rejected = .message_error };
            break :blk auth;
        } else blk: {
            const path_v = path orelse return .{ .rejected = .message_error };
            const scheme_v = scheme orelse return .{ .rejected = .message_error };
            if (path_v.len == 0 or scheme_v.len == 0) return .{ .rejected = .message_error };
            break :blk path_v;
        };
        if (authority) |auth| {
            if (host) |h| if (!eql(auth, h)) return .{ .rejected = .message_error };
        }

        // Materialise everything into the arena so the slices outlive the next
        // QPACK decode (which clears its store).
        const a = self.arena.allocator();
        var headers: std.ArrayListUnmanaged(Header) = .empty;
        const canonical_host: ?[]const u8 = if (authority) |auth| auth else host;
        if (canonical_host) |h| {
            if (h.len > 0) headers.append(a, .{ .name = "host", .value = try a.dupe(u8, h) }) catch return error.OutOfMemory;
        }
        for (regular.items) |h| {
            headers.append(a, .{ .name = try a.dupe(u8, h.name), .value = try a.dupe(u8, h.value) }) catch return error.OutOfMemory;
        }
        const target = try a.dupe(u8, target_v);
        const q = std.mem.indexOfScalar(u8, target, '?');
        const out = events.Request{
            .method = try a.dupe(u8, method_v),
            .target = target,
            .path = if (q) |i| target[0..i] else target,
            .query = if (q) |i| target[i + 1 ..] else target[target.len..],
            .http_version = "3",
            .headers = headers.items,
            .stream_id = id,
        };
        try self.acknowledgeQpackSectionIfPending(id, rs);
        return .{ .value = out };
    }

    /// Collapse a QPACK-decoded field section into a Response. The only legal
    /// response pseudo-header is `:status`; request pseudo-headers are malformed.
    fn decodeResponse(self: *Connection, id: u64, block: []const u8, rs: *RequestStream) Error!StreamOutcome(CollapsedResponse) {
        const decoded = self.qpack_dec.decode(block) catch |err| return self.onQpackDecodeError(err);
        self.markQpackSectionIfDynamic(rs);
        var status: ?u16 = null;
        var content_length: ?u64 = null;
        var regular: std.ArrayListUnmanaged(Header) = .empty;
        defer regular.deinit(self.gpa);
        var seen_regular = false;

        for (decoded) |h| {
            if (h.name.len == 0) return .{ .rejected = .message_error };
            if (h.name[0] == ':') {
                if (seen_regular) return .{ .rejected = .message_error };
                if (!eql(h.name, ":status")) return .{ .rejected = .message_error };
                if (status != null) return .{ .rejected = .message_error };
                if (h.value.len != 3) return .{ .rejected = .message_error };
                var code: u16 = 0;
                for (h.value) |d| {
                    if (d < '0' or d > '9') return .{ .rejected = .message_error };
                    code = code * 10 + (d - '0');
                }
                if (code < 100 or code > 599 or code == 101) return .{ .rejected = .message_error };
                status = code;
            } else {
                seen_regular = true;
                if (!fields.isValidFieldName(h.name)) return .{ .rejected = .message_error };
                if (!fields.validValue(h.value)) return .{ .rejected = .message_error };
                if (fields.isConnectionSpecific(h.name)) return .{ .rejected = .message_error };
                if (eql(h.name, "te") and !eql(h.value, "trailers")) return .{ .rejected = .message_error };
                if (eql(h.name, "content-length")) {
                    const cl = ascii.parseDecimal(u64, h.value) orelse return .{ .rejected = .message_error };
                    if (content_length) |prev| {
                        if (prev != cl) return .{ .rejected = .message_error };
                    } else content_length = cl;
                }
                regular.append(self.gpa, h) catch return error.OutOfMemory;
            }
        }
        const code = status orelse return .{ .rejected = .message_error };
        if (content_length != null and responseStatusDisallowsContentLength(code)) return .{ .rejected = .message_error };

        const a = self.arena.allocator();
        var headers: std.ArrayListUnmanaged(Header) = .empty;
        for (regular.items) |h| {
            headers.append(a, .{ .name = try a.dupe(u8, h.name), .value = try a.dupe(u8, h.value) }) catch return error.OutOfMemory;
        }
        const out = CollapsedResponse{
            .event = .{
                .status_code = code,
                .reason = "",
                .http_version = "3",
                .headers = headers.items,
                .stream_id = id,
            },
            .content_length = content_length,
        };
        try self.acknowledgeQpackSectionIfPending(id, rs);
        return .{ .value = out };
    }

    fn decodeTrailers(self: *Connection, id: u64, block: []const u8, rs: *RequestStream) Error!StreamOutcome(void) {
        const decoded = self.qpack_dec.decode(block) catch |err| return self.onQpackDecodeError(err);
        self.markQpackSectionIfDynamic(rs);
        var copied = self.gpa.alloc(Header, decoded.len) catch return error.OutOfMemory;
        var n: usize = 0;
        var keep_copied = false;
        defer {
            if (!keep_copied) {
                for (copied[0..n]) |h| {
                    self.gpa.free(h.name);
                    self.gpa.free(h.value);
                }
                self.gpa.free(copied);
            }
        }
        for (decoded) |h| {
            if (h.name.len == 0 or h.name[0] == ':') return .{ .rejected = .message_error };
            if (!fields.isValidFieldName(h.name)) return .{ .rejected = .message_error };
            if (!fields.validValue(h.value)) return .{ .rejected = .message_error };
            if (fields.isConnectionSpecific(h.name)) return .{ .rejected = .message_error };
            if (!fields.trailerFieldAllowed(h.name)) return .{ .rejected = .message_error };
            const name = self.gpa.dupe(u8, h.name) catch return error.OutOfMemory;
            errdefer self.gpa.free(name);
            const value = self.gpa.dupe(u8, h.value) catch return error.OutOfMemory;
            copied[n] = .{ .name = name, .value = value };
            n += 1;
        }
        if (rs.trailers != null) return .{ .rejected = .message_error };
        rs.trailers = copied;
        keep_copied = true;
        try self.acknowledgeQpackSectionIfPending(id, rs);
        return .{ .value = {} };
    }

    fn materializeTrailers(self: *Connection, rs: *RequestStream) Error![]const Header {
        const stored = rs.trailers orelse return &.{};
        const a = self.arena.allocator();
        const out = a.alloc(Header, stored.len) catch return error.OutOfMemory;
        for (stored, 0..) |h, i| {
            out[i] = .{
                .name = a.dupe(u8, h.name) catch return error.OutOfMemory,
                .value = a.dupe(u8, h.value) catch return error.OutOfMemory,
            };
        }
        rs.clearTrailers(self.gpa);
        return out;
    }

    fn dupe(self: *Connection, bytes: []const u8) Error![]const u8 {
        return self.arena.allocator().dupe(u8, bytes) catch return error.OutOfMemory;
    }

    fn push(self: *Connection, ev: H3Event) Error!void {
        self.queue.append(self.gpa, ev) catch return error.OutOfMemory;
    }

    /// Return DATA payload credit after the application has consumed it.
    pub fn consumeData(self: *Connection, id: u64, length: u64) Error!void {
        const rs = self.streams.getPtr(id) orelse return error.H3Error;
        if (length > rs.body_unconsumed) return error.H3Error;
        self.qc.creditStream(id, length);
        rs.body_unconsumed -= length;
        if (rs.state == .done and rs.body_unconsumed == 0) {
            if (self.qc.dropStream(id)) self.removeStreamState(id);
        }
    }

    /// Pull the next ready event, or `need_data` when the queue is drained. Mirrors
    /// the H1/H2 one-event-per-call contract.
    pub fn nextEvent(self: *Connection) H3Event {
        if (self.qpos >= self.queue.items.len) {
            self.queue.clearRetainingCapacity();
            self.qpos = 0;
            // Every queued event has been handed out (and, per the core's contract,
            // materialised by the caller before this call), so the strings they
            // borrowed can be reclaimed. Without this the arena grows for the life
            // of the connection - one block per request body and header set.
            _ = self.arena.reset(.retain_capacity);
            if (self.qc.closed) return .connection_closed;
            return .need_data;
        }
        const ev = self.queue.items[self.qpos];
        self.qpos += 1;
        return ev;
    }

    /// Whether the integrator must drain events before pumping another batch.
    pub fn eventQueueFull(self: *const Connection) bool {
        return self.queue.items.len - self.qpos >= self.limits.max_pending_events;
    }

    // ---- response send path (RFC 9114 4.1) -------------------------------------

    /// A response field is well-formed before it goes on the wire (RFC 9114 4.2):
    /// a lowercase token name (no pseudo-header - the server supplies :status), no
    /// connection-specific field, and a value with no control bytes (the write side
    /// is stricter than the read side and rejects CR/LF/NUL/HTAB and edge
    /// whitespace), so a re-serialised response cannot split or inject.
    fn validateResponseHeaders(headers: []const Header) Error!?u64 {
        var content_length: ?u64 = null;
        for (headers) |h| try validateResponseHeader(h, &content_length);
        return content_length;
    }

    /// Send a response head on request stream `id`: a HEADERS frame whose field
    /// section is `:status` plus `headers`, QPACK-encoded. Follow with `sendData`
    /// for the body and `endStream` to finish. Responses ride the client-initiated
    /// request stream; HEADERS must precede DATA and nothing follows the FIN, both
    /// enforced here. `headers` must not contain pseudo-headers (names beginning
    /// ":") - the server supplies :status.
    pub fn sendResponse(self: *Connection, id: u64, status: u16, headers: []const Header) Error!void {
        if (self.qc.role != .server) return error.H3Error;
        if (quic_stream.StreamType.of(id) != .client_bidi) return error.H3Error; // responses ride the request stream
        if (status < 200 or status > 599) return error.H3Error; // final responses are non-1xx
        if (self.peekSendState(id) != .idle) return error.H3Error; // HEADERS once, before DATA/FIN
        const content_length = try validateResponseHeaders(headers);
        if (content_length != null and responseStatusDisallowsContentLength(status)) return error.H3Error;

        var status_buf: [3]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch return error.H3Error;
        var all: std.ArrayList(Header) = .empty;
        defer all.deinit(self.gpa);
        all.append(self.gpa, .{ .name = ":status", .value = status_str }) catch return error.OutOfMemory;
        all.appendSlice(self.gpa, headers) catch return error.OutOfMemory;
        const settings = self.peer_settings orelse h3_stream.Settings{};
        const section_size = fieldSectionSize(all.items) catch return error.H3Error;
        if (section_size > settings.max_field_section_size) return error.H3Error;

        // Our control stream + SETTINGS must precede any response (RFC 9114 6.2.1).
        try self.initiateControl();
        var section: std.ArrayList(u8) = .empty;
        defer section.deinit(self.gpa);
        try self.encodeFieldSection(&section, id, all.items);

        var frame: std.ArrayListUnmanaged(u8) = .empty;
        defer frame.deinit(self.gpa);
        h3_frame.append(&frame, self.gpa, .headers, section.items) catch return error.OutOfMemory;
        const already_bodyless = self.send_bodyless.contains(id);
        if (!already_bodyless and (status == 204 or status == 304)) {
            self.send_bodyless.put(self.gpa, id, {}) catch return error.OutOfMemory;
            errdefer _ = self.send_bodyless.remove(id);
        }
        try self.installSendContentLength(id, content_length);
        errdefer self.clearSendBodyAccounting(id);
        try self.streamSend(id, frame.items, false);
        try self.setSendState(id, .headers_sent);
    }

    /// Send an informational 1xx response. It is a HEADERS frame like a final
    /// response, but it does not change the send state; the final response still
    /// follows on the same request stream.
    pub fn sendInformational(self: *Connection, id: u64, status: u16, headers: []const Header) Error!void {
        if (self.qc.role != .server) return error.H3Error;
        if (quic_stream.StreamType.of(id) != .client_bidi) return error.H3Error;
        if (status < 100 or status > 199 or status == 101) return error.H3Error;
        if (self.peekSendState(id) != .idle) return error.H3Error;
        const content_length = try validateResponseHeaders(headers);
        if (content_length != null) return error.H3Error;

        var status_buf: [3]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch return error.H3Error;
        var all: std.ArrayList(Header) = .empty;
        defer all.deinit(self.gpa);
        all.append(self.gpa, .{ .name = ":status", .value = status_str }) catch return error.OutOfMemory;
        all.appendSlice(self.gpa, headers) catch return error.OutOfMemory;
        const settings = self.peer_settings orelse h3_stream.Settings{};
        const section_size = fieldSectionSize(all.items) catch return error.H3Error;
        if (section_size > settings.max_field_section_size) return error.H3Error;

        try self.initiateControl();
        var section: std.ArrayList(u8) = .empty;
        defer section.deinit(self.gpa);
        try self.encodeFieldSection(&section, id, all.items);

        var frame: std.ArrayListUnmanaged(u8) = .empty;
        defer frame.deinit(self.gpa);
        h3_frame.append(&frame, self.gpa, .headers, section.items) catch return error.OutOfMemory;
        try self.streamSend(id, frame.items, false);
    }

    /// Send a request head from a client, opening the next client-initiated
    /// bidirectional stream. `end_stream` marks a bodyless request; otherwise body
    /// DATA follows via `sendData` and `endStream`.
    pub fn sendRequest(self: *Connection, method: []const u8, target: []const u8, scheme: []const u8, authority: []const u8, headers: []const Header, end_stream: bool) Error!u64 {
        if (self.qc.role != .client) return error.H3Error;
        const id = self.next_request_stream_id;
        if (id > varint.MAX) return error.H3Error;
        if (self.goaway_recv) |limit| {
            if (id >= limit) return error.H3Error;
        }

        var section: std.ArrayList(u8) = .empty;
        defer section.deinit(self.gpa);
        var all: std.ArrayList(Header) = .empty;
        defer all.deinit(self.gpa);
        if (!fields.isValidToken(method)) return error.H3Error;
        all.append(self.gpa, .{ .name = ":method", .value = method }) catch return error.OutOfMemory;
        const effective_authority = if (eql(method, "CONNECT") and authority.len == 0) target else authority;
        if (effective_authority.len == 0 or std.mem.indexOfAny(u8, effective_authority, " \t") != null) {
            return error.H3Error;
        }
        if (eql(method, "CONNECT")) {
            if (authority.len > 0 and target.len > 0 and !eql(authority, target)) return error.H3Error;
            try validateSendValue(effective_authority);
            all.append(self.gpa, .{ .name = ":authority", .value = effective_authority }) catch return error.OutOfMemory;
        } else {
            if (target.len == 0 or scheme.len == 0) return error.H3Error;
            const pseudo = [_]Header{
                .{ .name = ":scheme", .value = scheme },
                .{ .name = ":authority", .value = effective_authority },
                .{ .name = ":path", .value = target },
            };
            for (pseudo) |h| {
                try validateSendValue(h.value);
                all.append(self.gpa, h) catch return error.OutOfMemory;
            }
        }
        var content_length: ?u64 = null;
        var host: ?[]const u8 = null;
        for (headers) |h| {
            try validateRequestHeader(h, &content_length);
            if (eql(h.name, "host")) {
                if (host) |prev| {
                    if (!eql(prev, h.value)) return error.H3Error;
                } else host = h.value;
                if (!eql(effective_authority, h.value)) return error.H3Error;
            }
            all.append(self.gpa, h) catch return error.OutOfMemory;
        }
        const settings = self.peer_settings orelse h3_stream.Settings{};
        const section_size = fieldSectionSize(all.items) catch return error.H3Error;
        if (section_size > settings.max_field_section_size) return error.H3Error;
        if (end_stream) {
            if (content_length) |cl| if (cl != 0) return error.H3Error;
        }

        if ((self.send_state.get(id) orelse .idle) != .idle) return error.H3Error;
        try self.initiateControl();
        try self.encodeFieldSection(&section, id, all.items);

        var frame: std.ArrayListUnmanaged(u8) = .empty;
        defer frame.deinit(self.gpa);
        h3_frame.append(&frame, self.gpa, .headers, section.items) catch return error.OutOfMemory;
        const gop = self.streams.getOrPut(self.gpa, id) catch return error.OutOfMemory;
        if (!gop.found_existing) gop.value_ptr.* = .{};
        gop.value_ptr.head_response = eql(method, "HEAD");
        try self.installSendContentLength(id, content_length);
        errdefer self.clearSendBodyAccounting(id);
        if (end_stream) try self.checkSendContentComplete(id);
        try self.streamSend(id, frame.items, end_stream);
        try self.setSendState(id, if (end_stream) .fin_sent else .headers_sent);
        self.next_request_stream_id = std.math.add(u64, id, 4) catch return error.H3Error;
        if (self.next_request_stream_id > varint.MAX and id != varint.MAX) {
            self.next_request_stream_id = varint.MAX + 1;
        }
        return id;
    }

    /// Send a chunk of response body on stream `id` as an HTTP/3 DATA frame. The
    /// response head must have been sent first (RFC 9114 4.1).
    pub fn sendData(self: *Connection, id: u64, data: []const u8) Error!void {
        if (self.peekSendState(id) != .headers_sent) return error.H3Error; // DATA only after HEADERS, before FIN
        if (data.len > 0 and self.send_bodyless.contains(id)) return error.H3Error;
        const body_sent = try self.checkedSendBodyTotal(id, data.len);
        var frame: std.ArrayListUnmanaged(u8) = .empty;
        defer frame.deinit(self.gpa);
        h3_frame.append(&frame, self.gpa, .data, data) catch return error.OutOfMemory;
        try self.streamSend(id, frame.items, false);
        self.commitSendBodyTotal(id, body_sent);
    }

    /// Finish the response on stream `id` (send the stream FIN). The head must have
    /// been sent; a second endStream is rejected.
    pub fn endStream(self: *Connection, id: u64) Error!void {
        if (self.peekSendState(id) != .headers_sent) return error.H3Error;
        try self.checkSendContentComplete(id);
        try self.streamSend(id, &.{}, true);
        try self.setSendState(id, .fin_sent);
    }

    /// Finish a request/response with a trailer field section. In HTTP/3 the FIN is
    /// carried by the QUIC stream, so the trailing HEADERS frame is sent with `fin`.
    pub fn sendTrailers(self: *Connection, id: u64, trailers: []const Header) Error!void {
        if (trailers.len == 0) return self.endStream(id);
        if (self.peekSendState(id) != .headers_sent) return error.H3Error;
        if (self.send_bodyless.contains(id)) return error.H3Error;
        try self.checkSendContentComplete(id);
        for (trailers) |h| try validateTrailerHeader(h);
        const settings = self.peer_settings orelse h3_stream.Settings{};
        const section_size = fieldSectionSize(trailers) catch return error.H3Error;
        if (section_size > settings.max_field_section_size) return error.H3Error;

        var section: std.ArrayList(u8) = .empty;
        defer section.deinit(self.gpa);
        try self.encodeFieldSection(&section, id, trailers);

        var frame: std.ArrayListUnmanaged(u8) = .empty;
        defer frame.deinit(self.gpa);
        h3_frame.append(&frame, self.gpa, .headers, section.items) catch return error.OutOfMemory;
        try self.streamSend(id, frame.items, true);
        try self.setSendState(id, .fin_sent);
    }

    /// Abruptly cancel a request stream with `error_code` (RFC 9114 4.4): RESET_STREAM
    /// the response send half and STOP_SENDING the request recv half, so neither side
    /// keeps producing. Used to reject a request or abandon a response without closing
    /// the connection. The stream's send state is marked finished.
    pub fn resetStream(self: *Connection, id: u64, error_code: u64) Error!void {
        if (quic_stream.StreamType.of(id) != .client_bidi) return error.H3Error;
        if (error_code > varint.MAX) return error.H3Error;
        // A response that already finished (FIN sent) has nothing to reset; a second
        // reset would recreate a reclaimed QUIC send stream and emit a RESET_STREAM
        // with a stale final size. No-op once the send half is done.
        if (self.peekSendState(id) == .fin_sent) return;
        self.qc.resetStream(id, error_code) catch return error.H3Error;
        self.qc.stopSending(id, error_code) catch return error.H3Error;
        if (self.streams.getPtr(id)) |rs| {
            try self.cancelQpackSectionIfPending(id, rs);
            self.releaseStreamCredit(id, rs);
            rs.state = .rejected;
        }
        try self.setSendState(id, .fin_sent);
    }

    fn peekSendState(self: *const Connection, id: u64) SendState {
        return self.send_state.get(id) orelse .idle;
    }

    fn setSendState(self: *Connection, id: u64, s: SendState) Error!void {
        self.send_state.put(self.gpa, id, s) catch return error.OutOfMemory;
        if (s == .fin_sent) {
            _ = self.send_bodyless.remove(id);
            self.clearSendBodyAccounting(id);
        }
    }

    fn installSendContentLength(self: *Connection, id: u64, content_length: ?u64) Error!void {
        self.clearSendBodyAccounting(id);
        const cl = content_length orelse return;
        self.send_content_length.put(self.gpa, id, cl) catch return error.OutOfMemory;
        errdefer _ = self.send_content_length.remove(id);
        self.send_body_sent.put(self.gpa, id, 0) catch return error.OutOfMemory;
    }

    fn clearSendBodyAccounting(self: *Connection, id: u64) void {
        _ = self.send_content_length.remove(id);
        _ = self.send_body_sent.remove(id);
    }

    fn checkedSendBodyTotal(self: *Connection, id: u64, len: usize) Error!?u64 {
        const cl = self.send_content_length.get(id) orelse return null;
        const sent = self.send_body_sent.get(id) orelse 0;
        const next = std.math.add(u64, sent, std.math.cast(u64, len) orelse return error.H3Error) catch return error.H3Error;
        if (next > cl) return error.H3Error;
        return next;
    }

    fn commitSendBodyTotal(self: *Connection, id: u64, total: ?u64) void {
        if (total) |n| {
            if (self.send_body_sent.getPtr(id)) |sent| sent.* = n;
        }
    }

    fn checkSendContentComplete(self: *Connection, id: u64) Error!void {
        if (self.send_bodyless.contains(id)) return;
        const cl = self.send_content_length.get(id) orelse return;
        const sent = self.send_body_sent.get(id) orelse 0;
        if (sent != cl) return error.H3Error;
    }

    fn streamSend(self: *Connection, id: u64, bytes: []const u8, fin: bool) Error!void {
        self.qc.sendStreamData(id, bytes, fin) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.H3Error, // FinalSizeError etc.
        };
    }
};

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn validateContentLength(h: Header, content_length: *?u64) Error!void {
    if (!eql(h.name, "content-length")) return;
    const cl = ascii.parseDecimal(u64, h.value) orelse return error.H3Error;
    if (content_length.*) |prev| {
        if (prev != cl) return error.H3Error;
    } else content_length.* = cl;
}

fn validateRequestHeader(h: Header, content_length: *?u64) Error!void {
    if (!fields.isValidFieldName(h.name)) return error.H3Error;
    try validateSendValue(h.value);
    if (fields.isConnectionSpecific(h.name)) return error.H3Error;
    if (eql(h.name, "te") and !eql(h.value, "trailers")) return error.H3Error;
    try validateContentLength(h, content_length);
}

fn validateResponseHeader(h: Header, content_length: *?u64) Error!void {
    if (!fields.isValidFieldName(h.name)) return error.H3Error;
    try validateSendValue(h.value);
    if (fields.isConnectionSpecific(h.name)) return error.H3Error;
    if (eql(h.name, "te") and !eql(h.value, "trailers")) return error.H3Error;
    try validateContentLength(h, content_length);
}

fn responseStatusDisallowsContentLength(status: u16) bool {
    return (status >= 100 and status <= 199) or status == 204;
}

fn validateTrailerHeader(h: Header) Error!void {
    if (!fields.isValidFieldName(h.name)) return error.H3Error;
    try validateSendValue(h.value);
    if (fields.isConnectionSpecific(h.name)) return error.H3Error;
    if (!fields.trailerFieldAllowed(h.name)) return error.H3Error;
}

fn fieldSectionSize(headers: []const Header) Error!u64 {
    var size: u64 = 0;
    for (headers) |h| {
        const name_len: u64 = std.math.cast(u64, h.name.len) orelse return error.H3Error;
        const value_len: u64 = std.math.cast(u64, h.value.len) orelse return error.H3Error;
        const field_size = std.math.add(u64, name_len, value_len) catch return error.H3Error;
        size = std.math.add(u64, size, field_size) catch return error.H3Error;
        size = std.math.add(u64, size, 32) catch return error.H3Error;
    }
    return size;
}

fn validateSendValue(value: []const u8) Error!void {
    for (value) |ch| if (ch < 0x20 or ch == 0x7F) return error.H3Error;
    if (value.len > 0) {
        const first = value[0];
        const last = value[value.len - 1];
        if (first == ' ' or first == '\t' or last == ' ' or last == '\t') return error.H3Error;
    }
}

const testing = std.testing;

// Build a client 1-RTT datagram carrying a STREAM frame on the given bidi stream
// id whose body is the H3 frames, so a server QUIC+H3 stack decodes it. H3 request
// data is application data, so it rides the Application space (STREAM is illegal in
// Initial); the matching server installs the test app keys via testInstallAppKeys.
fn buildRequest(gpa: std.mem.Allocator, dcid: []const u8, stream_id: u64, h3_bytes: []const u8) ![]u8 {
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0a); // STREAM, LEN set, no OFF, no FIN
    try varint.append(&sframe, gpa, stream_id);
    try varint.append(&sframe, gpa, h3_bytes.len);
    try sframe.appendSlice(gpa, h3_bytes);
    return @import("../quic/connection.zig").test_support.buildApp(gpa, dcid, 0, sframe.items);
}

test "decode a GET request over HTTP/3" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc); // H3 request data rides the Application space
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A HEADERS frame whose QPACK block is: prefix RIC=0,Base=0; indexed :method
    // GET (idx 17), :scheme https (idx 23), :path "/" (idx 1), literal :authority.
    const qpack_block = [_]u8{
        0x00, 0x00, // prefix
        0xC0 | 17, // :method GET
        0xC0 | 23, // :scheme https
        0xC0 | 1, // :path /
        0x50 | 0, 0x03, 'e', 'x', 'y', // literal name-ref :authority = "exy"
    };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);

    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    const ev = h3.nextEvent();
    try testing.expect(ev == .request);
    try testing.expectEqualStrings("GET", ev.request.method);
    try testing.expectEqualStrings("/", ev.request.path);
    try testing.expectEqualStrings("3", ev.request.http_version);
    try testing.expectEqualStrings("host", ev.request.headers[0].name);
    try testing.expectEqualStrings("exy", ev.request.headers[0].value);
}

test "matching authority and host are canonicalized to one host" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x46 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const qpack_block = [_]u8{
        0x00,      0x00,
        0xC0 | 17, 0xC0 | 23,
        0xC0 | 1,  0x50 | 0,
        0x03,      'e',
        'x',       'y',
        0x20 | 4,  'h',
        'o',       's',
        't',       0x03,
        'e',       'x',
        'y',
    };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);

    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    const ev = h3.nextEvent();
    try testing.expect(ev == .request);
    try testing.expectEqual(@as(usize, 1), ev.request.headers.len);
    try testing.expectEqualStrings("host", ev.request.headers[0].name);
    try testing.expectEqualStrings("exy", ev.request.headers[0].value);
}

test "host header is used when authority is absent" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x47 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const qpack_block = [_]u8{
        0x00,      0x00,
        0xC0 | 17, 0xC0 | 23,
        0xC0 | 1,  0x20 | 4,
        'h',       'o',
        's',       't',
        0x03,      'e',
        'x',       'y',
    };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);

    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    const ev = h3.nextEvent();
    try testing.expect(ev == .request);
    try testing.expectEqual(@as(usize, 1), ev.request.headers.len);
    try testing.expectEqualStrings("host", ev.request.headers[0].name);
    try testing.expectEqualStrings("exy", ev.request.headers[0].value);
}

test "a CR/LF in a pseudo-header value is malformed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // :authority = "ex\r\ny" - a CR/LF smuggled into the pseudo-header value must
    // be rejected, or an h3->h1 downgrade could split it into a host header plus a
    // second request line.
    const qpack_block = [_]u8{
        0x00,     0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1,
        0x50 | 0, 0x05, 'e',       'x',       '\r',
        '\n',     'y',
    };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);

    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    // The malformed request resets the stream (no Request event, connection stays up).
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .need_data);
    try testing.expect(!qc.closed);
}

test "a request stream id above 2^32 is not truncated" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const qpack_block = [_]u8{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x50 | 0, 0x03, 'e', 'x', 'y' };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);

    // A client-initiated bidi stream id (0 mod 4) above the 32-bit range. A u32
    // truncation would surface it as 0, sending a later response on the wrong stream.
    const big_id: u64 = 0x1_0000_0000;
    const dgram = try buildRequest(gpa, &dcid, big_id, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(big_id);

    const ev = h3.nextEvent();
    try testing.expect(ev == .request);
    try testing.expectEqual(big_id, ev.request.stream_id);
}

test "CONNECT request uses authority form without scheme or path" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x45 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const qpack_block = [_]u8{
        0x00, 0x00, // prefix
        0xC0 | 15, // :method CONNECT
        0x50 | 0,
        0x0b,
        'e',
        'x',
        'a',
        'm',
        'p',
        'l',
        'e',
        ':',
        '4',
        '4',
        '3',
    };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);

    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    const ev = h3.nextEvent();
    try testing.expect(ev == .request);
    try testing.expectEqualStrings("CONNECT", ev.request.method);
    try testing.expectEqualStrings("example:443", ev.request.target);
    try testing.expectEqualStrings("example:443", ev.request.path);
    try testing.expectEqualStrings("", ev.request.query);
    try testing.expectEqualStrings("host", ev.request.headers[0].name);
    try testing.expectEqualStrings("example:443", ev.request.headers[0].value);
}

// Feed a HEADERS frame whose QPACK block is `qpack_block` and return the result of
// pumping stream 0 - so a malformed-request test asserts the H3Error directly.
// Pump a HEADERS-only request and report whether it was ACCEPTED (a Request event was
// produced). A malformed request is now rejected with a stream reset (not a connection
// error), so it returns false rather than error.H3Error.
fn pumpHeaders(gpa: std.mem.Allocator, qpack_block: []const u8) Error!bool {
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = quic_conn.Connection.init(gpa, .server, &dcid) catch return error.H3Error;
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    h3_frame.append(&h3_bytes, gpa, .headers, qpack_block) catch return error.H3Error;
    const dgram = buildRequest(gpa, &dcid, 0, h3_bytes.items) catch return error.H3Error;
    defer gpa.free(dgram);
    qc.receiveDatagram(dgram, 1000) catch return error.H3Error;
    try h3.pump(0);
    return h3.nextEvent() == .request;
}

test "a request method containing spaces is malformed" {
    const block = [_]u8{ 0x00, 0x00, 0x27, 0x00 } ++ ":method".* ++ [_]u8{0x13} ++
        "GET /admin HTTP/1.1".* ++ [_]u8{ 0xC0 | 23, 0xC0 | 1 };
    try testing.expect(!try pumpHeaders(testing.allocator, &block));
}

test "a request authority containing spaces is malformed" {
    const block = [_]u8{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x50, 0x16 } ++
        "a.example evil.example".*;
    try testing.expect(!try pumpHeaders(testing.allocator, &block));
}

test "a duplicate request pseudo-header is malformed" {
    // :method GET twice (RFC 9113 8.3 via RFC 9114 4.3.1).
    try testing.expect(!try pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0xC0 | 17 }));
}

test "CONNECT with scheme or path is malformed" {
    // Non-extended CONNECT uses :authority form; :scheme/:path are forbidden.
    try testing.expect(!try pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 15, 0xC0 | 23, 0xC0 | 1, 0x50 | 0, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', ':', '4', '4', '3' }));
}

test "an uppercase field name is malformed" {
    // literal name "Te" (0x20|2), value "x": a non-lowercase token (RFC 9114 4.2).
    try testing.expect(!try pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 2, 'T', 'e', 0x01, 'x' }));
}

test "a connection-specific field is malformed" {
    // literal name "connection" (len 10: 3-bit prefix 7 + continuation 3), value "x".
    try testing.expect(!try pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 7, 0x03, 'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', 0x01, 'x' }));
}

test "TE with a value other than trailers is malformed" {
    // literal name "te" (0x20|2), value "gzip".
    try testing.expect(!try pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 2, 't', 'e', 0x04, 'g', 'z', 'i', 'p' }));
}

test "TE trailers is accepted" {
    // The one legal TE value (RFC 9114 4.2): te: trailers must NOT be rejected.
    try testing.expect(try pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 2, 't', 'e', 0x08, 't', 'r', 'a', 'i', 'l', 'e', 'r', 's' }));
}

test "conflicting authority and host is malformed" {
    try testing.expect(!try pumpHeaders(testing.allocator, &.{
        0x00,      0x00,
        0xC0 | 17, 0xC0 | 23,
        0xC0 | 1,  0x50 | 0,
        0x03,      'e',
        'x',       'y',
        0x20 | 4,  'h',
        'o',       's',
        't',       0x03,
        'b',       'a',
        'd',
    }));
}

test "conflicting duplicate host headers are malformed" {
    try testing.expect(!try pumpHeaders(testing.allocator, &.{
        0x00,      0x00,
        0xC0 | 17, 0xC0 | 23,
        0xC0 | 1,  0x20 | 4,
        'h',       'o',
        's',       't',
        0x03,      'e',
        'x',       'y',
        0x20 | 4,  'h',
        'o',       's',
        't',       0x03,
        'b',       'a',
        'd',
    }));
}

test "a malformed request resets its stream but not the connection" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x88, 0x89, 0x8a, 0x8b };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var req: std.ArrayListUnmanaged(u8) = .empty;
    defer req.deinit(gpa);
    // A duplicate :method - malformed (RFC 9114 4.3.1).
    try h3_frame.append(&req, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0xC0 | 17 });
    const bad = try buildRequestOnFin(gpa, &dcid, 0, 0, req.items);
    defer gpa.free(bad);
    try qc.receiveDatagram(bad, 1000);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .need_data); // rejected, no request
    try testing.expect(!qc.closed); // the connection is NOT closed

    // The server reset the stream: a RESET_STREAM is queued to send.
    try qc.flushSend(2000);
    try testing.expect(qc.datagramsToSend().len > 0);

    // A subsequent VALID request on a new stream still works - the connection is alive.
    var ok: std.ArrayListUnmanaged(u8) = .empty;
    defer ok.deinit(gpa);
    try h3_frame.append(&ok, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 });
    const good = try buildRequestOnFin(gpa, &dcid, 4, 1, ok.items);
    defer gpa.free(good);
    try qc.receiveDatagram(good, 3000);
    try h3.pump(4);
    try testing.expect(h3.nextEvent() == .request);
}

test "a rejected open stream stays quarantined on a later frame" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x8c, 0x8d, 0x8e, 0x8f };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A malformed HEADERS (duplicate :method) on an OPEN stream (no FIN), so the
    // recv stream is not terminal and the H3 entry cannot be dropped yet.
    var bad: std.ArrayListUnmanaged(u8) = .empty;
    defer bad.deinit(gpa);
    try h3_frame.append(&bad, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0xC0 | 17 });
    const d1 = try buildRequest(gpa, &dcid, 0, bad.items); // no FIN
    defer gpa.free(d1);
    try qc.receiveDatagram(d1, 1000);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .need_data); // rejected, stream still tracked

    // The peer (ignoring our reset) sends a VALID HEADERS on the same stream. It must
    // NOT surface a request - the stream is quarantined.
    var more: std.ArrayListUnmanaged(u8) = .empty;
    defer more.deinit(gpa);
    try h3_frame.append(&more, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 });
    const d2 = try buildRequestAt(gpa, &dcid, bad.items.len, 1, more.items);
    defer gpa.free(d2);
    try qc.receiveDatagram(d2, 1100);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .need_data); // still no request
}

test "a partial request stream cannot slip past a GOAWAY by completing later" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x9a, 0x9b, 0x9c, 0x9d };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A HEADERS frame on stream 0 (type 0x01, declared length 5) of which only 3 of
    // the 5 payload bytes arrive: decode needs more, so the request stream is merely
    // tracked as idle and no Request is surfaced yet.
    const d1 = try buildRequest(gpa, &dcid, 0, &.{ 0x01, 0x05, 0x00, 0x00, 0xC0 | 17 });
    defer gpa.free(d1);
    try qc.receiveDatagram(d1, 1000);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .need_data);

    // The server then advertises a GOAWAY: it will not process stream 0 or above.
    try h3.shutdown(0);

    // The peer completes the header block (the remaining 2 bytes at stream offset 5).
    // Because the stream was only pre-tracked (idle), the GOAWAY guard must still
    // reject it - surfacing a Request here would process a request past the limit
    // the server just promised not to cross.
    const d2 = try buildRequestAt(gpa, &dcid, 5, 1, &.{ 0xC0 | 23, 0xC0 | 1 });
    defer gpa.free(d2);
    try qc.receiveDatagram(d2, 1100);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .need_data); // rejected, not surfaced
}

test "a control byte in a field value is malformed" {
    // literal name "x" (0x20|1), value "a\rb": CR is not a field-vchar (RFC 9110).
    try testing.expect(!try pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 1, 'x', 0x03, 'a', '\r', 'b' }));
}

test "a non-numeric Content-Length is malformed" {
    // content-length: "x" (name length 14 = 3-bit prefix 7 + continuation 7).
    try testing.expect(!try pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 20, 0xC0 | 23, 0xC0 | 1, 0x20 | 7, 0x07, 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 'l', 'e', 'n', 'g', 't', 'h', 0x01, 'x' }));
}

test "two disagreeing Content-Length values are malformed" {
    // content-length: 1 then content-length: 2 (name length 14 = 7 + continuation 7).
    const cl = [_]u8{ 0x20 | 7, 0x07, 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 'l', 'e', 'n', 'g', 't', 'h' };
    try testing.expect(!try pumpHeaders(testing.allocator, &(.{ 0x00, 0x00, 0xC0 | 20, 0xC0 | 23, 0xC0 | 1 } ++ cl ++ .{ 0x01, '1' } ++ cl ++ .{ 0x01, '2' })));
}

test "more body than Content-Length is malformed at the DATA frame" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try postWithContentLength(&h3_bytes, gpa, "2"); // declares 2, sends 5
    try h3_frame.append(&h3_bytes, gpa, .data, "body!");
    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);
    try testing.expect(!qc.closed);
    try testing.expect(h3.nextEvent() == .request);
    try testing.expect(h3.nextEvent() == .need_data);
}

test "a request with a body yields request then data" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xab, 0xcd, 0xef, 0x01 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc); // H3 request data rides the Application space
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const qpack_block = [_]u8{ 0x00, 0x00, 0xC0 | 20, 0xC0 | 23, 0xC0 | 1 }; // POST https /
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);
    try h3_frame.append(&h3_bytes, gpa, .data, "body!");

    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    try testing.expect(h3.nextEvent() == .request);
    const data_ev = h3.nextEvent();
    try testing.expect(data_ev == .data);
    try testing.expectEqualStrings("body!", data_ev.data.data);
}

// Build a request datagram whose STREAM frame sets the FIN bit, so the H3 layer
// sees the stream end (needed to exercise the Content-Length reconciliation).
fn buildRequestFin(gpa: std.mem.Allocator, dcid: []const u8, h3_bytes: []const u8) ![]u8 {
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0b); // STREAM, LEN|FIN set, no OFF
    try varint.append(&sframe, gpa, 0); // stream id 0
    try varint.append(&sframe, gpa, h3_bytes.len);
    try sframe.appendSlice(gpa, h3_bytes);
    return @import("../quic/connection.zig").test_support.buildApp(gpa, dcid, 0, sframe.items);
}

// Build an Application-space datagram carrying a zero-length STREAM frame with the
// FIN bit at `offset` on stream 0 - the request's FIN arriving separately from the
// HEADERS, as when a peer flushes the head and ends the message in a later send.
fn buildFinOnly(gpa: std.mem.Allocator, dcid: []const u8, packet_number: u64, offset: u64) ![]u8 {
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0f); // STREAM, OFF|LEN|FIN set
    try varint.append(&sframe, gpa, 0); // stream id 0
    try varint.append(&sframe, gpa, offset);
    try varint.append(&sframe, gpa, 0); // length 0, no data
    return @import("../quic/connection.zig").test_support.buildApp(gpa, dcid, packet_number, sframe.items);
}

test "a FIN-only completion reclaims the request stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const qpack_block = [_]u8{
        0x00, 0x00, // prefix
        0xC0 | 17, // :method GET
        0xC0 | 23, // :scheme https
        0xC0 | 1, // :path /
        0x50 | 0, 0x03, 'e', 'x', 'y', // literal :authority = "exy"
    };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);

    // The HEADERS arrive first, without a FIN: the request is delivered and the
    // stream is tracked, awaiting the end of the message.
    const headers_dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(headers_dgram);
    try qc.receiveDatagram(headers_dgram, 1000);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .request);
    try testing.expectEqual(@as(usize, 1), h3.streams.count());

    // The FIN then arrives as a separate zero-length STREAM frame. The message ends,
    // and the completed stream must be reclaimed - not left for pumpAll to revisit on
    // every future datagram (the FIN-only completion still has to be consumed to move
    // the recv side terminal).
    const fin_dgram = try buildFinOnly(gpa, &dcid, 1, h3_bytes.items.len);
    defer gpa.free(fin_dgram);
    try qc.receiveDatagram(fin_dgram, 1001);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .end_of_message);
    try testing.expectEqual(@as(usize, 0), h3.streams.count());
}

test "a request stream ending before HEADERS is request incomplete" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc5 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const dgram = try buildRequestFin(gpa, &dcid, &.{});
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);
    try testing.expect(!qc.closed);
    try testing.expect(h3.nextEvent() == .need_data);

    try qc.flushSend(2000);
    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    try peer.sendStreamData(0, &.{}, false);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 3000);
        off += len;
    }
    try testing.expect(peer.streamReset(0));
    try testing.expectEqual(@as(?u64, @intFromEnum(h3_error.ErrorCode.request_incomplete)), peer.streamResetCode(0));
}

// HEADERS for POST / with a content-length header of `cl` (e.g. "5").
fn postWithContentLength(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, cl: []const u8) !void {
    var block: std.ArrayListUnmanaged(u8) = .empty;
    defer block.deinit(gpa);
    try block.appendSlice(gpa, &.{ 0x00, 0x00, 0xC0 | 20, 0xC0 | 23, 0xC0 | 1 }); // POST https /
    try block.appendSlice(gpa, &.{ 0x20 | 7, @intCast(14 - 7) }); // literal name len 14
    try block.appendSlice(gpa, "content-length");
    try block.append(gpa, @intCast(cl.len)); // value, 7-bit length prefix
    try block.appendSlice(gpa, cl);
    try h3_frame.append(out, gpa, .headers, block.items);
}

test "the body matching Content-Length is accepted, a mismatch is malformed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };

    {
        var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
        defer qc.deinit();
        quic_conn.test_support.installAppKeys(&qc);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();
        var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer h3_bytes.deinit(gpa);
        try postWithContentLength(&h3_bytes, gpa, "5");
        try h3_frame.append(&h3_bytes, gpa, .data, "body!");
        const dgram = try buildRequestFin(gpa, &dcid, h3_bytes.items);
        defer gpa.free(dgram);
        try qc.receiveDatagram(dgram, 1000);
        try h3.pump(0); // 5 bytes == content-length 5: clean EOM
    }
    {
        var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
        defer qc.deinit();
        quic_conn.test_support.installAppKeys(&qc);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();
        var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer h3_bytes.deinit(gpa);
        try postWithContentLength(&h3_bytes, gpa, "10"); // declares 10, sends 5
        try h3_frame.append(&h3_bytes, gpa, .data, "body!");
        const dgram = try buildRequestFin(gpa, &dcid, h3_bytes.items);
        defer gpa.free(dgram);
        try qc.receiveDatagram(dgram, 1000);
        try h3.pump(0);
        try testing.expect(!qc.closed);
        try testing.expect(h3.nextEvent() == .request);
        try testing.expect(h3.nextEvent() == .data);
        try testing.expect(h3.nextEvent() == .need_data);
    }
    {
        var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
        defer qc.deinit();
        quic_conn.test_support.installAppKeys(&qc);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();
        var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer h3_bytes.deinit(gpa);
        try postWithContentLength(&h3_bytes, gpa, "4"); // declares 4, sends 5
        try h3_frame.append(&h3_bytes, gpa, .data, "body!");
        const dgram = try buildRequestFin(gpa, &dcid, h3_bytes.items);
        defer gpa.free(dgram);
        try qc.receiveDatagram(dgram, 1000);
        try h3.pump(0);
        try testing.expect(!qc.closed);
        try testing.expect(h3.nextEvent() == .request);
        try testing.expect(h3.nextEvent() == .need_data);
    }
}

test "an unknown non-grease frame on a request stream is ignored" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x2a, 0x2b, 0x2c, 0x2d };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    // An unknown frame type 0x2f (not a grease value, not a known control frame)
    // before the HEADERS: RFC 9114 9 says ignore it, so the request still parses.
    try h3_frame.append(&h3_bytes, gpa, @enumFromInt(0x2f), "junk");
    try h3_frame.append(&h3_bytes, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 });
    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .request);
}

test "an HTTP/2-only frame type on a request stream is unexpected" {
    const gpa = testing.allocator;
    var block: std.ArrayListUnmanaged(u8) = .empty;
    defer block.deinit(gpa);
    try h3_frame.append(&block, gpa, @enumFromInt(0x02), "");
    try testing.expectError(error.H3Error, pumpFrames(gpa, block.items));
}

test "a SETTINGS frame on a request stream is unexpected" {
    const gpa = testing.allocator;
    // SETTINGS (0x04) belongs on the control stream, never a request stream.
    var block: std.ArrayListUnmanaged(u8) = .empty;
    defer block.deinit(gpa);
    h3_frame.append(&block, gpa, .settings, "") catch unreachable;
    try testing.expectError(error.H3Error, pumpFrames(gpa, block.items));
}

// Feed an arbitrary H3 frame stream (already encoded) and pump stream 0.
fn pumpFrames(gpa: std.mem.Allocator, h3_bytes: []const u8) Error!void {
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = quic_conn.Connection.init(gpa, .server, &dcid) catch return error.H3Error;
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();
    const dgram = buildRequest(gpa, &dcid, 0, h3_bytes) catch return error.H3Error;
    defer gpa.free(dgram);
    qc.receiveDatagram(dgram, 1000) catch return error.H3Error;
    try h3.pump(0);
}

test "a completed request stream is dropped and a late frame does not resurrect it" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 });
    const dgram = try buildRequestFin(gpa, &dcid, h3_bytes.items); // FIN ends the stream
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    const request = h3.nextEvent();
    try testing.expect(request == .request);
    try testing.expect(request.request.end_stream);
    try testing.expect(h3.nextEvent() == .need_data);
    // The fully-delivered stream is dropped from both maps.
    var ids: [4]u64 = undefined;
    try testing.expectEqual(@as(usize, 0), qc.streamIds(&ids));

    try testing.expectEqual(@as(u32, 0), h3.streams.count()); // H3 map also dropped

    // A duplicate datagram for the now-retired stream is ignored: no resurrection on
    // either layer, no second request event.
    try qc.receiveDatagram(dgram, 1100);
    try h3.pump(0);
    try testing.expectEqual(@as(usize, 0), qc.streamIds(&ids));
    try testing.expectEqual(@as(u32, 0), h3.streams.count());
    try testing.expect(h3.nextEvent() == .need_data);
}

test "retiring a higher stream id does not block a new lower one" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var req: std.ArrayListUnmanaged(u8) = .empty;
    defer req.deinit(gpa);
    try h3_frame.append(&req, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 });

    // Complete stream 4 first (a watermark would now wrongly retire ids <= 4).
    const on4 = try buildRequestOnFin(gpa, &dcid, 4, 0, req.items);
    defer gpa.free(on4);
    try qc.receiveDatagram(on4, 1000);
    try h3.pump(4);
    const request4 = h3.nextEvent();
    try testing.expect(request4 == .request);
    try testing.expect(request4.request.end_stream);

    // A brand-new request on the lower stream 0 must still be delivered.
    const on0 = try buildRequestOnFin(gpa, &dcid, 0, 1, req.items);
    defer gpa.free(on0);
    try qc.receiveDatagram(on0, 1100);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .request);
}

test "a peer reset reclaims the request stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xba, 0xbb, 0xbc, 0xbd };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A RESET_STREAM (type 0x04) on stream 0 with final size 0, in a 1-RTT packet.
    var rframe: std.ArrayListUnmanaged(u8) = .empty;
    defer rframe.deinit(gpa);
    try rframe.append(gpa, 0x04); // RESET_STREAM
    try varint.append(&rframe, gpa, 0); // stream id 0
    try varint.append(&rframe, gpa, 0x10); // application error code
    try varint.append(&rframe, gpa, 0); // final size 0
    const dgram = try quic_conn.test_support.buildApp(gpa, &dcid, 0, rframe.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    // The peer reset surfaces as an rst_stream event carrying the peer's code.
    const ev = h3.nextEvent();
    try testing.expect(ev == .rst_stream);
    try testing.expectEqual(@as(u64, 0), ev.rst_stream.stream_id);
    try testing.expectEqual(@as(u64, 0x10), ev.rst_stream.error_code);

    // The reset stream is reclaimed (not left to accrete on a reset storm).
    var ids: [4]u64 = undefined;
    try testing.expectEqual(@as(usize, 0), qc.streamIds(&ids));
}

test "a peer STOP_SENDING resets our send half" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // The server has a response in flight on stream 0.
    try h3.sendResponse(0, 200, &.{});

    // The peer sends STOP_SENDING (type 0x05) on stream 0 asking us to stop.
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x05); // STOP_SENDING
    try varint.append(&sframe, gpa, 0); // stream id 0
    try varint.append(&sframe, gpa, 0x10); // error code
    const dgram = try quic_conn.test_support.buildApp(gpa, &dcid, 0, sframe.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);

    // Our send stream is now reset; flushing emits a RESET_STREAM the peer sees.
    try qc.flushSend(2000);
    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    try peer.sendStreamData(0, &.{}, false);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 3000);
        off += len;
    }
    try testing.expect(peer.streamReset(0));
}

// Build a request datagram on `stream_id` with the FIN bit set, at packet number `pn`.
fn buildRequestOnFin(gpa: std.mem.Allocator, dcid: []const u8, stream_id: u64, pn: u64, h3_bytes: []const u8) ![]u8 {
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0b); // STREAM, LEN|FIN set, no OFF
    try varint.append(&sframe, gpa, stream_id);
    try varint.append(&sframe, gpa, h3_bytes.len);
    try sframe.appendSlice(gpa, h3_bytes);
    return @import("../quic/connection.zig").test_support.buildApp(gpa, dcid, pn, sframe.items);
}

test "pumpStreams advances a request changed by each datagram" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xa6, 0xa7, 0xa8, 0xb9 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();
    h3.peer_settings = .{};

    var headers: std.ArrayListUnmanaged(u8) = .empty;
    defer headers.deinit(gpa);
    const qpack_block = [_]u8{ 0x00, 0x00, 0xC0 | 20, 0xC0 | 23, 0xC0 | 1 }; // POST https /
    try h3_frame.append(&headers, gpa, .headers, &qpack_block);
    var stream_frame: std.ArrayListUnmanaged(u8) = .empty;
    defer stream_frame.deinit(gpa);
    try quic_frame.encodeStream(&stream_frame, gpa, 0, 0, headers.items, false);
    const first = try quic_conn.test_support.buildApp(gpa, &dcid, 0, stream_frame.items);
    defer gpa.free(first);
    try qc.receiveDatagram(first, 1000);
    try h3.pumpStreams(qc.changedStreamIds());
    try testing.expect(h3.nextEvent() == .request);

    var data: std.ArrayListUnmanaged(u8) = .empty;
    defer data.deinit(gpa);
    try h3_frame.append(&data, gpa, .data, "x");
    stream_frame.clearRetainingCapacity();
    try quic_frame.encodeStream(&stream_frame, gpa, 0, headers.items.len, data.items, false);
    const second = try quic_conn.test_support.buildApp(gpa, &dcid, 1, stream_frame.items);
    defer gpa.free(second);
    try qc.receiveDatagram(second, 2000);
    try h3.pumpStreams(qc.changedStreamIds());
    try testing.expect(h3.nextEvent() == .data);
}

test "pumpAll advances more than the small stack stream snapshot" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xa6, 0xa7, 0xa8, 0xa9 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();
    h3.peer_settings = .{};

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    const qpack_block = [_]u8{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 }; // GET https /
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);

    var datagrams: [65][]u8 = undefined;
    defer for (datagrams) |d| gpa.free(d);
    for (&datagrams, 0..) |*d, i| {
        d.* = try buildRequestOnFin(gpa, &dcid, @as(u64, @intCast(i)) * 4, @intCast(i), h3_bytes.items);
        try qc.receiveDatagram(d.*, 1000 + @as(u64, @intCast(i)));
    }

    try h3.pumpAll();

    var requests: usize = 0;
    while (true) {
        const ev = h3.nextEvent();
        switch (ev) {
            .request => requests += 1,
            .need_data => break,
            else => {},
        }
    }
    try testing.expectEqual(@as(usize, datagrams.len), requests);
}

test "pumpAll rejects request streams before peer SETTINGS" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xa6, 0xa7, 0xa8, 0xaa };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    const qpack_block = [_]u8{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 }; // GET https /
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);

    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pumpAll());
    try testing.expect(qc.closed);

    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const pc = peer.peer_close.?;
    try testing.expect(pc.app);
    try testing.expectEqual(@intFromEnum(h3_error.ErrorCode.missing_settings), pc.error_code);
}

test "client decodes an HTTP/3 response over a request stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3 };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    try qc.sendStreamData(0, &.{}, false);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var section: std.ArrayList(u8) = .empty;
    defer section.deinit(gpa);
    try qpack_enc.encode(&section, gpa, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "5" },
        .{ .name = "server", .value = "zttp" },
    });

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, section.items);
    try h3_frame.append(&h3_bytes, gpa, .data, "hello");

    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    const resp = h3.nextEvent();
    try testing.expect(resp == .response);
    try testing.expectEqual(@as(u16, 200), resp.response.status_code);
    try testing.expectEqualStrings("3", resp.response.http_version);
    try testing.expectEqual(@as(u64, 0), resp.response.stream_id);
    try testing.expectEqualStrings("server", resp.response.headers[1].name);
    try testing.expectEqualStrings("zttp", resp.response.headers[1].value);

    const data = h3.nextEvent();
    try testing.expect(data == .data);
    try testing.expectEqualStrings("hello", data.data.data);
    try testing.expectEqual(@as(u64, 0), data.data.stream_id);

    const eom = h3.nextEvent();
    try testing.expect(eom == .end_of_message);
    try testing.expectEqual(@as(u64, 0), eom.end_of_message.stream_id);
    try testing.expect(h3.nextEvent() == .need_data);
}

test "a response stream ending with a truncated frame is a connection error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb7 };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    try qc.sendStreamData(0, &.{}, false);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var section: std.ArrayList(u8) = .empty;
    defer section.deinit(gpa);
    try qpack_enc.encode(&section, gpa, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "2" },
    });

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, section.items);
    try h3_bytes.appendSlice(gpa, &.{ 0x00, 0x02, 'x' }); // DATA declares 2 bytes, carries 1

    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(0));
    try testing.expect(qc.closed);
}

test "HEAD response may end before the advertised content length" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb4 };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    _ = try h3.sendRequest("HEAD", "/resource", "https", "example.test", &.{}, true);

    var section: std.ArrayList(u8) = .empty;
    defer section.deinit(gpa);
    try qpack_enc.encode(&section, gpa, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "5" },
    });

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, section.items);

    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    const resp = h3.nextEvent();
    try testing.expect(resp == .response);
    try testing.expectEqual(@as(u16, 200), resp.response.status_code);
    try testing.expectEqualStrings("content-length", resp.response.headers[0].name);
    try testing.expectEqualStrings("5", resp.response.headers[0].value);

    const eom = h3.nextEvent();
    try testing.expect(eom == .end_of_message);
    try testing.expectEqual(@as(u64, 0), eom.end_of_message.stream_id);
    try testing.expect(h3.nextEvent() == .need_data);
}

test "client rejects trailers on bodyless responses" {
    const gpa = testing.allocator;

    {
        const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xbe };
        var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
        defer qc.deinit();
        quic_conn.test_support.installAppKeys(&qc);
        try qc.sendStreamData(0, &.{}, false);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();

        _ = try h3.sendRequest("HEAD", "/resource", "https", "example.test", &.{}, true);

        var response: std.ArrayList(u8) = .empty;
        defer response.deinit(gpa);
        try qpack_enc.encode(&response, gpa, &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "5" },
        });
        var trailers: std.ArrayList(u8) = .empty;
        defer trailers.deinit(gpa);
        try qpack_enc.encode(&trailers, gpa, &.{.{ .name = "x-checksum", .value = "abc" }});

        var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer h3_bytes.deinit(gpa);
        try h3_frame.append(&h3_bytes, gpa, .headers, response.items);
        try h3_frame.append(&h3_bytes, gpa, .headers, trailers.items);

        const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
        defer gpa.free(dgram);
        try qc.receiveDatagram(dgram, 1000);
        try h3.pump(0);

        const resp = h3.nextEvent();
        try testing.expect(resp == .response);
        try testing.expectEqual(@as(u16, 200), resp.response.status_code);
        try testing.expect(h3.nextEvent() == .need_data);
        try testing.expectEqual(@as(u32, 0), h3.streams.count());
    }

    {
        const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xbf };
        var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
        defer qc.deinit();
        quic_conn.test_support.installAppKeys(&qc);
        try qc.sendStreamData(0, &.{}, false);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();

        var response: std.ArrayList(u8) = .empty;
        defer response.deinit(gpa);
        try qpack_enc.encode(&response, gpa, &.{.{ .name = ":status", .value = "204" }});
        var trailers: std.ArrayList(u8) = .empty;
        defer trailers.deinit(gpa);
        try qpack_enc.encode(&trailers, gpa, &.{.{ .name = "x-checksum", .value = "abc" }});

        var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer h3_bytes.deinit(gpa);
        try h3_frame.append(&h3_bytes, gpa, .headers, response.items);
        try h3_frame.append(&h3_bytes, gpa, .headers, trailers.items);

        const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
        defer gpa.free(dgram);
        try qc.receiveDatagram(dgram, 1000);
        try h3.pump(0);

        const resp = h3.nextEvent();
        try testing.expect(resp == .response);
        try testing.expectEqual(@as(u16, 204), resp.response.status_code);
        try testing.expect(h3.nextEvent() == .need_data);
        try testing.expectEqual(@as(u32, 0), h3.streams.count());
    }
}

test "client rejects Content-Length on responses that cannot carry it" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xbb };

    inline for (.{ "103", "204" }) |status| {
        var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
        defer qc.deinit();
        quic_conn.test_support.installAppKeys(&qc);
        try qc.sendStreamData(0, &.{}, false);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();

        var section: std.ArrayList(u8) = .empty;
        defer section.deinit(gpa);
        try qpack_enc.encode(&section, gpa, &.{
            .{ .name = ":status", .value = status },
            .{ .name = "content-length", .value = "0" },
        });

        var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer h3_bytes.deinit(gpa);
        try h3_frame.append(&h3_bytes, gpa, .headers, section.items);

        const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
        defer gpa.free(dgram);
        try qc.receiveDatagram(dgram, 1000);
        try h3.pump(0);
        try testing.expect(h3.nextEvent() == .need_data);
        try testing.expectEqual(@as(u32, 0), h3.streams.count());
    }
}

test "HEAD response send path rejects DATA and trailers" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb8 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 18, 0xC0 | 23, 0xC0 | 1 }); // HEAD / https
    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);
    const request = h3.nextEvent();
    try testing.expect(request == .request);
    try testing.expect(request.request.end_stream);

    try h3.sendResponse(0, 200, &.{.{ .name = "content-length", .value = "5" }});
    try testing.expectError(error.H3Error, h3.sendData(0, "x"));
    try testing.expectError(error.H3Error, h3.sendTrailers(0, &.{.{ .name = "x", .value = "y" }}));
    try h3.endStream(0);
}

test "response send path enforces outbound Content-Length" {
    const gpa = testing.allocator;
    {
        const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xba };
        var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
        defer qc.deinit();
        quic_conn.test_support.installAppKeys(&qc);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();

        try h3.sendResponse(0, 200, &.{.{ .name = "content-length", .value = "5" }});
        try h3.sendData(0, "he");
        try testing.expectError(error.H3Error, h3.endStream(0));
        try testing.expectError(error.H3Error, h3.sendTrailers(0, &.{.{ .name = "x-checksum", .value = "abc" }}));
        try h3.sendData(0, "llo");
        try h3.endStream(0);
        try testing.expectEqual(@as(u32, 0), h3.send_content_length.count());
        try testing.expectEqual(@as(u32, 0), h3.send_body_sent.count());
    }
    {
        const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xbd };
        var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
        defer qc.deinit();
        quic_conn.test_support.installAppKeys(&qc);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();

        try h3.sendResponse(0, 200, &.{.{ .name = "content-length", .value = "1" }});
        try testing.expectError(error.H3Error, h3.sendData(0, "xx"));
        try testing.expectEqual(@as(?u64, 0), h3.send_body_sent.get(0));
        try h3.sendData(0, "x");
        try h3.endStream(0);
    }
}

test "204 response send path rejects DATA and trailers" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb9 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    try h3.sendResponse(0, 204, &.{});
    try testing.expectError(error.H3Error, h3.sendData(0, "x"));
    try testing.expectError(error.H3Error, h3.sendTrailers(0, &.{.{ .name = "x", .value = "y" }}));
    try h3.endStream(0);
}

test "client decodes informational then final HTTP/3 response" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb5 };
    var server_qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer server_qc.deinit();
    quic_conn.test_support.installAppKeys(&server_qc);
    var server_h3 = Connection.init(gpa, &server_qc);
    defer server_h3.deinit();

    try server_h3.sendInformational(0, 103, &.{.{ .name = "link", .value = "</style.css>; rel=preload" }});
    try server_h3.sendResponse(0, 200, &.{.{ .name = "content-length", .value = "0" }});
    try server_h3.endStream(0);
    try server_qc.flushSend(1000);

    var client_qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer client_qc.deinit();
    quic_conn.test_support.installAppKeys(&client_qc);
    try client_qc.sendStreamData(0, &.{}, false);
    var client_h3 = Connection.init(gpa, &client_qc);
    defer client_h3.deinit();

    const buf = server_qc.datagramsToSend();
    var off: usize = 0;
    for (server_qc.datagramLengths()) |len| {
        try client_qc.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    try client_h3.pump(0);

    const info = client_h3.nextEvent();
    try testing.expect(info == .response);
    try testing.expectEqual(@as(u16, 103), info.response.status_code);
    try testing.expectEqualStrings("link", info.response.headers[0].name);

    const final = client_h3.nextEvent();
    try testing.expect(final == .response);
    try testing.expectEqual(@as(u16, 200), final.response.status_code);
    try testing.expect(client_h3.nextEvent() == .end_of_message);
}

test "client rejects 101 Switching Protocols in HTTP/3 response" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xba };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    try qc.sendStreamData(0, &.{}, false);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var section: std.ArrayList(u8) = .empty;
    defer section.deinit(gpa);
    try qpack_enc.encode(&section, gpa, &.{.{ .name = ":status", .value = "101" }});

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, section.items);

    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    try testing.expect(h3.nextEvent() == .need_data);
    try testing.expect(!qc.closed);
    try testing.expectEqual(@as(u32, 0), h3.streams.count());
}

test "client rejects a malformed PUSH_PROMISE as a frame error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xbb };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    try qc.sendStreamData(0, &.{}, false);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .push_promise, &.{});

    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(0));

    var peer = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const pc = peer.peer_close.?;
    try testing.expect(pc.app);
    try testing.expectEqual(@intFromEnum(h3_error.ErrorCode.frame_error), pc.error_code);
}

test "client rejects PUSH_PROMISE when push is disabled" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xbc };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    try qc.sendStreamData(0, &.{}, false);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .push_promise, &.{0x00});

    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(0));

    var peer = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const pc = peer.peer_close.?;
    try testing.expect(pc.app);
    try testing.expectEqual(@intFromEnum(h3_error.ErrorCode.id_error), pc.error_code);
}

test "HTTP/3 response trailers flow into EndOfMessage" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb6 };
    var server_qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer server_qc.deinit();
    quic_conn.test_support.installAppKeys(&server_qc);
    var server_h3 = Connection.init(gpa, &server_qc);
    defer server_h3.deinit();

    try server_h3.sendResponse(0, 200, &.{.{ .name = "content-length", .value = "4" }});
    try server_h3.sendData(0, "body");
    try server_h3.sendTrailers(0, &.{.{ .name = "x-checksum", .value = "abc" }});
    try server_qc.flushSend(1000);

    var client_qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer client_qc.deinit();
    quic_conn.test_support.installAppKeys(&client_qc);
    try client_qc.sendStreamData(0, &.{}, false);
    var client_h3 = Connection.init(gpa, &client_qc);
    defer client_h3.deinit();

    const buf = server_qc.datagramsToSend();
    var off: usize = 0;
    for (server_qc.datagramLengths()) |len| {
        try client_qc.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    try client_h3.pump(0);

    try testing.expect(client_h3.nextEvent() == .response);
    try testing.expect(client_h3.nextEvent() == .data);
    const eom = client_h3.nextEvent();
    try testing.expect(eom == .end_of_message);
    try testing.expectEqual(@as(usize, 1), eom.end_of_message.trailers.len);
    try testing.expectEqualStrings("x-checksum", eom.end_of_message.trailers[0].name);
    try testing.expectEqualStrings("abc", eom.end_of_message.trailers[0].value);
}

test "server dynamically encodes a response header when peer QPACK settings allow it" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb4 };
    var server_qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer server_qc.deinit();
    quic_conn.test_support.installAppKeys(&server_qc);
    var server_h3 = Connection.init(gpa, &server_qc);
    defer server_h3.deinit();
    server_h3.peer_settings = .{
        .qpack_max_table_capacity = 64,
        .qpack_blocked_streams = 1,
    };

    try server_h3.sendResponse(0, 200, &.{.{ .name = "x-dyn", .value = "v" }});
    try server_h3.endStream(0);
    try server_qc.flushSend(1000);

    var client_qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer client_qc.deinit();
    quic_conn.test_support.installAppKeys(&client_qc);
    try client_qc.sendStreamData(0, &.{}, false);
    var client_h3 = Connection.init(gpa, &client_qc);
    defer client_h3.deinit();

    const buf = server_qc.datagramsToSend();
    var off: usize = 0;
    for (server_qc.datagramLengths()) |len| {
        try client_qc.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    server_qc.clearSend();

    // The response HEADERS can arrive before the QPACK encoder stream; it blocks.
    try client_h3.pump(0);
    try testing.expect(client_h3.nextEvent() == .need_data);

    try client_h3.pump(11); // server-initiated QPACK encoder stream
    const resp = client_h3.nextEvent();
    try testing.expect(resp == .response);
    try testing.expectEqual(@as(u16, 200), resp.response.status_code);
    try testing.expectEqualStrings("x-dyn", resp.response.headers[0].name);
    try testing.expectEqualStrings("v", resp.response.headers[0].value);
    try testing.expect(client_h3.nextEvent() == .end_of_message);

    try client_qc.flushSend(3000);
    const ack_buf = client_qc.datagramsToSend();
    off = 0;
    for (client_qc.datagramLengths()) |len| {
        try server_qc.receiveDatagram(ack_buf[off .. off + len], 4000);
        off += len;
    }
    client_qc.clearSend();
    try server_h3.pump(6); // client-initiated QPACK decoder stream
    try testing.expectEqual(@as(u64, 1), server_h3.qpack_enc_state.known_received_count);
    try testing.expectEqual(@as(usize, 0), server_h3.qpack_enc_state.outstanding.items.len);
    try testing.expectEqual(@as(usize, 38), server_h3.qpack_enc_state.dynamic_size);
}

test "client sends an HTTP/3 request over the next request stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xba, 0xbb, 0xbc, 0xbd };
    var client_qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer client_qc.deinit();
    quic_conn.test_support.installAppKeys(&client_qc);
    var client_h3 = Connection.init(gpa, &client_qc);
    defer client_h3.deinit();

    const id = try client_h3.sendRequest("GET", "/client?q=1", "https", "example.test", &.{.{ .name = "accept", .value = "*/*" }}, true);
    try testing.expectEqual(@as(u64, 0), id);
    try client_qc.flushSend(1000);

    var server_qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer server_qc.deinit();
    quic_conn.test_support.installAppKeys(&server_qc);
    var server_h3 = Connection.init(gpa, &server_qc);
    defer server_h3.deinit();

    const buf = client_qc.datagramsToSend();
    var off: usize = 0;
    for (client_qc.datagramLengths()) |len| {
        try server_qc.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    try server_h3.pump(2);
    try server_h3.pump(0);

    try testing.expect(server_h3.nextEvent() == .settings);
    const req = server_h3.nextEvent();
    try testing.expect(req == .request);
    try testing.expectEqualStrings("GET", req.request.method);
    try testing.expectEqualStrings("/client?q=1", req.request.target);
    try testing.expectEqualStrings("/client", req.request.path);
    try testing.expectEqualStrings("q=1", req.request.query);
    try testing.expectEqualStrings("host", req.request.headers[0].name);
    try testing.expectEqualStrings("example.test", req.request.headers[0].value);
    try testing.expectEqualStrings("accept", req.request.headers[1].name);
    try testing.expectEqualStrings("*/*", req.request.headers[1].value);
    try testing.expect(req.request.end_stream);
    try testing.expect(server_h3.nextEvent() == .need_data);
}

test "client sends CONNECT without scheme or path pseudo-headers" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xba, 0xbb, 0xbc, 0xbe };
    var client_qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer client_qc.deinit();
    quic_conn.test_support.installAppKeys(&client_qc);
    var client_h3 = Connection.init(gpa, &client_qc);
    defer client_h3.deinit();

    const id = try client_h3.sendRequest("CONNECT", "example:443", "https", "example:443", &.{}, true);
    try testing.expectEqual(@as(u64, 0), id);
    try client_qc.flushSend(1000);

    var server_qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer server_qc.deinit();
    quic_conn.test_support.installAppKeys(&server_qc);
    var server_h3 = Connection.init(gpa, &server_qc);
    defer server_h3.deinit();

    const buf = client_qc.datagramsToSend();
    var off: usize = 0;
    for (client_qc.datagramLengths()) |len| {
        try server_qc.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    try server_h3.pump(2);
    try server_h3.pump(0);

    try testing.expect(server_h3.nextEvent() == .settings);
    const req = server_h3.nextEvent();
    try testing.expect(req == .request);
    try testing.expectEqualStrings("CONNECT", req.request.method);
    try testing.expectEqualStrings("example:443", req.request.target);
    try testing.expectEqualStrings("example:443", req.request.path);
    try testing.expectEqualStrings("", req.request.query);
    try testing.expectEqualStrings("host", req.request.headers[0].name);
    try testing.expectEqualStrings("example:443", req.request.headers[0].value);
}

test "client sends HTTP/3 request DATA before ending the stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xbe, 0xbf, 0xc0, 0xc1 };
    var client_qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer client_qc.deinit();
    quic_conn.test_support.installAppKeys(&client_qc);
    var client_h3 = Connection.init(gpa, &client_qc);
    defer client_h3.deinit();

    const id = try client_h3.sendRequest("POST", "/submit", "https", "example.test", &.{.{ .name = "content-length", .value = "4" }}, false);
    try testing.expectError(error.H3Error, client_h3.endStream(id));
    try client_h3.sendData(id, "body");
    try client_h3.endStream(id);
    try client_qc.flushSend(1000);

    var server_qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer server_qc.deinit();
    quic_conn.test_support.installAppKeys(&server_qc);
    var server_h3 = Connection.init(gpa, &server_qc);
    defer server_h3.deinit();

    const buf = client_qc.datagramsToSend();
    var off: usize = 0;
    for (client_qc.datagramLengths()) |len| {
        try server_qc.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    try server_h3.pump(2);
    try server_h3.pump(0);

    try testing.expect(server_h3.nextEvent() == .settings);
    const req = server_h3.nextEvent();
    try testing.expect(req == .request);
    try testing.expectEqualStrings("POST", req.request.method);
    const data = server_h3.nextEvent();
    try testing.expect(data == .data);
    try testing.expectEqualStrings("body", data.data.data);
    const eom = server_h3.nextEvent();
    try testing.expect(eom == .end_of_message);
}

test "client request send path enforces outbound Content-Length" {
    const gpa = testing.allocator;
    {
        const dcid = [_]u8{ 0xbe, 0xbf, 0xc0, 0xc2 };
        var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
        defer qc.deinit();
        quic_conn.test_support.installAppKeys(&qc);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();

        try testing.expectError(error.H3Error, h3.sendRequest("POST", "/submit", "https", "example.test", &.{.{ .name = "content-length", .value = "1" }}, true));
        try testing.expectEqual(@as(u64, 0), h3.next_request_stream_id);
        try testing.expect(!h3.control_sent);
        try testing.expectEqual(@as(usize, 0), qc.datagramsToSend().len);
    }
    {
        const dcid = [_]u8{ 0xbe, 0xbf, 0xc0, 0xc3 };
        var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
        defer qc.deinit();
        quic_conn.test_support.installAppKeys(&qc);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();

        const id = try h3.sendRequest("POST", "/submit", "https", "example.test", &.{.{ .name = "content-length", .value = "1" }}, false);
        try testing.expectError(error.H3Error, h3.sendData(id, "xx"));
        try testing.expectEqual(@as(?u64, 0), h3.send_body_sent.get(id));
        try h3.sendData(id, "x");
        try h3.endStream(id);
    }
}

test "client request send validates HTTP/3 fields" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xc2, 0xc3, 0xc4, 0xc5 };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    try testing.expectError(error.H3Error, h3.sendRequest("GET /admin", "/", "https", "example.test", &.{}, true));
    try testing.expectError(error.H3Error, h3.sendRequest("GET", "/bad\r\nx", "https", "example.test", &.{}, true));
    try testing.expectError(error.H3Error, h3.sendRequest("GET", "/", "https\r\nx", "example.test", &.{}, true));
    try testing.expectError(error.H3Error, h3.sendRequest("GET", "/", "https", "", &.{}, true));
    try testing.expectError(error.H3Error, h3.sendRequest("GET", "/", "https", " example.test", &.{}, true));
    try testing.expectError(error.H3Error, h3.sendRequest("GET", "/", "https", "example .test", &.{}, true));
    try testing.expectError(error.H3Error, h3.sendRequest("GET", "/", "https", "example.test", &.{.{ .name = "X-Bad", .value = "x" }}, true));
    try testing.expectError(error.H3Error, h3.sendRequest("GET", "/", "https", "example.test", &.{.{ .name = "connection", .value = "close" }}, true));
    try testing.expectError(error.H3Error, h3.sendRequest("POST", "/", "https", "example.test", &.{.{ .name = "content-length", .value = "x" }}, false));
    try testing.expectError(error.H3Error, h3.sendRequest("POST", "/", "https", "example.test", &.{
        .{ .name = "content-length", .value = "1" },
        .{ .name = "content-length", .value = "2" },
    }, false));
    try testing.expectError(error.H3Error, h3.sendRequest("GET", "/", "https", "example.test", &.{.{ .name = "host", .value = "other.test" }}, true));
    try testing.expectError(error.H3Error, h3.sendRequest("GET", "/", "https", "example.test", &.{
        .{ .name = "host", .value = "example.test" },
        .{ .name = "host", .value = "other.test" },
    }, true));
    try testing.expectError(error.H3Error, h3.sendRequest("CONNECT", "example:443", "https", "example:443", &.{.{ .name = "host", .value = "other:443" }}, true));
    try testing.expectError(error.H3Error, h3.sendRequest("CONNECT", "example:443", "https", "other:443", &.{}, true));
    try testing.expectEqual(@as(u64, 0), h3.next_request_stream_id);
    try testing.expect(!h3.control_sent);
    try testing.expectEqual(@as(usize, 0), qc.datagramsToSend().len);
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &.{}));
}

test "client rejects request pseudo-headers in an HTTP/3 response" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb4, 0xb5, 0xb6, 0xb7 };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    try qc.sendStreamData(0, &.{}, false);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const qpack_block = [_]u8{
        0x00, 0x00, // prefix
        0xC0 | 17, // illegal in a response: :method GET
    };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);

    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    try testing.expect(h3.nextEvent() == .need_data);
    try testing.expect(!qc.closed);
    try testing.expectEqual(@as(u32, 0), h3.streams.count());
}

test "DATA before HEADERS is rejected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x07, 0x07, 0x07, 0x07 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc); // H3 request data rides the Application space
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .data, "x");
    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(0));
}

test "a request stream ending with a truncated frame is a connection error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x07, 0x07, 0x07, 0x08 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 });
    try h3_bytes.appendSlice(gpa, &.{ 0x00, 0x02, 'x' }); // DATA declares 2 bytes, carries 1
    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(0));
    try testing.expect(qc.closed);
}

// Build a 1-RTT packet whose STREAM frame carries `h3_bytes` at `offset` on stream
// 0 (the OFF flag is set), with packet number `pn` so a second datagram decrypts.
fn buildRequestAt(gpa: std.mem.Allocator, dcid: []const u8, offset: u64, pn: u64, h3_bytes: []const u8) ![]u8 {
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0e); // STREAM, OFF|LEN set
    try varint.append(&sframe, gpa, 0); // stream id 0
    try varint.append(&sframe, gpa, offset);
    try varint.append(&sframe, gpa, h3_bytes.len);
    try sframe.appendSlice(gpa, h3_bytes);
    return @import("../quic/connection.zig").test_support.buildApp(gpa, dcid, pn, sframe.items);
}

test "a request split across two datagrams parses correctly (parsed-offset regression)" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc); // H3 request data rides the Application space
    var h3 = Connection.initWithLimits(gpa, &qc, .{ .max_pending_events = 1 });
    defer h3.deinit();
    h3.peer_settings = .{};

    const qpack_block = [_]u8{ 0x00, 0x00, 0xC0 | 20, 0xC0 | 23, 0xC0 | 1 }; // POST https /
    var headers_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer headers_bytes.deinit(gpa);
    try h3_frame.append(&headers_bytes, gpa, .headers, &qpack_block);
    var data_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer data_bytes.deinit(gpa);
    try h3_frame.append(&data_bytes, gpa, .data, "second-datagram-body");

    // Datagram 1: just the HEADERS frame.
    const dg1 = try buildRequestAt(gpa, &dcid, 0, 0, headers_bytes.items);
    defer gpa.free(dg1);
    try qc.receiveDatagram(dg1, 1000);
    try h3.pumpStreams(&.{0});
    try testing.expect(h3.eventQueueFull());

    // Datagram 2: the DATA frame at the offset right after the HEADERS frame.
    const dg2 = try buildRequestAt(gpa, &dcid, headers_bytes.items.len, 1, data_bytes.items);
    defer gpa.free(dg2);
    try qc.receiveDatagram(dg2, 2000);
    try testing.expectError(error.EventQueueFull, h3.pumpStreams(&.{0}));
    try testing.expect(h3.nextEvent() == .request);
    try testing.expect(h3.nextEvent() == .need_data);
    try h3.pumpStreams(&.{0});
    const data_ev = h3.nextEvent();
    try testing.expect(data_ev == .data);
    try testing.expectEqualStrings("second-datagram-body", data_ev.data.data);
}

test "the event arena is reclaimed when the queue drains" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc); // H3 request data rides the Application space
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const qpack_block = [_]u8{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);
    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);
    const req = h3.nextEvent();
    try testing.expect(req == .request);
    try testing.expectEqualStrings("GET", req.request.method);
    // Draining to need_data resets the arena. A second request on a new stream
    // must still decode correctly (the reset reclaims the first request's copies
    // without corrupting the decode path).
    try testing.expect(h3.nextEvent() == .need_data);

    const dgram2 = try buildRequestOnFin(gpa, &dcid, 4, 1, h3_bytes.items); // stream 4 (client bidi)
    defer gpa.free(dgram2);
    try qc.receiveDatagram(dgram2, 2000);
    try h3.pump(4);
    const req2 = h3.nextEvent();
    try testing.expect(req2 == .request);
    try testing.expectEqualStrings("GET", req2.request.method);
}

test "a server sends a response: HEADERS then DATA then FIN" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x99, 0xaa, 0xbb, 0xcc };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // Respond 200 on server-initiated bidi stream id 1 with a body.
    const headers = [_]Header{.{ .name = "content-type", .value = "text/plain" }};
    try h3.sendResponse(0, 200, &headers);
    try h3.sendData(0, "hello");
    try h3.endStream(0);

    // The QUIC send stream now holds the HEADERS frame, the DATA frame, and a FIN.
    // Flush into a datagram and read it back through a peer to confirm reassembly.
    try qc.flushSend(1000);
    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    try peer.sendStreamData(0, &.{}, false);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const got = peer.streamData(0);
    try testing.expect(peer.streamFinished(0));

    // The first H3 frame is HEADERS; the next is DATA carrying "hello".
    const d1 = try h3_frame.decode(got);
    try testing.expectEqual(h3_frame.FrameType.headers, d1.frame.ftype);
    const d2 = try h3_frame.decode(got[d1.len..]);
    try testing.expectEqual(h3_frame.FrameType.data, d2.frame.ftype);
    try testing.expectEqualStrings("hello", d2.frame.payload);
}

test "the server resets a request stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x90, 0x91, 0x92, 0x93 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A partial response, then cancel the stream (RFC 9114 4.4): RESET_STREAM the
    // response and STOP_SENDING the request.
    try h3.sendResponse(0, 200, &.{});
    try h3.resetStream(0, 0x010c); // H3_REQUEST_CANCELLED
    try qc.flushSend(1000);

    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    try peer.sendStreamData(0, &.{}, false);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    try testing.expect(peer.streamReset(0)); // the peer sees the response stream reset

    // A reset on a non-request (server uni) stream id is rejected.
    try testing.expectError(error.H3Error, h3.resetStream(3, 0x010c));
}

test "resetStream rejects an out-of-range QUIC error code without side effects" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x90, 0x91, 0x92, 0x94 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    try h3.sendResponse(0, 200, &.{});
    qc.clearSend();
    try testing.expectError(error.H3Error, h3.resetStream(0, varint.MAX + 1));
    try testing.expectEqual(SendState.headers_sent, h3.peekSendState(0));
    try testing.expectEqual(@as(usize, 0), qc.datagramsToSend().len);
    try h3.sendData(0, "still-open");
}

test "a reset after the response finished is a no-op" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x94, 0x95, 0x96, 0x97 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    try h3.sendResponse(0, 200, &.{});
    try h3.endStream(0); // the response finished (FIN sent)
    qc.clearSend();
    try qc.flushSend(1000);
    qc.clearSend();
    // A reset now must not recreate a reclaimed send stream / emit a stale frame.
    try h3.resetStream(0, 0x010c);
    try qc.flushSend(1000);
    try testing.expectEqual(@as(usize, 0), qc.datagramsToSend().len); // nothing sent
}

test "the server opens its control stream with a SETTINGS frame" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x31, 0x33, 0x37, 0x39 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A response auto-opens the control stream first (RFC 9114 6.2.1); idempotent.
    try h3.sendResponse(0, 200, &.{});
    try h3.initiateControl(); // a second call is a no-op
    try qc.flushSend(1000);

    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    try peer.sendStreamData(0, &.{}, false);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }

    // Stream 3 (the first server uni) carries the control stream: a type prefix
    // 0x00, then a SETTINGS frame advertising max_field_section_size.
    const ctrl = peer.streamData(3);
    try testing.expect(ctrl.len > 1);
    const t = h3_stream.decodeUniType(ctrl).?;
    try testing.expectEqual(h3_stream.UniStreamType.control, t.utype);
    const f = try h3_frame.decode(ctrl[t.len..]);
    try testing.expectEqual(h3_frame.FrameType.settings, f.frame.ftype);
    const s = try h3_stream.parseSettings(f.frame.payload);
    try testing.expectEqual(@as(u64, 1 << 16), s.max_field_section_size);
    try testing.expectEqual(@as(u64, QPACK_MAX_TABLE_CAPACITY), s.qpack_max_table_capacity);
    try testing.expectEqual(@as(u64, QPACK_BLOCKED_STREAMS), s.qpack_blocked_streams);
}

test "the client opens its control stream on the first client uni stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x41, 0x43, 0x45, 0x47 };
    var client_qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer client_qc.deinit();
    quic_conn.test_support.installAppKeys(&client_qc);
    var client_h3 = Connection.init(gpa, &client_qc);
    defer client_h3.deinit();

    try client_h3.initiateControl();
    try client_qc.flushSend(1000);

    var server_qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer server_qc.deinit();
    quic_conn.test_support.installAppKeys(&server_qc);
    var server_h3 = Connection.init(gpa, &server_qc);
    defer server_h3.deinit();

    const buf = client_qc.datagramsToSend();
    var off: usize = 0;
    for (client_qc.datagramLengths()) |len| {
        try server_qc.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    try server_h3.pump(2);

    try testing.expectEqual(@as(?u64, 2), server_h3.control_recv_id);
    try testing.expect(server_h3.peer_settings != null);
    try testing.expectEqual(@as(u64, 1 << 16), server_h3.peer_settings.?.max_field_section_size);
    try testing.expectEqual(@as(u64, QPACK_MAX_TABLE_CAPACITY), server_h3.peer_settings.?.qpack_max_table_capacity);
    try testing.expectEqual(@as(u64, QPACK_BLOCKED_STREAMS), server_h3.peer_settings.?.qpack_blocked_streams);
}

test "shutdown sends a GOAWAY on the control stream after SETTINGS" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x60, 0x61, 0x62, 0x63 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    try h3.shutdown(8); // graceful shutdown: do not process request stream 8 or higher
    try qc.flushSend(1000);

    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }

    // The control stream is SETTINGS then GOAWAY(8).
    const ctrl = peer.streamData(3);
    const t = h3_stream.decodeUniType(ctrl).?;
    const f1 = try h3_frame.decode(ctrl[t.len..]);
    try testing.expectEqual(h3_frame.FrameType.settings, f1.frame.ftype);
    const f2 = try h3_frame.decode(ctrl[t.len + f1.len ..]);
    try testing.expectEqual(h3_frame.FrameType.goaway, f2.frame.ftype);
    const id = try varint.decode(f2.frame.payload);
    try testing.expectEqual(@as(u64, 8), id.value);
}

test "client shutdown sends a GOAWAY with a push id" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x60, 0x61, 0x62, 0x64 };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    try h3.shutdown(1); // client GOAWAY uses the push-id namespace, not stream ids.
    try qc.flushSend(1000);

    var peer = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }

    // The client's control stream is stream 2: SETTINGS then GOAWAY(1).
    const ctrl = peer.streamData(2);
    const t = h3_stream.decodeUniType(ctrl).?;
    const f1 = try h3_frame.decode(ctrl[t.len..]);
    try testing.expectEqual(h3_frame.FrameType.settings, f1.frame.ftype);
    const f2 = try h3_frame.decode(ctrl[t.len + f1.len ..]);
    try testing.expectEqual(h3_frame.FrameType.goaway, f2.frame.ftype);
    const id = try varint.decode(f2.frame.payload);
    try testing.expectEqual(@as(u64, 1), id.value);
}

test "a later GOAWAY may only lower the id" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x64, 0x65, 0x66, 0x67 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    try h3.shutdown(8);
    try h3.shutdown(4); // narrowing is allowed
    try testing.expectError(error.H3Error, h3.shutdown(12)); // widening is not
}

test "a client GOAWAY may only lower the push id" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x64, 0x65, 0x66, 0x68 };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    try h3.shutdown(1);
    try h3.shutdown(0); // narrowing is allowed
    try testing.expectError(error.H3Error, h3.shutdown(2)); // widening is not
}

test "shutdown rejects a non-request-stream id" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x68, 0x69, 0x6a, 0x6b };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // id 3 is a server uni stream, not a client request stream (RFC 9114 5.2).
    try testing.expectError(error.H3Error, h3.shutdown(3));
    // An id past the 62-bit varint range is rejected before any control stream opens.
    try testing.expectError(error.H3Error, h3.shutdown((1 << 62)));
    try testing.expectEqual(@as(usize, 0), qc.datagramsToSend().len); // nothing was sent
}

test "after GOAWAY a request at or above the id is not processed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x6c, 0x6d, 0x6e, 0x6f };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var req: std.ArrayListUnmanaged(u8) = .empty;
    defer req.deinit(gpa);
    try h3_frame.append(&req, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 });

    try h3.shutdown(8); // we will not process request stream 8 or higher

    // A request on stream 8 (>= the GOAWAY id) is drained, not surfaced.
    const on8 = try buildRequestOnFin(gpa, &dcid, 8, 0, req.items);
    defer gpa.free(on8);
    try qc.receiveDatagram(on8, 1000);
    try h3.pump(8);
    try testing.expect(h3.nextEvent() == .need_data); // no request event
    var ids: [8]u64 = undefined;
    try testing.expect(qc.streamIds(&ids) == 0); // and the stream is reclaimed
    try testing.expectEqual(@as(u32, 0), h3.streams.count());

    // A request on stream 0 (below the id) is still processed normally.
    const on0 = try buildRequestOnFin(gpa, &dcid, 0, 1, req.items);
    defer gpa.free(on0);
    try qc.receiveDatagram(on0, 1100);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .request);
}

test "the response send API rejects invalid sequences and inputs" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x1a, 0x2b, 0x3c, 0x4d };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // DATA before HEADERS is rejected.
    try testing.expectError(error.H3Error, h3.sendData(0, "x"));
    try testing.expectEqual(@as(u32, 0), h3.send_state.count());
    // An out-of-range status is rejected.
    try testing.expectError(error.H3Error, h3.sendResponse(0, 99, &.{}));
    // Interim statuses must use sendInformational, not the final-response API.
    try testing.expectError(error.H3Error, h3.sendResponse(0, 100, &.{}));
    // Content-Length is forbidden on informational and 204 responses (RFC 9110).
    try testing.expectError(error.H3Error, h3.sendInformational(0, 103, &[_]Header{.{ .name = "content-length", .value = "0" }}));
    try testing.expectError(error.H3Error, h3.sendResponse(0, 204, &[_]Header{.{ .name = "content-length", .value = "0" }}));
    try testing.expectEqual(@as(u32, 0), h3.send_state.count());
    try h3.sendInformational(0, 100, &.{});
    // A pseudo-header in the response headers is rejected (the server sets :status).
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &[_]Header{.{ .name = ":status", .value = "200" }}));
    // An uppercase / non-token field name is rejected (RFC 9114 4.2).
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &[_]Header{.{ .name = "X-Bad", .value = "x" }}));
    // A connection-specific field is rejected.
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &[_]Header{.{ .name = "connection", .value = "close" }}));
    // A CR/LF/control byte in a value is rejected (no header splitting).
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &[_]Header{.{ .name = "x", .value = "a\r\nb" }}));
    // TE other than "trailers" is rejected (RFC 9114 4.2), like the request path.
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &[_]Header{.{ .name = "te", .value = "gzip" }}));
    // Bad or conflicting Content-Length values are rejected before serialization.
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &[_]Header{.{ .name = "content-length", .value = "x" }}));
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &[_]Header{
        .{ .name = "content-length", .value = "1" },
        .{ .name = "content-length", .value = "2" },
    }));
    // A response on a non-client-bidi stream is rejected.
    try testing.expectError(error.H3Error, h3.sendResponse(1, 200, &.{}));
    try testing.expectEqual(@as(u32, 0), h3.send_state.count());

    // A valid response, then a second HEADERS is rejected, and writes after FIN too.
    try h3.sendResponse(0, 200, &.{});
    try testing.expectEqual(@as(u32, 1), h3.send_state.count());
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &.{}));
    try h3.endStream(0);
    try testing.expectError(error.H3Error, h3.sendData(0, "late"));
}

test "outbound HEADERS respect peer max field section size" {
    const gpa = testing.allocator;
    {
        const dcid = [_]u8{ 0x1a, 0x2b, 0x3c, 0x4e };
        var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
        defer qc.deinit();
        quic_conn.test_support.installAppKeys(&qc);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();

        h3.peer_settings = .{ .max_field_section_size = 41 };
        try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &.{}));
        try testing.expect(!h3.control_sent);
        try testing.expectEqual(@as(usize, 0), qc.datagramsToSend().len);
    }
    {
        const dcid = [_]u8{ 0x1a, 0x2b, 0x3c, 0x4f };
        var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
        defer qc.deinit();
        quic_conn.test_support.installAppKeys(&qc);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();

        h3.peer_settings = .{ .max_field_section_size = 41 };
        try testing.expectError(error.H3Error, h3.sendRequest("GET", "/", "https", "example.test", &.{}, true));
        try testing.expectEqual(@as(u64, 0), h3.next_request_stream_id);
        try testing.expect(!h3.control_sent);
        try testing.expectEqual(@as(usize, 0), qc.datagramsToSend().len);
    }
    {
        const dcid = [_]u8{ 0x1a, 0x2b, 0x3c, 0x50 };
        var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
        defer qc.deinit();
        quic_conn.test_support.installAppKeys(&qc);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();

        h3.peer_settings = .{ .max_field_section_size = 42 };
        try h3.sendResponse(0, 200, &.{});
        try testing.expectError(error.H3Error, h3.sendTrailers(0, &.{.{ .name = "x-big", .value = "abcdef" }}));
        try testing.expectEqual(.headers_sent, h3.peekSendState(0));
    }
}

// Build a 1-RTT datagram carrying `bytes` on unidirectional stream `uni_id` at the
// given packet number, so a uni-stream test can feed the type prefix + content.
fn buildUni(gpa: std.mem.Allocator, dcid: []const u8, uni_id: u64, pn: u64, bytes: []const u8) ![]u8 {
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0a); // STREAM, LEN set, no OFF/FIN
    try varint.append(&sframe, gpa, uni_id);
    try varint.append(&sframe, gpa, bytes.len);
    try sframe.appendSlice(gpa, bytes);
    return @import("../quic/connection.zig").test_support.buildApp(gpa, dcid, pn, sframe.items);
}

fn buildUniAt(gpa: std.mem.Allocator, dcid: []const u8, uni_id: u64, offset: u64, pn: u64, bytes: []const u8) ![]u8 {
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0e); // STREAM, OFF|LEN set
    try varint.append(&sframe, gpa, uni_id);
    try varint.append(&sframe, gpa, offset);
    try varint.append(&sframe, gpa, bytes.len);
    try sframe.appendSlice(gpa, bytes);
    return @import("../quic/connection.zig").test_support.buildApp(gpa, dcid, pn, sframe.items);
}

fn newH3Server(gpa: std.mem.Allocator, dcid: []const u8, qc: *quic_conn.Connection) Connection {
    qc.* = quic_conn.Connection.init(gpa, .server, dcid) catch unreachable;
    quic_conn.test_support.installAppKeys(qc);
    return Connection.init(gpa, qc);
}

test "the peer's control stream + SETTINGS is read without error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // Client control stream (uni id 2): type 0x00, then a SETTINGS frame.
    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00); // control stream type
    try h3_frame.append(&ctrl, gpa, .settings, &.{ 0x06, 0x44, 0x00 }); // max_field_section_size 0x400
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(2);
    try testing.expectEqual(@as(?u64, 2), h3.control_recv_id);
    try testing.expectEqual(@as(u64, 0x400), h3.peer_settings.?.max_field_section_size);
    const ev = h3.nextEvent();
    try testing.expect(ev == .settings);
    try testing.expectEqual(@as(usize, 1), ev.settings.params.len);
    try testing.expectEqual(@as(u64, @intFromEnum(h3_stream.SettingId.max_field_section_size)), ev.settings.params[0].id);
    try testing.expectEqual(@as(u64, 0x400), ev.settings.params[0].value);
}

test "an HTTP/3 SETTINGS event preserves 62-bit setting ids and values" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc4 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var settings_payload: std.ArrayListUnmanaged(u8) = .empty;
    defer settings_payload.deinit(gpa);
    const big_id: u64 = 1 << 34;
    const big_value: u64 = 1 << 33;
    try varint.append(&settings_payload, gpa, big_id);
    try varint.append(&settings_payload, gpa, big_value);

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00); // control stream type
    try h3_frame.append(&ctrl, gpa, .settings, settings_payload.items);
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(2);

    const ev = h3.nextEvent();
    try testing.expect(ev == .settings);
    try testing.expectEqual(@as(usize, 1), ev.settings.params.len);
    try testing.expectEqual(big_id, ev.settings.params[0].id);
    try testing.expectEqual(big_value, ev.settings.params[0].value);
}

test "a GOAWAY received after SETTINGS is recorded" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xab, 0xac, 0xad, 0xae };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .goaway, &.{0x08}); // GOAWAY id 8
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(2);
    try testing.expectEqual(@as(?u64, 8), h3.goaway_recv);
}

test "a received GOAWAY id may only decrease" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xaf, 0xb0, 0xb1, 0xb2 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // SETTINGS, GOAWAY 8, then GOAWAY 12 (a higher id): H3_ID_ERROR.
    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .goaway, &.{0x08});
    try h3_frame.append(&ctrl, gpa, .goaway, &.{0x0c});
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

test "a client accepts a server GOAWAY with a client request stream id" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb3, 0xb4, 0xb5, 0xb6 };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .goaway, &.{0x08});
    const dgram = try buildUni(gpa, &dcid, 3, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(3);
    try testing.expectEqual(@as(?u64, 8), h3.goaway_recv);
}

test "a client does not open the first request after receiving GOAWAY zero" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb3, 0xb4, 0xb5, 0xb8 };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .goaway, &.{0x00});
    const dgram = try buildUni(gpa, &dcid, 3, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(3);

    try testing.expectError(error.H3Error, h3.sendRequest("GET", "/", "https", "example.test", &.{}, true));
    try testing.expectEqual(@as(u64, 0), h3.next_request_stream_id);
    try testing.expect(!h3.control_sent);
}

test "a client may only open request streams below a received GOAWAY id" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb3, 0xb4, 0xb5, 0xb9 };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .goaway, &.{0x04});
    const dgram = try buildUni(gpa, &dcid, 3, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(3);

    try testing.expectEqual(@as(u64, 0), try h3.sendRequest("GET", "/", "https", "example.test", &.{}, true));
    try testing.expectEqual(@as(u64, 4), h3.next_request_stream_id);
    try testing.expectError(error.H3Error, h3.sendRequest("GET", "/late", "https", "example.test", &.{}, true));
    try testing.expectEqual(@as(u64, 4), h3.next_request_stream_id);
}

test "a client surfaces a large HTTP/3 GOAWAY id without truncation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb3, 0xb4, 0xb5, 0xb7 };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const big_id: u64 = 1 << 34; // client-bidi stream id, larger than u32.
    var goaway_payload: std.ArrayListUnmanaged(u8) = .empty;
    defer goaway_payload.deinit(gpa);
    try varint.append(&goaway_payload, gpa, big_id);

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .goaway, goaway_payload.items);
    const dgram = try buildUni(gpa, &dcid, 3, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(3);

    const settings = h3.nextEvent();
    try testing.expect(settings == .settings);
    const ev = h3.nextEvent();
    try testing.expect(ev == .goaway);
    try testing.expectEqual(big_id, ev.goaway.last_stream_id);
    try testing.expectEqual(@as(?u64, big_id), h3.goaway_recv);
}

test "a client rejects a server GOAWAY with a non-request-stream id" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb7, 0xb8, 0xb9, 0xba };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .goaway, &.{0x03}); // server uni stream id, not client-bidi
    const dgram = try buildUni(gpa, &dcid, 3, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(3));
}

test "a malformed GOAWAY payload is a frame error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xbb, 0xbc, 0xbd, 0xbe };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .goaway, &.{0x40}); // truncated two-byte varint
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

test "a GOAWAY payload with trailing bytes is a frame error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xbf, 0xc0, 0xc1, 0xc2 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .goaway, &.{ 0x00, 0x00 });
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

test "the control stream's first frame must be SETTINGS" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // Control stream whose first frame is GOAWAY (0x07), not SETTINGS: missing_settings.
    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .goaway, &.{0x00});
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

// Build a uni-stream datagram with the FIN bit set, so a "stream closed" test can
// finish a unidirectional stream.
fn buildUniFin(gpa: std.mem.Allocator, dcid: []const u8, uni_id: u64, bytes: []const u8) ![]u8 {
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0b); // STREAM, LEN|FIN
    try varint.append(&sframe, gpa, uni_id);
    try varint.append(&sframe, gpa, bytes.len);
    try sframe.appendSlice(gpa, bytes);
    return @import("../quic/connection.zig").test_support.buildApp(gpa, dcid, 0, sframe.items);
}

test "closing the control stream is a connection error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x4a, 0x4b, 0x4c, 0x4d };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // The control stream type, then a FIN, before any SETTINGS: critical stream
    // closed (RFC 9114 6.2.1, H3_CLOSED_CRITICAL_STREAM).
    const dgram = try buildUniFin(gpa, &dcid, 2, &.{0x00});
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

test "closing the control stream with a truncated frame is a frame error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x4a, 0x4b, 0x4c, 0x4e };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // Control stream type, then a partial SETTINGS frame header. The clean FIN
    // truncates an HTTP/3 frame, so this is H3_FRAME_ERROR rather than only
    // H3_CLOSED_CRITICAL_STREAM.
    const dgram = try buildUniFin(gpa, &dcid, 2, &.{ 0x00, 0x04 });
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
    try testing.expect(qc.closed);

    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const pc = peer.peer_close.?;
    try testing.expect(pc.app);
    try testing.expectEqual(@intFromEnum(h3_error.ErrorCode.frame_error), pc.error_code);
}

test "an empty uni stream finished before its type is reclaimed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x4e, 0x4f, 0x50, 0x51 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // A uni stream that is FIN'd with NO bytes at all: the type varint never arrives,
    // so it is an abandoned empty stream. It must be reclaimed, not retained.
    const dgram = try buildUniFin(gpa, &dcid, 2, &.{});
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(2);
    var ids: [4]u64 = undefined;
    try testing.expectEqual(@as(usize, 0), qc.streamIds(&ids));
    try testing.expectEqual(@as(u32, 0), h3.uni_streams.count());
}

test "a second SETTINGS on the control stream is unexpected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd4, 0xd5, 0xd6, 0xd7 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .settings, &.{}); // empty SETTINGS (valid)
    try h3_frame.append(&ctrl, gpa, .settings, &.{}); // a second one (illegal)
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

test "a SETTINGS with a duplicate identifier is a connection error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd8, 0xd9, 0xda, 0xdb };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .settings, &.{ 0x06, 0x01, 0x06, 0x02 }); // 0x06 twice
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

test "a second control stream is a connection error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xc4, 0xc5, 0xc6, 0xc7 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    const d2 = try buildUni(gpa, &dcid, 2, 0, &.{0x00}); // control on uni 2
    defer gpa.free(d2);
    try qc.receiveDatagram(d2, 1000);
    try h3.pump(2);
    const d6 = try buildUni(gpa, &dcid, 6, 1, &.{0x00}); // a second control on uni 6
    defer gpa.free(d6);
    try qc.receiveDatagram(d6, 1100);
    try testing.expectError(error.H3Error, h3.pump(6));
}

test "DATA on the control stream is unexpected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xc8, 0xc9, 0xca, 0xcb };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00); // control type
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .data, "x"); // DATA is illegal here
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

test "an HTTP/2-only frame type on the control stream is unexpected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xc8, 0xc9, 0xca, 0xcc };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00); // control type
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, @enumFromInt(0x02), "");
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

test "a valid MAX_PUSH_ID on the control stream is ignored" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00); // control type
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .max_push_id, &.{0x00});
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(2);
    try testing.expectEqual(@as(?u64, 0), h3.max_push_id_recv);
}

test "a malformed MAX_PUSH_ID on the control stream is a frame error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xd8 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00); // control type
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .max_push_id, &.{ 0x00, 0x00 }); // trailing varint
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

test "a decreasing MAX_PUSH_ID is an id error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xd9 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00); // control type
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .max_push_id, &.{0x04});
    try h3_frame.append(&ctrl, gpa, .max_push_id, &.{0x03});
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

test "a client rejects MAX_PUSH_ID from a server" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xda };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00); // control type
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .max_push_id, &.{0x00});
    const dgram = try buildUni(gpa, &dcid, 3, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(3));
}

test "CANCEL_PUSH is rejected when no push was promised" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xdb };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00); // control type
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .cancel_push, &.{0x00});
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

test "PUSH_PROMISE on the control stream is unexpected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00); // control type
    try h3_frame.append(&ctrl, gpa, .settings, &.{});
    try h3_frame.append(&ctrl, gpa, .push_promise, &.{0x00});
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

test "a control-stream violation closes with the specific H3 error code" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // First control-stream frame is DATA, not SETTINGS: H3_MISSING_SETTINGS (0x10a).
    // The "SETTINGS first" rule is checked before DATA's normal placement rule.
    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .data, "x");
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
    try testing.expect(qc.closed);

    // The queued CONNECTION_CLOSE carries the application error H3_MISSING_SETTINGS.
    // Feed each built datagram separately (an ACK may precede the close packet).
    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const pc = peer.peer_close.?;
    try testing.expect(pc.app);
    try testing.expectEqual(@intFromEnum(h3_error.ErrorCode.missing_settings), pc.error_code);
}

test "a malformed SETTINGS closes with the specific H3 error code" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .settings, &.{ 0x02, 0x00 }); // reserved HTTP/2 setting id
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
    try testing.expect(qc.closed);

    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const pc = peer.peer_close.?;
    try testing.expect(pc.app);
    try testing.expectEqual(@intFromEnum(h3_error.ErrorCode.settings_error), pc.error_code);
}

test "a QPACK encoder stream can feed a dynamic request header" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xcf };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // Client QPACK encoder stream (uni id 2): type 0x02, Set Capacity=128, then
    // Insert With Literal Name x=y.
    const enc_dgram = try buildUni(gpa, &dcid, 2, 0, &.{ 0x02, 0x3f, 0x61, 0x41, 'x', 0x01, 'y' });
    defer gpa.free(enc_dgram);
    try qc.receiveDatagram(enc_dgram, 1000);
    try h3.pump(2);
    try testing.expectEqual(@as(usize, 0), qc.streamData(2).len);

    // The request HEADERS then references that dynamic entry alongside static
    // pseudo-headers: RIC=1, Base=1, indexed dynamic relative index 0.
    const qpack_block = [_]u8{ 0x02, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x80 };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);
    const req_dgram = try buildRequestOnFin(gpa, &dcid, 0, 1, h3_bytes.items);
    defer gpa.free(req_dgram);
    try qc.receiveDatagram(req_dgram, 2000);
    try h3.pump(0);

    const ev = h3.nextEvent();
    try testing.expect(ev == .request);
    try testing.expectEqualStrings("x", ev.request.headers[0].name);
    try testing.expectEqualStrings("y", ev.request.headers[0].value);
    try testing.expect(ev.request.end_stream);
    try testing.expect(h3.nextEvent() == .need_data);

    try qc.flushSend(3000);
    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 2);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 4000);
        off += len;
    }
    try testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x01, 0x80 }, peer.streamData(7));
}

test "a request blocked on QPACK resumes when encoder inserts arrive" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xd3 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    const qpack_block = [_]u8{ 0x02, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x80 };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);
    const req_dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
    defer gpa.free(req_dgram);
    try qc.receiveDatagram(req_dgram, 1000);
    try h3.pump(0);

    try testing.expect(h3.nextEvent() == .need_data);
    try testing.expectEqual(@as(usize, 0), qc.streamData(0).len); // HEADERS was consumed and stored.

    const enc_dgram = try buildUni(gpa, &dcid, 2, 1, &.{ 0x02, 0x3f, 0x61, 0x41, 'x', 0x01, 'y' });
    defer gpa.free(enc_dgram);
    try qc.receiveDatagram(enc_dgram, 2000);
    try h3.pump(2);

    const ev = h3.nextEvent();
    try testing.expect(ev == .request);
    try testing.expectEqualStrings("x", ev.request.headers[0].name);
    try testing.expectEqualStrings("y", ev.request.headers[0].value);
    try testing.expect(ev.request.end_stream);
    try testing.expect(h3.nextEvent() == .need_data);
}

test "a QPACK-blocked request cannot slip past a GOAWAY when it unblocks" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xd4 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // A HEADERS block referencing a dynamic entry blocks on QPACK: it is consumed
    // and stored, the stream tracked as idle, no Request surfaced.
    const qpack_block = [_]u8{ 0x02, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x80 };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);
    const req_dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, h3_bytes.items);
    defer gpa.free(req_dgram);
    try qc.receiveDatagram(req_dgram, 1000);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .need_data);

    // The server advertises a GOAWAY at stream 0 while the request is still blocked.
    try h3.shutdown(0);

    // The encoder inserts arrive and unblock the headers. The resume path must
    // honor the GOAWAY too - reject the request, do not surface it past the limit.
    const enc_dgram = try buildUni(gpa, &dcid, 2, 1, &.{ 0x02, 0x3f, 0x61, 0x41, 'x', 0x01, 'y' });
    defer gpa.free(enc_dgram);
    try qc.receiveDatagram(enc_dgram, 2000);
    try h3.pump(2);
    try testing.expect(h3.nextEvent() == .need_data); // rejected, not surfaced
}

test "too many QPACK-blocked request streams is a decompression error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xd4 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    const qpack_block = [_]u8{ 0x02, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x80 };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);

    var i: u64 = 0;
    while (i < QPACK_BLOCKED_STREAMS) : (i += 1) {
        const d = try buildRequestOnFin(gpa, &dcid, i * 4, i, h3_bytes.items);
        defer gpa.free(d);
        try qc.receiveDatagram(d, 1000 + i);
        try h3.pump(i * 4);
    }

    const overflow_stream = QPACK_BLOCKED_STREAMS * 4;
    const overflow = try buildRequestOnFin(gpa, &dcid, overflow_stream, QPACK_BLOCKED_STREAMS, h3_bytes.items);
    defer gpa.free(overflow);
    try qc.receiveDatagram(overflow, 3000);
    try testing.expectError(error.H3Error, h3.pump(overflow_stream));
    try testing.expect(qc.closed);
}

test "a rejected dynamic request sends QPACK stream cancellation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xd2 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // Insert an uppercase field name. QPACK decoding succeeds, but HTTP/3 field
    // validation rejects the request, so the dynamic section must be cancelled.
    const enc_dgram = try buildUni(gpa, &dcid, 2, 0, &.{ 0x02, 0x3f, 0x61, 0x41, 'X', 0x01, 'y' });
    defer gpa.free(enc_dgram);
    try qc.receiveDatagram(enc_dgram, 1000);
    try h3.pump(2);

    const qpack_block = [_]u8{ 0x02, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x80 };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);
    const req_dgram = try buildRequestOnFin(gpa, &dcid, 0, 1, h3_bytes.items);
    defer gpa.free(req_dgram);
    try qc.receiveDatagram(req_dgram, 2000);
    try h3.pump(0);

    try testing.expect(h3.nextEvent() == .need_data);
    try testing.expect(!qc.closed);

    try qc.flushSend(3000);
    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    try peer.sendStreamData(0, &.{}, false);
    quic_conn.test_support.setAppNextPn(&peer, 2);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 4000);
        off += len;
    }
    // Decoder stream: type, Insert Count Increment(1), Stream Cancellation(stream 0).
    try testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x01, 0x40 }, peer.streamData(7));
}

test "a split QPACK encoder instruction waits for more stream bytes" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xd1 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // Offset 0: stream type, complete capacity update, and only the first two bytes
    // of Insert With Literal Name. H3 may consume the type and capacity, but must
    // leave the partial insert buffered instead of closing the connection.
    const dg1 = try buildUni(gpa, &dcid, 2, 0, &.{ 0x02, 0x3f, 0x61, 0x41, 'x' });
    defer gpa.free(dg1);
    try qc.receiveDatagram(dg1, 1000);
    try h3.pump(2);
    try testing.expect(!qc.closed);
    try testing.expectEqualStrings(&[_]u8{ 0x41, 'x' }, qc.streamData(2));

    // Offset 5 completes the insert with value "y"; the combined buffered bytes can
    // now update the dynamic table.
    const dg2 = try buildUniAt(gpa, &dcid, 2, 5, 1, &.{ 0x01, 'y' });
    defer gpa.free(dg2);
    try qc.receiveDatagram(dg2, 1100);
    try h3.pump(2);
    try testing.expectEqual(@as(usize, 0), qc.streamData(2).len);

    const qpack_block = [_]u8{ 0x02, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x80 };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);
    const req_dgram = try buildRequestOnFin(gpa, &dcid, 0, 2, h3_bytes.items);
    defer gpa.free(req_dgram);
    try qc.receiveDatagram(req_dgram, 2000);
    try h3.pump(0);

    const ev = h3.nextEvent();
    try testing.expect(ev == .request);
    try testing.expectEqualStrings("x", ev.request.headers[0].name);
    try testing.expectEqualStrings("y", ev.request.headers[0].value);
}

test "a malformed QPACK encoder stream is a decompression connection error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xd0 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    const dgram = try buildUni(gpa, &dcid, 2, 0, &.{ 0x02, 0x00 }); // duplicate index 0 before any insert
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
    try testing.expect(qc.closed);

    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const pc = peer.peer_close.?;
    try testing.expect(pc.app);
    try testing.expectEqual(@intFromEnum(h3_error.ErrorCode.qpack_encoder_stream_error), pc.error_code);
}

test "a malformed QPACK decoder stream is a decoder stream error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xd6 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    const dgram = try buildUni(gpa, &dcid, 2, 0, &.{ 0x03, 0x00 }); // Insert Count Increment(0)
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
    try testing.expect(qc.closed);

    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const pc = peer.peer_close.?;
    try testing.expect(pc.app);
    try testing.expectEqual(@intFromEnum(h3_error.ErrorCode.qpack_decoder_stream_error), pc.error_code);
}

test "closing the QPACK encoder stream with a truncated instruction is an encoder stream error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xd8 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // Stream type 0x02, Set Capacity=128, then only the first byte of an
    // Insert With Literal Name instruction.
    const dgram = try buildUniFin(gpa, &dcid, 2, &.{ 0x02, 0x3f, 0x61, 0x41 });
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
    try testing.expect(qc.closed);

    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const pc = peer.peer_close.?;
    try testing.expect(pc.app);
    try testing.expectEqual(@intFromEnum(h3_error.ErrorCode.qpack_encoder_stream_error), pc.error_code);
}

test "closing the QPACK decoder stream with a truncated instruction is a decoder stream error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xd9 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    const dgram = try buildUniFin(gpa, &dcid, 2, &.{ 0x03, 0x3f }); // truncated Insert Count Increment
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
    try testing.expect(qc.closed);

    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const pc = peer.peer_close.?;
    try testing.expect(pc.app);
    try testing.expectEqual(@intFromEnum(h3_error.ErrorCode.qpack_decoder_stream_error), pc.error_code);
}

test "a second QPACK encoder stream is a stream creation error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xd7 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    const first = try buildUni(gpa, &dcid, 2, 0, &.{0x02});
    defer gpa.free(first);
    try qc.receiveDatagram(first, 1000);
    try h3.pump(2);
    try testing.expectEqual(@as(?u64, 2), h3.qpack_encoder_recv_id);

    const second = try buildUni(gpa, &dcid, 6, 1, &.{0x02});
    defer gpa.free(second);
    try qc.receiveDatagram(second, 2000);
    try testing.expectError(error.H3Error, h3.pump(6));
    try testing.expect(qc.closed);
}

test "a second QPACK decoder stream is a stream creation error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xd8 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    const first = try buildUni(gpa, &dcid, 2, 0, &.{0x03});
    defer gpa.free(first);
    try qc.receiveDatagram(first, 1000);
    try h3.pump(2);
    try testing.expectEqual(@as(?u64, 2), h3.qpack_decoder_recv_id);

    const second = try buildUni(gpa, &dcid, 6, 1, &.{0x03});
    defer gpa.free(second);
    try qc.receiveDatagram(second, 2000);
    try testing.expectError(error.H3Error, h3.pump(6));
    try testing.expect(qc.closed);
}

test "closing the QPACK encoder stream is a critical stream error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xd5 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    const dgram = try buildUniFin(gpa, &dcid, 2, &.{0x02});
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
    try testing.expect(qc.closed);
}

test "closing the QPACK decoder stream is a critical stream error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xd6 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    const dgram = try buildUniFin(gpa, &dcid, 2, &.{0x03});
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
    try testing.expect(qc.closed);
}

test "a finished ignored uni stream is reclaimed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xe5, 0xe6, 0xe7, 0xe8 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // An unknown uni stream that the peer opens and immediately finishes (FIN).
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0b); // STREAM, LEN|FIN
    try varint.append(&sframe, gpa, 2);
    try varint.append(&sframe, gpa, 1);
    try sframe.append(gpa, 0x21); // reserved/unknown stream type
    const dgram = try @import("../quic/connection.zig").test_support.buildApp(gpa, &dcid, 0, sframe.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(2);

    // The finished ignored stream is dropped from both maps, not retained.
    var ids: [4]u64 = undefined;
    try testing.expectEqual(@as(usize, 0), qc.streamIds(&ids));
    try testing.expectEqual(@as(u32, 0), h3.uni_streams.count());
}

test "a client-created push stream is a connection error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xea, 0xeb, 0xec, 0xed };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0b); // STREAM, LEN|FIN
    try varint.append(&sframe, gpa, 2); // client-initiated uni stream
    try varint.append(&sframe, gpa, 1);
    try sframe.append(gpa, 0x01); // push stream type
    const dgram = try @import("../quic/connection.zig").test_support.buildApp(gpa, &dcid, 0, sframe.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
}

test "a truncated server push stream header is a frame error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xea, 0xeb, 0xec, 0xee };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0b); // STREAM, LEN|FIN
    try varint.append(&sframe, gpa, 3); // server-initiated uni stream
    try varint.append(&sframe, gpa, 1);
    try sframe.append(gpa, 0x01); // push stream type
    const dgram = try @import("../quic/connection.zig").test_support.buildApp(gpa, &dcid, 0, sframe.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(3));

    var peer = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const pc = peer.peer_close.?;
    try testing.expect(pc.app);
    try testing.expectEqual(@intFromEnum(h3_error.ErrorCode.frame_error), pc.error_code);
}

test "a split truncated server push id is a frame error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xea, 0xeb, 0xec, 0xf0 };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var first: std.ArrayListUnmanaged(u8) = .empty;
    defer first.deinit(gpa);
    try first.append(gpa, 0x0a); // STREAM, LEN, no FIN
    try varint.append(&first, gpa, 3); // server-initiated uni stream
    try varint.append(&first, gpa, 2);
    try first.appendSlice(gpa, &.{ 0x01, 0x40 }); // push stream type, partial two-byte push id
    const dg1 = try @import("../quic/connection.zig").test_support.buildApp(gpa, &dcid, 0, first.items);
    defer gpa.free(dg1);
    try qc.receiveDatagram(dg1, 1000);
    try h3.pump(3);
    try testing.expectEqual(@as(usize, 1), qc.streamData(3).len);

    var second: std.ArrayListUnmanaged(u8) = .empty;
    defer second.deinit(gpa);
    try second.append(gpa, 0x0f); // STREAM, OFF|LEN|FIN
    try varint.append(&second, gpa, 3);
    try varint.append(&second, gpa, 2); // offset after type + partial push id
    try varint.append(&second, gpa, 0);
    const dg2 = try @import("../quic/connection.zig").test_support.buildApp(gpa, &dcid, 1, second.items);
    defer gpa.free(dg2);
    try qc.receiveDatagram(dg2, 1100);
    try testing.expectError(error.H3Error, h3.pump(3));

    var peer = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 2);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const pc = peer.peer_close.?;
    try testing.expect(pc.app);
    try testing.expectEqual(@intFromEnum(h3_error.ErrorCode.frame_error), pc.error_code);
}

test "a reset server push stream with a partial push id is reclaimed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xea, 0xeb, 0xec, 0xf1 };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var first: std.ArrayListUnmanaged(u8) = .empty;
    defer first.deinit(gpa);
    try first.append(gpa, 0x0a); // STREAM, LEN, no FIN
    try varint.append(&first, gpa, 3); // server-initiated uni stream
    try varint.append(&first, gpa, 2);
    try first.appendSlice(gpa, &.{ 0x01, 0x40 }); // push stream type, partial two-byte push id
    const data = try @import("../quic/connection.zig").test_support.buildApp(gpa, &dcid, 0, first.items);
    defer gpa.free(data);
    try qc.receiveDatagram(data, 1000);
    try h3.pump(3);

    const reset = try @import("../quic/connection.zig").test_support.buildApp(gpa, &dcid, 1, &.{ 0x04, 0x03, 0x00, 0x03 });
    defer gpa.free(reset);
    try qc.receiveDatagram(reset, 1100);
    try h3.pump(3);

    var ids: [1]u64 = undefined;
    try testing.expectEqual(@as(usize, 0), qc.streamIds(&ids));
    try testing.expectEqual(@as(u32, 0), h3.uni_streams.count());
    try testing.expect(!qc.closed);
}

test "a server push stream is rejected when the client did not enable push" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xea, 0xeb, 0xec, 0xef };
    var qc = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer qc.deinit();
    quic_conn.test_support.installAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0b); // STREAM, LEN|FIN
    try varint.append(&sframe, gpa, 3); // server-initiated uni stream
    try varint.append(&sframe, gpa, 2);
    try sframe.append(gpa, 0x01); // push stream type
    try sframe.append(gpa, 0x00); // push id 0
    const dgram = try @import("../quic/connection.zig").test_support.buildApp(gpa, &dcid, 0, sframe.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(3));

    var peer = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer peer.deinit();
    quic_conn.test_support.installAppKeys(&peer);
    quic_conn.test_support.setAppNextPn(&peer, 1);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const pc = peer.peer_close.?;
    try testing.expect(pc.app);
    try testing.expectEqual(@intFromEnum(h3_error.ErrorCode.id_error), pc.error_code);
}

test "an ignored uni stream finished by a separate FIN is still reclaimed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xf5, 0xf6, 0xf7, 0xf8 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // Datagram 1: unknown stream type + 1 byte, no FIN. The content is consumed.
    var d1: std.ArrayListUnmanaged(u8) = .empty;
    defer d1.deinit(gpa);
    try d1.append(gpa, 0x0a); // STREAM, LEN, no FIN
    try varint.append(&d1, gpa, 2);
    try varint.append(&d1, gpa, 2);
    try d1.appendSlice(gpa, &.{ 0x21, 0xaa }); // unknown type + a byte
    const dg1 = try @import("../quic/connection.zig").test_support.buildApp(gpa, &dcid, 0, d1.items);
    defer gpa.free(dg1);
    try qc.receiveDatagram(dg1, 1000);
    try h3.pump(2);

    // Datagram 2: a bare FIN at offset 2 (no new bytes). The reclamation must still
    // fire even though this pump consumes nothing new.
    var d2: std.ArrayListUnmanaged(u8) = .empty;
    defer d2.deinit(gpa);
    try d2.append(gpa, 0x0f); // STREAM, OFF|LEN|FIN
    try varint.append(&d2, gpa, 2);
    try varint.append(&d2, gpa, 2); // offset 2
    try varint.append(&d2, gpa, 0); // zero length
    const dg2 = try @import("../quic/connection.zig").test_support.buildApp(gpa, &dcid, 1, d2.items);
    defer gpa.free(dg2);
    try qc.receiveDatagram(dg2, 1100);
    try h3.pump(2);

    var ids: [4]u64 = undefined;
    try testing.expectEqual(@as(usize, 0), qc.streamIds(&ids));
    try testing.expectEqual(@as(u32, 0), h3.uni_streams.count());
}
