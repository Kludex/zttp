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
    /// A stream-level HTTP/3 error (RFC 9114 4.1.2): a malformed request that resets
    /// just that stream, leaving the connection up. Caught in the pump, never escapes
    /// to the integrator.
    StreamError,
    OutOfMemory,
};

// A request stream's receive progress (RFC 9114 4.1): the lone HEADERS, then DATA,
// then an optional single trailing HEADERS (trailers), then the FIN.
const ReqState = enum { idle, headers_done, trailers_done, done, rejected };

const RequestStream = struct {
    state: ReqState = .idle,
    /// The declared request body length (RFC 9114 4.1.2), or null if no
    /// Content-Length was sent. Reconciled against the DATA bytes at the FIN.
    content_length: ?u64 = null,
    body_received: u64 = 0,
    /// Whether a peer-reset event has already been emitted for this stream, so a
    /// re-pump (if the stream could not yet be dropped) does not re-fire it.
    rst_emitted: bool = false,
    /// The decoded trailing field section (RFC 9114 4.1), held until the FIN folds it
    /// into the end_of_message event. Empty when the request had no trailers. The
    /// slices live in the connection arena, like the request headers.
    trailers: []const Header = &.{},
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

/// The server-initiated unidirectional stream ids (RFC 9000 2.1): server uni ids are
/// 4*N+3. The control stream is the first; the two QPACK streams (RFC 9204 4.2) are
/// the next two. A peer MUST open all three regardless of QPACK table capacity, so
/// strict clients (nghttp3, quiche) abort if the encoder/decoder streams are missing.
const CONTROL_STREAM_ID: u64 = 3;
const QPACK_ENCODER_STREAM_ID: u64 = 7;
const QPACK_DECODER_STREAM_ID: u64 = 11;
/// The count of server-initiated uni streams HTTP/3 always opens (the three above);
/// a peer must grant at least this many in initial_max_streams_uni.
const SERVER_UNI_STREAMS: u64 = 3;

pub const Connection = struct {
    gpa: std.mem.Allocator,
    qc: *quic_conn.Connection,
    streams: std.AutoHashMapUnmanaged(u64, RequestStream) = .empty,
    send_state: std.AutoHashMapUnmanaged(u64, SendState) = .empty,
    qpack_dec: qpack.Decoder,
    queue: std.ArrayListUnmanaged(H3Event) = .empty,
    qpos: usize = 0,
    /// Owned copies of the strings each queued event borrows; freed when the queue
    /// is reset. QPACK's decode store is reused per call, so we materialise here.
    arena: std.heap.ArenaAllocator,
    /// Whether our control stream (type + SETTINGS) has been opened (RFC 9114
    /// 6.2.1). The control stream is opened once, before any response.
    control_sent: bool = false,
    /// Per inbound unidirectional stream: its decoded type, once enough bytes have
    /// arrived to read the type-prefix varint (it may span datagrams).
    uni_streams: std.AutoHashMapUnmanaged(u64, UniStream) = .empty,
    /// The peer's control-stream id, set when its type prefix is read. A second
    /// control stream is a connection error (RFC 9114 6.2.1).
    control_recv_id: ?u64 = null,
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
    /// The H3 error code a stream-level rejection (failStream) wants the pump to reset
    /// the current stream with; consumed by pumpRequest. Carries the code across the
    /// error.StreamError return (Zig errors hold no payload).
    pending_reject: ?h3_error.ErrorCode = null,

    pub fn init(gpa: std.mem.Allocator, qc: *quic_conn.Connection) Connection {
        return .{
            .gpa = gpa,
            .qc = qc,
            .qpack_dec = qpack.Decoder.init(gpa, MAX_FIELD_SECTION_SIZE),
            .arena = std.heap.ArenaAllocator.init(gpa),
        };
    }

    pub fn deinit(self: *Connection) void {
        var it = self.streams.valueIterator();
        while (it.next()) |rs| if (rs.trailers.len > 0) freeHeaders(self.gpa, rs.trailers);
        self.streams.deinit(self.gpa);
        self.send_state.deinit(self.gpa);
        self.uni_streams.deinit(self.gpa);
        self.qpack_dec.deinit();
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

    /// Reject one request stream without closing the connection (RFC 9114 4.1.2): the
    /// pump catches error.StreamError, reads this code, and resets the stream. A
    /// malformed request thus costs one stream, not the whole connection.
    fn failStream(self: *Connection, code: h3_error.ErrorCode) Error {
        self.pending_reject = code;
        return error.StreamError;
    }

    /// Reset request stream `id` with `code` and drop its state: RESET_STREAM the
    /// response, STOP_SENDING the request, drain and reclaim. Used both for a
    /// malformed request (failStream) and a request covered by our GOAWAY.
    fn rejectStream(self: *Connection, id: u64, code: h3_error.ErrorCode) Error!void {
        self.qc.resetStream(id, @intFromEnum(code)) catch return error.H3Error;
        self.qc.stopSending(id, @intFromEnum(code)) catch return error.H3Error;
        // Consume the unread bytes so the recv state can reach terminal and dropStream
        // can reclaim now. A zero-length FIN leaves no pending bytes but still must be
        // consumed (consumeStream(id, 0) flips a finished stream to data_read);
        // otherwise the stream lingers in .rejected until an unrelated later repump.
        const pending = self.qc.streamData(id).len;
        if (pending > 0 or self.qc.streamFinished(id) or self.qc.streamReset(id)) self.qc.consumeStream(id, pending);
        // Drop the stream if the transport can (recv terminal); otherwise mark it
        // .rejected so a later pump quarantines it (drains, no more events) rather than
        // re-parsing a stream we already reset, which could surface a spurious request.
        if (self.qc.dropStream(id)) {
            self.freeStream(id);
        } else if (self.streams.getPtr(id)) |rs| {
            rs.state = .rejected;
        }
    }

    /// Open our three server-initiated unidirectional streams (RFC 9114 6.2.1,
    /// RFC 9204 4.2): the control stream carrying SETTINGS, plus the QPACK encoder and
    /// decoder streams. A conformant peer treats the absence of our SETTINGS as
    /// H3_MISSING_SETTINGS and may refuse to send requests, and strict clients abort
    /// if the QPACK streams are missing - so all three must precede any response.
    /// Idempotent: each is opened at most once. Each stream's type byte prefixes its
    /// content; the QPACK streams carry no instructions (table capacity 0).
    pub fn initiateControl(self: *Connection) Error!void {
        if (self.control_sent) return;
        // HTTP/3 needs three server-initiated uni streams (control + the two QPACK
        // streams). A peer that grants fewer cannot run HTTP/3, so rather than open
        // streams past its initial_max_streams_uni - which it would answer with a
        // STREAM_LIMIT_ERROR - close cleanly up front (RFC 9000 4.6 / RFC 9114 6.2).
        if (self.qc.peerMaxStreamsUni() < SERVER_UNI_STREAMS) {
            return self.fail(.general_protocol_error, "peer granted too few unidirectional streams for HTTP/3");
        }
        var settings: std.ArrayListUnmanaged(u8) = .empty;
        defer settings.deinit(self.gpa);
        // SETTINGS_MAX_FIELD_SECTION_SIZE = our decode cap. QPACK capacity and
        // blocked-streams default to 0 (RFC 9204 5), so they need not be sent.
        varint.append(&settings, self.gpa, @intFromEnum(h3_stream.SettingId.max_field_section_size)) catch return error.OutOfMemory;
        varint.append(&settings, self.gpa, MAX_FIELD_SECTION_SIZE) catch return error.OutOfMemory;

        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(self.gpa);
        out.append(self.gpa, @intFromEnum(h3_stream.UniStreamType.control)) catch return error.OutOfMemory;
        h3_frame.append(&out, self.gpa, .settings, settings.items) catch return error.OutOfMemory;

        // Commit BEFORE sending: a failure partway through (OOM) must not let a later
        // call re-open the control stream and queue a second SETTINGS, which a peer
        // treats as a connection error. A half-initialised connection is already
        // degraded; re-attempting would corrupt it, not recover it.
        self.control_sent = true;
        try self.streamSend(CONTROL_STREAM_ID, out.items, false);
        // The QPACK encoder/decoder streams: just the type byte each. At table
        // capacity 0 no encoder/decoder instructions are ever sent, but the streams
        // must exist for the peer's QPACK to consider the connection well-formed. The
        // grant was checked above; full credit accounting (a peer MAX_STREAMS raising
        // the limit, blocking past it) is a follow-up, mooted here by the fixed count.
        try self.streamSend(QPACK_ENCODER_STREAM_ID, &.{@intFromEnum(h3_stream.UniStreamType.qpack_encoder)}, false);
        try self.streamSend(QPACK_DECODER_STREAM_ID, &.{@intFromEnum(h3_stream.UniStreamType.qpack_decoder)}, false);
    }

    /// Begin a graceful shutdown: send a GOAWAY on the control stream (RFC 9114 5.2)
    /// announcing `stream_id` as the first client request stream we will NOT process
    /// - the peer finishes everything below it and opens nothing higher. The control
    /// stream is opened first if needed. A later GOAWAY may only lower the id (a
    /// higher one is rejected), so a shutdown can narrow but never widen what we
    /// promise to handle.
    pub fn shutdown(self: *Connection, stream_id: u64) Error!void {
        // A server's GOAWAY id names a client request stream (RFC 9114 5.2), so it is
        // a client-bidi id and within the 62-bit varint range. Validate BEFORE any
        // side effect (opening the control stream), so a bad id is a clean rejection.
        if (stream_id > varint.MAX) return error.H3Error;
        if (quic_stream.StreamType.of(stream_id) != .client_bidi) return error.H3Error;
        if (self.goaway_sent) |prev| if (stream_id > prev) return error.H3Error;
        try self.initiateControl();
        var payload: std.ArrayListUnmanaged(u8) = .empty;
        defer payload.deinit(self.gpa);
        varint.append(&payload, self.gpa, stream_id) catch return error.OutOfMemory;
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(self.gpa);
        h3_frame.append(&out, self.gpa, .goaway, payload.items) catch return error.OutOfMemory;
        try self.streamSend(CONTROL_STREAM_ID, out.items, false);
        self.goaway_sent = stream_id;
    }

    /// Advance the parse of request stream `id` from whatever ordered bytes the
    /// QUIC transport now has. Newly completed events are appended to the queue.
    /// The caller (the adapter) calls this when it knows a stream got data; a
    /// production driver would call it for every stream that advanced.
    /// Advance the parse of every stream the transport currently knows about.
    /// The adapter calls this after each datagram so it need not track which
    /// streams advanced. The 64-id snapshot bound is far above any realistic
    /// concurrent-stream count for a young connection.
    pub fn pumpAll(self: *Connection) Error!void {
        var ids: [64]u64 = undefined;
        const n = self.qc.streamIds(&ids);
        for (ids[0..n]) |id| try self.pump(id);
        // Surface any peer STOP_SENDING (a response cancellation) left for a stream
        // whose recv side already completed and is gone from streamIds, so a cancelled
        // GET is reported rather than discovered only when a response write fails.
        var ss: [64]u64 = undefined;
        const m = self.qc.stopSendingIds(&ss);
        for (ss[0..m]) |id| try self.surfaceStopSending(id);
    }

    /// Emit a one-shot rst_stream event for a peer STOP_SENDING on `id` (consuming it),
    /// unless the stream is still tracked - in which case pumpRequest surfaces it with
    /// the right rst_emitted bookkeeping. For a completed/untracked stream there is no
    /// RequestStream, so the consume itself makes it fire once.
    fn surfaceStopSending(self: *Connection, id: u64) Error!void {
        if (self.streams.contains(id)) return; // a live stream: pumpRequest handles it
        const code = self.qc.peekStopSending(id) orelse return;
        try self.push(.{ .rst_stream = .{ .stream_id = id, .error_code = code } });
        _ = self.qc.takeStopSending(id); // consume only after the event is queued
    }

    pub fn pump(self: *Connection, id: u64) Error!void {
        switch (quic_stream.StreamType.of(id)) {
            .client_bidi => try self.pumpRequest(id),
            .client_uni => try self.pumpUni(id),
            else => {}, // server-initiated streams are ours; nothing to read here
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
            if (id >= limit and !self.streams.contains(id)) {
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
            if (finished and self.qc.dropStream(id)) self.freeStream(id);
            return;
        }

        // Parse from the start of the ordered bytes the transport currently holds:
        // every fully-decoded frame is consumed (removed from the QUIC stream)
        // before this returns, so the next pump always begins at offset 0 with the
        // not-yet-consumed tail (a partial frame plus any newer bytes). Tracking a
        // persistent offset here would desync once consumeStream slides the buffer.
        const ready = self.qc.streamData(id);
        var consumed_total: usize = 0;
        while (consumed_total < ready.len) {
            const rest = ready[consumed_total..];
            const d = h3_frame.decode(rest) catch break; // NeedData: wait for more
            self.onFrame(id, rs, d.frame) catch |e| switch (e) {
                // A stream-level error (a malformed request): reset just this stream
                // and stop processing it, rather than poisoning the whole connection.
                error.StreamError => {
                    const code = self.pending_reject orelse h3_error.ErrorCode.message_error;
                    self.pending_reject = null;
                    // If the integrator already saw the request (e.g. malformed
                    // trailers after the head and body), surface a terminal rst_stream
                    // so it stops waiting on an end_of_message that will never come.
                    // Set the flag only after the push succeeds, so an OOM here leaves
                    // a retry able to surface it rather than resetting silently.
                    if (rs.state != .idle and !rs.rst_emitted) {
                        try self.push(.{ .rst_stream = .{ .stream_id = id, .error_code = @intFromEnum(code) } });
                        rs.rst_emitted = true;
                    }
                    return self.rejectStream(id, code); // rs dangles after the drop inside
                },
                else => return e,
            };
            consumed_total += d.len;
        }
        if (self.qc.streamFinished(id) and (rs.state == .headers_done or rs.state == .trailers_done)) {
            // The stream ended: any bytes the frame loop could not decode are a frame
            // truncated by the FIN (the loop only breaks on NeedData, and no more bytes
            // will come), a connection error (RFC 9114 4.1, H3_FRAME_ERROR) - not a
            // silently-accepted complete request.
            if (consumed_total < ready.len) return self.fail(.frame_error, "a frame truncated by the stream end");
            // Fewer body bytes than the declared Content-Length is a malformed message
            // (RFC 9114 4.1.2); the over-count is caught per-DATA above. Like any
            // malformed request it resets just this stream - and since the request was
            // already surfaced, a terminal rst_stream so the integrator stops waiting.
            if (rs.content_length) |cl| if (rs.body_received != cl) {
                if (!rs.rst_emitted) {
                    try self.push(.{ .rst_stream = .{ .stream_id = id, .error_code = @intFromEnum(h3_error.ErrorCode.message_error) } });
                    rs.rst_emitted = true;
                }
                return self.rejectStream(id, .message_error); // drains the stream and drops it
            };
            // The event borrows from the per-event arena (reclaimed on the next drain,
            // like the request headers); rs.trailers is the gpa copy that survived
            // across pumps and is freed when the stream drops below.
            const ev_trailers = try self.arenaDupeHeaders(rs.trailers);
            try self.push(.{ .end_of_message = .{ .trailers = ev_trailers, .stream_id = id } });
            rs.state = .done;
        }
        // Consume BEFORE dropping: consuming the last byte of a finished stream is
        // what moves its receive state to terminal, which dropStream then reclaims.
        if (consumed_total > 0) self.qc.consumeStream(id, consumed_total);
        // A peer RESET_STREAM cancels the request: surface it as an event (with the
        // The peer cancelled this stream - by RESET_STREAM on the request side, or by
        // STOP_SENDING on the response side (it aborted the response, perhaps before we
        // even started it). Either way surface it once as an rst_stream event so the
        // integrator stops working on it, rather than discovering the cancellation only
        // when a later response write fails. The flag guards against a re-fire if the
        // stream cannot be dropped yet (e.g. an allocator failure).
        const reset_code = self.qc.streamResetCode(id); // non-destructive
        const stop_code = self.qc.peekStopSending(id); // non-destructive
        if ((reset_code != null or stop_code != null) and !rs.rst_emitted) {
            // Push BEFORE consuming the STOP_SENDING, so an OOM here leaves the code in
            // place for the next pump to retry rather than losing the cancellation.
            try self.push(.{ .rst_stream = .{ .stream_id = id, .error_code = reset_code orelse stop_code orelse 0 } });
            rs.rst_emitted = true;
            _ = self.qc.takeStopSending(id); // consume now that the event is queued
        }
        // Drop the per-stream state on both layers once the request is fully delivered
        // (EOM) OR the peer reset the request side, so an open-then-reset storm cannot
        // grow the maps (the memory half of the Rapid-Reset class). A STOP_SENDING-only
        // cancellation leaves the request side open, so the stream stays until the peer
        // also ends it; the QUIC send half is retained until its bytes are acked.
        if (rs.state == .done or self.qc.streamReset(id)) {
            if (self.qc.dropStream(id)) self.freeStream(id); // rs dangles after this
        }
    }

    /// Advance an inbound unidirectional stream (RFC 9114 6.2). The first varint is
    /// the stream type; the control stream then carries frames, the QPACK and push
    /// streams carry content we do not use (cap-0 QPACK, no push), and an unknown
    /// type is abandoned. The type-prefix read tolerates a varint that straddles
    /// datagrams (it stays unconsumed until complete).
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
            // QPACK encoder/decoder streams (cap-0: no instructions) and push streams
            // (we never enable push): drain and ignore so flow control is re-granted.
            .qpack_encoder, .qpack_decoder, .push => consumed = ready.len,
            // An unknown unidirectional stream type MUST be abandoned (RFC 9114 6.2);
            // drain it rather than letting its bytes accrete.
            _ => consumed = ready.len,
        }
        const finished = self.qc.streamFinished(id) or self.qc.streamReset(id);
        // The control stream is critical: closing it (FIN or reset) is a connection
        // error (RFC 9114 6.2.1, H3_CLOSED_CRITICAL_STREAM), and closing it before its
        // mandatory SETTINGS frame would otherwise leave peer_settings null forever.
        if (u.utype.? == .control and finished) return self.fail(.closed_critical_stream, "the control stream was closed");
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

    /// A frame on the control stream (RFC 9114 7.2.4, 6.2.1). The first frame MUST be
    /// SETTINGS, exactly once; DATA/HEADERS are never legal here. The parsed SETTINGS
    /// are applied (the peer's max field-section size bounds what we send; an
    /// unparsable or duplicate-id SETTINGS is a connection error).
    fn onControlFrame(self: *Connection, u: *UniStream, f: h3_frame.Frame) Error!void {
        if (f.ftype == .settings) {
            if (u.settings_seen) return self.fail(.frame_unexpected, "second SETTINGS");
            const s = h3_stream.parseSettings(f.payload) catch return self.fail(.settings_error, "malformed SETTINGS");
            u.settings_seen = true;
            self.peer_settings = s;
            try self.push(.{ .settings = .{ .params = try self.settingsParams(s) } });
            return;
        }
        if (f.ftype == .data or f.ftype == .headers) return self.fail(.frame_unexpected, "DATA/HEADERS on the control stream");
        // Any other frame (GOAWAY, MAX_PUSH_ID, grease) before SETTINGS means the
        // first frame was not SETTINGS - missing_settings (RFC 9114 6.2.1).
        if (!u.settings_seen) return self.fail(.missing_settings, "control stream did not begin with SETTINGS");
        if (f.ftype == .goaway) {
            const d = varint.decode(f.payload) catch return self.fail(.frame_error, "malformed GOAWAY");
            if (d.len != f.payload.len) return self.fail(.frame_error, "GOAWAY has trailing bytes");
            // A peer's GOAWAY id may only decrease (RFC 9114 5.2); a higher one is an
            // H3_ID_ERROR. The id names the largest push id / response stream the peer
            // will accept - it never grows.
            if (self.goaway_recv) |prev| if (d.value > prev) return self.fail(.id_error, "GOAWAY id increased");
            self.goaway_recv = d.value;
            // RFC 9114 GOAWAY carries only an id; the H3 layer has no per-connection
            // error code or debug payload, so the shared event's fields are zero/empty.
            try self.push(.{ .goaway = .{ .last_stream_id = d.value, .error_code = 0 } });
        }
        // MAX_PUSH_ID / CANCEL_PUSH / grease after SETTINGS: ignored (no push support).
    }

    /// Materialise the known SETTINGS the peer actually sent as (id, value) pairs,
    /// backed by the event arena. Only present identifiers are emitted, so the
    /// integrator sees the wire rather than RFC defaults.
    fn settingsParams(self: *Connection, s: h3_stream.Settings) Error![]const events.SettingPair {
        var pairs: [3]events.SettingPair = undefined;
        var n: usize = 0;
        if (s.seen_cap) {
            pairs[n] = .{ .id = settingId(.qpack_max_table_capacity), .value = s.qpack_max_table_capacity };
            n += 1;
        }
        if (s.seen_size) {
            pairs[n] = .{ .id = settingId(.max_field_section_size), .value = s.max_field_section_size };
            n += 1;
        }
        if (s.seen_blocked) {
            pairs[n] = .{ .id = settingId(.qpack_blocked_streams), .value = s.qpack_blocked_streams };
            n += 1;
        }
        return self.arena.allocator().dupe(events.SettingPair, pairs[0..n]) catch return error.OutOfMemory;
    }

    /// The known HTTP/3 SETTINGS ids all fit the shared (u16) SettingPair id.
    fn settingId(comptime id: h3_stream.SettingId) u16 {
        return @intFromEnum(id);
    }

    fn onFrame(self: *Connection, id: u64, rs: *RequestStream, f: h3_frame.Frame) Error!void {
        switch (f.ftype) {
            .headers => switch (rs.state) {
                // The request head.
                .idle => {
                    const req = try self.decodeRequest(id, f.payload, rs);
                    try self.push(.{ .request = req });
                    rs.state = .headers_done;
                },
                // A HEADERS after the body is the single permitted trailing field
                // section (RFC 9114 4.1). Decoded now, surfaced with the FIN.
                .headers_done => {
                    rs.trailers = try self.decodeTrailers(f.payload);
                    rs.state = .trailers_done;
                },
                // A second trailing section, or one before any request head, is
                // malformed.
                else => return self.failStream(.message_error),
            },
            .data => {
                // DATA outside the head..trailers window is an invalid frame SEQUENCE,
                // a connection error (RFC 9114 4.1, H3_FRAME_UNEXPECTED).
                if (rs.state != .headers_done) return self.fail(.frame_unexpected, "DATA outside the request body");
                // A body that disagrees with the declared Content-Length is a malformed
                // MESSAGE (RFC 9114 4.1.2), so it resets just this stream - matching how
                // the header-side Content-Length checks already fail. One client's bad
                // body must not tear down every multiplexed request.
                rs.body_received = std.math.add(u64, rs.body_received, f.payload.len) catch return self.failStream(.message_error);
                if (rs.content_length) |cl| if (rs.body_received > cl) return self.failStream(.message_error);
                const body = try self.dupe(f.payload);
                try self.push(.{ .data = .{ .data = body, .stream_id = id } });
            },
            // Control-stream frames are not allowed on a request stream (RFC 9114
            // 7.1): H3_FRAME_UNEXPECTED.
            .cancel_push, .settings, .push_promise, .goaway, .max_push_id => return self.fail(.frame_unexpected, "control frame on a request stream"),
            // Any other (unknown) frame type, grease or not, MUST be ignored on
            // receipt (RFC 9114 9). The frame is already fully buffered, so the pump
            // loop skips it by Decoded.len.
            else => {},
        }
    }

    /// Collapse a QPACK-decoded field section into a Request, pulling the four
    /// pseudo-headers into the shared shape and keeping the rest as headers.
    fn decodeRequest(self: *Connection, id: u64, block: []const u8, rs: *RequestStream) Error!events.Request {
        // A malformed request (a bad QPACK block or any field violation below) is a
        // STREAM-level error (RFC 9114 4.1.2): it resets just this stream via
        // failStream, leaving the connection up. With a cap-0 QPACK decoder there is
        // no shared dynamic-table state, so a decode failure is safely stream-local.
        const decoded = self.qpack_dec.decode(block) catch return self.failStream(.message_error);
        var method: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var authority: ?[]const u8 = null;
        var scheme: ?[]const u8 = null;
        var regular: std.ArrayListUnmanaged(Header) = .empty;
        defer regular.deinit(self.gpa);
        var seen_regular = false;

        for (decoded) |h| {
            if (h.name.len > 0 and h.name[0] == ':') {
                if (seen_regular) return self.failStream(.message_error); // pseudo after regular (RFC 9114 4.3)
                // A pseudo-header value is validated like any other (no CR/LF/NUL/
                // control), so a :authority carrying CR/LF cannot be synthesized into
                // a `host` header and split a downgraded HTTP/1.1 request line.
                if (!fields.validValue(h.value)) return self.failStream(.message_error);
                // A request pseudo-header appears at most once (RFC 9114 4.3.1 ->
                // RFC 9113 8.3); a duplicate is malformed.
                const slot = if (eql(h.name, ":method")) &method else if (eql(h.name, ":path")) &path else if (eql(h.name, ":authority")) &authority else if (eql(h.name, ":scheme")) &scheme else return self.failStream(.message_error);
                if (slot.* != null) return self.failStream(.message_error);
                slot.* = h.value;
            } else {
                seen_regular = true;
                // RFC 9114 4.2 inherits the HTTP/2 field rules: lowercase token
                // names, no connection-specific fields, and TE only "trailers".
                if (!fields.isValidFieldName(h.name)) return self.failStream(.message_error);
                if (!fields.validValue(h.value)) return self.failStream(.message_error);
                if (fields.isConnectionSpecific(h.name)) return self.failStream(.message_error);
                if (eql(h.name, "te") and !eql(h.value, "trailers")) return self.failStream(.message_error);
                if (eql(h.name, "content-length")) {
                    const cl = ascii.parseDecimal(u64, h.value) orelse return self.failStream(.message_error);
                    // A repeated Content-Length is malformed unless it agrees (RFC 9110).
                    if (rs.content_length) |prev| {
                        if (prev != cl) return self.failStream(.message_error);
                    } else rs.content_length = cl;
                }
                regular.append(self.gpa, h) catch return error.OutOfMemory;
            }
        }
        const method_v = method orelse return self.failStream(.message_error);
        const path_v = path orelse return self.failStream(.message_error);
        const scheme_v = scheme orelse return self.failStream(.message_error);
        if (method_v.len == 0 or path_v.len == 0 or scheme_v.len == 0) return self.failStream(.message_error);

        // Materialise everything into the arena so the slices outlive the next
        // QPACK decode (which clears its store).
        const a = self.arena.allocator();
        var headers: std.ArrayListUnmanaged(Header) = .empty;
        if (authority) |auth| {
            if (auth.len > 0) headers.append(a, .{ .name = "host", .value = try a.dupe(u8, auth) }) catch return error.OutOfMemory;
        }
        for (regular.items) |h| {
            headers.append(a, .{ .name = try a.dupe(u8, h.name), .value = try a.dupe(u8, h.value) }) catch return error.OutOfMemory;
        }
        const target = try a.dupe(u8, path_v);
        const q = std.mem.indexOfScalar(u8, target, '?');
        return .{
            .method = try a.dupe(u8, method_v),
            .target = target,
            .path = if (q) |i| target[0..i] else target,
            .query = if (q) |i| target[i + 1 ..] else target[target.len..],
            .http_version = "3",
            .headers = headers.items,
            .stream_id = id,
        };
    }

    /// Decode a trailing field section (RFC 9114 4.1). Trailers are ordinary fields
    /// only: a pseudo-header is forbidden, and the same name/value rules as the
    /// request headers apply (lowercase token names, no connection-specific fields,
    /// no CR/LF/NUL smuggling). The result is owned by `gpa` (not the per-event arena)
    /// because the trailing HEADERS and the FIN that emits them can land in different
    /// pumps, between which the arena is reset on event drain - freed in freeStream.
    fn decodeTrailers(self: *Connection, block: []const u8) Error![]const Header {
        const decoded = self.qpack_dec.decode(block) catch return self.failStream(.message_error);
        var trailers: std.ArrayListUnmanaged(Header) = .empty;
        errdefer freeHeaders(self.gpa, trailers.items);
        for (decoded) |h| {
            if (!isValidTrailerField(h)) return self.failStream(.message_error);
            if (!fields.validValue(h.value)) return self.failStream(.message_error);
            const name = self.gpa.dupe(u8, h.name) catch return error.OutOfMemory;
            errdefer self.gpa.free(name);
            const value = self.gpa.dupe(u8, h.value) catch return error.OutOfMemory;
            errdefer self.gpa.free(value);
            trailers.append(self.gpa, .{ .name = name, .value = value }) catch return error.OutOfMemory;
        }
        return trailers.toOwnedSlice(self.gpa) catch return error.OutOfMemory;
    }

    /// Whether a field name is legal in a trailer section (RFC 9110 6.5.1): a lowercase
    /// token, not a pseudo-header, not connection-specific, and not one of the framing,
    /// routing, or control fields that only make sense in the header section.
    fn isValidTrailerField(h: Header) bool {
        if (!fields.isValidFieldName(h.name)) return false; // pseudo-headers ':' and uppercase fail here
        if (fields.isConnectionSpecific(h.name)) return false; // connection, transfer-encoding, upgrade, ...
        // The fields RFC 9110 6.5.1 disallows in trailers: message framing, routing,
        // request modifiers, authentication, response control, and the
        // payload-processing fields a recipient needs before the body.
        const forbidden = [_][]const u8{
            "content-length", "host",             "te",            "trailer",
            "content-type",   "content-encoding", "content-range", "cache-control",
            "expect",         "max-forwards",     "authorization", "set-cookie",
            "vary",           "expires",
        };
        for (forbidden) |name| if (eql(h.name, name)) return false;
        return true;
    }

    /// Free a gpa-owned header list (each name and value, then the slice).
    fn freeHeaders(gpa: std.mem.Allocator, headers: []const Header) void {
        for (headers) |h| {
            gpa.free(h.name);
            gpa.free(h.value);
        }
        gpa.free(headers);
    }

    /// Drop a request stream from the H3 map, freeing the gpa-owned trailers it held.
    fn freeStream(self: *Connection, id: u64) void {
        if (self.streams.fetchRemove(id)) |kv| {
            if (kv.value.trailers.len > 0) freeHeaders(self.gpa, kv.value.trailers);
        }
    }

    fn dupe(self: *Connection, bytes: []const u8) Error![]const u8 {
        return self.arena.allocator().dupe(u8, bytes) catch return error.OutOfMemory;
    }

    /// Copy a header list into the per-event arena, so an emitted event can borrow it
    /// safely until the next event drain (when the arena is reset).
    fn arenaDupeHeaders(self: *Connection, headers: []const Header) Error![]const Header {
        if (headers.len == 0) return &.{};
        const a = self.arena.allocator();
        const out = a.alloc(Header, headers.len) catch return error.OutOfMemory;
        for (headers, out) |h, *o| o.* = .{ .name = try a.dupe(u8, h.name), .value = try a.dupe(u8, h.value) };
        return out;
    }

    fn push(self: *Connection, ev: H3Event) Error!void {
        self.queue.append(self.gpa, ev) catch return error.OutOfMemory;
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
            return .need_data;
        }
        const ev = self.queue.items[self.qpos];
        self.qpos += 1;
        return ev;
    }

    // ---- response send path (RFC 9114 4.1) -------------------------------------

    /// A response field is well-formed before it goes on the wire (RFC 9114 4.2):
    /// a lowercase token name (no pseudo-header - the server supplies :status), no
    /// connection-specific field, and a value with no control bytes (the write side
    /// is stricter than the read side and rejects CR/LF/NUL/HTAB and edge
    /// whitespace), so a re-serialised response cannot split or inject.
    fn validateResponseHeader(h: Header) Error!void {
        if (!fields.isValidFieldName(h.name)) return error.H3Error; // pseudo / uppercase / non-token
        if (fields.isConnectionSpecific(h.name)) return error.H3Error;
        if (eql(h.name, "te") and !eql(h.value, "trailers")) return error.H3Error; // RFC 9114 4.2
        for (h.value) |ch| if (ch < 0x20 or ch == 0x7F) return error.H3Error;
        if (h.value.len > 0) {
            const first = h.value[0];
            const last = h.value[h.value.len - 1];
            if (first == ' ' or first == '\t' or last == ' ' or last == '\t') return error.H3Error;
        }
    }

    /// Send a response head on request stream `id`: a HEADERS frame whose field
    /// section is `:status` plus `headers`, QPACK-encoded. Follow with `sendData`
    /// for the body and `endStream` to finish. Responses ride the client-initiated
    /// request stream; HEADERS must precede DATA and nothing follows the FIN, both
    /// enforced here. `headers` must not contain pseudo-headers (names beginning
    /// ":") - the server supplies :status.
    pub fn sendResponse(self: *Connection, id: u64, status: u16, headers: []const Header) Error!void {
        if (status < 200 or status > 599) return error.H3Error; // the final response (1xx goes via sendInformational)
        if (try self.sendStateOf(id) != .idle) return error.H3Error; // the final HEADERS once, before DATA/FIN
        try self.sendHeaderSection(id, status, headers);
        try self.setSendState(id, .headers_sent);
    }

    /// Send a 1xx interim response on stream `id` (RFC 9114 4.1 / RFC 9110 15.2): a
    /// HEADERS frame whose field section is just `:status` (100-199) plus `headers`,
    /// e.g. 103 Early Hints. Any number may precede the final sendResponse, so it
    /// leaves the send state untouched - a later DATA/FIN still belongs to the final
    /// response. Rejected once the final HEADERS has been sent.
    pub fn sendInformational(self: *Connection, id: u64, status: u16, headers: []const Header) Error!void {
        if (status < 100 or status > 199) return error.H3Error; // interim status range
        if (status == 101) return error.H3Error; // Switching Protocols is HTTP/1.1 only
        if (try self.sendStateOf(id) != .idle) return error.H3Error; // only before the final response
        try self.sendHeaderSection(id, status, headers);
    }

    /// Serialize and send one response HEADERS frame: the QPACK field section is the
    /// prefix (RIC 0, Base 0), then `:status`, then `headers`. Shared by the final
    /// response and the interim 1xx path; the state transition is the caller's.
    fn sendHeaderSection(self: *Connection, id: u64, status: u16, headers: []const Header) Error!void {
        if (quic_stream.StreamType.of(id) != .client_bidi) return error.H3Error; // responses ride the request stream
        for (headers) |h| try validateResponseHeader(h);
        // Our control stream + SETTINGS must precede any response (RFC 9114 6.2.1).
        try self.initiateControl();

        var section: std.ArrayList(u8) = .empty;
        defer section.deinit(self.gpa);
        section.appendSlice(self.gpa, &.{ 0x00, 0x00 }) catch return error.OutOfMemory;
        var status_buf: [3]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch return error.H3Error;
        qpack_enc.encodeHeader(&section, self.gpa, .{ .name = ":status", .value = status_str }) catch return error.OutOfMemory;
        for (headers) |h| qpack_enc.encodeHeader(&section, self.gpa, h) catch return error.OutOfMemory;

        var frame: std.ArrayListUnmanaged(u8) = .empty;
        defer frame.deinit(self.gpa);
        h3_frame.append(&frame, self.gpa, .headers, section.items) catch return error.OutOfMemory;
        try self.streamSend(id, frame.items, false);
    }

    /// Send a chunk of response body on stream `id` as an HTTP/3 DATA frame. The
    /// response head must have been sent first (RFC 9114 4.1).
    pub fn sendData(self: *Connection, id: u64, data: []const u8) Error!void {
        if (try self.sendStateOf(id) != .headers_sent) return error.H3Error; // DATA only after HEADERS, before FIN
        var frame: std.ArrayListUnmanaged(u8) = .empty;
        defer frame.deinit(self.gpa);
        h3_frame.append(&frame, self.gpa, .data, data) catch return error.OutOfMemory;
        try self.streamSend(id, frame.items, false);
    }

    /// Finish the response on stream `id` (send the stream FIN). The head must have
    /// been sent; a second endStream is rejected.
    pub fn endStream(self: *Connection, id: u64) Error!void {
        return self.endMessage(id, &.{});
    }

    /// Finish the response on stream `id`, optionally with a trailing field section
    /// (RFC 9114 4.1). `trailers` carries ordinary fields only - no pseudo-headers -
    /// and is sent as a trailing HEADERS frame just before the FIN. With no trailers
    /// this is a bare FIN. The head must have been sent; a second call is rejected.
    pub fn endMessage(self: *Connection, id: u64, trailers: []const Header) Error!void {
        if (try self.sendStateOf(id) != .headers_sent) return error.H3Error;
        if (trailers.len > 0) {
            // Trailers are ordinary fields only (RFC 9110 6.5.1): no pseudo-header, no
            // framing/routing/control field, no control bytes - the same rule the recv
            // side enforces, plus the response value strictness.
            for (trailers) |h| {
                if (!isValidTrailerField(h)) return error.H3Error;
                try validateResponseHeader(h); // value strictness (no CR/LF/NUL/edge-whitespace)
            }
            var section: std.ArrayList(u8) = .empty;
            defer section.deinit(self.gpa);
            section.appendSlice(self.gpa, &.{ 0x00, 0x00 }) catch return error.OutOfMemory; // QPACK prefix RIC=0, Base=0
            for (trailers) |h| qpack_enc.encodeHeader(&section, self.gpa, h) catch return error.OutOfMemory;
            var frame: std.ArrayListUnmanaged(u8) = .empty;
            defer frame.deinit(self.gpa);
            h3_frame.append(&frame, self.gpa, .headers, section.items) catch return error.OutOfMemory;
            try self.streamSend(id, frame.items, false);
        }
        try self.streamSend(id, &.{}, true);
        try self.setSendState(id, .fin_sent);
    }

    /// Abruptly cancel a request stream with `error_code` (RFC 9114 4.4): RESET_STREAM
    /// the response send half and STOP_SENDING the request recv half, so neither side
    /// keeps producing. Used to reject a request or abandon a response without closing
    /// the connection. The stream's send state is marked finished.
    pub fn resetStream(self: *Connection, id: u64, error_code: u64) Error!void {
        if (quic_stream.StreamType.of(id) != .client_bidi) return error.H3Error;
        // A response that already finished (FIN sent) has nothing to reset; a second
        // reset would recreate a reclaimed QUIC send stream and emit a RESET_STREAM
        // with a stale final size. No-op once the send half is done.
        if (try self.sendStateOf(id) == .fin_sent) return;
        self.qc.resetStream(id, error_code) catch return error.H3Error;
        self.qc.stopSending(id, error_code) catch return error.H3Error;
        try self.setSendState(id, .fin_sent);
    }

    fn sendStateOf(self: *Connection, id: u64) Error!SendState {
        const gop = self.send_state.getOrPut(self.gpa, id) catch return error.OutOfMemory;
        if (!gop.found_existing) gop.value_ptr.* = .idle;
        return gop.value_ptr.*;
    }

    fn setSendState(self: *Connection, id: u64, s: SendState) Error!void {
        self.send_state.put(self.gpa, id, s) catch return error.OutOfMemory;
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
    return @import("../quic/connection.zig").testBuildApp(gpa, dcid, 0, sframe.items);
}

test "decode a GET request over HTTP/3" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc); // H3 request data rides the Application space
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

test "a request's trailing HEADERS surfaces as end_of_message trailers" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // HEADERS (GET / host exy), then a DATA frame, then a trailing HEADERS carrying one
    // ordinary field (x-checksum: ok) - the trailers - then the FIN.
    var body: std.ArrayListUnmanaged(u8) = .empty;
    defer body.deinit(gpa);
    try h3_frame.append(&body, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x50 | 0, 0x03, 'e', 'x', 'y' });
    try h3_frame.append(&body, gpa, .data, "hi");
    var trailer_block: std.ArrayList(u8) = .empty;
    defer trailer_block.deinit(gpa);
    try trailer_block.appendSlice(gpa, &.{ 0x00, 0x00 }); // QPACK prefix RIC=0, Base=0
    try qpack_enc.encodeHeader(&trailer_block, gpa, .{ .name = "x-checksum", .value = "ok" });
    try h3_frame.append(&body, gpa, .headers, trailer_block.items);

    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, body.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pumpAll();

    try testing.expect(h3.nextEvent() == .request);
    try testing.expect(h3.nextEvent() == .data);
    const eom = h3.nextEvent();
    try testing.expect(eom == .end_of_message);
    try testing.expectEqual(@as(usize, 1), eom.end_of_message.trailers.len);
    try testing.expectEqualStrings("x-checksum", eom.end_of_message.trailers[0].name);
    try testing.expectEqualStrings("ok", eom.end_of_message.trailers[0].value);
}

test "trailers arriving before the FIN in a separate datagram still surface" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x13, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // Datagram 1: HEADERS + DATA + the trailing HEADERS, NO fin. The trailers are
    // decoded now and stashed across pumps; an intervening event drain resets the
    // arena, so the stash must be gpa-owned (the use-after-free this guards).
    var body: std.ArrayListUnmanaged(u8) = .empty;
    defer body.deinit(gpa);
    try h3_frame.append(&body, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x50 | 0, 0x03, 'e', 'x', 'y' });
    try h3_frame.append(&body, gpa, .data, "hi");
    var trailer_block: std.ArrayList(u8) = .empty;
    defer trailer_block.deinit(gpa);
    try trailer_block.appendSlice(gpa, &.{ 0x00, 0x00 });
    try qpack_enc.encodeHeader(&trailer_block, gpa, .{ .name = "x-checksum", .value = "ok" });
    try h3_frame.append(&body, gpa, .headers, trailer_block.items);
    const d1 = try buildRequest(gpa, &dcid, 0, body.items); // no FIN
    defer gpa.free(d1);
    try qc.receiveDatagram(d1, 1000);
    try h3.pumpAll();
    // Drain the request + data events: this resets the arena while trailers are stashed.
    try testing.expect(h3.nextEvent() == .request);
    try testing.expect(h3.nextEvent() == .data);
    try testing.expect(h3.nextEvent() == .need_data);

    // Datagram 2: an empty STREAM frame at the body's end offset carrying the FIN.
    var sf: std.ArrayListUnmanaged(u8) = .empty;
    defer sf.deinit(gpa);
    try sf.append(gpa, 0x0f); // STREAM, OFF|LEN|FIN
    try varint.append(&sf, gpa, 0); // stream id 0
    try varint.append(&sf, gpa, body.items.len); // offset = bytes already sent
    try varint.append(&sf, gpa, 0); // length 0
    const d2 = try @import("../quic/connection.zig").testBuildApp(gpa, &dcid, 1, sf.items);
    defer gpa.free(d2);
    try qc.receiveDatagram(d2, 1100);
    try h3.pumpAll();

    const eom = h3.nextEvent();
    try testing.expect(eom == .end_of_message);
    try testing.expectEqual(@as(usize, 1), eom.end_of_message.trailers.len);
    try testing.expectEqualStrings("ok", eom.end_of_message.trailers[0].value);
}

test "a pseudo-header in trailers is malformed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x12, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // The trailing section indexes :method GET (a pseudo-header), forbidden in trailers.
    var body: std.ArrayListUnmanaged(u8) = .empty;
    defer body.deinit(gpa);
    try h3_frame.append(&body, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x50 | 0, 0x03, 'e', 'x', 'y' });
    try h3_frame.append(&body, gpa, .data, "hi");
    try h3_frame.append(&body, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17 }); // :method in trailers

    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, body.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pumpAll();

    // The request head and body still surfaced; the bad trailers reset the stream
    // (a terminal rst_stream, no end_of_message), and the connection stays up.
    try testing.expect(h3.nextEvent() == .request);
    try testing.expect(h3.nextEvent() == .data);
    try testing.expect(h3.nextEvent() == .rst_stream);
    try testing.expect(h3.nextEvent() == .need_data);
    try testing.expect(!qc.closed);
}

test "a framing field in trailers is malformed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x14, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // The trailer section carries content-length, a framing field forbidden in
    // trailers (RFC 9110 6.5.1) - it resets the stream, connection stays up.
    var body: std.ArrayListUnmanaged(u8) = .empty;
    defer body.deinit(gpa);
    try h3_frame.append(&body, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x50 | 0, 0x03, 'e', 'x', 'y' });
    try h3_frame.append(&body, gpa, .data, "hi");
    var trailer_block: std.ArrayList(u8) = .empty;
    defer trailer_block.deinit(gpa);
    try trailer_block.appendSlice(gpa, &.{ 0x00, 0x00 });
    try qpack_enc.encodeHeader(&trailer_block, gpa, .{ .name = "content-length", .value = "2" });
    try h3_frame.append(&body, gpa, .headers, trailer_block.items);

    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, body.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pumpAll();

    try testing.expect(h3.nextEvent() == .request);
    try testing.expect(h3.nextEvent() == .data);
    try testing.expect(h3.nextEvent() == .rst_stream);
    try testing.expect(!qc.closed);
}

test "a frame truncated by the FIN after trailers is a connection error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x15, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A valid request with trailers, then a DATA frame header claiming 5 bytes but
    // carrying none before the FIN - a frame truncated by the stream end. Accepting it
    // would deliver the request as complete (RFC 9114 4.1: H3_FRAME_ERROR).
    var body: std.ArrayListUnmanaged(u8) = .empty;
    defer body.deinit(gpa);
    try h3_frame.append(&body, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x50 | 0, 0x03, 'e', 'x', 'y' });
    try h3_frame.append(&body, gpa, .data, "hi");
    var trailer_block: std.ArrayList(u8) = .empty;
    defer trailer_block.deinit(gpa);
    try trailer_block.appendSlice(gpa, &.{ 0x00, 0x00 });
    try qpack_enc.encodeHeader(&trailer_block, gpa, .{ .name = "x-checksum", .value = "ok" });
    try h3_frame.append(&body, gpa, .headers, trailer_block.items);
    try body.appendSlice(gpa, &.{ 0x00, 0x05 }); // DATA (type 0x00) len 5, no payload: truncated

    const dgram = try buildRequestOnFin(gpa, &dcid, 0, 0, body.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pumpAll());
    try testing.expect(qc.closed); // a frame error closes the connection
}

test "a CR/LF in a pseudo-header value is malformed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
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
    quic_conn.testInstallAppKeys(&qc);
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

// Feed a HEADERS frame whose QPACK block is `qpack_block` and return the result of
// pumping stream 0 - so a malformed-request test asserts the H3Error directly.
// Pump a HEADERS-only request and report whether it was ACCEPTED (a Request event was
// produced). A malformed request is now rejected with a stream reset (not a connection
// error), so it returns false rather than error.H3Error.
fn pumpHeaders(gpa: std.mem.Allocator, qpack_block: []const u8) Error!bool {
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = quic_conn.Connection.init(gpa, .server, &dcid) catch return error.H3Error;
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
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

test "a duplicate request pseudo-header is malformed" {
    // :method GET twice (RFC 9113 8.3 via RFC 9114 4.3.1).
    try testing.expect(!try pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0xC0 | 17 }));
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

test "a malformed request resets its stream but not the connection" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x88, 0x89, 0x8a, 0x8b };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
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
    quic_conn.testInstallAppKeys(&qc);
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

test "more body than Content-Length resets the stream, not the connection" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try postWithContentLength(&h3_bytes, gpa, "2"); // declares 2, sends 5
    try h3_frame.append(&h3_bytes, gpa, .data, "body!");
    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    // A malformed message (RFC 9114 4.1.2) resets just this stream: the request was
    // surfaced, then a terminal rst_stream; the connection stays up.
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .request);
    try testing.expect(h3.nextEvent() == .rst_stream);
    try testing.expect(!qc.closed);
}

test "a request with a body yields request then data" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xab, 0xcd, 0xef, 0x01 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc); // H3 request data rides the Application space
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
    return @import("../quic/connection.zig").testBuildApp(gpa, dcid, 0, sframe.items);
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
        quic_conn.testInstallAppKeys(&qc);
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
        quic_conn.testInstallAppKeys(&qc);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();
        var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer h3_bytes.deinit(gpa);
        try postWithContentLength(&h3_bytes, gpa, "10"); // declares 10, sends 5
        try h3_frame.append(&h3_bytes, gpa, .data, "body!");
        const dgram = try buildRequestFin(gpa, &dcid, h3_bytes.items);
        defer gpa.free(dgram);
        try qc.receiveDatagram(dgram, 1000);
        // Too few body bytes at the FIN is a malformed message: the request and its
        // data surfaced, then a terminal rst_stream - the connection is not torn down.
        try h3.pump(0);
        try testing.expect(h3.nextEvent() == .request);
        try testing.expect(h3.nextEvent() == .data);
        try testing.expect(h3.nextEvent() == .rst_stream);
        try testing.expect(!qc.closed);
        // The reset reclaims the stream immediately (the zero-length FIN is consumed),
        // not leaving it pinned until an unrelated later pump.
        try testing.expect(!qc.hasStream(0));
    }
}

test "an unknown non-grease frame on a request stream is ignored" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x2a, 0x2b, 0x2c, 0x2d };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
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
    quic_conn.testInstallAppKeys(&qc);
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
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 });
    const dgram = try buildRequestFin(gpa, &dcid, h3_bytes.items); // FIN ends the stream
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    try testing.expect(h3.nextEvent() == .request);
    try testing.expect(h3.nextEvent() == .end_of_message);
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
    quic_conn.testInstallAppKeys(&qc);
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
    try testing.expect(h3.nextEvent() == .request);
    try testing.expect(h3.nextEvent() == .end_of_message);

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
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A RESET_STREAM (type 0x04) on stream 0 with final size 0, in a 1-RTT packet.
    var rframe: std.ArrayListUnmanaged(u8) = .empty;
    defer rframe.deinit(gpa);
    try rframe.append(gpa, 0x04); // RESET_STREAM
    try varint.append(&rframe, gpa, 0); // stream id 0
    try varint.append(&rframe, gpa, 0x10); // application error code
    try varint.append(&rframe, gpa, 0); // final size 0
    const dgram = try quic_conn.testBuildApp(gpa, &dcid, 0, rframe.items);
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
    quic_conn.testInstallAppKeys(&qc);
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
    const dgram = try quic_conn.testBuildApp(gpa, &dcid, 0, sframe.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);

    // Our send stream is now reset; flushing emits a RESET_STREAM the peer sees.
    try qc.flushSend(2000);
    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.testInstallAppKeys(&peer);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 3000);
        off += len;
    }
    try testing.expect(peer.streamReset(0));
}

test "a peer STOP_SENDING surfaces an rst_stream event" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xa4, 0xa5, 0xa6, 0xa7 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A full request arrives on stream 0 (the H3 layer now tracks it).
    var req: std.ArrayListUnmanaged(u8) = .empty;
    defer req.deinit(gpa);
    try h3_frame.append(&req, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 });
    const rdgram = try buildRequest(gpa, &dcid, 0, req.items); // no FIN: request side stays open
    defer gpa.free(rdgram);
    try qc.receiveDatagram(rdgram, 1000);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .request);

    // The peer cancels ONLY the response side with STOP_SENDING (no RESET_STREAM).
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x05);
    try varint.append(&sframe, gpa, 0);
    try varint.append(&sframe, gpa, 0x10);
    const sdgram = try quic_conn.testBuildApp(gpa, &dcid, 1, sframe.items);
    defer gpa.free(sdgram);
    try qc.receiveDatagram(sdgram, 1100);
    try h3.pump(0);

    // The cancellation surfaces as an rst_stream event with the peer's code.
    const ev = h3.nextEvent();
    try testing.expect(ev == .rst_stream);
    try testing.expectEqual(@as(u64, 0x10), ev.rst_stream.error_code);
}

test "a STOP_SENDING after a completed request still surfaces" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xa8, 0xa9, 0xaa, 0xab };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A complete GET (HEADERS + FIN): the request finishes and its stream is dropped.
    var req: std.ArrayListUnmanaged(u8) = .empty;
    defer req.deinit(gpa);
    try h3_frame.append(&req, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 });
    const rdgram = try buildRequestOnFin(gpa, &dcid, 0, 0, req.items);
    defer gpa.free(rdgram);
    try qc.receiveDatagram(rdgram, 1000);
    try h3.pumpAll();
    try testing.expect(h3.nextEvent() == .request);
    try testing.expect(h3.nextEvent() == .end_of_message);
    var ids: [4]u64 = undefined;
    try testing.expectEqual(@as(usize, 0), qc.streamIds(&ids)); // the stream is gone

    // The peer later cancels the response with STOP_SENDING on the now-gone stream.
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x05);
    try varint.append(&sframe, gpa, 0);
    try varint.append(&sframe, gpa, 0x10);
    const sdgram = try quic_conn.testBuildApp(gpa, &dcid, 1, sframe.items);
    defer gpa.free(sdgram);
    try qc.receiveDatagram(sdgram, 1100);
    try h3.pumpAll();

    // It is still surfaced, even though the stream is no longer tracked.
    const ev = h3.nextEvent();
    try testing.expect(ev == .rst_stream);
    try testing.expectEqual(@as(u64, 0x10), ev.rst_stream.error_code);
    // And it fires exactly once.
    try testing.expect(h3.nextEvent() == .need_data);
    try h3.pumpAll();
    try testing.expect(h3.nextEvent() == .need_data);
}

// Build a request datagram on `stream_id` with the FIN bit set, at packet number `pn`.
fn buildRequestOnFin(gpa: std.mem.Allocator, dcid: []const u8, stream_id: u64, pn: u64, h3_bytes: []const u8) ![]u8 {
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0b); // STREAM, LEN|FIN set, no OFF
    try varint.append(&sframe, gpa, stream_id);
    try varint.append(&sframe, gpa, h3_bytes.len);
    try sframe.appendSlice(gpa, h3_bytes);
    return @import("../quic/connection.zig").testBuildApp(gpa, dcid, pn, sframe.items);
}

test "DATA before HEADERS is rejected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x07, 0x07, 0x07, 0x07 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc); // H3 request data rides the Application space
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .data, "x");
    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    // An invalid frame SEQUENCE (RFC 9114 4.1) is a connection error, unlike a
    // malformed message (a bad Content-Length), which only resets the stream.
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
    return @import("../quic/connection.zig").testBuildApp(gpa, dcid, pn, sframe.items);
}

test "a request split across two datagrams parses correctly (parsed-offset regression)" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc); // H3 request data rides the Application space
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

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
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .request);
    try testing.expect(h3.nextEvent() == .need_data);

    // Datagram 2: the DATA frame at the offset right after the HEADERS frame.
    const dg2 = try buildRequestAt(gpa, &dcid, headers_bytes.items.len, 1, data_bytes.items);
    defer gpa.free(dg2);
    try qc.receiveDatagram(dg2, 2000);
    try h3.pump(0);
    const data_ev = h3.nextEvent();
    try testing.expect(data_ev == .data);
    try testing.expectEqualStrings("second-datagram-body", data_ev.data.data);
}

test "the event arena is reclaimed when the queue drains" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc); // H3 request data rides the Application space
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

    const dgram2 = try buildRequest(gpa, &dcid, 4, h3_bytes.items); // stream 4 (client bidi)
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
    quic_conn.testInstallAppKeys(&qc);
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
    quic_conn.testInstallAppKeys(&peer);
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

test "a server sends response trailers as a trailing HEADERS frame" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x9a, 0xab, 0xbc, 0xcd };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A framing field (content-length) and TE are forbidden in a trailer section,
    // checked before anything goes on the wire.
    try h3.sendResponse(0, 200, &.{});
    try h3.sendData(0, "hi");
    try testing.expectError(error.H3Error, h3.endMessage(0, &[_]Header{.{ .name = "content-length", .value = "2" }}));
    try testing.expectError(error.H3Error, h3.endMessage(0, &[_]Header{.{ .name = "te", .value = "trailers" }}));
    try testing.expectError(error.H3Error, h3.endMessage(0, &[_]Header{.{ .name = "content-encoding", .value = "gzip" }}));
    const trailers = [_]Header{.{ .name = "x-checksum", .value = "ok" }};
    try h3.endMessage(0, &trailers);
    // A pseudo-header in trailers is rejected; the send half is already finished.
    try testing.expectError(error.H3Error, h3.endMessage(0, &[_]Header{.{ .name = ":status", .value = "200" }}));

    try qc.flushSend(1000);
    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.testInstallAppKeys(&peer);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const got = peer.streamData(0);
    try testing.expect(peer.streamFinished(0));

    // HEADERS, then DATA, then a trailing HEADERS whose QPACK block decodes to the trailer.
    const d1 = try h3_frame.decode(got);
    const d2 = try h3_frame.decode(got[d1.len..]);
    const d3 = try h3_frame.decode(got[d1.len + d2.len ..]);
    try testing.expectEqual(h3_frame.FrameType.headers, d3.frame.ftype);
    var dec = qpack.Decoder.init(gpa, 1 << 16);
    defer dec.deinit();
    const fields_out = try dec.decode(d3.frame.payload);
    try testing.expectEqual(@as(usize, 1), fields_out.len);
    try testing.expectEqualStrings("x-checksum", fields_out[0].name);
    try testing.expectEqualStrings("ok", fields_out[0].value);
}

test "a server sends a 1xx interim response before the final one" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x9b, 0xac, 0xbd, 0xce };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // 103 Early Hints (an interim response), repeatable, then the final 200.
    const hints = [_]Header{.{ .name = "link", .value = "</style.css>; rel=preload" }};
    try h3.sendInformational(0, 103, &hints);
    try h3.sendInformational(0, 100, &.{}); // a second interim is allowed
    // 101 Switching Protocols does not exist in HTTP/3.
    try testing.expectError(error.H3Error, h3.sendInformational(0, 101, &.{}));
    try h3.sendResponse(0, 200, &.{});
    try h3.endStream(0);
    // sendResponse rejects a 1xx; sendInformational rejects a final status and a
    // second call after the final HEADERS.
    try testing.expectError(error.H3Error, h3.sendResponse(4, 103, &.{}));
    try testing.expectError(error.H3Error, h3.sendInformational(0, 200, &.{}));
    try testing.expectError(error.H3Error, h3.sendInformational(0, 103, &.{}));

    try qc.flushSend(1000);
    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.testInstallAppKeys(&peer);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const got = peer.streamData(0);

    // Three HEADERS frames ride in order: 103, 100, 200. Decode the first's :status.
    const d1 = try h3_frame.decode(got);
    try testing.expectEqual(h3_frame.FrameType.headers, d1.frame.ftype);
    var dec = qpack.Decoder.init(gpa, 1 << 16);
    defer dec.deinit();
    const f1 = try dec.decode(d1.frame.payload);
    try testing.expectEqualStrings(":status", f1[0].name);
    try testing.expectEqualStrings("103", f1[0].value);
    const d2 = try h3_frame.decode(got[d1.len..]);
    try testing.expectEqual(h3_frame.FrameType.headers, d2.frame.ftype); // the second interim (100)
    const d3 = try h3_frame.decode(got[d1.len + d2.len ..]);
    try testing.expectEqual(h3_frame.FrameType.headers, d3.frame.ftype); // the final 200
}

test "the server resets a request stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x90, 0x91, 0x92, 0x93 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A partial response, then cancel the stream (RFC 9114 4.4): RESET_STREAM the
    // response and STOP_SENDING the request.
    try h3.sendResponse(0, 200, &.{});
    try h3.resetStream(0, 0x010c); // H3_REQUEST_CANCELLED
    try qc.flushSend(1000);

    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.testInstallAppKeys(&peer);
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

test "a reset after the response finished is a no-op" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x94, 0x95, 0x96, 0x97 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
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

test "a peer granting too few uni streams cannot run HTTP/3" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x3a, 0x3b, 0x3c, 0x3d };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    qc.peer_tp.initial_max_streams_uni = 2; // below the 3 HTTP/3 requires
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // Opening the mandatory streams would exceed the peer's limit, so the connection
    // is closed cleanly up front rather than provoking a STREAM_LIMIT_ERROR.
    try testing.expectError(error.H3Error, h3.initiateControl());
    try testing.expect(qc.closed);
}

test "the server opens its control stream with a SETTINGS frame" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x31, 0x33, 0x37, 0x39 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A response auto-opens the control stream first (RFC 9114 6.2.1); idempotent.
    try h3.sendResponse(0, 200, &.{});
    try h3.initiateControl(); // a second call is a no-op
    try qc.flushSend(1000);

    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.testInstallAppKeys(&peer);
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

    // The two QPACK streams are opened too (RFC 9204 4.2): stream 7 is the encoder
    // (type 0x02), stream 11 the decoder (type 0x03), each just its type byte since
    // table capacity 0 means no instructions ever follow.
    const enc = peer.streamData(7);
    const et = h3_stream.decodeUniType(enc).?;
    try testing.expectEqual(h3_stream.UniStreamType.qpack_encoder, et.utype);
    try testing.expectEqual(@as(usize, enc.len), et.len); // nothing after the type byte
    const dec = peer.streamData(11);
    const dt = h3_stream.decodeUniType(dec).?;
    try testing.expectEqual(h3_stream.UniStreamType.qpack_decoder, dt.utype);
    try testing.expectEqual(@as(usize, dec.len), dt.len);
}

test "shutdown sends a GOAWAY on the control stream after SETTINGS" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x60, 0x61, 0x62, 0x63 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    try h3.shutdown(8); // graceful shutdown: do not process request stream 8 or higher
    try qc.flushSend(1000);

    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.testInstallAppKeys(&peer);
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

test "a later GOAWAY may only lower the id" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x64, 0x65, 0x66, 0x67 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    try h3.shutdown(8);
    try h3.shutdown(4); // narrowing is allowed
    try testing.expectError(error.H3Error, h3.shutdown(12)); // widening is not
}

test "shutdown rejects a non-request-stream id" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x68, 0x69, 0x6a, 0x6b };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
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
    quic_conn.testInstallAppKeys(&qc);
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
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // DATA before HEADERS is rejected.
    try testing.expectError(error.H3Error, h3.sendData(0, "x"));
    // An out-of-range status is rejected.
    try testing.expectError(error.H3Error, h3.sendResponse(0, 99, &.{}));
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
    // A response on a non-client-bidi stream is rejected.
    try testing.expectError(error.H3Error, h3.sendResponse(1, 200, &.{}));

    // A valid response, then a second HEADERS is rejected, and writes after FIN too.
    try h3.sendResponse(0, 200, &.{});
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &.{}));
    try h3.endStream(0);
    try testing.expectError(error.H3Error, h3.sendData(0, "late"));
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
    return @import("../quic/connection.zig").testBuildApp(gpa, dcid, pn, sframe.items);
}

fn newH3Server(gpa: std.mem.Allocator, dcid: []const u8, qc: *quic_conn.Connection) Connection {
    qc.* = quic_conn.Connection.init(gpa, .server, dcid) catch unreachable;
    quic_conn.testInstallAppKeys(qc);
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
    // The peer's SETTINGS also surfaces as an event carrying only what it sent.
    const ev = h3.nextEvent();
    try testing.expect(ev == .settings);
    try testing.expectEqual(@as(usize, 1), ev.settings.params.len);
    try testing.expectEqual(@as(u16, 0x06), ev.settings.params[0].id);
    try testing.expectEqual(@as(u64, 0x400), ev.settings.params[0].value);
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
    // SETTINGS (empty) then GOAWAY 8 surface as two events.
    try testing.expect(h3.nextEvent() == .settings);
    const ev = h3.nextEvent();
    try testing.expect(ev == .goaway);
    try testing.expectEqual(@as(u64, 8), ev.goaway.last_stream_id);
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
    return @import("../quic/connection.zig").testBuildApp(gpa, dcid, 0, sframe.items);
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
    try h3_frame.append(&ctrl, gpa, .data, "x"); // DATA is illegal here
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

    // First control-stream frame is GOAWAY, not SETTINGS: H3_MISSING_SETTINGS (0x10a).
    var ctrl: std.ArrayListUnmanaged(u8) = .empty;
    defer ctrl.deinit(gpa);
    try ctrl.append(gpa, 0x00);
    try h3_frame.append(&ctrl, gpa, .goaway, &.{0x00});
    const dgram = try buildUni(gpa, &dcid, 2, 0, ctrl.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(2));
    try testing.expect(qc.closed);

    // The queued CONNECTION_CLOSE carries the application error H3_MISSING_SETTINGS.
    // Feed each built datagram separately (an ACK may precede the close packet).
    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.testInstallAppKeys(&peer);
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

test "a QPACK encoder stream is drained and ignored" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcc, 0xcd, 0xce, 0xcf };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    const dgram = try buildUni(gpa, &dcid, 2, 0, &.{ 0x02, 0xde, 0xad }); // qpack encoder + junk
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(2); // no error; bytes drained
    try testing.expectEqual(@as(usize, 0), qc.streamData(2).len);
}

test "a finished ignored uni stream is reclaimed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xe5, 0xe6, 0xe7, 0xe8 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // A push stream (uni id 2) that the peer opens and immediately finishes (FIN).
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0b); // STREAM, LEN|FIN
    try varint.append(&sframe, gpa, 2);
    try varint.append(&sframe, gpa, 1);
    try sframe.append(gpa, 0x01); // push stream type
    const dgram = try @import("../quic/connection.zig").testBuildApp(gpa, &dcid, 0, sframe.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(2);

    // The finished ignored stream is dropped from both maps, not retained.
    var ids: [4]u64 = undefined;
    try testing.expectEqual(@as(usize, 0), qc.streamIds(&ids));
    try testing.expectEqual(@as(u32, 0), h3.uni_streams.count());
}

test "an ignored uni stream finished by a separate FIN is still reclaimed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xf5, 0xf6, 0xf7, 0xf8 };
    var qc: quic_conn.Connection = undefined;
    var h3 = newH3Server(gpa, &dcid, &qc);
    defer qc.deinit();
    defer h3.deinit();

    // Datagram 1: push stream type + 1 byte, no FIN. The content is consumed.
    var d1: std.ArrayListUnmanaged(u8) = .empty;
    defer d1.deinit(gpa);
    try d1.append(gpa, 0x0a); // STREAM, LEN, no FIN
    try varint.append(&d1, gpa, 2);
    try varint.append(&d1, gpa, 2);
    try d1.appendSlice(gpa, &.{ 0x01, 0xaa }); // push type + a byte
    const dg1 = try @import("../quic/connection.zig").testBuildApp(gpa, &dcid, 0, d1.items);
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
    const dg2 = try @import("../quic/connection.zig").testBuildApp(gpa, &dcid, 1, d2.items);
    defer gpa.free(dg2);
    try qc.receiveDatagram(dg2, 1100);
    try h3.pump(2);

    var ids: [4]u64 = undefined;
    try testing.expectEqual(@as(usize, 0), qc.streamIds(&ids));
    try testing.expectEqual(@as(u32, 0), h3.uni_streams.count());
}
