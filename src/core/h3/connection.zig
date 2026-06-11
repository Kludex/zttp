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
    /// A malformed HTTP/3 frame, a bad QPACK block, or a missing pseudo-header:
    /// an HTTP/3 connection or stream error (RFC 9114 4.1.2 / 7).
    H3Error,
    OutOfMemory,
};

const ReqState = enum { idle, headers_done, done };

const RequestStream = struct {
    state: ReqState = .idle,
    /// The declared request body length (RFC 9114 4.1.2), or null if no
    /// Content-Length was sent. Reconciled against the DATA bytes at the FIN.
    content_length: ?u64 = null,
    body_received: u64 = 0,
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

/// The first server-initiated unidirectional stream id (RFC 9000 2.1): server uni
/// ids are 4*N+3, so the control stream is 3.
const CONTROL_STREAM_ID: u64 = 3;

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

    pub fn init(gpa: std.mem.Allocator, qc: *quic_conn.Connection) Connection {
        return .{
            .gpa = gpa,
            .qc = qc,
            .qpack_dec = qpack.Decoder.init(gpa, MAX_FIELD_SECTION_SIZE),
            .arena = std.heap.ArenaAllocator.init(gpa),
        };
    }

    pub fn deinit(self: *Connection) void {
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

    /// Open our unidirectional control stream and send SETTINGS as its first frame
    /// (RFC 9114 6.2.1, 7.2.4). A conformant peer treats the absence of our SETTINGS
    /// as H3_MISSING_SETTINGS and may refuse to send requests, so this must precede
    /// any response. Idempotent: the control stream is opened at most once. The
    /// stream-type byte (0x00) prefixes the SETTINGS frame on the same stream.
    pub fn initiateControl(self: *Connection) Error!void {
        if (self.control_sent) return;
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
        try self.streamSend(CONTROL_STREAM_ID, out.items, false);
        self.control_sent = true;
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
    }

    pub fn pump(self: *Connection, id: u64) Error!void {
        switch (quic_stream.StreamType.of(id)) {
            .client_bidi => try self.pumpRequest(id),
            .client_uni => try self.pumpUni(id),
            else => {}, // server-initiated streams are ours; nothing to read here
        }
    }

    fn pumpRequest(self: *Connection, id: u64) Error!void {
        // Don't recreate H3 state for a stream the transport no longer has (retired
        // after completion/reset): a late frame for it is already ignored there, and
        // recreating an idle entry here would resurrect it on the H3 map.
        if (!self.streams.contains(id) and !self.qc.hasStream(id)) return;
        const gop = self.streams.getOrPut(self.gpa, id) catch return error.OutOfMemory;
        if (!gop.found_existing) gop.value_ptr.* = .{};
        const rs = gop.value_ptr;

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
            try self.onFrame(id, rs, d.frame);
            consumed_total += d.len;
        }
        if (self.qc.streamFinished(id) and rs.state == .headers_done) {
            // Fewer body bytes than the declared Content-Length is malformed (RFC
            // 9114 4.1.2); the over-count is caught per-DATA above.
            if (rs.content_length) |cl| if (rs.body_received != cl) return error.H3Error;
            try self.push(.{ .end_of_message = .{ .trailers = &.{}, .stream_id = id } });
            rs.state = .done;
        }
        // Consume BEFORE dropping: consuming the last byte of a finished stream is
        // what moves its receive state to terminal, which dropStream then reclaims.
        if (consumed_total > 0) self.qc.consumeStream(id, consumed_total);
        // Drop the per-stream state on both layers once the request is fully
        // delivered (EOM) OR the peer reset the stream, so an open-then-reset storm
        // cannot grow the maps (the memory half of the Rapid-Reset class). The QUIC
        // send half is retained until its bytes are acked, so a still-in-flight
        // response is not freed from under recovery.
        if (rs.state == .done or self.qc.streamReset(id)) {
            if (self.qc.dropStream(id)) _ = self.streams.remove(id); // rs dangles after this
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
            const d = h3_stream.decodeUniType(ready) orelse return; // type varint not all here yet
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
        // Reclaim a finished/reset ignored uni stream so a peer cannot grow the maps
        // by opening-and-finishing many of them. The control stream is critical (RFC
        // 9114 6.2.1) and kept for the connection's life; the rest are disposable.
        const ignored_done = u.utype.? != .control and (self.qc.streamFinished(id) or self.qc.streamReset(id));
        // Consume even zero bytes when the stream just finished: a bare FIN at the
        // final offset (arriving in its own frame after the content was already
        // drained) leaves nothing new to consume, but the consume is what flips the
        // recv state to terminal so dropStream can reclaim it.
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
            return;
        }
        if (f.ftype == .data or f.ftype == .headers) return self.fail(.frame_unexpected, "DATA/HEADERS on the control stream");
        // Any other frame (GOAWAY, MAX_PUSH_ID, grease) before SETTINGS means the
        // first frame was not SETTINGS - missing_settings; after, it is ignored.
        if (!u.settings_seen) return self.fail(.missing_settings, "control stream did not begin with SETTINGS");
    }

    fn onFrame(self: *Connection, id: u64, rs: *RequestStream, f: h3_frame.Frame) Error!void {
        switch (f.ftype) {
            .headers => {
                if (rs.state != .idle) return error.H3Error; // trailers after body are a follow-up
                const req = try self.decodeRequest(id, f.payload, rs);
                try self.push(.{ .request = req });
                rs.state = .headers_done;
            },
            .data => {
                if (rs.state != .headers_done) return self.fail(.frame_unexpected, "DATA before HEADERS"); // RFC 9114 4.1
                rs.body_received = std.math.add(u64, rs.body_received, f.payload.len) catch return self.fail(.message_error, "request body length overflow");
                // More body than the declared Content-Length is malformed (RFC 9114 4.1.2).
                if (rs.content_length) |cl| if (rs.body_received > cl) return self.fail(.message_error, "body exceeds Content-Length");
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
        const decoded = self.qpack_dec.decode(block) catch return error.H3Error;
        var method: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var authority: ?[]const u8 = null;
        var scheme: ?[]const u8 = null;
        var regular: std.ArrayListUnmanaged(Header) = .empty;
        defer regular.deinit(self.gpa);
        var seen_regular = false;

        for (decoded) |h| {
            if (h.name.len > 0 and h.name[0] == ':') {
                if (seen_regular) return error.H3Error; // pseudo after regular (RFC 9114 4.3)
                // A request pseudo-header appears at most once (RFC 9114 4.3.1 ->
                // RFC 9113 8.3); a duplicate is malformed.
                const slot = if (eql(h.name, ":method")) &method else if (eql(h.name, ":path")) &path else if (eql(h.name, ":authority")) &authority else if (eql(h.name, ":scheme")) &scheme else return error.H3Error;
                if (slot.* != null) return error.H3Error;
                slot.* = h.value;
            } else {
                seen_regular = true;
                // RFC 9114 4.2 inherits the HTTP/2 field rules: lowercase token
                // names, no connection-specific fields, and TE only "trailers".
                if (!fields.isValidFieldName(h.name)) return error.H3Error;
                if (!fields.validValue(h.value)) return error.H3Error;
                if (fields.isConnectionSpecific(h.name)) return error.H3Error;
                if (eql(h.name, "te") and !eql(h.value, "trailers")) return error.H3Error;
                if (eql(h.name, "content-length")) {
                    const cl = ascii.parseDecimal(u64, h.value) orelse return error.H3Error;
                    // A repeated Content-Length is malformed unless it agrees (RFC 9110).
                    if (rs.content_length) |prev| {
                        if (prev != cl) return error.H3Error;
                    } else rs.content_length = cl;
                }
                regular.append(self.gpa, h) catch return error.OutOfMemory;
            }
        }
        const method_v = method orelse return error.H3Error;
        const path_v = path orelse return error.H3Error;
        const scheme_v = scheme orelse return error.H3Error;
        if (method_v.len == 0 or path_v.len == 0 or scheme_v.len == 0) return error.H3Error;

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

    fn dupe(self: *Connection, bytes: []const u8) Error![]const u8 {
        return self.arena.allocator().dupe(u8, bytes) catch return error.OutOfMemory;
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
        if (quic_stream.StreamType.of(id) != .client_bidi) return error.H3Error; // responses ride the request stream
        if (status < 100 or status > 599) return error.H3Error; // RFC 9110 status range
        if (try self.sendStateOf(id) != .idle) return error.H3Error; // HEADERS once, before DATA/FIN
        for (headers) |h| try validateResponseHeader(h);
        // Our control stream + SETTINGS must precede any response (RFC 9114 6.2.1).
        try self.initiateControl();

        // The QPACK field section: prefix (RIC 0, Base 0), then :status, then headers.
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
        try self.setSendState(id, .headers_sent);
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
        if (try self.sendStateOf(id) != .headers_sent) return error.H3Error;
        try self.streamSend(id, &.{}, true);
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
fn pumpHeaders(gpa: std.mem.Allocator, qpack_block: []const u8) Error!void {
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
}

test "a duplicate request pseudo-header is malformed" {
    // :method GET twice (RFC 9113 8.3 via RFC 9114 4.3.1).
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0xC0 | 17 }));
}

test "an uppercase field name is malformed" {
    // literal name "Te" (0x20|2), value "x": a non-lowercase token (RFC 9114 4.2).
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 2, 'T', 'e', 0x01, 'x' }));
}

test "a connection-specific field is malformed" {
    // literal name "connection" (len 10: 3-bit prefix 7 + continuation 3), value "x".
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 7, 0x03, 'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', 0x01, 'x' }));
}

test "TE with a value other than trailers is malformed" {
    // literal name "te" (0x20|2), value "gzip".
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 2, 't', 'e', 0x04, 'g', 'z', 'i', 'p' }));
}

test "TE trailers is accepted" {
    // The one legal TE value (RFC 9114 4.2): te: trailers must NOT be rejected.
    try pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 2, 't', 'e', 0x08, 't', 'r', 'a', 'i', 'l', 'e', 'r', 's' });
}

test "a control byte in a field value is malformed" {
    // literal name "x" (0x20|1), value "a\rb": CR is not a field-vchar (RFC 9110).
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 1, 'x', 0x03, 'a', '\r', 'b' }));
}

test "a non-numeric Content-Length is malformed" {
    // content-length: "x" (name length 14 = 3-bit prefix 7 + continuation 7).
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 20, 0xC0 | 23, 0xC0 | 1, 0x20 | 7, 0x07, 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 'l', 'e', 'n', 'g', 't', 'h', 0x01, 'x' }));
}

test "two disagreeing Content-Length values are malformed" {
    // content-length: 1 then content-length: 2 (name length 14 = 7 + continuation 7).
    const cl = [_]u8{ 0x20 | 7, 0x07, 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 'l', 'e', 'n', 'g', 't', 'h' };
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &(.{ 0x00, 0x00, 0xC0 | 20, 0xC0 | 23, 0xC0 | 1 } ++ cl ++ .{ 0x01, '1' } ++ cl ++ .{ 0x01, '2' })));
}

test "more body than Content-Length is malformed at the DATA frame" {
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
    try testing.expectError(error.H3Error, h3.pump(0));
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
        try testing.expectError(error.H3Error, h3.pump(0));
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

    // The reset stream is reclaimed (not left to accrete on a reset storm).
    var ids: [4]u64 = undefined;
    try testing.expectEqual(@as(usize, 0), qc.streamIds(&ids));
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
    try testing.expectError(error.H3Error, h3.pump(0));
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
