//! The Python `Connection` object: a thin wrapper over the core engine exposing
//! the sans-IO pull API. `receive_data(bytes)` appends to the parse buffer;
//! `next_event()` returns the next Request/Response/Data/EndOfMessage event, or
//! the NEED_DATA singleton. The write side (send/data_to_send) is added on top.

const std = @import("std");
const py = @import("py.zig");
const c = py.c;
const core = @import("core");
const Reader = core.h1.reader.Reader;
const Role = core.h1.reader.Role;
const Writer = core.h1.writer.Writer;
const events = core.events;
const events_obj = @import("events_obj.zig");
const exceptions = @import("exceptions.zig");

const H2Connection = core.h2.connection.Connection;
const H2Role = core.h2.connection.Role;
const H2Writer = core.h2.writer.Writer;

const QuicConnection = core.quic.connection.Connection;
const H3Connection = core.h3.connection.Connection;
const FlightConfig = core.quic.tls.flight.Config;
const Signer = core.quic.tls.sign.Signer;

const gpa = std.heap.c_allocator;

const SERVER: c_long = 1;
const CLIENT: c_long = 2;
const HTTP1: c_long = 1;
const HTTP2: c_long = 2;
const HTTP3: c_long = 3;

/// The HTTP/1.1 engine: the pull-API reader, the writer, and the per-connection
/// state the send path needs (the request method the next response answers, the
/// keep-alive / upgrade signals captured at parse time).
const H1Engine = struct {
    /// Embedded by value: the engine is one allocation, so constructing a
    /// Connection does not pay a separate heap allocation for the Reader.
    reader: Reader,
    /// Created on the first send_* call: server connections that only parse
    /// never pay the Writer's allocation.
    writer: ?*Writer = null,
    /// The method of the message the next response answers (server: the parsed
    /// request; client: the request we sent), so the connection auto-derives
    /// bodyless framing. Cleared per cycle by start_next_cycle.
    req_method: [16]u8 = undefined,
    req_method_len: usize = 0,
    /// Connection signals for the last parsed request, captured at event time so
    /// they outlive the head buffer. `upgrade_obj` is held Python bytes (or null).
    should_close: bool = false,
    upgrade_obj: py.Object = null,
    /// Single-copy body path: when a fed buffer's prefix is a Content-Length
    /// body, the bytes object is held here (incref'd, its memory stable)
    /// instead of being copied into the reader; next_event materialises Data
    /// events straight from it. `pending` is the not-yet-consumed remainder.
    pending_obj: py.Object = null,
    pending: []const u8 = &.{},

    fn rememberMethod(self: *H1Engine, m: []const u8) void {
        if (m.len > self.req_method.len) {
            self.req_method_len = 0;
            return;
        }
        @memcpy(self.req_method[0..m.len], m);
        self.req_method_len = m.len;
    }

    fn method(self: *const H1Engine) []const u8 {
        return self.req_method[0..self.req_method_len];
    }

    /// The writer, created on first use, or null with a Python error set.
    fn ensureWriter(self: *H1Engine) ?*Writer {
        if (self.writer) |w| return w;
        const w = gpa.create(Writer) catch {
            _ = c.PyErr_NoMemory();
            return null;
        };
        w.* = Writer.init(gpa);
        self.writer = w;
        return w;
    }

    fn stash(self: *H1Engine, obj: py.Object, rest: []const u8) void {
        py.incref(obj);
        self.pending_obj = obj;
        self.pending = rest;
    }

    fn dropPending(self: *H1Engine) void {
        py.xdecref(self.pending_obj);
        self.pending_obj = null;
        self.pending = &.{};
    }

    /// Move the stashed remainder into the reader's own buffer (the slow path
    /// the stash bypassed). Returns false with a Python error set on failure.
    fn flushPending(self: *H1Engine) bool {
        if (self.pending_obj == null) return true;
        const rest = self.pending;
        defer self.dropPending();
        self.reader.feed(rest) catch |err| {
            _ = exceptions.raiseParse(err);
            return false;
        };
        return true;
    }

    /// Feeds smaller than this take the plain buffered path: the head-split
    /// scan below costs one extra pass over the head, which only pays for
    /// itself when a sizeable body follows.
    const head_split_min_feed = 1024;

    fn receiveData(self: *H1Engine, data: []const u8, obj: py.Object) py.Object {
        if (!self.flushPending()) return null;
        if (data.len > 0 and self.reader.backlogEmpty()) {
            if (self.reader.bodyLengthRemaining() != null) {
                self.stash(obj, data);
                return py.none();
            }
            if (data.len >= head_split_min_feed and self.reader.atMessageStart()) {
                if (core.h1.reader.findHeadEnd(data)) |head_end| {
                    self.reader.feed(data[0..head_end]) catch |err| return exceptions.raiseParse(err);
                    if (head_end < data.len) self.stash(obj, data[head_end..]);
                    return py.none();
                }
            }
        }
        self.reader.feed(data) catch |err| return exceptions.raiseParse(err);
        return py.none();
    }

    fn deinit(self: *H1Engine) void {
        self.reader.deinit();
        if (self.writer) |w| {
            w.deinit();
            gpa.destroy(w);
        }
        py.xdecref(self.upgrade_obj);
        py.xdecref(self.pending_obj);
    }
};

/// The HTTP/2 engine: the read-side connection plus the writer. `handshake_sent`
/// gates the lazy preface. All send operations are stream-scoped and addressed by
/// an explicit id (from send_request's return or conn.stream(id)), so no
/// "current stream" is tracked here - the stream state lives in the core.
const H2Engine = struct {
    conn: *H2Connection,
    writer: *H2Writer,
    handshake_sent: bool = false,

    /// Serialize our connection preface, advertising the SETTINGS we enforce so a
    /// peer respects our limits (e.g. max_concurrent_streams) rather than the RFC
    /// defaults. Shared by every site that may emit the preface first.
    fn sendOurPreface(self: *H2Engine) core.h2.writer.WriteError!void {
        var buf: [4][2]u32 = undefined;
        try self.writer.sendPreface(self.conn.localSettingsParams(&buf));
    }

    fn ensureHandshake(self: *H2Engine) bool {
        if (self.handshake_sent) return true;
        self.sendOurPreface() catch {
            _ = c.PyErr_NoMemory();
            return false;
        };
        self.handshake_sent = true;
        return true;
    }

    /// Serialize a request head and return the stream id it opened, or null on
    /// error (with a Python error set). The id is registered for flow control so
    /// later DATA on it is gated by the send window.
    fn sendRequestId(self: *H2Engine, mb: []const u8, tb: []const u8, hdrs: *BorrowedHeaders) ?u32 {
        if (!self.ensureHandshake()) return null;
        var regular: []events.Header = hdrs.headers;
        const authority = h2SplitAuthority(hdrs.headers, &regular);
        const id = self.writer.sendRequest(mb, tb, "https", authority, regular, false) catch |e| {
            _ = h2RaiseWrite(e);
            return null;
        };
        self.conn.registerSendStream(id) catch {
            _ = c.PyErr_NoMemory();
            return null;
        };
        // A HEAD response carries no body regardless of content-length (RFC 9110
        // 8.6); mark the stream so the response's content-length check is skipped.
        if (asciiEqlIgnoreCase(mb, "HEAD")) self.conn.markBodylessRequest(id);
        return id;
    }

    /// Initialise an h2c-upgraded connection: seed the request as stream 1 (RFC 7540 3.2). The method/target
    /// and headers come from the HTTP/1.1 request the server already parsed; scheme
    /// is "http" (h2c is cleartext) and :authority is derived from the host header.
    /// `settings_header` is the base64url HTTP2-Settings value (RFC 7540 3.2.1) the
    /// client sent, or null. Returns true on success, false with a Python error set.
    fn initiateUpgrade(self: *H2Engine, method: []const u8, target: []const u8, hdrs: *BorrowedHeaders, settings_header: ?[]const u8) bool {
        var settings_buf: [256]u8 = undefined;
        var settings: ?[]const u8 = null;
        if (settings_header) |b64| {
            const dec = std.base64.url_safe_no_pad.Decoder;
            const len = dec.calcSizeForSlice(b64) catch {
                _ = py.raiseValue("settings_header is not valid base64url");
                return false;
            };
            if (len > settings_buf.len) {
                _ = py.raiseValue("settings_header is too large");
                return false;
            }
            dec.decode(settings_buf[0..len], b64) catch {
                _ = py.raiseValue("settings_header is not valid base64url");
                return false;
            };
            settings = settings_buf[0..len];
        }
        var regular: []events.Header = hdrs.headers;
        const authority = h2SplitAuthority(hdrs.headers, &regular);
        self.conn.initiateUpgradeConnection(method, target, "http", if (authority.len == 0) null else authority, regular, settings) catch |e| switch (e) {
            error.Malformed => {
                _ = py.raise(exceptions.LocalProtocolError, "the upgrade request is not a valid HTTP/2 request (forbidden header or bad pseudo-header)");
                return false;
            },
            error.BadSettings => {
                _ = py.raise(exceptions.LocalProtocolError, "the HTTP2-Settings header is not a valid SETTINGS payload");
                return false;
            },
            error.AlreadyStarted => {
                _ = py.raiseRuntime("the connection has already started; initiate the upgrade before feeding any bytes");
                return false;
            },
            error.OutOfMemory => {
                _ = c.PyErr_NoMemory();
                return false;
            },
        };
        return true;
    }

    fn sendResponse(self: *H2Engine, stream_id: u32, status: u16, hdrs: *BorrowedHeaders, end_stream: bool) py.Object {
        if (!self.ensureHandshake()) return null;
        self.writer.sendResponse(stream_id, status, hdrs.headers, end_stream) catch |e| return h2RaiseWrite(e);
        if (end_stream) {
            self.conn.endResponseStream(stream_id) catch return c.PyErr_NoMemory();
        } else {
            self.conn.registerSendStream(stream_id) catch return c.PyErr_NoMemory();
        }
        return py.none();
    }

    /// Serialize an interim 1xx response head on `stream_id`. An interim never ends
    /// the stream (the read side treats a 1xx with END_STREAM as a reset), and the
    /// final response still follows on the same stream.
    fn sendInformational(self: *H2Engine, stream_id: u32, status: u16, hdrs: *BorrowedHeaders) py.Object {
        if (!self.ensureHandshake()) return null;
        self.writer.sendResponse(stream_id, status, hdrs.headers, false) catch |e| return h2RaiseWrite(e);
        self.conn.registerSendStream(stream_id) catch return c.PyErr_NoMemory();
        return py.none();
    }

    /// Queue body bytes on `id` through the flow-controlled send path: the core
    /// emits what the connection and stream send windows allow and parks the rest.
    fn sendData(self: *H2Engine, id: u32, data: []const u8) py.Object {
        self.conn.sendStreamData(self.writer, id, data, false) catch |e| return h2RaiseWrite(e);
        return py.none();
    }

    fn endStream(self: *H2Engine, id: u32) py.Object {
        self.conn.sendStreamData(self.writer, id, &.{}, true) catch |e| return h2RaiseWrite(e);
        return py.none();
    }

    fn resetStream(self: *H2Engine, id: u32, code: u32) py.Object {
        if (!self.ensureHandshake()) return null;
        self.writer.sendRstStream(id, @enumFromInt(code)) catch |e| return h2RaiseWrite(e);
        self.conn.localReset(id);
        return py.none();
    }

    fn goaway(self: *H2Engine, code: u32, last_stream_id: ?u32) py.Object {
        if (!self.ensureHandshake()) return null;
        const last = last_stream_id orelse self.conn.lastPeerStreamId();
        self.writer.sendGoaway(last, @enumFromInt(code), &.{}) catch |e| return h2RaiseWrite(e);
        return py.none();
    }

    /// Drain parked DATA that a freshly-parsed WINDOW_UPDATE / SETTINGS credit now
    /// permits. Called from next_event after such an event is produced.
    /// Auto-handle the connection-management frames RFC 9113 expects a peer to
    /// answer without app involvement: ACK the peer's SETTINGS and PING, and
    /// advertise consumed receive window via WINDOW_UPDATE. The serialized frames
    /// land in the writer buffer for the next data_to_send.
    fn autoRespond(self: *H2Engine, ev: events.H2Event) core.h2.writer.WriteError!void {
        // Our own preface must be the first frame WE send (RFC 9113 3.4), so emit
        // it before any ACK/WINDOW_UPDATE this event would otherwise queue first.
        if (!self.handshake_sent) {
            try self.sendOurPreface();
            self.handshake_sent = true;
        }
        switch (ev) {
            .settings => try self.writer.sendSettingsAck(),
            .ping => |p| if (!p.ack) try self.writer.sendPingAck(p.opaque_data),
            else => {},
        }
        // Advertise consumed receive window. Not gated on the .data event: a DATA
        // frame of pure padding consumes window but surfaces no event, so flushing
        // here (threshold-checked, idempotent) keeps the peer's send window open.
        try self.conn.flushRecvWindows(self.writer);
        // A parsed WINDOW_UPDATE / SETTINGS may have credited a send window; drain
        // any DATA parked waiting for it.
        if (ev == .window_update or ev == .settings) try self.conn.flushSendable(self.writer);
    }

    /// Serialize the GOAWAY owed after a connection-fatal error (RFC 9113 5.4.1),
    /// so data_to_send carries it before the integrator closes. Best-effort: if
    /// the writer itself OOMs there is nothing useful to do but close.
    fn emitGoawayIfOwed(self: *H2Engine) void {
        if (self.conn.takeGoawayOwed()) |code| {
            if (!self.handshake_sent) {
                self.sendOurPreface() catch return;
                self.handshake_sent = true;
            }
            self.writer.sendGoaway(self.conn.lastPeerStreamId(), code, &.{}) catch {};
        }
    }

    fn deinit(self: *H2Engine) void {
        self.conn.deinit();
        gpa.destroy(self.conn);
        self.writer.deinit();
        gpa.destroy(self.writer);
    }
};

/// The server TLS material the QUIC handshake needs but the sans-IO core cannot
/// invent: the certificate, signing key, transport parameters, selected ALPN, and
/// the per-connection entropy (ServerHello random + ephemeral seed). The integrator
/// supplies it at construction; the bytes are copied so they outlive the Python
/// args. `signer` is derived from the 32-byte key seed once, up front, so a bad key
/// is rejected at construction rather than on the first datagram.
const ServerConfig = struct {
    cert: []u8,
    transport_params: []u8,
    alpn: ?[]u8,
    signer: Signer,
    random: [32]u8,
    ephemeral_seed: [32]u8,

    fn deinit(self: *ServerConfig) void {
        gpa.free(self.cert);
        gpa.free(self.transport_params);
        if (self.alpn) |a| gpa.free(a);
    }

    fn flightConfig(self: *const ServerConfig) FlightConfig {
        return .{
            .random = self.random,
            .ephemeral_seed = self.ephemeral_seed,
            .signer = self.signer,
            .cert_chain = self.cert,
            .alpn = self.alpn,
            .transport_params = self.transport_params,
        };
    }
};

/// The HTTP/3 engine. The QUIC transport and the HTTP/3 engine on top of it are
/// built lazily on the first datagram - the connection id is read from the client's
/// first Initial packet, so it is not known at construction. `qc`/`h3` stay null
/// until then; `config` carries the server credentials forward to that point.
const H3Engine = struct {
    config: ServerConfig,
    qc: ?*QuicConnection = null,
    h3: ?*H3Connection = null,
    /// The integrator's clock at the last receive_datagram / handle_timeout. A Stream
    /// send does not carry its own `now` (the API matches H2's, which has no clock),
    /// so it packetises against the most recent time the caller gave us.
    now: u64 = 0,

    fn receiveDatagram(self: *H3Engine, dgram: []const u8, now: u64) py.Object {
        self.now = now;
        if (self.qc == null) {
            // Build the transport from the connection id in the client's first
            // Initial. A non-Initial first datagram has nowhere to take the id from.
            if (dgram.len == 0 or !core.quic.packet.isLong(dgram[0])) {
                return py.raise(exceptions.RemoteProtocolError, "the first HTTP/3 datagram must be a long-header Initial");
            }
            const hdr = core.quic.packet.parseLong(dgram) catch
                return py.raise(exceptions.RemoteProtocolError, "malformed QUIC Initial packet");
            // Only an Initial's dcid is the original destination id the server must
            // echo as a transport parameter; a Handshake/0-RTT first datagram would
            // seed the connection with the wrong one.
            if (hdr.ltype != .initial) {
                return py.raise(exceptions.RemoteProtocolError, "the first HTTP/3 datagram must be a long-header Initial");
            }
            const q = gpa.create(QuicConnection) catch return c.PyErr_NoMemory();
            q.* = QuicConnection.initServer(gpa, hdr.dcid, self.config.flightConfig()) catch |e| {
                gpa.destroy(q);
                return exceptions.raiseQuic(e);
            };
            const h = gpa.create(H3Connection) catch {
                q.deinit();
                gpa.destroy(q);
                return c.PyErr_NoMemory();
            };
            h.* = H3Connection.init(gpa, q);
            self.qc = q;
            self.h3 = h;
        }

        self.qc.?.receiveDatagram(dgram, now) catch |e| return exceptions.raiseQuic(e);
        self.h3.?.pumpAll() catch |e| return exceptions.raiseH3(e);
        return py.none();
    }

    fn nextEvent(self: *H3Engine) py.Object {
        const h = self.h3 orelse return py.newRef(events_obj.need_data); // no datagram fed yet
        return events_obj.fromH3Event(h.nextEvent());
    }

    /// The pending outbound datagrams (handshake flight, ACKs, response STREAM
    /// frames) as a list of bytes, one per UDP datagram - QUIC datagram boundaries
    /// are semantic, so each must reach the peer as its own packet, unlike the byte
    /// stream the H1/H2 data_to_send returns. The queue is cleared on success.
    fn dataToSend(self: *H3Engine) py.Object {
        const q = self.qc orelse return py.newList(0); // nothing built yet
        const flat = q.datagramsToSend();
        const lengths = q.datagramLengths();
        const list = py.newList(@intCast(lengths.len));
        if (list == null) return null;
        var off: usize = 0;
        for (lengths, 0..) |len, i| {
            const item = py.fromBytes(flat[off .. off + len]);
            if (item == null) {
                py.decref(list);
                return null;
            }
            py.listSet(list, @intCast(i), item);
            off += len;
        }
        q.clearSend();
        return list;
    }

    /// Drive a response onto `stream_id`, then packetise so the bytes surface in the
    /// next data_to_send. Send requires 1-RTT keys (the handshake must be complete),
    /// which flushSend enforces by no-op'ing until they exist.
    fn sendResponse(self: *H3Engine, id: u64, status: u16, headers: []const events.Header) py.Object {
        const h = self.h3 orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        h.sendResponse(id, status, headers) catch |e| return exceptions.raiseH3(e);
        return self.flush();
    }

    fn sendData(self: *H3Engine, id: u64, data: []const u8) py.Object {
        const h = self.h3 orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        h.sendData(id, data) catch |e| return exceptions.raiseH3(e);
        return self.flush();
    }

    fn endStream(self: *H3Engine, id: u64) py.Object {
        const h = self.h3 orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        h.endStream(id) catch |e| return exceptions.raiseH3(e);
        return self.flush();
    }

    /// Cancel a request stream with `error_code` (RFC 9114 4.4): RESET_STREAM the
    /// response and STOP_SENDING the request, then packetise.
    fn resetStream(self: *H3Engine, id: u64, error_code: u64) py.Object {
        const h = self.h3 orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        h.resetStream(id, error_code) catch |e| return exceptions.raiseH3(e);
        return self.flush();
    }

    /// Begin a graceful shutdown: send a GOAWAY announcing `stream_id` as the first
    /// request stream we will not process (RFC 9114 5.2), then packetise it.
    fn shutdown(self: *H3Engine, stream_id: u64) py.Object {
        const h = self.h3 orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        h.shutdown(stream_id) catch |e| return exceptions.raiseH3(e);
        return self.flush();
    }

    /// Open the control stream + SETTINGS now (RFC 9114 6.2.1), rather than lazily on
    /// the first response, and packetise it. Mirrors H2's initiate_connection.
    fn initiate(self: *H3Engine) py.Object {
        const h = self.h3 orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        h.initiateControl() catch |e| return exceptions.raiseH3(e);
        return self.flush();
    }

    fn flush(self: *H3Engine) py.Object {
        // AmplificationLimited is not an error: it means the unvalidated peer's 3x
        // budget is spent, so the bytes stay queued and surface on a later flush once
        // a Handshake packet validates the address. Treat it as a deferred no-send.
        self.qc.?.flushSend(self.now) catch |e| switch (e) {
            error.AmplificationLimited => {},
            else => return exceptions.raiseQuic(e),
        };
        return py.none();
    }

    fn nextTimeout(self: *H3Engine) py.Object {
        const q = self.qc orelse return py.none();
        return if (q.nextTimeout()) |t| c.PyLong_FromUnsignedLongLong(@intCast(t)) else py.none();
    }

    fn handleTimeout(self: *H3Engine, now: u64) py.Object {
        self.now = now;
        const q = self.qc orelse return py.none();
        q.onTimeout(now) catch |e| switch (e) {
            error.AmplificationLimited => {},
            else => return exceptions.raiseQuic(e),
        };
        // A PTO requeues STREAM data into the send stream; only flushSend packetises
        // it, so the probe surfaces in the next data_to_send rather than stalling.
        return self.flush();
    }

    fn isClosed(self: *const H3Engine) bool {
        const q = self.qc orelse return false;
        return q.closed;
    }

    /// The id of a GOAWAY received from the peer (RFC 9114 5.2), or None - so an
    /// integrator learns the peer is shutting down and stops opening new streams.
    fn goawayReceived(self: *const H3Engine) py.Object {
        const h = self.h3 orelse return py.none();
        const id = h.goaway_recv orelse return py.none();
        return c.PyLong_FromUnsignedLongLong(id);
    }

    /// The peer's CONNECTION_CLOSE as (error_code, reason, is_application), or None if
    /// the peer has not sent one - so an integrator learns WHY the peer closed, not
    /// just that it did.
    fn closeInfo(self: *const H3Engine) py.Object {
        const q = self.qc orelse return py.none();
        const pc = q.peer_close orelse return py.none();
        const tuple = py.tupleNew(3);
        if (tuple == null) return null;
        const code = c.PyLong_FromUnsignedLongLong(pc.error_code);
        const reason = py.fromBytes(pc.reason);
        const app = py.boolean(pc.app);
        if (code == null or reason == null or app == null) {
            py.xdecref(code);
            py.xdecref(reason);
            py.xdecref(app);
            py.decref(tuple);
            return null;
        }
        py.tupleSet(tuple, 0, code);
        py.tupleSet(tuple, 1, reason);
        py.tupleSet(tuple, 2, app);
        return tuple;
    }

    /// The peer's HTTP/3 SETTINGS as a dict of the named values, or None until its
    /// control stream's SETTINGS frame has been parsed. So an integrator can honour
    /// the peer's max field-section size and QPACK limits.
    fn peerSettings(self: *const H3Engine) py.Object {
        const h = self.h3 orelse return py.none();
        const s = h.peer_settings orelse return py.none();
        const dict = c.PyDict_New();
        if (dict == null) return null;
        if (!setU64(dict, "max_field_section_size", s.max_field_section_size) or
            !setU64(dict, "qpack_max_table_capacity", s.qpack_max_table_capacity) or
            !setU64(dict, "qpack_blocked_streams", s.qpack_blocked_streams))
        {
            py.decref(dict);
            return null;
        }
        return dict;
    }

    fn setU64(dict: py.Object, key: [*c]const u8, value: u64) bool {
        const v = c.PyLong_FromUnsignedLongLong(value);
        if (v == null) return false;
        defer py.decref(v);
        return c.PyDict_SetItemString(dict, key, v) == 0;
    }

    fn deinit(self: *H3Engine) void {
        if (self.h3) |h| {
            h.deinit();
            gpa.destroy(h);
        }
        if (self.qc) |q| {
            q.deinit();
            gpa.destroy(q);
        }
        self.config.deinit();
    }
};

/// One Python Connection drives exactly one protocol engine, chosen at
/// construction. Modelling it as a tagged union (rather than a set of nullable
/// per-protocol fields) makes the "exactly one is live" invariant structural -
/// an illegal mix of per-protocol state cannot be represented - and lets each
/// new protocol slot in as another arm instead of another branch in every method.
const Engine = union(enum) {
    h1: H1Engine,
    h2: H2Engine,
    h3: H3Engine,

    fn deinit(self: *Engine) void {
        switch (self.*) {
            inline else => |*e| e.deinit(),
        }
    }
};

const ConnectionObject = extern struct {
    ob_base: c.PyObject,
    /// Points into `engine_storage` when live, null once torn down. The engine
    /// lives inside the PyObject so constructing a Connection costs no separate
    /// heap allocation for it.
    engine: ?*Engine,
    engine_storage: [@sizeOf(Engine)]u8 align(@alignOf(Engine)),
};

var connection_type: py.Object = null;
var h1_connection_type: py.Object = null;
var h2_connection_type: py.Object = null;
var h3_connection_type: py.Object = null;
var stream_type: py.Object = null;

/// A handle to one HTTP/2 stream on a Connection. It is a borrowed view: the
/// Connection owns the stream state (the core's stream map); the handle holds the
/// stream id plus an owned reference to the Connection (so the connection cannot
/// be freed while a handle to it lives) and re-validates on every call. The send
/// window, pending-DATA buffer, and lifecycle all live in the core - the handle
/// is a command surface, never its own I/O buffer, so bytes still drain through
/// the Connection's single data_to_send.
// The multiplexed engine a Stream handle drives - HTTP/2 or HTTP/3. Both own the
// per-stream state; the handle is a borrowed, re-validated command surface over
// whichever the connection runs.
const StreamEngine = union(enum) {
    h2: *H2Engine,
    h3: *H3Engine,
};

const StreamObject = extern struct {
    ob_base: c.PyObject,
    conn: ?*c.PyObject, // owned reference to the ConnectionObject
    stream_id: u64, // 62-bit for QUIC; 31-bit for HTTP/2

    /// The multiplexed engine behind the handle, or a Python error if the connection
    /// was torn down or is single-stream (HTTP/1.1). The connection object can outlive
    /// its engine, so this re-validates on every call.
    fn engine(self: *StreamObject) ?StreamEngine {
        const conn_obj: *ConnectionObject = @ptrCast(self.conn orelse {
            _ = py.raiseRuntime("connection is closed");
            return null;
        });
        const eng = conn_obj.engine orelse {
            _ = py.raiseRuntime("connection is closed");
            return null;
        };
        return switch (eng.*) {
            .h2 => |*h| .{ .h2 = h },
            .h3 => |*h| .{ .h3 = h },
            .h1 => {
                _ = py.raiseRuntime("streams exist only on a multiplexed (HTTP/2 or HTTP/3) connection");
                return null;
            },
        };
    }
};

/// Build a Stream handle for `stream_id` on `conn_obj` (a ConnectionObject). Holds
/// an owned reference to the connection. Returns null with a Python error set on
/// allocation failure. Public so events_obj can attach `event.stream`.
pub fn makeStream(conn_obj: ?*c.PyObject, stream_id: u64) py.Object {
    const tp: *c.PyTypeObject = @ptrCast(stream_type);
    const alloc = tp.tp_alloc.?;
    const obj = alloc(tp, 0);
    if (obj == null) return null;
    const self: *StreamObject = @ptrCast(obj);
    py.incref(conn_obj);
    self.conn = conn_obj;
    self.stream_id = stream_id;
    return obj;
}

fn stream_dealloc(self_obj: ?*c.PyObject) callconv(.c) void {
    const self: *StreamObject = @ptrCast(self_obj.?);
    py.xdecref(self.conn);
    py.freeInstance(@ptrCast(self));
}

fn stream_send_response(self_obj: ?*c.PyObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    const e = self.engine() orelse return null;
    var status: c_long = 0;
    var hdrs_seq: ?*c.PyObject = null;
    var end_stream: c_int = 0;
    var kwlist = [_][*c]u8{ @constCast("status"), @constCast("headers"), @constCast("end_stream"), null };
    if (c.PyArg_ParseTupleAndKeywords(args, kwds, "l|Op", @ptrCast(&kwlist), &status, &hdrs_seq, &end_stream) == 0) return null;
    if (status < 0 or status > 999) return py.raiseValue("status code out of range");
    var hdrs: ?BorrowedHeaders = null;
    defer if (hdrs) |*h| h.deinit();
    if (hdrs_seq != null and !py.isNone(hdrs_seq)) {
        hdrs = borrowHeaders(hdrs_seq) orelse return null;
    }
    var h = hdrs orelse BorrowedHeaders{ .headers = &.{}, .refs = &.{} };
    return switch (e) {
        .h2 => |x| x.sendResponse(@intCast(self.stream_id), @intCast(status), &h, end_stream != 0),
        .h3 => |x| blk: {
            const r = x.sendResponse(self.stream_id, @intCast(status), h.headers);
            if (r == null or end_stream == 0) break :blk r;
            py.decref(r);
            break :blk x.endStream(self.stream_id);
        },
    };
}

fn stream_send_informational(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    const e = self.engine() orelse return null;
    const h2 = switch (e) {
        .h2 => |x| x,
        .h3 => return py.raise(exceptions.LocalProtocolError, "HTTP/3 interim responses are not supported yet"),
    };
    var status: c_long = 0;
    var hdrs_seq: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "l|O", &status, &hdrs_seq) == 0) return null;
    if (status < 100 or status > 199) return py.raiseValue("informational status code must be in 100..199");
    if (status == 101) return py.raiseValue("HTTP/2 has no 101 Switching Protocols");
    var hdrs: ?BorrowedHeaders = null;
    defer if (hdrs) |*h| h.deinit();
    if (hdrs_seq != null and !py.isNone(hdrs_seq)) {
        hdrs = borrowHeaders(hdrs_seq) orelse return null;
    }
    var h = hdrs orelse BorrowedHeaders{ .headers = &.{}, .refs = &.{} };
    return h2.sendInformational(@intCast(self.stream_id), @intCast(status), &h);
}

fn stream_send_window_get(self_obj: ?*c.PyObject, _: ?*anyopaque) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    const e = self.engine() orelse return null;
    const h2 = switch (e) {
        .h2 => |x| x,
        .h3 => return py.none(), // per-stream send windows are not surfaced for HTTP/3 yet
    };
    const w = h2.conn.streamSendWindow(@intCast(self.stream_id)) orelse return py.none();
    return c.PyLong_FromLong(w);
}

fn stream_pending_bytes_get(self_obj: ?*c.PyObject, _: ?*anyopaque) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    const e = self.engine() orelse return null;
    const h2 = switch (e) {
        .h2 => |x| x,
        .h3 => return py.none(),
    };
    const n = h2.conn.streamPendingBytes(@intCast(self.stream_id)) orelse return py.none();
    return c.PyLong_FromUnsignedLongLong(n);
}

fn stream_send_data(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    const e = self.engine() orelse return null;
    const data = py.asBytes(arg) orelse return null;
    return switch (e) {
        .h2 => |x| x.sendData(@intCast(self.stream_id), data),
        .h3 => |x| x.sendData(self.stream_id, data),
    };
}

fn stream_end_message(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    const e = self.engine() orelse return null;
    var hdrs_seq: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "|O", &hdrs_seq) == 0) return null;
    if (hdrs_seq != null and !py.isNone(hdrs_seq)) {
        return py.raise(exceptions.LocalProtocolError, "send-side trailers are not supported yet");
    }
    return switch (e) {
        .h2 => |x| x.endStream(@intCast(self.stream_id)),
        .h3 => |x| x.endStream(self.stream_id),
    };
}

// The default HTTP/3 reset code: H3_REQUEST_CANCELLED (RFC 9114 8.1).
const H3_REQUEST_CANCELLED: c_ulonglong = 0x010c;

fn stream_reset(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    const e = self.engine() orelse return null;
    switch (e) {
        .h2 => |h2| {
            var code: c_ulong = @intFromEnum(core.h2.constants.ErrorCode.cancel);
            if (c.PyArg_ParseTuple(args, "|k", &code) == 0) return null;
            if (code > 0xFFFF_FFFF) return py.raiseValue("error code out of range");
            return h2.resetStream(@intCast(self.stream_id), @intCast(code));
        },
        .h3 => |h3e| {
            var code: c_ulonglong = H3_REQUEST_CANCELLED;
            if (c.PyArg_ParseTuple(args, "|K", &code) == 0) return null;
            if (code > core.quic.varint.MAX) return py.raiseValue("error code exceeds the 62-bit QUIC range");
            return h3e.resetStream(self.stream_id, @intCast(code));
        },
    }
}

fn stream_id_get(self_obj: ?*c.PyObject, _: ?*anyopaque) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    return c.PyLong_FromUnsignedLongLong(self.stream_id);
}

fn stream_repr(self_obj: ?*c.PyObject) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    return c.PyUnicode_FromFormat("Stream(stream_id=%llu)", self.stream_id);
}

var stream_methods = [_]py.MethodDef{
    .{ .ml_name = "send_response", .ml_meth = @ptrCast(&stream_send_response), .ml_flags = c.METH_VARARGS | c.METH_KEYWORDS, .ml_doc = "Serialize a response head on this stream: send_response(status, headers=None, end_stream=False). Pass end_stream=True for a bodyless response (204 / 304 / HEAD) to ride END_STREAM on the HEADERS frame and skip the trailing empty DATA frame." },
    .{ .ml_name = "send_informational", .ml_meth = stream_send_informational, .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize an interim 1xx response head on this stream: send_informational(status, headers=None). The final response still follows on the same stream." },
    .{ .ml_name = "send_data", .ml_meth = stream_send_data, .ml_flags = c.METH_O, .ml_doc = "Queue body bytes on this stream (flow-controlled; parked until the send window allows)." },
    .{ .ml_name = "end_message", .ml_meth = stream_end_message, .ml_flags = c.METH_VARARGS, .ml_doc = "End the outgoing message on this stream (empty END_STREAM DATA)." },
    .{ .ml_name = "reset", .ml_meth = stream_reset, .ml_flags = c.METH_VARARGS, .ml_doc = "Send RST_STREAM to cancel this stream: reset(error_code=CANCEL)." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

var stream_getset = [_]c.PyGetSetDef{
    .{ .name = "stream_id", .get = stream_id_get, .set = null, .doc = "The HTTP/2 stream id this handle addresses.", .closure = null },
    .{ .name = "send_window", .get = stream_send_window_get, .set = null, .doc = "Body bytes that may still leave on this stream before a WINDOW_UPDATE (may be negative after a SETTINGS shrink), or None if the stream is no longer live.", .closure = null },
    .{ .name = "pending_bytes", .get = stream_pending_bytes_get, .set = null, .doc = "Body bytes queued on this stream that the send window has not yet admitted, or None if the stream is no longer live.", .closure = null },
    .{ .name = null, .get = null, .set = null, .doc = null, .closure = null },
};

var stream_slots = [_]py.Slot{
    .{ .slot = c.Py_tp_dealloc, .pfunc = @ptrCast(@constCast(&stream_dealloc)) },
    .{ .slot = c.Py_tp_methods, .pfunc = @ptrCast(&stream_methods) },
    .{ .slot = c.Py_tp_getset, .pfunc = @ptrCast(&stream_getset) },
    .{ .slot = c.Py_tp_repr, .pfunc = @ptrCast(@constCast(&stream_repr)) },
    .{ .slot = 0, .pfunc = null },
};

var stream_spec = py.Spec{
    .name = "zttp.Stream",
    .basicsize = @sizeOf(StreamObject),
    .itemsize = 0,
    .flags = c.Py_TPFLAGS_DEFAULT,
    .slots = &stream_slots,
};

// Parse (role, protocol) from the constructor args. `default_protocol` is what a
// missing `protocol` arg means - HTTP1 for the base Connection, but a subtype
// fixes it (and the arg is rejected if it disagrees, so H2Connection(role, HTTP1)
// can't lie). Returns false with a Python error set on bad input.
fn parseArgs(args: ?*c.PyObject, kwds: ?*c.PyObject, role: *Role, protocol_out: *c_long, fixed: ?c_long) bool {
    var role_val: c_long = 0;
    var protocol_val: c_long = fixed orelse HTTP1;
    const positional = if (kwds == null) c.PyTuple_Size(args) else -1;
    if (positional == 1 or positional == 2) {
        // The common positional forms skip PyArg_ParseTupleAndKeywords, which
        // costs more than the rest of construction combined.
        role_val = c.PyLong_AsLong(c.PyTuple_GetItem(args, 0));
        if (role_val == -1 and c.PyErr_Occurred() != null) return false;
        if (positional == 2) {
            protocol_val = c.PyLong_AsLong(c.PyTuple_GetItem(args, 1));
            if (protocol_val == -1 and c.PyErr_Occurred() != null) return false;
        }
    } else {
        // The kwlist parameter type differs across CPython versions (char** in 3.12,
        // const char* const* in 3.13+), so build a plain C-pointer array and ptrCast
        // it to whatever the translated signature expects.
        var kwlist = [_][*c]u8{ @constCast("role"), @constCast("protocol"), null };
        if (c.PyArg_ParseTupleAndKeywords(args, kwds, "l|l", @ptrCast(&kwlist), &role_val, &protocol_val) == 0) return false;
    }
    role.* = switch (role_val) {
        SERVER => .server,
        CLIENT => .client,
        else => {
            _ = py.raiseValue("role must be zttp.SERVER or zttp.CLIENT");
            return false;
        },
    };
    if (protocol_val != HTTP1 and protocol_val != HTTP2 and protocol_val != HTTP3) {
        _ = py.raiseValue("protocol must be zttp.HTTP1, zttp.HTTP2, or zttp.HTTP3");
        return false;
    }
    if (protocol_val == HTTP3 and role.* != .server) {
        _ = py.raiseValue("HTTP/3 currently supports the server read path only");
        return false;
    }
    if (fixed) |f| {
        if (protocol_val != f) {
            _ = py.raiseValue("protocol does not match this Connection subclass; construct zttp.Connection to choose by protocol");
            return false;
        }
    }
    protocol_out.* = protocol_val;
    return true;
}

// Allocate an instance of `tp` and build the engine for `protocol_val`. Shared by
// the concrete subtypes' tp_new.
fn allocAndBuild(tp: ?*c.PyTypeObject, role: Role, protocol_val: c_long) py.Object {
    const alloc = tp.?.tp_alloc.?;
    const obj = alloc(tp, 0);
    if (obj == null) return null;
    const self: *ConnectionObject = @ptrCast(obj);
    self.engine = null;
    const engine: *Engine = @ptrCast(@alignCast(&self.engine_storage));
    if (!buildEngine(engine, role, protocol_val)) {
        py.decref(obj);
        return null;
    }
    self.engine = engine;
    return obj;
}

// Base `Connection` tp_new: a factory. Called as `Connection(role, protocol=...)`
// it picks the H1/H2 subtype and returns an instance of THAT type, so the runtime
// type is truthful (isinstance(obj, Connection) still holds via the base). Called
// on a user subclass of Connection, it builds in place with the requested protocol
// (the subclass is honoured; no foreign-type substitution).
fn new_base(tp: ?*c.PyTypeObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
    // HTTP/3 carries server-credential kwargs that the (role, protocol) parser would
    // reject, so detect it first by a cheap peek and route the whole call through
    // new_h3, which owns the full parse. The H1/H2 fast path is unchanged.
    if (peekProtocol(args, kwds) == HTTP3) {
        const target = if (@intFromPtr(tp) == @intFromPtr(connection_type)) @as(?*c.PyTypeObject, @ptrCast(h3_connection_type)) else tp;
        return new_h3(target, args, kwds);
    }
    var role: Role = .server;
    var protocol_val: c_long = HTTP1;
    if (!parseArgs(args, kwds, &role, &protocol_val, null)) return null;
    if (@intFromPtr(tp) == @intFromPtr(connection_type)) {
        const sub: ?*c.PyTypeObject = @ptrCast(switch (protocol_val) {
            HTTP2 => h2_connection_type,
            else => h1_connection_type,
        });
        return allocAndBuild(sub, role, protocol_val);
    }
    return allocAndBuild(tp, role, protocol_val);
}

// Peek the `protocol` argument (2nd positional or the `protocol` kwarg) without the
// strict kwlist parse, so the factory can branch to HTTP/3's bespoke parser before a
// (role, protocol)-only parser would reject HTTP/3's extra credential kwargs. Returns
// -1 (a non-protocol) if absent or unreadable; the real parse then reports the error.
fn peekProtocol(args: ?*c.PyObject, kwds: ?*c.PyObject) c_long {
    if (args != null and c.PyTuple_Size(args) >= 2) {
        const v = c.PyLong_AsLong(c.PyTuple_GetItem(args, 1));
        if (!(v == -1 and c.PyErr_Occurred() != null)) return v;
        c.PyErr_Clear();
    }
    if (kwds != null) {
        const item = c.PyDict_GetItemString(kwds, "protocol"); // borrowed
        if (item != null) {
            const v = c.PyLong_AsLong(item);
            if (!(v == -1 and c.PyErr_Occurred() != null)) return v;
            c.PyErr_Clear();
        }
    }
    return -1;
}

fn new_h1(tp: ?*c.PyTypeObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
    var role: Role = .server;
    var protocol_val: c_long = HTTP1;
    if (!parseArgs(args, kwds, &role, &protocol_val, HTTP1)) return null;
    return allocAndBuild(tp, role, HTTP1);
}

fn new_h2(tp: ?*c.PyTypeObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
    var role: Role = .server;
    var protocol_val: c_long = HTTP2;
    if (!parseArgs(args, kwds, &role, &protocol_val, HTTP2)) return null;
    return allocAndBuild(tp, role, HTTP2);
}

// H3Connection(role, protocol=HTTP3, *, certificate, private_key, transport_params,
// random, ephemeral_seed, alpn=None). role and protocol stay positional-or-keyword so
// the Connection(SERVER, HTTP3, certificate=...) factory form works; the credentials
// are keyword-only (the `$` in the format) and mandatory - a sans-IO QUIC server
// cannot invent its own certificate or entropy. The bytes are copied into a
// ServerConfig the engine owns.
fn new_h3(tp: ?*c.PyTypeObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
    var role_val: c_long = 0;
    var protocol_val: c_long = HTTP3;
    var cert_obj: ?*c.PyObject = null;
    var key_obj: ?*c.PyObject = null;
    var tp_obj: ?*c.PyObject = null;
    var random_obj: ?*c.PyObject = null;
    var ephemeral_obj: ?*c.PyObject = null;
    var alpn_obj: ?*c.PyObject = null;
    var kwlist = [_][*c]u8{
        @constCast("role"),           @constCast("protocol"),         @constCast("certificate"),
        @constCast("private_key"),    @constCast("transport_params"), @constCast("random"),
        @constCast("ephemeral_seed"), @constCast("alpn"),             null,
    };
    if (c.PyArg_ParseTupleAndKeywords(args, kwds, "l|l$OOOOOO", @ptrCast(&kwlist), &role_val, &protocol_val, &cert_obj, &key_obj, &tp_obj, &random_obj, &ephemeral_obj, &alpn_obj) == 0) return null;
    if (cert_obj == null or key_obj == null or tp_obj == null or random_obj == null or ephemeral_obj == null) {
        return py.raiseType("HTTP/3 requires the server credentials: certificate, private_key, transport_params, random, ephemeral_seed");
    }
    if (role_val != SERVER) return py.raiseValue("HTTP/3 currently supports the server read path only");
    if (protocol_val != HTTP3) return py.raiseValue("protocol does not match this Connection subclass; construct zttp.Connection to choose by protocol");

    const config = buildServerConfig(cert_obj, key_obj, tp_obj, random_obj, ephemeral_obj, alpn_obj) orelse return null;
    const alloc = tp.?.tp_alloc.?;
    const obj = alloc(tp, 0);
    if (obj == null) {
        var cfg = config;
        cfg.deinit();
        return null;
    }
    const self: *ConnectionObject = @ptrCast(obj);
    self.engine = null;
    const engine: *Engine = @ptrCast(@alignCast(&self.engine_storage));
    engine.* = .{ .h3 = .{ .config = config } };
    self.engine = engine;
    return obj;
}

// Copy the integrator's server credentials into an owned ServerConfig, validating
// the fixed-size seeds and deriving the Signer up front. On any failure sets a Python
// error, frees whatever was already copied, and returns null.
fn buildServerConfig(cert_obj: ?*c.PyObject, key_obj: ?*c.PyObject, tp_obj: ?*c.PyObject, random_obj: ?*c.PyObject, ephemeral_obj: ?*c.PyObject, alpn_obj: ?*c.PyObject) ?ServerConfig {
    const cert_src = py.asBytes(cert_obj) orelse return null;
    const key_src = py.asBytes(key_obj) orelse return null;
    const tp_src = py.asBytes(tp_obj) orelse return null;
    const random_src = py.asBytes(random_obj) orelse return null;
    const ephemeral_src = py.asBytes(ephemeral_obj) orelse return null;
    if (key_src.len != 32) {
        _ = py.raiseValue("private_key must be 32 bytes (the signing key seed)");
        return null;
    }
    if (random_src.len != 32) {
        _ = py.raiseValue("random must be 32 bytes (the ServerHello random)");
        return null;
    }
    if (ephemeral_src.len != 32) {
        _ = py.raiseValue("ephemeral_seed must be 32 bytes");
        return null;
    }
    const signer = Signer.fromSeed(key_src[0..32].*) catch {
        _ = py.raiseValue("private_key is not a valid signing key seed");
        return null;
    };

    const cert = gpa.dupe(u8, cert_src) catch {
        _ = c.PyErr_NoMemory();
        return null;
    };
    const tp_copy = gpa.dupe(u8, tp_src) catch {
        gpa.free(cert);
        _ = c.PyErr_NoMemory();
        return null;
    };
    // ALPN is mandatory in QUIC (RFC 9001 8.1) and an HTTP/3 server's protocol is
    // "h3"; the parameter overrides the token (e.g. an interop draft name), it is
    // not an opt-out of negotiation.
    const alpn_src: []const u8 = if (alpn_obj != null and !py.isNone(alpn_obj))
        py.asBytes(alpn_obj) orelse {
            gpa.free(cert);
            gpa.free(tp_copy);
            return null;
        }
    else
        "h3";
    const alpn = gpa.dupe(u8, alpn_src) catch {
        gpa.free(cert);
        gpa.free(tp_copy);
        _ = c.PyErr_NoMemory();
        return null;
    };
    return .{
        .cert = cert,
        .transport_params = tp_copy,
        .alpn = alpn,
        .signer = signer,
        .random = random_src[0..32].*,
        .ephemeral_seed = ephemeral_src[0..32].*,
    };
}

// HTTP/3 is never built here: new_h3 constructs its engine directly because it needs
// the parsed server config. This builds the H1/H2 engines for the shared alloc path.
fn buildEngine(engine: *Engine, role: Role, protocol_val: c_long) bool {
    if (protocol_val == HTTP2) {
        const conn = gpa.create(H2Connection) catch {
            _ = c.PyErr_NoMemory();
            return false;
        };
        conn.* = H2Connection.init(gpa, if (role == .server) H2Role.server else H2Role.client);
        const writer = gpa.create(H2Writer) catch {
            conn.deinit();
            gpa.destroy(conn);
            _ = c.PyErr_NoMemory();
            return false;
        };
        writer.* = H2Writer.init(gpa, if (role == .server) core.h2.writer.Role.server else core.h2.writer.Role.client);
        engine.* = .{ .h2 = .{ .conn = conn, .writer = writer } };
        return true;
    }

    engine.* = .{ .h1 = .{ .reader = Reader.init(gpa, role) } };
    return true;
}

fn dealloc(self_obj: ?*c.PyObject) callconv(.c) void {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    if (self.engine) |engine| {
        engine.deinit();
    }
    py.freeInstance(@ptrCast(self));
}

/// The H1 engine, or a Python error if torn down (closed) or HTTP/2. The H1-only
/// API (keep-alive / upgrade, and the message-scoped send_* methods) lives on the
/// Connection; HTTP/2 is stream-scoped, so its sends go through a Stream and these
/// methods report that rather than pretending the connection is closed.
fn h1(self: *ConnectionObject) ?*H1Engine {
    const engine = self.engine orelse {
        _ = py.raiseRuntime("connection is closed");
        return null;
    };
    switch (engine.*) {
        .h1 => |*e| return e,
        .h2 => {
            _ = py.raiseRuntime("this is an HTTP/2 connection; send on a Stream (conn.stream(id) or the Stream returned by send_request)");
            return null;
        },
        .h3 => {
            _ = py.raiseRuntime("this is an HTTP/3 connection; the write side is not implemented yet");
            return null;
        },
    }
}

fn receive_data(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const bytes = py.asBytes(arg) orelse return null;
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    switch (engine.*) {
        .h2 => |*e| {
            e.conn.feed(bytes) catch |err| {
                e.emitGoawayIfOwed(); // a fatal feed (e.g. max_buffer flood) still owes a GOAWAY
                return exceptions.raiseH2(err);
            };
            return py.none();
        },
        .h1 => |*e| return e.receiveData(bytes, arg),
        .h3 => return py.raiseRuntime("receive_data is not valid for an HTTP/3 connection; use receive_datagram"),
    }
}

fn receive_datagram(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    switch (engine.*) {
        .h3 => |*e| {
            var dgram_obj: ?*c.PyObject = null;
            var now: c_ulonglong = 0;
            if (c.PyArg_ParseTuple(args, "O|K", &dgram_obj, &now) == 0) return null;
            const dgram = py.asBytes(dgram_obj) orelse return null;
            return e.receiveDatagram(dgram, @intCast(now));
        },
        else => return py.raiseRuntime("receive_datagram is only valid for an HTTP/3 connection"),
    }
}

fn next_event(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    switch (engine.*) {
        .h3 => |*e| return e.nextEvent(),
        .h2 => |*e| {
            const ev = e.conn.nextEvent() catch |err| {
                e.emitGoawayIfOwed(); // queue one GOAWAY for the next data_to_send
                return exceptions.raiseH2(err);
            };
            e.autoRespond(ev) catch |err| return h2RaiseWrite(err);
            return events_obj.fromH2Event(ev);
        },
        .h1 => |*e| {
            while (true) {
                const ev = e.reader.nextEvent() catch |err| {
                    e.dropPending();
                    return exceptions.raiseParse(err);
                };
                if (ev == .need_data and e.pending_obj != null) {
                    if (e.reader.backlogEmpty()) {
                        if (e.reader.bodyLengthRemaining()) |rem| {
                            // Materialise body bytes straight from the stashed
                            // buffer - the one copy - and account for them.
                            const take: usize = @intCast(@min(rem, @as(u64, e.pending.len)));
                            const out = events_obj.fromH1Event(.{ .data = .{ .data = e.pending[0..take] } });
                            if (out == null) return null;
                            e.reader.skipBodyLength(take);
                            e.pending = e.pending[take..];
                            if (e.pending.len == 0) {
                                e.dropPending();
                            } else if (e.reader.bodyLengthRemaining() == null) {
                                // The remainder is the next pipelined message.
                                if (!e.flushPending()) {
                                    py.decref(out);
                                    return null;
                                }
                            }
                            return out;
                        }
                    }
                    // The stash cannot be consumed in place (chunked body,
                    // message done, or buffered bytes precede it): buffer it
                    // and ask the reader again.
                    if (!e.flushPending()) return null;
                    continue;
                }
                if (ev == .request) {
                    e.rememberMethod(ev.request.method);
                    e.should_close = e.reader.shouldClose();
                    py.xdecref(e.upgrade_obj);
                    if (e.reader.upgrade()) |u| {
                        e.upgrade_obj = py.fromBytes(u);
                        if (e.upgrade_obj == null) return null; // propagate the pending MemoryError
                    } else e.upgrade_obj = null;
                }
                return events_obj.fromH1Event(ev);
            }
        },
    }
}

/// Headers borrowed (zero-copy) from a Python sequence of (name, value) bytes
/// pairs. The Header slices point into the name/value bytes objects, whose
/// references are HELD in `refs` until `deinit` - so they cannot be freed out
/// from under the writer even if the sequence synthesizes fresh bytes per
/// __getitem__ (the borrowed-pointer use-after-free guard).
const BorrowedHeaders = struct {
    headers: []events.Header,
    refs: []py.Object, // owned: 2 per header (name, value), decref'd on deinit

    fn deinit(self: *BorrowedHeaders) void {
        for (self.refs) |r| py.xdecref(r);
        gpa.free(self.refs);
        gpa.free(self.headers);
    }
};

/// Borrow a list/tuple of (name, value) bytes pairs. On failure sets a Python
/// error and returns null. The caller MUST call deinit() after the writer call
/// that consumes the slices returns.
fn borrowHeaders(seq: py.Object) ?BorrowedHeaders {
    const n = c.PySequence_Size(seq);
    if (n < 0) {
        _ = py.raiseType("headers must be a sequence of (name, value) pairs");
        return null;
    }
    const count: usize = @intCast(n);
    const slice = gpa.alloc(events.Header, count) catch {
        _ = c.PyErr_NoMemory();
        return null;
    };
    const refs = gpa.alloc(py.Object, count * 2) catch {
        gpa.free(slice);
        _ = c.PyErr_NoMemory();
        return null;
    };
    @memset(refs, null);
    var result = BorrowedHeaders{ .headers = slice, .refs = refs };

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const item = c.PySequence_GetItem(seq, @intCast(i)); // new ref
        if (item == null) {
            result.deinit();
            return null;
        }
        const name = c.PySequence_GetItem(item, 0);
        const value = c.PySequence_GetItem(item, 1);
        py.decref(item);
        refs[i * 2] = name; // held (may be null; xdecref-safe) so the buffer survives
        refs[i * 2 + 1] = value;
        if (name == null or value == null) {
            _ = py.raiseType("each header must be a (name, value) pair");
            result.deinit();
            return null;
        }
        const nb = py.asBytes(name) orelse {
            result.deinit();
            return null;
        };
        const vb = py.asBytes(value) orelse {
            result.deinit();
            return null;
        };
        slice[i] = .{ .name = nb, .value = vb };
    }
    return result;
}

// HTTP/2 send helpers -------------------------------------------------------

const asciiEqlIgnoreCase = core.ascii.eqIgnoreCase;

// Build the HTTP/2 regular-header list and pull out :authority. For a request the
// adapter derives :authority from a `host` (or `:authority`) field and drops it
// from the regular headers - HTTP/2 forbids `host` and carries it as a pseudo-
// header instead. `:scheme` defaults to https.
fn h2SplitAuthority(headers: []events.Header, out: *[]events.Header) []const u8 {
    var authority: []const u8 = "";
    var n: usize = 0;
    for (headers) |h| {
        if (asciiEqlIgnoreCase(h.name, "host") or asciiEqlIgnoreCase(h.name, ":authority")) {
            if (authority.len == 0) authority = h.value;
            continue;
        }
        headers[n] = h;
        n += 1;
    }
    out.* = headers[0..n];
    return authority;
}

fn h2RaiseWrite(e: core.h2.writer.WriteError) py.Object {
    const local = exceptions.LocalProtocolError;
    return switch (e) {
        error.OutOfMemory => c.PyErr_NoMemory(),
        error.LocalProtocol => py.raise(local, "invalid HTTP/2 send: a pseudo-header order, status, or stream id was rejected"),
        error.InvalidField => py.raise(local, "invalid field: a header name/value contained CR/LF/NUL or an uppercase byte"),
    };
}

fn send_request(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    var method: ?*c.PyObject = null;
    var target: ?*c.PyObject = null;
    var version: ?*c.PyObject = null;
    var hdrs_seq: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "OOOO", &method, &target, &version, &hdrs_seq) == 0) return null;
    const mb = py.asBytes(method) orelse return null;
    const tb = py.asBytes(target) orelse return null;
    const vb = py.asBytes(version) orelse return null;
    var hdrs = borrowHeaders(hdrs_seq) orelse return null;
    defer hdrs.deinit();
    switch (engine.*) {
        .h2 => |*e| {
            // HTTP/2: the version arg is ignored (always "2"); :authority is
            // derived from a host header and :scheme defaults to https. The
            // client originates the stream, so the handle is returned here.
            const id = e.sendRequestId(mb, tb, &hdrs) orelse return null;
            return makeStream(self_obj, id);
        },
        .h1 => |*e| {
            const w = e.ensureWriter() orelse return null;
            w.sendRequest(mb, tb, vb, hdrs.headers) catch |err| return raiseWrite(err);
            e.rememberMethod(mb);
            e.reader.setRequestMethod(mb);
            return py.none();
        },
        .h3 => return py.raiseRuntime("the HTTP/3 write side is not implemented yet"),
    }
}

fn initiate_upgrade_connection(self_obj: ?*c.PyObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    const e = switch (engine.*) {
        .h2 => |*x| x,
        else => return py.raiseRuntime("initiate_upgrade_connection() exists only on an HTTP/2 connection"),
    };
    var method: ?*c.PyObject = null;
    var target: ?*c.PyObject = null;
    var hdrs_seq: ?*c.PyObject = null;
    var settings_obj: ?*c.PyObject = null;
    var kwlist = [_][*c]u8{ @constCast("method"), @constCast("target"), @constCast("headers"), @constCast("settings_header"), null };
    if (c.PyArg_ParseTupleAndKeywords(args, kwds, "OOO|O", @ptrCast(&kwlist), &method, &target, &hdrs_seq, &settings_obj) == 0) return null;
    const mb = py.asBytes(method) orelse return null;
    const tb = py.asBytes(target) orelse return null;
    var settings_header: ?[]const u8 = null;
    if (settings_obj != null and !py.isNone(settings_obj)) {
        settings_header = py.asBytes(settings_obj) orelse return null;
    }
    var hdrs = borrowHeaders(hdrs_seq) orelse return null;
    defer hdrs.deinit();
    if (!e.initiateUpgrade(mb, tb, &hdrs, settings_header)) return null;
    return makeStream(self_obj, 1);
}

fn send_response(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const e = h1(self) orelse return null; // HTTP/2 answers via a Stream (conn.stream(id))
    var status: c_long = 0;
    var hdrs_seq: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "l|O", &status, &hdrs_seq) == 0) return null;
    if (status < 0 or status > 999) return py.raiseValue("status code out of range");

    var hdrs: ?BorrowedHeaders = null;
    defer if (hdrs) |*h| h.deinit();
    if (hdrs_seq != null and !py.isNone(hdrs_seq)) {
        hdrs = borrowHeaders(hdrs_seq) orelse return null;
    }
    const header_slice = if (hdrs) |h| h.headers else &.{};

    const rb = core.h1.writer.reasonPhrase(@intCast(status));
    const w = e.ensureWriter() orelse return null;
    w.sendResponse("1.1", @intCast(status), rb, header_slice, e.method()) catch |err| return raiseWrite(err);
    return py.none();
}

fn send_informational(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const e = h1(self) orelse return null;
    var status: c_long = 0;
    var hdrs_seq: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "l|O", &status, &hdrs_seq) == 0) return null;
    if (status < 100 or status > 199) return py.raiseValue("informational status code must be in 100..199");
    if (status == 101) return py.raiseValue("101 Switching Protocols is a terminal upgrade response, not interim");
    const w = e.ensureWriter() orelse return null;
    if (hdrs_seq == null or py.isNone(hdrs_seq)) {
        w.sendInformational(@intCast(status), &.{}) catch |err| return raiseWrite(err);
    } else {
        var hdrs = borrowHeaders(hdrs_seq) orelse return null;
        defer hdrs.deinit();
        w.sendInformational(@intCast(status), hdrs.headers) catch |err| return raiseWrite(err);
    }
    return py.none();
}

fn send_data(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const e = h1(self) orelse return null; // HTTP/2 sends body via a Stream
    const data = py.asBytes(arg) orelse return null;
    const w = e.ensureWriter() orelse return null;
    w.sendData(data) catch |err| return raiseWrite(err);
    return py.none();
}

fn end_message(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const e = h1(self) orelse return null; // HTTP/2 ends a message via a Stream
    var hdrs_seq: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "|O", &hdrs_seq) == 0) return null;
    const w = e.ensureWriter() orelse return null;
    if (hdrs_seq == null or py.isNone(hdrs_seq)) {
        w.endMessage(&.{}) catch |err| return raiseWrite(err);
    } else {
        var hdrs = borrowHeaders(hdrs_seq) orelse return null;
        defer hdrs.deinit();
        w.endMessage(hdrs.headers) catch |err| return raiseWrite(err);
    }
    return py.none();
}

fn data_to_send(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    const pending = switch (engine.*) {
        .h2 => |*e| e.writer.pending(),
        .h1 => |*e| if (e.writer) |w| w.pending() else "",
        .h3 => |*e| return e.dataToSend(),
    };
    const out = py.fromBytes(pending);
    if (out == null) return null;
    switch (engine.*) {
        .h2 => |*e| e.writer.clear(),
        .h1 => |*e| if (e.writer) |w| w.clear(),
        .h3 => unreachable,
    }
    return out;
}

fn raiseWrite(e: core.h1.writer.WriteError) py.Object {
    const local = exceptions.LocalProtocolError;
    return switch (e) {
        error.OutOfMemory => c.PyErr_NoMemory(),
        error.MessageNotEnded => py.raise(local, "a message is already in progress: end it before sending another head"),
        error.NoBodyAllowed => py.raise(local, "cannot send body data now: send a head first, or this message takes no body"),
        error.BodyTooLong => py.raise(local, "sent more body than the declared Content-Length"),
        error.BodyTooShort => py.raise(local, "the message ended before the declared Content-Length was reached"),
        error.TrailersNotAllowed => py.raise(local, "trailers can only follow a chunked body"),
        error.NoMessageInProgress => py.raise(local, "no message is in progress to end"),
        error.InvalidField => py.raise(local, "invalid field: a header/method/target/version/reason was malformed or contained CR/LF/control bytes"),
    };
}

fn next_message(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    // Convenience for keep-alive: reset the reader for the next request/response.
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const e = h1(self) orelse return null;
    e.reader.reset();
    // req_method is intentionally NOT cleared: a caller may call start_next_cycle()
    // before serializing the previous response (e.g. pipelined keep-alive reads),
    // and send_response reads it to frame HEAD / CONNECT responses as bodyless. It
    // is overwritten when the next request is parsed, so a stale value is never seen.
    e.should_close = false;
    py.xdecref(e.upgrade_obj);
    e.upgrade_obj = null;
    return py.none();
}

fn should_close(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const e = h1(self) orelse return null;
    return py.boolean(e.should_close);
}

fn upgrade(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const e = h1(self) orelse return null;
    const obj = e.upgrade_obj orelse return py.none();
    py.incref(obj);
    return obj;
}

fn stream(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    // HTTP/2 ids are 31-bit and stream 0 is the connection (RFC 9113 5.1.1); QUIC
    // (HTTP/3) ids are 62-bit and stream 0 is the first client bidi stream.
    const max_id: i128, const min_id: i128 = switch (engine.*) {
        .h2 => .{ 0x7FFF_FFFF, 1 },
        .h3 => .{ (1 << 62) - 1, 0 },
        .h1 => return py.raiseRuntime("streams exist only on a multiplexed (HTTP/2 or HTTP/3) connection"),
    };
    // Parse as long long (64-bit on every platform; c_long is only 32-bit on
    // Windows, where a large id would otherwise raise OverflowError from PyLong_AsLong
    // instead of the range ValueError below).
    const id = c.PyLong_AsLongLong(arg);
    if (id == -1 and c.PyErr_Occurred() != null) return null;
    if (id < min_id or id > max_id) return py.raiseValue("stream_id out of range for this connection");
    return makeStream(self_obj, @intCast(id));
}

fn h2_close(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    const h = switch (engine.*) {
        .h2 => |*x| x,
        else => return py.raiseRuntime("close() exists only on an HTTP/2 connection"),
    };
    var code: c_ulong = @intFromEnum(core.h2.constants.ErrorCode.no_error);
    var last_obj: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "|kO", &code, &last_obj) == 0) return null;
    if (code > 0xFFFF_FFFF) return py.raiseValue("error code out of range");
    var last: ?u32 = null;
    if (last_obj != null and !py.isNone(last_obj)) {
        const v = c.PyLong_AsLongLong(last_obj);
        if (v < 0) {
            if (c.PyErr_Occurred() != null) return null;
            return py.raiseValue("last_stream_id must be a non-negative integer");
        }
        if (v > 0x7FFF_FFFF) return py.raiseValue("last_stream_id exceeds the 31-bit HTTP/2 limit");
        last = @intCast(v);
    }
    return h.goaway(@intCast(code), last);
}

// HTTP/3 send helpers ------------------------------------------------------

fn h3(self: *ConnectionObject) ?*H3Engine {
    const engine = self.engine orelse {
        _ = py.raiseRuntime("connection is closed");
        return null;
    };
    switch (engine.*) {
        .h3 => |*e| return e,
        else => {
            _ = py.raiseRuntime("this method exists only on an HTTP/3 connection");
            return null;
        },
    }
}

fn h3_next_timeout(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    return e.nextTimeout();
}

fn h3_handle_timeout(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    const now = c.PyLong_AsUnsignedLongLong(arg);
    if (now == @as(c_ulonglong, @bitCast(@as(c_longlong, -1))) and c.PyErr_Occurred() != null) return null;
    return e.handleTimeout(@intCast(now));
}

fn h3_is_closed(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    return py.boolean(e.isClosed());
}

fn h3_close_info(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    return e.closeInfo();
}

fn h3_initiate(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    return e.initiate();
}

fn h3_peer_settings(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    return e.peerSettings();
}

fn h3_shutdown(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    const id = c.PyLong_AsUnsignedLongLong(arg);
    if (id == @as(c_ulonglong, @bitCast(@as(c_longlong, -1))) and c.PyErr_Occurred() != null) return null;
    return e.shutdown(@intCast(id));
}

fn h3_goaway_received(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    return e.goawayReceived();
}

// HTTP/2 connection-level send helpers --------------------------------------

fn h2_initiate(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    const h = switch (engine.*) {
        .h2 => |*x| x,
        else => return py.raiseRuntime("initiate_connection() exists only on an HTTP/2 connection"),
    };
    if (!h.ensureHandshake()) return null;
    return py.none();
}

fn h2_send_window_get(self_obj: ?*c.PyObject, _: ?*anyopaque) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    const h = switch (engine.*) {
        .h2 => |*x| x,
        else => return py.raiseRuntime("send_window exists only on an HTTP/2 connection"),
    };
    return c.PyLong_FromLong(h.conn.connSendWindow());
}

fn h2_has_pending_send(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    const h = switch (engine.*) {
        .h2 => |*x| x,
        else => return py.raiseRuntime("has_pending_send() exists only on an HTTP/2 connection"),
    };
    return py.boolean(h.conn.hasPendingSend());
}

// The read API, shared by both protocols and inherited by the subtypes. The base
// Connection is the factory: constructing it picks H1Connection / H2Connection by
// protocol (new_base), so the runtime type is truthful while isinstance(obj,
// Connection) still holds.
var base_methods = [_]py.MethodDef{
    .{ .ml_name = "receive_data", .ml_meth = receive_data, .ml_flags = c.METH_O, .ml_doc = "Append received bytes (empty bytes signals EOF)." },
    .{ .ml_name = "next_event", .ml_meth = next_event, .ml_flags = c.METH_NOARGS, .ml_doc = "Return the next parse event, or NEED_DATA." },
    .{ .ml_name = "data_to_send", .ml_meth = data_to_send, .ml_flags = c.METH_NOARGS, .ml_doc = "Return and clear the pending outgoing bytes." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

// HTTP/1.1: the message-scoped send API plus keep-alive / upgrade signals.
var h1_methods = [_]py.MethodDef{
    .{ .ml_name = "start_next_cycle", .ml_meth = next_message, .ml_flags = c.METH_NOARGS, .ml_doc = "Reset to read the next message on a keep-alive connection." },
    .{ .ml_name = "send_request", .ml_meth = send_request, .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize a request head: send_request(method, target, version, headers)." },
    .{ .ml_name = "send_response", .ml_meth = send_response, .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize a response head: send_response(status, headers=None). The reason phrase is derived from the status; the version is 1.1. Bodyless framing (HEAD / 204 / 304) is derived automatically." },
    .{ .ml_name = "send_informational", .ml_meth = send_informational, .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize an interim 1xx response: send_informational(status, headers=None). The real response still follows on the same cycle." },
    .{ .ml_name = "send_data", .ml_meth = send_data, .ml_flags = c.METH_O, .ml_doc = "Serialize a run of body bytes (chunk-framed if the head was chunked)." },
    .{ .ml_name = "end_message", .ml_meth = end_message, .ml_flags = c.METH_VARARGS, .ml_doc = "End the outgoing message: end_message(trailers=None)." },
    .{ .ml_name = "should_close", .ml_meth = should_close, .ml_flags = c.METH_NOARGS, .ml_doc = "Whether the connection must close after the last request (Connection: close / HTTP/1.0)." },
    .{ .ml_name = "upgrade", .ml_meth = upgrade, .ml_flags = c.METH_NOARGS, .ml_doc = "The last request's Upgrade value if it asked to upgrade (Connection: upgrade), else None." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

// HTTP/2: everything is stream-scoped. The client originates a stream by sending
// a request (returns a Stream); the server reaches one with stream(id). There is
// no connection-level body send - that is what the Stream handle is for.
var h2_methods = [_]py.MethodDef{
    .{ .ml_name = "initiate_connection", .ml_meth = h2_initiate, .ml_flags = c.METH_NOARGS, .ml_doc = "Emit the connection preface (client preface + SETTINGS, or the server's SETTINGS) now, rather than lazily on the first send. Idempotent." },
    .{ .ml_name = "send_request", .ml_meth = send_request, .ml_flags = c.METH_VARARGS, .ml_doc = "Open a request stream and return its Stream: send_request(method, target, version, headers). :authority is derived from a host header; the version arg is ignored." },
    .{ .ml_name = "initiate_upgrade_connection", .ml_meth = @ptrCast(&initiate_upgrade_connection), .ml_flags = c.METH_VARARGS | c.METH_KEYWORDS, .ml_doc = "Initialise an h2c-upgraded connection: initiate_upgrade_connection(method, target, headers, settings_header=None). Seeds the already-parsed HTTP/1.1 request as stream 1 and applies the client's base64url HTTP2-Settings, returning the stream's Stream. Call on a fresh server connection before feeding the client's HTTP/2 preface; next_event() then yields the request." },
    .{ .ml_name = "stream", .ml_meth = stream, .ml_flags = c.METH_O, .ml_doc = "Return a Stream handle for stream_id. The connection owns the stream state; the handle is a stream-scoped command surface (send_response / send_data / end_message)." },
    .{ .ml_name = "close", .ml_meth = h2_close, .ml_flags = c.METH_VARARGS, .ml_doc = "Send GOAWAY to shut the connection down: close(error_code=NO_ERROR, last_stream_id=None). last_stream_id defaults to the highest peer stream processed." },
    .{ .ml_name = "has_pending_send", .ml_meth = h2_has_pending_send, .ml_flags = c.METH_NOARGS, .ml_doc = "Whether any stream still has body bytes (or a FIN) parked waiting for the send window." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

var h2_getset = [_]c.PyGetSetDef{
    .{ .name = "send_window", .get = h2_send_window_get, .set = null, .doc = "The connection-level send window: body bytes that may leave across all streams before a WINDOW_UPDATE (may be negative after a SETTINGS shrink).", .closure = null },
    .{ .name = null, .get = null, .set = null, .doc = null, .closure = null },
};

// HTTP/3: fed by UDP datagrams rather than a byte stream. The QUIC transport and
// HTTP/3 engine are built lazily on the first datagram; the handshake is driven from
// the server config supplied at construction. Sends go through a Stream handle
// (conn.stream(id)), exactly like HTTP/2 - the one multiplexed write surface.
// Outgoing datagrams (handshake flight, ACKs, responses) drain through the inherited
// data_to_send. `now` is the integrator's monotonic clock, in the same unit it later
// feeds handle_timeout; a Stream send uses the most recent `now` the caller gave.
var h3_methods = [_]py.MethodDef{
    .{ .ml_name = "receive_datagram", .ml_meth = receive_datagram, .ml_flags = c.METH_VARARGS, .ml_doc = "Feed one received UDP datagram: receive_datagram(datagram, now=0)." },
    .{ .ml_name = "stream", .ml_meth = stream, .ml_flags = c.METH_O, .ml_doc = "Return a Stream handle for stream_id (the request's stream_id). The handle is the stream-scoped send surface: send_response / send_data / end_message." },
    .{ .ml_name = "next_timeout", .ml_meth = h3_next_timeout, .ml_flags = c.METH_NOARGS, .ml_doc = "The next loss/PTO deadline (same clock as now), or None if no timer is armed." },
    .{ .ml_name = "handle_timeout", .ml_meth = h3_handle_timeout, .ml_flags = c.METH_O, .ml_doc = "Fire the timer at time now: handle_timeout(now). Re-queues probes; drain them with data_to_send." },
    .{ .ml_name = "initiate_connection", .ml_meth = h3_initiate, .ml_flags = c.METH_NOARGS, .ml_doc = "Open the control stream and send SETTINGS now (RFC 9114 6.2.1), rather than lazily on the first response. Idempotent. Drain it with data_to_send." },
    .{ .ml_name = "is_closed", .ml_meth = h3_is_closed, .ml_flags = c.METH_NOARGS, .ml_doc = "Whether the connection has been closed (a peer CONNECTION_CLOSE was received)." },
    .{ .ml_name = "close_info", .ml_meth = h3_close_info, .ml_flags = c.METH_NOARGS, .ml_doc = "The peer's CONNECTION_CLOSE as (error_code, reason, is_application), or None if the peer has not closed." },
    .{ .ml_name = "peer_settings", .ml_meth = h3_peer_settings, .ml_flags = c.METH_NOARGS, .ml_doc = "The peer's HTTP/3 SETTINGS as a dict (max_field_section_size, qpack_max_table_capacity, qpack_blocked_streams), or None until its SETTINGS frame has been received." },
    .{ .ml_name = "shutdown", .ml_meth = h3_shutdown, .ml_flags = c.METH_O, .ml_doc = "Begin a graceful shutdown: send a GOAWAY announcing stream_id as the first request stream not processed (RFC 9114 5.2). A later GOAWAY may only lower the id. Drain it with data_to_send." },
    .{ .ml_name = "goaway_received", .ml_meth = h3_goaway_received, .ml_flags = c.METH_NOARGS, .ml_doc = "The id of a GOAWAY received from the peer (RFC 9114 5.2), or None - the peer is shutting down and will not process streams at or above this id." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

var base_slots = [_]py.Slot{
    .{ .slot = c.Py_tp_new, .pfunc = @ptrCast(@constCast(&new_base)) },
    .{ .slot = c.Py_tp_dealloc, .pfunc = @ptrCast(@constCast(&dealloc)) },
    .{ .slot = c.Py_tp_methods, .pfunc = @ptrCast(&base_methods) },
    .{ .slot = 0, .pfunc = null },
};

var h1_slots = [_]py.Slot{
    .{ .slot = c.Py_tp_new, .pfunc = @ptrCast(@constCast(&new_h1)) },
    .{ .slot = c.Py_tp_methods, .pfunc = @ptrCast(&h1_methods) },
    .{ .slot = 0, .pfunc = null },
};

var h2_slots = [_]py.Slot{
    .{ .slot = c.Py_tp_new, .pfunc = @ptrCast(@constCast(&new_h2)) },
    .{ .slot = c.Py_tp_methods, .pfunc = @ptrCast(&h2_methods) },
    .{ .slot = c.Py_tp_getset, .pfunc = @ptrCast(&h2_getset) },
    .{ .slot = 0, .pfunc = null },
};

var h3_slots = [_]py.Slot{
    .{ .slot = c.Py_tp_new, .pfunc = @ptrCast(@constCast(&new_h3)) },
    .{ .slot = c.Py_tp_methods, .pfunc = @ptrCast(&h3_methods) },
    .{ .slot = 0, .pfunc = null },
};

var base_spec = py.Spec{
    .name = "zttp.Connection",
    .basicsize = @sizeOf(ConnectionObject),
    .itemsize = 0,
    .flags = c.Py_TPFLAGS_DEFAULT | c.Py_TPFLAGS_BASETYPE,
    .slots = &base_slots,
};

var h1_spec = py.Spec{
    .name = "zttp.H1Connection",
    .basicsize = @sizeOf(ConnectionObject),
    .itemsize = 0,
    .flags = c.Py_TPFLAGS_DEFAULT,
    .slots = &h1_slots,
};

var h2_spec = py.Spec{
    .name = "zttp.H2Connection",
    .basicsize = @sizeOf(ConnectionObject),
    .itemsize = 0,
    .flags = c.Py_TPFLAGS_DEFAULT,
    .slots = &h2_slots,
};

var h3_spec = py.Spec{
    .name = "zttp.H3Connection",
    .basicsize = @sizeOf(ConnectionObject),
    .itemsize = 0,
    .flags = c.Py_TPFLAGS_DEFAULT,
    .slots = &h3_slots,
};

pub fn register(module: py.Object) bool {
    connection_type = py.typeFromSpec(&base_spec);
    if (connection_type == null) return false;
    h1_connection_type = py.typeFromSpecWithBase(&h1_spec, connection_type);
    if (h1_connection_type == null) return false;
    h2_connection_type = py.typeFromSpecWithBase(&h2_spec, connection_type);
    if (h2_connection_type == null) return false;
    h3_connection_type = py.typeFromSpecWithBase(&h3_spec, connection_type);
    if (h3_connection_type == null) return false;
    stream_type = py.typeFromSpec(&stream_spec);
    if (stream_type == null) return false;
    _ = c.PyModule_AddObjectRef(module, "Connection", connection_type);
    _ = c.PyModule_AddObjectRef(module, "H1Connection", h1_connection_type);
    _ = c.PyModule_AddObjectRef(module, "H2Connection", h2_connection_type);
    _ = c.PyModule_AddObjectRef(module, "H3Connection", h3_connection_type);
    _ = c.PyModule_AddObjectRef(module, "Stream", stream_type);
    _ = c.PyModule_AddIntConstant(module, "SERVER", SERVER);
    _ = c.PyModule_AddIntConstant(module, "CLIENT", CLIENT);
    _ = c.PyModule_AddIntConstant(module, "HTTP1", HTTP1);
    _ = c.PyModule_AddIntConstant(module, "HTTP2", HTTP2);
    _ = c.PyModule_AddIntConstant(module, "HTTP3", HTTP3);
    return true;
}
