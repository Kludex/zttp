//! The Python `Connection` object: a thin wrapper over the core engine exposing
//! the sans-IO pull API. `receive_data(buffer)` appends to the parse buffer;
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
const TransportParameterConfiguration = core.quic.transport_params.Configuration;
const H3Connection = core.h3.connection.Connection;
const FlightConfig = core.quic.tls.flight.Config;
const ResumptionCredential = core.quic.tls.flight.ResumptionCredential;
const tls_sign = core.quic.tls.sign;
const Signer = tls_sign.Signer;

const gpa = std.heap.c_allocator;

const SERVER: c_long = 1;
const CLIENT: c_long = 2;
const HTTP1: c_long = 1;
const HTTP2: c_long = 2;
const HTTP3: c_long = 3;
const MAX_SERVER_TICKET_STORE: usize = 64;
const DEFAULT_SERVER_TRANSPORT_PARAMS = [_]u8{
    0x04, 0x04, 0x80, 0x10, 0x00, 0x00, // initial_max_data = 1048576
    0x08, 0x01, 0x08, // initial_max_streams_bidi = 8
    0x09, 0x01, 0x08, // initial_max_streams_uni = 8
    0x06, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_bidi_remote = 262144
    0x07, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_uni = 262144
};
const DEFAULT_CLIENT_TRANSPORT_PARAMS = [_]u8{
    0x04, 0x04, 0x80, 0x01, 0x00, 0x00, // initial_max_data = 65536
    0x05, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_bidi_local = 262144
    0x06, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_bidi_remote = 262144
    0x07, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_uni = 262144
    0x08, 0x01, 0x10, // initial_max_streams_bidi = 16
    0x09, 0x01, 0x10, // initial_max_streams_uni = 16
};

// Fixed backing keeps per-handshake slices valid while tickets rotate.
var server_ticket_store: [MAX_SERVER_TICKET_STORE]ResumptionCredential = undefined;
var server_ticket_store_len: usize = 0;
var module_lock_object: py.Object = null;

fn serverTickets() []ResumptionCredential {
    return server_ticket_store[0..server_ticket_store_len];
}

/// A Python-owned receive span retained outside the pure-Zig reader. Keeping
/// the owner and slice behind one adapter state centralises every reference
/// transition without adding a union tag to each connection.
const PendingInput = struct {
    owner: py.Object = null,
    bytes: []const u8 = &.{},

    const retain_body_min = 512;

    inline fn retain(self: *PendingInput, reader: *Reader, owner: py.Object, bytes: []const u8) core.errors.ParseError!void {
        std.debug.assert(owner != null);
        std.debug.assert(bytes.len > 0);
        std.debug.assert(self.owner == null);
        std.debug.assert(self.bytes.len == 0);
        try reader.checkBufferLimit(bytes.len);
        py.incref(owner);
        self.owner = owner;
        self.bytes = bytes;
    }

    inline fn clear(self: *PendingInput) void {
        std.debug.assert((self.owner != null) == (self.bytes.len != 0));
        py.xdecref(self.owner);
        self.owner = null;
        self.bytes = &.{};
    }

    inline fn hasData(self: *const PendingInput) bool {
        std.debug.assert((self.owner != null) == (self.bytes.len != 0));
        return self.owner != null;
    }

    /// Move the retained span into the reader's owned buffer. The reference is
    /// released whether the feed succeeds or fails.
    inline fn flushInto(self: *PendingInput, reader: *Reader) core.errors.ParseError!void {
        if (self.owner == null) return;
        defer self.clear();
        try reader.feed(self.bytes);
    }

    /// Emit the next Content-Length body span directly from its Python owner.
    /// The caller has established that the reader backlog is empty and a body
    /// remainder exists.
    inline fn emitBody(self: *PendingInput, reader: *Reader) py.Object {
        std.debug.assert(self.owner != null);
        std.debug.assert(self.bytes.len != 0);
        const rem = reader.bodyLengthRemaining().?;
        const take: usize = @intCast(@min(rem, @as(u64, self.bytes.len)));
        const can_retain = if (take >= retain_body_min) blk: {
            const owned = py.asBytes(self.owner).?;
            break :blk take == self.bytes.len and
                self.bytes.ptr == owned.ptr and
                self.bytes.len == owned.len;
        } else false;
        const out = if (can_retain)
            events_obj.makeH1DataFromBytes(self.owner)
        else
            events_obj.fromH1Event(.{ .data = .{ .data = self.bytes[0..take] } });
        if (out == null) return null;

        reader.skipBodyLength(take);
        if (take == self.bytes.len) {
            self.clear();
        } else {
            self.bytes = self.bytes[take..];
        }
        if (self.owner != null and reader.bodyLengthRemaining() == null) {
            // The remainder belongs to the next pipelined message.
            self.flushInto(reader) catch |err| {
                py.decref(out);
                return exceptions.raiseParse(err);
            };
        }
        return out;
    }

    inline fn deinit(self: *PendingInput) void {
        self.clear();
    }
};

/// Per-message HTTP/1 adapter state. The request method is retained across an
/// early start_next_cycle so a delayed response still gets HEAD/CONNECT
/// framing, while `active_this_cycle` distinguishes that owed response from a
/// stale method when the next request head fails. Connection signals are copied
/// here at head-event time because the reader's snapshot borrows its buffer.
const H1MessageContext = struct {
    response_method: [16]u8 = undefined,
    response_method_len: usize = 0,
    active_this_cycle: bool = false,
    should_close: bool = false,
    upgrade_obj: py.Object = null,

    inline fn rememberRequest(self: *H1MessageContext, method: []const u8) void {
        self.active_this_cycle = true;
        if (method.len > self.response_method.len) {
            self.response_method_len = 0;
            return;
        }
        @memcpy(self.response_method[0..method.len], method);
        self.response_method_len = method.len;
    }

    inline fn framingMethod(self: *const H1MessageContext) []const u8 {
        return self.response_method[0..self.response_method_len];
    }

    inline fn captureRequest(self: *H1MessageContext, method: []const u8, info: core.h1.reader.HeadInfo) bool {
        self.rememberRequest(method);
        self.should_close = info.should_close;
        py.xdecref(self.upgrade_obj);
        self.upgrade_obj = if (info.upgrade) |value| py.fromBytes(value) else null;
        return info.upgrade == null or self.upgrade_obj != null;
    }

    inline fn captureResponse(self: *H1MessageContext, info: core.h1.reader.HeadInfo) void {
        // A client that asked to close already set the flag when it serialized
        // the request; an omitted response token does not take that back.
        self.should_close = self.should_close or info.should_close;
    }

    inline fn parseFailed(self: *H1MessageContext) void {
        if (!self.active_this_cycle) self.response_method_len = 0;
    }

    fn startNextCycle(self: *H1MessageContext) void {
        self.active_this_cycle = false;
        // Keep response_method: callers may start the next read cycle before
        // serializing the response to the request they just received.
        self.should_close = false;
        py.xdecref(self.upgrade_obj);
        self.upgrade_obj = null;
    }

    fn deinit(self: *H1MessageContext) void {
        py.xdecref(self.upgrade_obj);
    }
};

fn randomBytes(comptime len: usize) ?[len]u8 {
    var out: [len]u8 = undefined;
    const os = c.PyImport_ImportModule("os") orelse return null;
    defer py.decref(os);
    const bytes_obj = c.PyObject_CallMethod(os, "urandom", "n", @as(c.Py_ssize_t, @intCast(len))) orelse return null;
    defer py.decref(bytes_obj);
    const src = py.asBytes(bytes_obj) orelse return null;
    if (src.len != len) {
        _ = py.raiseRuntime("os.urandom returned an unexpected number of bytes");
        return null;
    }
    @memcpy(out[0..], src);
    return out;
}

fn optionalBytes(obj: ?*c.PyObject, default: []const u8) ?[]const u8 {
    if (obj == null or py.isNone(obj)) return default;
    return py.asBytes(obj);
}

fn readTransportInteger(dict: py.Object, key: [*c]const u8, target: *?u64, found: *usize) bool {
    const value = c.PyDict_GetItemString(dict, key) orelse return true;
    found.* += 1;
    if (@intFromPtr(c.Py_TYPE(value)) != @intFromPtr(py.data("PyLong_Type"))) {
        _ = py.raiseValue("transport parameter integer values must be non-negative integers");
        return false;
    }
    const parsed = c.PyLong_AsUnsignedLongLong(value);
    if (parsed == std.math.maxInt(c_ulonglong) and c.PyErr_Occurred() != null) {
        c.PyErr_Clear();
        _ = py.raiseValue("transport parameter integer values must fit in an unsigned 64-bit integer");
        return false;
    }
    target.* = @intCast(parsed);
    return true;
}

fn transportParameters(
    obj: ?*c.PyObject,
    role: c_long,
    encoded: *std.ArrayListUnmanaged(u8),
) ?[]const u8 {
    if (obj == null or py.isNone(obj)) {
        return if (role == SERVER) &DEFAULT_SERVER_TRANSPORT_PARAMS else &DEFAULT_CLIENT_TRANSPORT_PARAMS;
    }

    const is_dict = c.PyObject_IsInstance(obj, @ptrCast(py.data("PyDict_Type")));
    if (is_dict < 0) return null;
    if (is_dict == 0) {
        _ = py.raiseType("transport_params must be a QuicTransportParameters dictionary");
        return null;
    }

    var configuration: TransportParameterConfiguration = if (role == SERVER)
        .{
            .initial_max_data = 1048576,
            .initial_max_stream_data_bidi_remote = 262144,
            .initial_max_stream_data_uni = 262144,
            .initial_max_streams_bidi = 8,
            .initial_max_streams_uni = 8,
        }
    else
        .{
            .initial_max_data = 65536,
            .initial_max_stream_data_bidi_local = 262144,
            .initial_max_stream_data_bidi_remote = 262144,
            .initial_max_stream_data_uni = 262144,
            .initial_max_streams_bidi = 16,
            .initial_max_streams_uni = 16,
        };
    var found: usize = 0;
    if (!readTransportInteger(obj, "max_idle_timeout", &configuration.max_idle_timeout, &found)) return null;
    if (!readTransportInteger(obj, "max_udp_payload_size", &configuration.max_udp_payload_size, &found)) return null;
    if (!readTransportInteger(obj, "initial_max_data", &configuration.initial_max_data, &found)) return null;
    if (!readTransportInteger(
        obj,
        "initial_max_stream_data_bidi_local",
        &configuration.initial_max_stream_data_bidi_local,
        &found,
    )) return null;
    if (!readTransportInteger(
        obj,
        "initial_max_stream_data_bidi_remote",
        &configuration.initial_max_stream_data_bidi_remote,
        &found,
    )) return null;
    if (!readTransportInteger(
        obj,
        "initial_max_stream_data_uni",
        &configuration.initial_max_stream_data_uni,
        &found,
    )) return null;
    if (!readTransportInteger(
        obj,
        "initial_max_streams_bidi",
        &configuration.initial_max_streams_bidi,
        &found,
    )) return null;
    if (!readTransportInteger(
        obj,
        "initial_max_streams_uni",
        &configuration.initial_max_streams_uni,
        &found,
    )) return null;
    if (!readTransportInteger(obj, "ack_delay_exponent", &configuration.ack_delay_exponent, &found)) return null;
    if (!readTransportInteger(obj, "max_ack_delay", &configuration.max_ack_delay, &found)) return null;
    if (!readTransportInteger(
        obj,
        "active_connection_id_limit",
        &configuration.active_connection_id_limit,
        &found,
    )) return null;

    if (c.PyDict_GetItemString(obj, "stateless_reset_token")) |value| {
        found += 1;
        if (role == CLIENT) {
            _ = py.raiseValue("stateless_reset_token is only valid for HTTP/3 servers");
            return null;
        }
        const token = py.asBytes(value) orelse return null;
        if (token.len != 16) {
            _ = py.raiseValue("stateless_reset_token must be exactly 16 bytes");
            return null;
        }
        configuration.stateless_reset_token = token[0..16].*;
    }
    if (c.PyDict_GetItemString(obj, "disable_active_migration")) |value| {
        found += 1;
        if (value != c.Py_True() and value != c.Py_False()) {
            _ = py.raiseValue("disable_active_migration must be a bool");
            return null;
        }
        configuration.disable_active_migration = value == c.Py_True();
    }
    if (found != @as(usize, @intCast(c.PyDict_Size(obj)))) {
        _ = py.raiseValue("transport_params contains an unknown field");
        return null;
    }

    core.quic.transport_params.encodeConfiguration(encoded, gpa, configuration) catch |err| switch (err) {
        error.OutOfMemory => {
            _ = c.PyErr_NoMemory();
            return null;
        },
        error.Malformed => {
            _ = py.raiseValue("transport_params contains a value outside the QUIC range");
            return null;
        },
    };
    return encoded.items;
}

fn optionalBytes32(obj: ?*c.PyObject, msg: [*c]const u8) ?[32]u8 {
    if (obj == null or py.isNone(obj)) return randomBytes(32) orelse return null;
    const src = py.asBytes(obj) orelse return null;
    if (src.len != 32) {
        _ = py.raiseValue(msg);
        return null;
    }
    return src[0..32].*;
}

const TlsCredentialObjects = struct {
    certificate: ?*c.PyObject = null,
    certificates: ?*c.PyObject = null,
    private_key: ?*c.PyObject = null,
    private_key_scalar: ?*c.PyObject = null,
};

fn parseTlsCredentials(obj: ?*c.PyObject) ?TlsCredentialObjects {
    if (obj == null or py.isNone(obj)) return .{};
    const is_dict = c.PyObject_IsInstance(obj, @ptrCast(py.data("PyDict_Type")));
    if (is_dict < 0) return null;
    if (is_dict == 0) {
        _ = py.raiseType("credentials must be a TlsCredentials dictionary");
        return null;
    }

    const certificate = c.PyDict_GetItemString(obj, "certificate");
    const certificates = c.PyDict_GetItemString(obj, "certificates");
    const private_key = c.PyDict_GetItemString(obj, "private_key");
    const private_key_scalar = c.PyDict_GetItemString(obj, "private_key_scalar");
    if (private_key != null and private_key_scalar != null) {
        _ = py.raiseValue("pass either private_key or private_key_scalar, not both");
        return null;
    }
    if (private_key == null and private_key_scalar == null) {
        _ = py.raiseType("credentials must include private_key or private_key_scalar");
        return null;
    }
    if (certificate != null and certificates != null) {
        _ = py.raiseValue("pass either certificate or certificates, not both");
        return null;
    }
    if (certificate == null and certificates == null) {
        _ = py.raiseValue("credentials must include certificate or certificates");
        return null;
    }
    if (c.PyDict_Size(obj) != 2) {
        _ = py.raiseValue("credentials contains an unknown field");
        return null;
    }
    return .{
        .certificate = certificate,
        .certificates = certificates,
        .private_key = private_key,
        .private_key_scalar = private_key_scalar,
    };
}

fn randomSigner() ?Signer {
    var attempts: u8 = 0;
    while (attempts < 16) : (attempts += 1) {
        const seed = randomBytes(32) orelse return null;
        if (Signer.fromSeed(seed)) |signer| return signer else |_| continue;
    }
    _ = py.raiseRuntime("could not generate a valid HTTP/3 server signing key");
    return null;
}

fn rememberServerTicket(identity: []const u8, psk: [32]u8, lifetime: u32, age_add: u32, issued_at_ms: u64, max_early_data_size: ?u32) !void {
    if (lifetime == 0) return;
    var critical_section: py.CriticalSection = .{};
    critical_section.beginObject(module_lock_object);
    defer critical_section.end();
    for (serverTickets()) |*entry| {
        if (std.mem.eql(u8, entry.identity, identity)) {
            entry.psk = psk;
            entry.ticket_lifetime = lifetime;
            entry.ticket_age_add = age_add;
            entry.issued_at_ms = issued_at_ms;
            entry.max_early_data_size = max_early_data_size;
            entry.early_data_used = false;
            return;
        }
    }
    const owned_identity = try gpa.dupe(u8, identity);
    errdefer gpa.free(owned_identity);
    if (server_ticket_store_len == MAX_SERVER_TICKET_STORE) {
        const oldest = server_ticket_store[0];
        std.mem.copyForwards(
            ResumptionCredential,
            server_ticket_store[0 .. MAX_SERVER_TICKET_STORE - 1],
            server_ticket_store[1..MAX_SERVER_TICKET_STORE],
        );
        server_ticket_store_len -= 1;
        gpa.free(oldest.identity);
    }
    server_ticket_store[server_ticket_store_len] = .{
        .identity = owned_identity,
        .psk = psk,
        .ticket_lifetime = lifetime,
        .ticket_age_add = age_add,
        .issued_at_ms = issued_at_ms,
        .max_early_data_size = max_early_data_size,
    };
    server_ticket_store_len += 1;
}

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
    message: H1MessageContext = .{},
    /// Single-copy body path: retains a Python-owned Content-Length body span
    /// outside the reader until next_event can materialise it directly.
    pending: PendingInput = .{},

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

    /// Feeds smaller than this take the plain buffered path: the head-split
    /// scan below costs one extra pass over the head, which only pays for
    /// itself when a sizeable body follows.
    const head_split_min_feed = 1024;

    fn feedData(self: *H1Engine, data: []const u8, stable_owner: py.Object) bool {
        self.pending.flushInto(&self.reader) catch |err| {
            _ = exceptions.raiseParse(err);
            return false;
        };
        if (data.len > 0 and self.reader.eofSeen()) {
            _ = exceptions.raiseParse(error.ProtocolError);
            return false;
        }
        if (stable_owner != null and data.len > 0 and self.reader.backlogEmpty()) {
            if (self.reader.bodyLengthRemaining() != null) {
                self.pending.retain(&self.reader, stable_owner, data) catch |err| {
                    _ = exceptions.raiseParse(err);
                    return false;
                };
                return true;
            }
            if (data.len >= head_split_min_feed and self.reader.atMessageStart()) {
                if (core.h1.reader.findHeadEnd(data)) |head_end| {
                    self.reader.checkBufferLimit(data.len) catch |err| {
                        _ = exceptions.raiseParse(err);
                        return false;
                    };
                    self.reader.feed(data[0..head_end]) catch |err| {
                        _ = exceptions.raiseParse(err);
                        return false;
                    };
                    if (head_end < data.len) self.pending.retain(&self.reader, stable_owner, data[head_end..]) catch |err| {
                        _ = exceptions.raiseParse(err);
                        return false;
                    };
                    return true;
                }
            }
        }
        self.reader.feed(data) catch |err| {
            _ = exceptions.raiseParse(err);
            return false;
        };
        return true;
    }

    fn receiveData(self: *H1Engine, data: []const u8, stable_owner: py.Object) py.Object {
        return if (self.feedData(data, stable_owner)) py.none() else null;
    }

    fn deinit(self: *H1Engine) void {
        self.reader.deinit();
        if (self.writer) |w| {
            w.deinit();
            gpa.destroy(w);
        }
        self.message.deinit();
        self.pending.deinit();
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
        const authority = h2SplitAuthority(hdrs.headers, &regular) catch {
            _ = py.raise(exceptions.LocalProtocolError, "conflicting host and :authority headers");
            return null;
        };
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
        const authority = h2SplitAuthority(hdrs.headers, &regular) catch {
            _ = py.raise(exceptions.LocalProtocolError, "conflicting host and :authority headers");
            return false;
        };
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
        self.writer.sendGoAway(last, @enumFromInt(code), &.{}) catch |e| return h2RaiseWrite(e);
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
    fn emitGoAwayIfOwed(self: *H2Engine) void {
        if (self.conn.takeGoAwayOwed()) |code| {
            if (!self.handshake_sent) {
                self.sendOurPreface() catch return;
                self.handshake_sent = true;
            }
            self.writer.sendGoAway(self.conn.lastPeerStreamId(), code, &.{}) catch {};
        }
    }

    fn deinit(self: *H2Engine) void {
        self.conn.deinit();
        gpa.destroy(self.conn);
        self.writer.deinit();
        gpa.destroy(self.writer);
    }
};

/// The server TLS material the QUIC handshake needs: certificate, signing key,
/// transport parameters, selected ALPN, and per-connection entropy. zttp generates
/// ephemeral credentials for the simple `Connection(SERVER, protocol=HTTP3)` case,
/// while callers can still override them for interop and deterministic tests.
/// The bytes are copied so they outlive the Python args. `signer` is derived from
/// the 32-byte key seed once, up front, so a bad key is rejected at construction.
const ServerConfig = struct {
    certificates: [][]u8,
    transport_params: []u8,
    alpn: ?[]u8,
    resumption_identity: ?[]u8 = null,
    resumption_psk: ?[32]u8 = null,
    signer: Signer,
    random: [32]u8,
    ephemeral_seed: [32]u8,

    fn deinit(self: *ServerConfig) void {
        for (self.certificates) |certificate| gpa.free(certificate);
        gpa.free(self.certificates);
        gpa.free(self.transport_params);
        if (self.alpn) |a| gpa.free(a);
        if (self.resumption_identity) |id| gpa.free(id);
    }

    fn flightConfig(self: *const ServerConfig, now: u64) FlightConfig {
        return .{
            .random = self.random,
            .ephemeral_seed = self.ephemeral_seed,
            .signer = self.signer,
            .cert_chain = self.certificates[0],
            .certificates = self.certificates,
            .alpn = self.alpn,
            .transport_params = self.transport_params,
            .resumption = if (self.resumption_identity) |identity| .{ .identity = identity, .psk = self.resumption_psk.? } else null,
            .resumption_store = serverTickets(),
            .now_ms = now / std.time.us_per_ms,
        };
    }
};

/// The HTTP/3 engine. A server builds QUIC/H3 lazily on the first datagram because
/// the client's Initial supplies the connection id. A client builds QUIC/H3 eagerly
/// at construction because it chooses the connection id and immediately emits its
/// first Initial.
const H3Engine = struct {
    config: ?ServerConfig = null,
    qc: ?*QuicConnection = null,
    h3: ?*H3Connection = null,
    endpoint_server_cid: ?[]u8 = null,
    retry_original_dcid: ?[]u8 = null,
    endpoint_address_validated: bool = false,
    /// The integrator's clock at the last receive_datagram / handle_timeout. A Stream
    /// send does not carry its own `now` (the API matches H2's, which has no clock),
    /// so it packetises against the most recent time the caller gave us.
    now: u64 = 0,

    fn needsTicketStore(self: *const H3Engine) bool {
        const q = self.qc orelse return self.config != null;
        const tls = q.tls orelse return false;
        return tls.state == .wait_client_hello;
    }

    fn receiveDatagram(self: *H3Engine, dgram: []const u8, now: u64, peer_address: ?[]const u8) py.Object {
        if (self.h3) |h| {
            if (h.eventQueueFull()) {
                return py.raise(
                    exceptions.LocalProtocolError,
                    "drain pending HTTP/3 events before receiving more data",
                );
            }
        }
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
            const cfg = self.config orelse return py.raise(exceptions.LocalProtocolError, "this HTTP/3 connection has no server configuration");
            const q = gpa.create(QuicConnection) catch return c.PyErr_NoMemory();
            q.* = (if (self.endpoint_server_cid) |server_cid|
                if (self.retry_original_dcid) |original_dcid|
                    QuicConnection.initServerAfterRetry(gpa, original_dcid, server_cid, cfg.flightConfig(now))
                else
                    QuicConnection.initServerWithCid(gpa, hdr.dcid, server_cid, cfg.flightConfig(now))
            else
                QuicConnection.initServer(gpa, hdr.dcid, cfg.flightConfig(now))) catch |e| {
                gpa.destroy(q);
                return exceptions.raiseQuic(e);
            };
            const h = gpa.create(H3Connection) catch {
                q.deinit();
                gpa.destroy(q);
                return c.PyErr_NoMemory();
            };
            if (self.endpoint_address_validated) q.markAddressValidated();
            h.* = H3Connection.init(gpa, q);
            self.qc = q;
            self.h3 = h;
        }

        if (peer_address) |addr| {
            self.qc.?.receiveDatagramFrom(dgram, now, addr) catch |e| return exceptions.raiseQuic(e);
        } else {
            self.qc.?.receiveDatagram(dgram, now) catch |e| return exceptions.raiseQuic(e);
        }
        self.h3.?.pumpStreams(self.qc.?.changedStreamIds()) catch |e| return exceptions.raiseH3(e);
        return py.none();
    }

    fn setEndpointContext(
        self: *H3Engine,
        server_cid: []const u8,
        original_dcid: ?[]const u8,
        address_validated: bool,
    ) py.Object {
        if (self.config == null or self.qc != null or self.endpoint_server_cid != null) {
            return py.raise(exceptions.LocalProtocolError, "endpoint context requires a fresh HTTP/3 server connection");
        }
        if (server_cid.len == 0 or server_cid.len > core.quic.constants.MAX_CID_LEN) {
            return py.raiseValue("server_connection_id must be 1..20 bytes");
        }
        if (original_dcid) |cid| {
            if (cid.len < 8 or cid.len > core.quic.constants.MAX_CID_LEN) {
                return py.raiseValue("original_destination_connection_id must be 8..20 bytes");
            }
        }
        const owned_server_cid = gpa.dupe(u8, server_cid) catch return c.PyErr_NoMemory();
        const owned_original_dcid = if (original_dcid) |cid|
            gpa.dupe(u8, cid) catch {
                gpa.free(owned_server_cid);
                return c.PyErr_NoMemory();
            }
        else
            null;
        self.endpoint_server_cid = owned_server_cid;
        self.retry_original_dcid = owned_original_dcid;
        self.endpoint_address_validated = address_validated;
        return py.none();
    }

    fn endpointReady(self: *const H3Engine) py.Object {
        return py.boolean(if (self.qc) |q| q.hasAuthenticatedInitial() else false);
    }

    fn endpointConnectionIdGeneration(self: *const H3Engine) py.Object {
        const q = self.qc orelse return c.PyLong_FromUnsignedLongLong(0);
        return c.PyLong_FromUnsignedLongLong(q.localConnectionIdGeneration());
    }

    fn endpointPeerAddress(self: *const H3Engine) py.Object {
        const q = self.qc orelse return py.none();
        const address = q.defaultPathAddress() orelse return py.none();
        return py.fromBytes(address);
    }

    fn nextEvent(self: *H3Engine) py.Object {
        const h = self.h3 orelse return py.newRef(events_obj.need_data); // no datagram fed yet
        return events_obj.fromH3Event(h.nextEvent());
    }

    fn consumeData(self: *H3Engine, id: u64, length: u64) py.Object {
        const h = self.h3 orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        h.consumeData(id, length) catch return py.raiseValue("unknown stream or length exceeds its unconsumed DATA");
        return self.flush();
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

    /// Like dataToSend, but preserves the optional address key associated with each
    /// QUIC datagram so integrators can route migration/path-validation traffic.
    fn dataToSendWithAddresses(self: *H3Engine) py.Object {
        const q = self.qc orelse return py.newList(0);
        const result_type = resultType(&outbound_datagram_type, "OutboundDatagram") orelse return null;
        if (!ensureOutboundNames()) return null;
        const flat = q.datagramsToSend();
        const lengths = q.datagramLengths();
        const tokens = q.datagramPathTokens();
        const list = py.newList(@intCast(lengths.len));
        if (list == null) return null;
        var off: usize = 0;
        for (lengths, 0..) |len, i| {
            const data = py.fromBytes(flat[off .. off + len]);
            if (data == null) {
                py.decref(list);
                return null;
            }
            const peer_address = if (tokens.len > i) blk: {
                if (tokens[i]) |token| {
                    const address = q.pathAddress(token) orelse break :blk py.none();
                    break :blk py.fromBytes(address);
                }
                break :blk py.none();
            } else py.none();
            if (peer_address == null) {
                py.decref(data);
                py.decref(list);
                return null;
            }
            const result = newOutboundDatagram(result_type, data, peer_address);
            if (result == null) {
                py.decref(list);
                return null;
            }
            py.listSet(list, @intCast(i), result);
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

    fn sendInformational(self: *H3Engine, id: u64, status: u16, headers: []const events.Header) py.Object {
        const h = self.h3 orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        h.sendInformational(id, status, headers) catch |e| return exceptions.raiseH3(e);
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

    fn endMessage(self: *H3Engine, id: u64, trailers: []const events.Header) py.Object {
        const h = self.h3 orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        if (trailers.len == 0) {
            h.endStream(id) catch |e| return exceptions.raiseH3(e);
        } else {
            h.sendTrailers(id, trailers) catch |e| return exceptions.raiseH3(e);
        }
        return self.flush();
    }

    fn sendTrailers(self: *H3Engine, id: u64, trailers: []const events.Header) py.Object {
        const h = self.h3 orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        h.sendTrailers(id, trailers) catch |e| return exceptions.raiseH3(e);
        return self.flush();
    }

    /// Cancel a request stream with `error_code` (RFC 9114 4.4): RESET_STREAM the
    /// response and STOP_SENDING the request, then packetise.
    fn resetStream(self: *H3Engine, id: u64, error_code: u64) py.Object {
        const h = self.h3 orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        h.resetStream(id, error_code) catch |e| return exceptions.raiseH3(e);
        return self.flush();
    }

    /// Begin a graceful shutdown: send a GOAWAY. Servers announce the first request
    /// stream they will not process; clients announce the first push ID they will not
    /// accept (RFC 9114 5.2), then packetise it.
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

    fn challengePath(self: *H3Engine, peer_address: []const u8, data: []const u8) py.Object {
        const q = self.qc orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        if (peer_address.len == 0) return py.raiseValue("peer_address must not be empty");
        if (data.len != 8) return py.raiseValue("path challenge data must be exactly 8 bytes");
        q.challengePathOn(data[0..8].*, peer_address) catch |e| return exceptions.raiseQuic(e);
        return self.flush();
    }

    fn usePeerConnectionId(self: *H3Engine, seq: u64) py.Object {
        const q = self.qc orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        q.usePeerConnectionId(seq) catch |e| switch (e) {
            error.OutOfMemory => return c.PyErr_NoMemory(),
            else => return py.raiseValue("unknown or retired peer connection id sequence"),
        };
        return py.none();
    }

    fn localConnectionIds(self: *const H3Engine) py.Object {
        const q = self.qc orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        const ids = gpa.alloc(core.quic.connection.LocalConnectionId, q.localConnectionIdCount()) catch return c.PyErr_NoMemory();
        defer gpa.free(ids);
        const count = q.localConnectionIds(ids);
        const result_type = resultType(&local_connection_id_type, "LocalConnectionId") orelse return null;
        const list = py.newList(@intCast(count));
        if (list == null) return null;
        for (ids[0..count], 0..) |id, index| {
            const tuple = py.tupleNew(2);
            if (tuple == null) {
                py.decref(list);
                return null;
            }
            const sequence = c.PyLong_FromUnsignedLongLong(id.sequence_number);
            const connection_id = py.fromBytes(id.connection_id);
            if (sequence == null or connection_id == null) {
                py.xdecref(sequence);
                py.xdecref(connection_id);
                py.decref(tuple);
                py.decref(list);
                return null;
            }
            py.tupleSet(tuple, 0, sequence);
            py.tupleSet(tuple, 1, connection_id);
            const value = c.PyObject_CallObject(result_type, tuple);
            py.decref(tuple);
            if (value == null) {
                py.decref(list);
                return null;
            }
            py.listSet(list, @intCast(index), value);
        }
        return list;
    }

    fn issueConnectionId(
        self: *H3Engine,
        seq: u64,
        cid: []const u8,
        token: []const u8,
        retire_prior_to: u64,
        endpoint: bool,
    ) py.Object {
        if (self.endpoint_server_cid != null and !endpoint) {
            return py.raise(exceptions.LocalProtocolError, "use QuicEndpoint.issue_connection_id() for this connection");
        }
        const q = self.qc orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        if (cid.len == 0 or cid.len > 20) return py.raiseValue("connection_id must be 1..20 bytes");
        if (token.len != 16) return py.raiseValue("stateless_reset_token must be exactly 16 bytes");
        q.issueLocalConnectionId(seq, retire_prior_to, cid, token[0..16].*) catch |e| switch (e) {
            error.OutOfMemory => return c.PyErr_NoMemory(),
            else => return py.raiseValue("invalid local connection id sequence, retire_prior_to, value, or active connection id limit"),
        };
        return self.flush();
    }

    fn requestKeyUpdate(self: *H3Engine) py.Object {
        const q = self.qc orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        q.updateApplicationSendKeys() catch |e| switch (e) {
            error.OutOfMemory => return c.PyErr_NoMemory(),
            else => return py.raise(exceptions.LocalProtocolError, "cannot request a key update before 1-RTT keys are available"),
        };
        return py.none();
    }

    /// Send a QUIC CONNECTION_CLOSE. By default this is an HTTP/3 application
    /// close; callers can request a transport close for QUIC transport errors.
    fn close(self: *H3Engine, app: bool, error_code: u64, reason: []const u8) py.Object {
        const q = self.qc orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        q.close(app, error_code, reason) catch |e| switch (e) {
            error.OutOfMemory => return c.PyErr_NoMemory(),
            else => return exceptions.raiseQuic(e),
        };
        return py.none();
    }

    fn sendSessionTicket(self: *H3Engine, lifetime: u32, age_add: u32, nonce: []const u8, ticket: []const u8, extensions: []const u8, max_early_data_size: ?u32) py.Object {
        const q = self.qc orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        const psk = q.sendSessionTicket(lifetime, age_add, nonce, ticket, extensions, max_early_data_size, self.now) catch |e| switch (e) {
            error.OutOfMemory => return c.PyErr_NoMemory(),
            else => return py.raise(exceptions.LocalProtocolError, "cannot send a TLS session ticket before the HTTP/3 server handshake is confirmed, or the ticket fields are invalid"),
        };
        if (psk) |value| {
            rememberServerTicket(ticket, value, lifetime, age_add, self.now / std.time.us_per_ms, max_early_data_size) catch return c.PyErr_NoMemory();
        }
        return if (psk) |value| py.fromBytes(&value) else py.none();
    }

    fn sendNewToken(self: *H3Engine, token: []const u8) py.Object {
        const q = self.qc orelse return py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
        q.sendNewToken(token, self.now) catch |e| switch (e) {
            error.OutOfMemory => return c.PyErr_NoMemory(),
            else => return py.raise(exceptions.LocalProtocolError, "cannot send a NEW_TOKEN before the HTTP/3 server handshake is confirmed, or the token is empty"),
        };
        return self.flush();
    }

    fn sessionTickets(self: *const H3Engine) py.Object {
        const q = self.qc orelse return py.newList(0);
        const st_type = resultType(&session_ticket_type, "SessionTicket") orelse return null;
        const tickets = q.sessionTickets();
        const list = py.newList(@intCast(tickets.len));
        if (list == null) return null;
        for (tickets, 0..) |ticket, i| {
            const tuple = py.tupleNew(7);
            if (tuple == null) {
                py.decref(list);
                return null;
            }
            const lifetime = c.PyLong_FromUnsignedLong(ticket.ticket_lifetime);
            const age_add = c.PyLong_FromUnsignedLong(ticket.ticket_age_add);
            const nonce = py.fromBytes(ticket.nonce);
            const data = py.fromBytes(ticket.ticket);
            const extensions = py.fromBytes(ticket.extensions);
            const max_early_data_size = if (ticket.max_early_data_size) |value| c.PyLong_FromUnsignedLong(value) else py.none();
            const psk = if (ticket.psk) |value| py.fromBytes(&value) else py.none();
            if (lifetime == null or age_add == null or nonce == null or data == null or extensions == null or max_early_data_size == null or psk == null) {
                py.xdecref(lifetime);
                py.xdecref(age_add);
                py.xdecref(nonce);
                py.xdecref(data);
                py.xdecref(extensions);
                py.xdecref(max_early_data_size);
                py.xdecref(psk);
                py.decref(tuple);
                py.decref(list);
                return null;
            }
            py.tupleSet(tuple, 0, lifetime);
            py.tupleSet(tuple, 1, age_add);
            py.tupleSet(tuple, 2, nonce);
            py.tupleSet(tuple, 3, data);
            py.tupleSet(tuple, 4, extensions);
            py.tupleSet(tuple, 5, max_early_data_size);
            py.tupleSet(tuple, 6, psk);
            const row = c.PyObject_CallObject(st_type, tuple);
            py.decref(tuple);
            if (row == null) {
                py.decref(list);
                return null;
            }
            py.listSet(list, @intCast(i), row);
        }
        return list;
    }

    fn validationTokens(self: *const H3Engine) py.Object {
        const q = self.qc orelse return py.newList(0);
        const tokens = q.validationTokens();
        const list = py.newList(@intCast(tokens.len));
        if (list == null) return null;
        for (tokens, 0..) |token, i| {
            const item = py.fromBytes(token);
            if (item == null) {
                py.decref(list);
                return null;
            }
            py.listSet(list, @intCast(i), item);
        }
        return list;
    }

    /// Serialize a client request head onto the next HTTP/3 request stream. This is
    /// only reachable once a client-side QUIC connection has been constructed; a
    /// server-side H3 object still reports local misuse.
    fn sendRequest(self: *H3Engine, method: []const u8, target: []const u8, hdrs: *BorrowedHeaders) ?u64 {
        const h = self.h3 orelse {
            _ = py.raise(exceptions.LocalProtocolError, "no datagram received yet: the HTTP/3 connection is not established");
            return null;
        };
        var regular: []events.Header = hdrs.headers;
        const authority = h2SplitAuthority(hdrs.headers, &regular) catch {
            _ = py.raise(exceptions.LocalProtocolError, "conflicting host and :authority headers");
            return null;
        };
        const id = h.sendRequest(method, target, "https", authority, regular, false) catch |e| {
            _ = h3RaiseLocal(e);
            return null;
        };
        const flushed = self.flush();
        if (flushed == null) return null;
        py.decref(flushed);
        return id;
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

    fn idleTimedOut(self: *const H3Engine) bool {
        const q = self.qc orelse return false;
        return q.idleTimedOut();
    }

    /// The id of a GOAWAY received from the peer (RFC 9114 5.2), or None - so an
    /// integrator learns the peer is shutting down and stops opening new streams.
    fn goawayReceived(self: *const H3Engine) py.Object {
        const h = self.h3 orelse return py.none();
        const id = h.goaway_recv orelse return py.none();
        return c.PyLong_FromUnsignedLongLong(id);
    }

    /// The peer's CONNECTION_CLOSE as a zttp.results.CloseInfo, or None if
    /// the peer has not sent one - so an integrator learns WHY the peer closed, not
    /// just that it did.
    fn closeInfo(self: *const H3Engine) py.Object {
        const q = self.qc orelse return py.none();
        const ci_type = resultType(&close_info_type, "CloseInfo") orelse return null;
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
        const row = c.PyObject_CallObject(ci_type, tuple);
        py.decref(tuple);
        return row;
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
        if (self.config) |*cfg| cfg.deinit();
        if (self.endpoint_server_cid) |cid| gpa.free(cid);
        if (self.retry_original_dcid) |cid| gpa.free(cid);
    }
};

const ResumptionCredentialArgs = struct {
    identity: []const u8,
    psk: [32]u8,
    obfuscated_ticket_age: u32 = 0,
    early_data: bool = false,
};

fn parseResumptionCredential(
    identity_obj: ?*c.PyObject,
    psk_obj: ?*c.PyObject,
    age_obj: ?*c.PyObject,
    early_obj: ?*c.PyObject,
) ?ResumptionCredentialArgs {
    const have_identity = identity_obj != null and !py.isNone(identity_obj);
    const have_psk = psk_obj != null and !py.isNone(psk_obj);
    if (!have_identity and !have_psk) {
        if (age_obj != null and !py.isNone(age_obj)) {
            _ = py.raiseValue("obfuscated_ticket_age requires resumption_identity and resumption_psk");
            return null;
        }
        if (early_obj != null and !py.isNone(early_obj)) {
            const early = c.PyObject_IsTrue(early_obj);
            if (early < 0) return null;
            if (early != 0) {
                _ = py.raiseValue("early_data requires resumption_identity and resumption_psk");
                return null;
            }
        }
        return null;
    }
    if (!have_identity or !have_psk) {
        _ = py.raiseValue("resumption_identity and resumption_psk must be provided together");
        return null;
    }
    const identity = py.asBytes(identity_obj) orelse return null;
    const psk_src = py.asBytes(psk_obj) orelse return null;
    if (identity.len == 0 or identity.len > 0xffff) {
        _ = py.raiseValue("resumption_identity must be 1..65535 bytes");
        return null;
    }
    if (psk_src.len != 32) {
        _ = py.raiseValue("resumption_psk must be exactly 32 bytes");
        return null;
    }

    var age: u32 = 0;
    if (age_obj != null and !py.isNone(age_obj)) {
        const value = c.PyLong_AsUnsignedLongLong(age_obj);
        if (value == @as(c_ulonglong, @bitCast(@as(c_longlong, -1))) and c.PyErr_Occurred() != null) return null;
        if (value > std.math.maxInt(u32)) {
            _ = py.raiseValue("obfuscated_ticket_age must fit in uint32");
            return null;
        }
        age = @intCast(value);
    }

    var early = false;
    if (early_obj != null and !py.isNone(early_obj)) {
        const value = c.PyObject_IsTrue(early_obj);
        if (value < 0) return null;
        early = value != 0;
    }

    return .{
        .identity = identity,
        .psk = psk_src[0..32].*,
        .obfuscated_ticket_age = age,
        .early_data = early,
    };
}

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
// The frozen dataclasses returned by session_tickets() / close_info(), defined in
// zttp/results.py and loaded lazily on first use (importing a sibling module during
// the extension's own init would race the package __init__). Cached for the process.
var session_ticket_type: py.Object = null;
var close_info_type: py.Object = null;
var datagram_header_type: py.Object = null;
var local_connection_id_type: py.Object = null;
var outbound_datagram_type: py.Object = null;
var outbound_data_name: py.Object = null;
var outbound_peer_address_name: py.Object = null;

/// Module-level `parse_datagram_header(datagram) -> DatagramHeader`: the routable
/// prefix of a received QUIC datagram, for demultiplexing a shared UDP socket onto
/// per-connection state without constructing a connection.
fn parse_datagram_header(_: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    var data = py.BorrowedBuffer.init(arg) orelse return null;
    defer data.deinit();
    const hdr = core.quic.packet.parseDatagramHeader(data.bytes) catch
        return py.raise(exceptions.RemoteProtocolError, "malformed QUIC packet header");
    const dh_type = resultType(&datagram_header_type, "DatagramHeader") orelse return null;
    const tuple = py.tupleNew(6);
    if (tuple == null) return null;
    const dcid = py.fromBytes(hdr.dcid);
    const scid = py.fromBytes(hdr.scid);
    const version = c.PyLong_FromUnsignedLong(hdr.version);
    const long = py.boolean(hdr.long);
    const initial = py.boolean(hdr.initial);
    const token = py.fromBytes(hdr.token);
    if (dcid == null or scid == null or version == null or long == null or initial == null or token == null) {
        py.xdecref(dcid);
        py.xdecref(scid);
        py.xdecref(version);
        py.xdecref(long);
        py.xdecref(initial);
        py.xdecref(token);
        py.decref(tuple);
        return null;
    }
    py.tupleSet(tuple, 0, dcid);
    py.tupleSet(tuple, 1, scid);
    py.tupleSet(tuple, 2, version);
    py.tupleSet(tuple, 3, long);
    py.tupleSet(tuple, 4, initial);
    py.tupleSet(tuple, 5, token);
    const row = c.PyObject_CallObject(dh_type, tuple);
    py.decref(tuple);
    return row;
}

fn build_version_negotiation(_: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    var client_destination_obj: ?*c.PyObject = null;
    var client_source_obj: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "OO", &client_destination_obj, &client_source_obj) == 0) return null;
    const client_destination = py.asBytes(client_destination_obj) orelse return null;
    const client_source = py.asBytes(client_source_obj) orelse return null;
    if (client_destination.len > core.quic.constants.MAX_CID_LEN or
        client_source.len > core.quic.constants.MAX_CID_LEN)
    {
        return py.raiseValue("connection IDs must be at most 20 bytes");
    }

    var packet: std.ArrayListUnmanaged(u8) = .empty;
    defer packet.deinit(gpa);
    core.quic.packet.writeVersionNegotiation(&packet, gpa, client_source, client_destination) catch
        return c.PyErr_NoMemory();
    return py.fromBytes(packet.items);
}

/// Build a QUIC v1 Retry packet without allocating connection state. The caller
/// creates and validates the opaque token, including any client-address binding.
fn build_retry(_: ?*c.PyObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
    var original_obj: ?*c.PyObject = null;
    var client_obj: ?*c.PyObject = null;
    var server_obj: ?*c.PyObject = null;
    var token_obj: ?*c.PyObject = null;
    var version: c_uint = core.quic.constants.VERSION_1;
    var kwlist = [_][*c]u8{
        @constCast("original_destination_connection_id"),
        @constCast("client_source_connection_id"),
        @constCast("server_source_connection_id"),
        @constCast("token"),
        @constCast("version"),
        null,
    };
    if (c.PyArg_ParseTupleAndKeywords(
        args,
        kwds,
        "OOOO|I",
        @ptrCast(&kwlist),
        &original_obj,
        &client_obj,
        &server_obj,
        &token_obj,
        &version,
    ) == 0) return null;

    const original = py.asBytes(original_obj) orelse return null;
    const client = py.asBytes(client_obj) orelse return null;
    const server = py.asBytes(server_obj) orelse return null;
    const token = py.asBytes(token_obj) orelse return null;
    if (version != core.quic.constants.VERSION_1) return py.raiseValue("only QUIC version 1 Retry packets are supported");
    if (original.len < 8 or original.len > core.quic.constants.MAX_CID_LEN) {
        return py.raiseValue("original_destination_connection_id must be 8..20 bytes");
    }
    if (client.len > core.quic.constants.MAX_CID_LEN) {
        return py.raiseValue("client_source_connection_id must be at most 20 bytes");
    }
    if (server.len == 0 or server.len > core.quic.constants.MAX_CID_LEN) {
        return py.raiseValue("server_source_connection_id must be 1..20 bytes");
    }
    if (token.len == 0) return py.raiseValue("token must not be empty");

    var packet: std.ArrayListUnmanaged(u8) = .empty;
    defer packet.deinit(gpa);
    core.quic.packet.writeRetry(&packet, gpa, client, server, token, original) catch return c.PyErr_NoMemory();
    return py.fromBytes(packet.items);
}

pub var module_methods = [_]c.PyMethodDef{
    .{ .ml_name = "parse_datagram_header", .ml_meth = parse_datagram_header, .ml_flags = c.METH_O, .ml_doc = "Parse the routable prefix of a received QUIC datagram: parse_datagram_header(datagram) -> DatagramHeader. Reads no connection state; for demultiplexing a shared UDP socket by connection id." },
    .{ .ml_name = "_build_version_negotiation", .ml_meth = build_version_negotiation, .ml_flags = c.METH_VARARGS, .ml_doc = "Build a stateless QUIC Version Negotiation packet for QuicEndpoint." },
    .{ .ml_name = "_build_retry", .ml_meth = @ptrCast(&build_retry), .ml_flags = c.METH_VARARGS | c.METH_KEYWORDS, .ml_doc = "Build a stateless QUIC v1 Retry packet for QuicEndpoint." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

fn ensureOutboundNames() bool {
    var critical_section: py.CriticalSection = .{};
    critical_section.beginObject(module_lock_object);
    defer critical_section.end();
    if (outbound_data_name == null) outbound_data_name = c.PyUnicode_InternFromString("data");
    if (outbound_peer_address_name == null) {
        outbound_peer_address_name = c.PyUnicode_InternFromString("peer_address");
    }
    return outbound_data_name != null and outbound_peer_address_name != null;
}

fn newOutboundDatagram(result_type: py.Object, data: py.Object, peer_address: py.Object) py.Object {
    const result = py.allocInstance(result_type);
    if (result == null) {
        py.decref(data);
        py.decref(peer_address);
        return null;
    }
    if (c.PyObject_GenericSetAttr(result, outbound_data_name, data) < 0 or
        c.PyObject_GenericSetAttr(result, outbound_peer_address_name, peer_address) < 0)
    {
        py.decref(data);
        py.decref(peer_address);
        py.decref(result);
        return null;
    }
    py.decref(data);
    py.decref(peer_address);
    return result;
}

// Return the zttp.results dataclass named `name`, importing and caching it once.
fn resultType(cache: *py.Object, name: [*c]const u8) py.Object {
    var critical_section: py.CriticalSection = .{};
    critical_section.beginObject(module_lock_object);
    defer critical_section.end();
    if (cache.* != null) return cache.*;
    const mod = py.import("zttp.results") orelse return null;
    defer py.decref(mod);
    const t = py.getAttr(mod, name) orelse return null; // owned; retained for the process
    cache.* = t;
    return t;
}

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

fn lockedConnectionMethod(comptime method: anytype) *const @TypeOf(method) {
    return &struct {
        fn call(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
            var critical_section: py.CriticalSection = .{};
            critical_section.beginObject(self_obj.?);
            defer critical_section.end();
            return method(self_obj, arg);
        }
    }.call;
}

fn connectionNeedsModuleLock(self_obj: ?*c.PyObject) bool {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return false;
    return switch (engine.*) {
        .h3 => |*h3_engine| h3_engine.needsTicketStore(),
        else => false,
    };
}

fn lockedConnectionAndModuleMethod(comptime method: anytype) *const @TypeOf(method) {
    return &struct {
        fn call(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
            var probe: py.CriticalSection = .{};
            probe.beginObject(self_obj.?);
            const needs_module_lock = connectionNeedsModuleLock(self_obj);
            probe.end();

            if (needs_module_lock) {
                var critical_section: py.CriticalSection2 = .{};
                critical_section.beginObjects(self_obj.?, module_lock_object);
                defer critical_section.end();
                return method(self_obj, arg);
            }

            var critical_section: py.CriticalSection = .{};
            critical_section.beginObject(self_obj.?);
            defer critical_section.end();
            return method(self_obj, arg);
        }
    }.call;
}

fn lockedConnectionKeywordMethod(comptime method: anytype) *const @TypeOf(method) {
    return &struct {
        fn call(self_obj: ?*c.PyObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
            var critical_section: py.CriticalSection = .{};
            critical_section.beginObject(self_obj.?);
            defer critical_section.end();
            return method(self_obj, args, kwds);
        }
    }.call;
}

fn lockedConnectionGetter(comptime getter: anytype) *const @TypeOf(getter) {
    return &struct {
        fn call(self_obj: ?*c.PyObject, closure: ?*anyopaque) callconv(.c) py.Object {
            var critical_section: py.CriticalSection = .{};
            critical_section.beginObject(self_obj.?);
            defer critical_section.end();
            return getter(self_obj, closure);
        }
    }.call;
}

fn lockedStreamMethod(comptime method: anytype) *const @TypeOf(method) {
    return &struct {
        fn call(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
            const self: *StreamObject = @ptrCast(self_obj.?);
            const conn = self.conn orelse return py.raiseRuntime("connection is closed");
            var critical_section: py.CriticalSection = .{};
            critical_section.beginObject(conn);
            defer critical_section.end();
            return method(self_obj, arg);
        }
    }.call;
}

fn lockedStreamKeywordMethod(comptime method: anytype) *const @TypeOf(method) {
    return &struct {
        fn call(self_obj: ?*c.PyObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
            const self: *StreamObject = @ptrCast(self_obj.?);
            const conn = self.conn orelse return py.raiseRuntime("connection is closed");
            var critical_section: py.CriticalSection = .{};
            critical_section.beginObject(conn);
            defer critical_section.end();
            return method(self_obj, args, kwds);
        }
    }.call;
}

fn lockedStreamGetter(comptime getter: anytype) *const @TypeOf(getter) {
    return &struct {
        fn call(self_obj: ?*c.PyObject, closure: ?*anyopaque) callconv(.c) py.Object {
            const self: *StreamObject = @ptrCast(self_obj.?);
            const conn = self.conn orelse return py.raiseRuntime("connection is closed");
            var critical_section: py.CriticalSection = .{};
            critical_section.beginObject(conn);
            defer critical_section.end();
            return getter(self_obj, closure);
        }
    }.call;
}

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
    var hdrs = BorrowedHeaders{};
    defer hdrs.deinit();
    if (hdrs_seq != null and !py.isNone(hdrs_seq)) {
        if (!hdrs.borrow(hdrs_seq)) return null;
    }
    return switch (e) {
        .h2 => |x| x.sendResponse(@intCast(self.stream_id), @intCast(status), &hdrs, end_stream != 0),
        .h3 => |x| blk: {
            const r = x.sendResponse(self.stream_id, @intCast(status), hdrs.headers);
            if (r == null or end_stream == 0) break :blk r;
            py.decref(r);
            break :blk x.endStream(self.stream_id);
        },
    };
}

fn stream_send_informational(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    const e = self.engine() orelse return null;
    var status: c_long = 0;
    var hdrs_seq: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "l|O", &status, &hdrs_seq) == 0) return null;
    if (status < 100 or status > 199) return py.raiseValue("informational status code must be in 100..199");
    // 101 Switching Protocols is an HTTP/1.1 mechanism; neither HTTP/2 nor HTTP/3 use it.
    if (status == 101) return py.raiseValue("HTTP/2 and HTTP/3 have no 101 Switching Protocols");
    var hdrs = BorrowedHeaders{};
    defer hdrs.deinit();
    if (hdrs_seq != null and !py.isNone(hdrs_seq)) {
        if (!hdrs.borrow(hdrs_seq)) return null;
    }
    return switch (e) {
        .h2 => |x| x.sendInformational(@intCast(self.stream_id), @intCast(status), &hdrs),
        .h3 => |x| x.sendInformational(self.stream_id, @intCast(status), hdrs.headers),
    };
}

fn stream_send_window_get(self_obj: ?*c.PyObject, _: ?*anyopaque) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    const e = self.engine() orelse return null;
    return switch (e) {
        .h2 => |h2| {
            const w = h2.conn.streamSendWindow(@intCast(self.stream_id)) orelse return py.none();
            return c.PyLong_FromLong(w);
        },
        .h3 => |h3_engine| {
            const q = h3_engine.qc orelse return py.none();
            const w = q.streamSendWindow(self.stream_id) orelse return py.none();
            return c.PyLong_FromUnsignedLongLong(w);
        },
    };
}

fn stream_pending_bytes_get(self_obj: ?*c.PyObject, _: ?*anyopaque) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    const e = self.engine() orelse return null;
    return switch (e) {
        .h2 => |h2| {
            const n = h2.conn.streamPendingBytes(@intCast(self.stream_id)) orelse return py.none();
            return c.PyLong_FromUnsignedLongLong(n);
        },
        .h3 => |h3_engine| {
            const q = h3_engine.qc orelse return py.none();
            const n = q.streamPendingBytes(self.stream_id) orelse return py.none();
            return c.PyLong_FromUnsignedLongLong(n);
        },
    };
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
    const has_headers = hdrs_seq != null and !py.isNone(hdrs_seq);
    switch (e) {
        // HTTP/2 send-side trailers are still a follow-up; an empty/absent list is the
        // ordinary END_STREAM.
        .h2 => |x| {
            if (has_headers) return py.raise(exceptions.LocalProtocolError, "HTTP/2 send-side trailers are not supported yet");
            return x.endStream(@intCast(self.stream_id));
        },
        .h3 => |x| {
            var hdrs = BorrowedHeaders{};
            defer hdrs.deinit();
            if (has_headers and !hdrs.borrow(hdrs_seq)) return null;
            return x.endMessage(self.stream_id, hdrs.headers);
        },
    }
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
    .{ .ml_name = "send_response", .ml_meth = @ptrCast(lockedStreamKeywordMethod(stream_send_response)), .ml_flags = c.METH_VARARGS | c.METH_KEYWORDS, .ml_doc = "Serialize a response head on this stream: send_response(status, headers=None, end_stream=False). Pass end_stream=True for a bodyless response (204 / 304 / HEAD) to ride END_STREAM on the HEADERS frame and skip the trailing empty DATA frame." },
    .{ .ml_name = "send_informational", .ml_meth = lockedStreamMethod(stream_send_informational), .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize an interim 1xx response head on this stream: send_informational(status, headers=None). The final response still follows on the same stream." },
    .{ .ml_name = "send_data", .ml_meth = lockedStreamMethod(stream_send_data), .ml_flags = c.METH_O, .ml_doc = "Queue body bytes on this stream (flow-controlled; parked until the send window allows)." },
    .{ .ml_name = "end_message", .ml_meth = lockedStreamMethod(stream_end_message), .ml_flags = c.METH_VARARGS, .ml_doc = "End the outgoing message on this stream: end_message(trailers=None). HTTP/3 sends a trailing HEADERS frame for trailers; HTTP/2 send-side trailers are not supported yet." },
    .{ .ml_name = "reset", .ml_meth = lockedStreamMethod(stream_reset), .ml_flags = c.METH_VARARGS, .ml_doc = "Send RST_STREAM to cancel this stream: reset(error_code=CANCEL)." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

var stream_getset = [_]c.PyGetSetDef{
    .{ .name = "stream_id", .get = stream_id_get, .set = null, .doc = "The HTTP/2 stream id this handle addresses.", .closure = null },
    .{ .name = "send_window", .get = lockedStreamGetter(stream_send_window_get), .set = null, .doc = "Body bytes that may still leave on this stream before a WINDOW_UPDATE (may be negative after a SETTINGS shrink), or None if the stream is no longer live.", .closure = null },
    .{ .name = "pending_bytes", .get = lockedStreamGetter(stream_pending_bytes_get), .set = null, .doc = "Body bytes queued on this stream that the send window has not yet admitted, or None if the stream is no longer live.", .closure = null },
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
// it picks the H1/H2/H3 subtype and returns an instance of THAT type, so the runtime
// type is truthful (isinstance(obj, Connection) still holds via the base). Connection
// itself is not a usable instance type - it carries only the shared read API - so
// subclassing it is rejected rather than yielding a half-built object.
fn new_base(tp: ?*c.PyTypeObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
    // A user subclass of Connection is none of the concrete subtypes, so it would get
    // an instance with only next_event() and none of the transport's read/write
    // surface (receive_data / data_to_send / the send API live on the subtypes).
    // Reject it with a clear error instead of handing back a broken object.
    if (@intFromPtr(tp) != @intFromPtr(connection_type)) {
        return py.raiseType("zttp.Connection is a factory and cannot be subclassed; call zttp.Connection(role, protocol=...) to build an H1/H2/H3Connection");
    }
    // HTTP/3 carries server-credential kwargs that the (role, protocol) parser would
    // reject, so detect it first by a cheap peek and route the whole call through
    // new_h3, which owns the full parse. The H1/H2 fast path is unchanged.
    if (peekProtocol(args, kwds) == HTTP3) {
        return new_h3(@ptrCast(h3_connection_type), args, kwds);
    }
    var role: Role = .server;
    var protocol_val: c_long = HTTP1;
    if (!parseArgs(args, kwds, &role, &protocol_val, null)) return null;
    const sub: ?*c.PyTypeObject = @ptrCast(switch (protocol_val) {
        HTTP2 => h2_connection_type,
        else => h1_connection_type,
    });
    return allocAndBuild(sub, role, protocol_val);
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

// H3Connection(role, protocol=HTTP3, *, credentials=None, transport_params=None,
// random=None, ephemeral_seed=None, alpn=None,
// connection_id=None, server_name=None, server_certificate=None, resumption_identity=None,
// resumption_psk=None, obfuscated_ticket_age=0, early_data=False,
// remembered_transport_params=None, validation_token=None).
// role and protocol stay
// positional-or-keyword so the Connection(SERVER, HTTP3, ...) factory form works.
// The advanced QUIC/TLS fields are optional overrides; normal callers only choose
// the role/protocol and any application-level values such as server_name.
fn new_h3(tp: ?*c.PyTypeObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
    var role_val: c_long = 0;
    var protocol_val: c_long = HTTP3;
    var credentials_obj: ?*c.PyObject = null;
    var tp_obj: ?*c.PyObject = null;
    var random_obj: ?*c.PyObject = null;
    var ephemeral_obj: ?*c.PyObject = null;
    var alpn_obj: ?*c.PyObject = null;
    var cid_obj: ?*c.PyObject = null;
    var sni_obj: ?*c.PyObject = null;
    var server_certificate_obj: ?*c.PyObject = null;
    var resumption_obj: ?*c.PyObject = null;
    var obfuscated_ticket_age_obj: ?*c.PyObject = null;
    var early_data_obj: ?*c.PyObject = null;
    var remembered_tp_obj: ?*c.PyObject = null;
    var validation_token_obj: ?*c.PyObject = null;
    var kwlist = [_][*c]u8{
        @constCast("role"),               @constCast("protocol"),                    @constCast("credentials"),
        @constCast("transport_params"),   @constCast("random"),                      @constCast("ephemeral_seed"),
        @constCast("alpn"),               @constCast("connection_id"),               @constCast("server_name"),
        @constCast("server_certificate"), @constCast("resumption"),                  @constCast("obfuscated_ticket_age"),
        @constCast("early_data"),         @constCast("remembered_transport_params"), @constCast("validation_token"),
        null,
    };
    if (c.PyArg_ParseTupleAndKeywords(
        args,
        kwds,
        "l|l$OOOOOOOOOOOOO",
        @ptrCast(&kwlist),
        &role_val,
        &protocol_val,
        &credentials_obj,
        &tp_obj,
        &random_obj,
        &ephemeral_obj,
        &alpn_obj,
        &cid_obj,
        &sni_obj,
        &server_certificate_obj,
        &resumption_obj,
        &obfuscated_ticket_age_obj,
        &early_data_obj,
        &remembered_tp_obj,
        &validation_token_obj,
    ) == 0) return null;
    if (protocol_val != HTTP3) return py.raiseValue("protocol does not match this Connection subclass; construct zttp.Connection to choose by protocol");
    if (role_val != SERVER and role_val != CLIENT) return py.raiseValue("role must be zttp.SERVER or zttp.CLIENT");

    var encoded_tp: std.ArrayListUnmanaged(u8) = .empty;
    defer encoded_tp.deinit(gpa);
    const tp_src = transportParameters(tp_obj, role_val, &encoded_tp) orelse return null;

    const credentials = parseTlsCredentials(credentials_obj) orelse return null;
    var resumption_identity_obj: ?*c.PyObject = null;
    var resumption_psk_obj: ?*c.PyObject = null;
    defer py.xdecref(resumption_identity_obj);
    defer py.xdecref(resumption_psk_obj);
    if (resumption_obj != null and !py.isNone(resumption_obj)) {
        resumption_identity_obj = c.PyObject_GetAttrString(resumption_obj, "identity") orelse return null;
        resumption_psk_obj = c.PyObject_GetAttrString(resumption_obj, "psk") orelse return null;
    }

    const alloc = tp.?.tp_alloc.?;
    const obj = alloc(tp, 0);
    if (obj == null) return null;
    const self: *ConnectionObject = @ptrCast(obj);
    self.engine = null;
    const engine: *Engine = @ptrCast(@alignCast(&self.engine_storage));
    if (role_val == SERVER) {
        if (server_certificate_obj != null and !py.isNone(server_certificate_obj)) {
            py.decref(obj);
            return py.raiseValue("server_certificate is only valid for HTTP/3 clients");
        }
        if (obfuscated_ticket_age_obj != null and !py.isNone(obfuscated_ticket_age_obj)) {
            py.decref(obj);
            return py.raiseValue("obfuscated_ticket_age is only valid for HTTP/3 clients");
        }
        if (early_data_obj != null and !py.isNone(early_data_obj)) {
            const early = c.PyObject_IsTrue(early_data_obj);
            if (early < 0) {
                py.decref(obj);
                return null;
            }
            if (early != 0) {
                py.decref(obj);
                return py.raiseValue("early_data is only valid for HTTP/3 clients");
            }
        }
        if (remembered_tp_obj != null and !py.isNone(remembered_tp_obj)) {
            py.decref(obj);
            return py.raiseValue("remembered_transport_params is only valid for HTTP/3 clients");
        }
        if (validation_token_obj != null and !py.isNone(validation_token_obj)) {
            py.decref(obj);
            return py.raiseValue("validation_token is only valid for HTTP/3 clients");
        }
        const config = buildServerConfig(
            credentials,
            tp_src,
            random_obj,
            ephemeral_obj,
            alpn_obj,
            resumption_identity_obj,
            resumption_psk_obj,
        ) orelse {
            py.decref(obj);
            return null;
        };
        engine.* = .{ .h3 = .{ .config = config } };
    } else if (role_val == CLIENT) {
        engine.* = .{ .h3 = buildClientH3(
            tp,
            tp_src,
            random_obj,
            ephemeral_obj,
            alpn_obj,
            cid_obj,
            sni_obj,
            server_certificate_obj,
            resumption_identity_obj,
            resumption_psk_obj,
            obfuscated_ticket_age_obj,
            early_data_obj,
            remembered_tp_obj,
            validation_token_obj,
        ) orelse {
            py.decref(obj);
            return null;
        } };
    } else {
        py.decref(obj);
        return py.raiseValue("role must be zttp.SERVER or zttp.CLIENT");
    }
    self.engine = engine;
    return obj;
}

fn buildClientH3(
    _: ?*c.PyTypeObject,
    tp_src: []const u8,
    random_obj: ?*c.PyObject,
    ephemeral_obj: ?*c.PyObject,
    alpn_obj: ?*c.PyObject,
    cid_obj: ?*c.PyObject,
    sni_obj: ?*c.PyObject,
    server_certificate_obj: ?*c.PyObject,
    resumption_identity_obj: ?*c.PyObject,
    resumption_psk_obj: ?*c.PyObject,
    obfuscated_ticket_age_obj: ?*c.PyObject,
    early_data_obj: ?*c.PyObject,
    remembered_tp_obj: ?*c.PyObject,
    validation_token_obj: ?*c.PyObject,
) ?H3Engine {
    const random = optionalBytes32(random_obj, "random must be exactly 32 bytes") orelse return null;
    const ephemeral_seed = optionalBytes32(ephemeral_obj, "ephemeral_seed must be exactly 32 bytes") orelse return null;
    const default_cid = randomBytes(8) orelse return null;
    const cid = optionalBytes(cid_obj, &default_cid) orelse return null;
    if (cid.len == 0 or cid.len > core.quic.constants.MAX_CID_LEN) {
        _ = py.raiseValue("connection_id must be 1..20 bytes");
        return null;
    }
    const alpn = if (alpn_obj != null and !py.isNone(alpn_obj)) py.asBytes(alpn_obj) orelse return null else "h3";
    const server_name = if (sni_obj != null and !py.isNone(sni_obj)) py.asBytes(sni_obj) orelse return null else null;
    const server_certificate = if (server_certificate_obj != null and !py.isNone(server_certificate_obj))
        py.asBytes(server_certificate_obj) orelse return null
    else
        &.{};
    if (server_certificate_obj != null and !py.isNone(server_certificate_obj) and server_certificate.len == 0) {
        _ = py.raiseValue("server_certificate must not be empty");
        return null;
    }
    const validation_token = if (validation_token_obj != null and !py.isNone(validation_token_obj)) blk: {
        const token = py.asBytes(validation_token_obj) orelse return null;
        if (token.len == 0) {
            _ = py.raiseValue("validation_token must not be empty");
            return null;
        }
        break :blk token;
    } else null;
    const resumption = parseResumptionCredential(resumption_identity_obj, resumption_psk_obj, obfuscated_ticket_age_obj, early_data_obj);
    if (resumption == null and c.PyErr_Occurred() != null) return null;
    const q = gpa.create(QuicConnection) catch {
        _ = c.PyErr_NoMemory();
        return null;
    };
    q.* = QuicConnection.initClient(gpa, cid, .{
        .random = random,
        .ephemeral_seed = ephemeral_seed,
        .transport_params = tp_src,
        .alpn = alpn,
        .server_name = server_name,
        .server_certificate = server_certificate,
        .resumption = if (resumption) |r| .{
            .identity = r.identity,
            .obfuscated_ticket_age = r.obfuscated_ticket_age,
            .psk = r.psk,
            .early_data = r.early_data,
        } else null,
        .validation_token = validation_token,
    }, 0) catch |e| {
        gpa.destroy(q);
        _ = exceptions.raiseQuic(e);
        return null;
    };
    if (remembered_tp_obj != null and !py.isNone(remembered_tp_obj)) {
        const remembered = py.asBytes(remembered_tp_obj) orelse {
            q.deinit();
            gpa.destroy(q);
            return null;
        };
        q.applyRememberedPeerTransportParameters(remembered) catch |e| {
            q.deinit();
            gpa.destroy(q);
            _ = exceptions.raiseQuic(e);
            return null;
        };
    }
    const h = gpa.create(H3Connection) catch {
        q.deinit();
        gpa.destroy(q);
        _ = c.PyErr_NoMemory();
        return null;
    };
    h.* = H3Connection.init(gpa, q);
    return .{ .qc = q, .h3 = h };
}

fn freeCertificateChain(certificates: [][]u8) void {
    for (certificates) |certificate| gpa.free(certificate);
    gpa.free(certificates);
}

fn copyCertificateChain(credentials: TlsCredentialObjects, default_certificate: []const u8) ?[][]u8 {
    if (credentials.certificate) |certificate_obj| {
        const source = py.asBytes(certificate_obj) orelse return null;
        if (source.len == 0) {
            _ = py.raiseValue("every certificate must be non-empty bytes");
            return null;
        }
        const certificates = gpa.alloc([]u8, 1) catch {
            _ = c.PyErr_NoMemory();
            return null;
        };
        certificates[0] = gpa.dupe(u8, source) catch {
            gpa.free(certificates);
            _ = c.PyErr_NoMemory();
            return null;
        };
        return certificates;
    }

    const certificates_obj = credentials.certificates orelse {
        const certificates = gpa.alloc([]u8, 1) catch {
            _ = c.PyErr_NoMemory();
            return null;
        };
        certificates[0] = gpa.dupe(u8, default_certificate) catch {
            gpa.free(certificates);
            _ = c.PyErr_NoMemory();
            return null;
        };
        return certificates;
    };
    const sequence = c.PySequence_Fast(certificates_obj, "certificates must be a sequence") orelse return null;
    defer py.decref(sequence);
    const count = c.PySequence_Size(sequence);
    if (count <= 0) {
        _ = py.raiseValue("the certificate chain must not be empty");
        return null;
    }
    const certificates = gpa.alloc([]u8, @intCast(count)) catch {
        _ = c.PyErr_NoMemory();
        return null;
    };
    var copied: usize = 0;
    var failed = true;
    defer if (failed) {
        for (certificates[0..copied]) |certificate| gpa.free(certificate);
        gpa.free(certificates);
    };
    while (copied < certificates.len) : (copied += 1) {
        const item = c.PySequence_GetItem(sequence, @intCast(copied)) orelse return null;
        defer py.decref(item);
        const source = py.asBytes(item) orelse return null;
        if (source.len == 0) {
            _ = py.raiseValue("every certificate must be non-empty bytes");
            return null;
        }
        certificates[copied] = gpa.dupe(u8, source) catch {
            _ = c.PyErr_NoMemory();
            return null;
        };
    }
    failed = false;
    return certificates;
}

// Copy the integrator's server credentials into an owned ServerConfig, validating
// the fixed-size seeds and deriving the Signer up front. On any failure sets a Python
// error, frees whatever was already copied, and returns null.
fn buildServerConfig(
    credentials: TlsCredentialObjects,
    tp_src: []const u8,
    random_obj: ?*c.PyObject,
    ephemeral_obj: ?*c.PyObject,
    alpn_obj: ?*c.PyObject,
    resumption_identity_obj: ?*c.PyObject,
    resumption_psk_obj: ?*c.PyObject,
) ?ServerConfig {
    const random = optionalBytes32(random_obj, "random must be exactly 32 bytes") orelse return null;
    const ephemeral_seed = optionalBytes32(ephemeral_obj, "ephemeral_seed must be exactly 32 bytes") orelse return null;
    var signer: Signer = undefined;
    var default_cert: [tls_sign.PUBLIC_SEC1_LEN]u8 = undefined;
    if (credentials.private_key) |key_obj| {
        const key_src = py.asBytes(key_obj) orelse return null;
        if (key_src.len != 32) {
            _ = py.raiseValue("private_key must be 32 bytes (the signing key seed)");
            return null;
        }
        signer = Signer.fromSeed(key_src[0..32].*) catch {
            _ = py.raiseValue("private_key is not a valid signing key seed");
            return null;
        };
    } else if (credentials.private_key_scalar) |key_obj| {
        const key_src = py.asBytes(key_obj) orelse return null;
        if (key_src.len != 32) {
            _ = py.raiseValue("private_key_scalar must be exactly 32 bytes");
            return null;
        }
        signer = Signer.fromPrivateKey(key_src[0..32].*) catch {
            _ = py.raiseValue("private_key_scalar is not a valid P-256 scalar");
            return null;
        };
    } else {
        signer = randomSigner() orelse return null;
        default_cert = signer.publicKeySec1();
    }
    const resumption = parseResumptionCredential(resumption_identity_obj, resumption_psk_obj, null, null);
    if (resumption == null and c.PyErr_Occurred() != null) return null;

    const certificates = copyCertificateChain(credentials, &default_cert) orelse return null;
    const leaf_public_key = tls_sign.certificatePublicKeySec1(certificates[0]) catch {
        freeCertificateChain(certificates);
        _ = py.raiseValue("the leaf certificate must contain a P-256 public key");
        return null;
    };
    const signer_public_key = signer.publicKeySec1();
    if (!std.mem.eql(u8, leaf_public_key, &signer_public_key)) {
        freeCertificateChain(certificates);
        _ = py.raiseValue("the leaf certificate public key does not match the signing key");
        return null;
    }
    const tp_copy = gpa.dupe(u8, tp_src) catch {
        freeCertificateChain(certificates);
        _ = c.PyErr_NoMemory();
        return null;
    };
    // ALPN is mandatory in QUIC (RFC 9001 8.1) and an HTTP/3 server's protocol is
    // "h3"; the parameter overrides the token (e.g. an interop draft name), it is
    // not an opt-out of negotiation.
    const alpn_src: []const u8 = if (alpn_obj != null and !py.isNone(alpn_obj))
        py.asBytes(alpn_obj) orelse {
            freeCertificateChain(certificates);
            gpa.free(tp_copy);
            return null;
        }
    else
        "h3";
    const alpn = gpa.dupe(u8, alpn_src) catch {
        freeCertificateChain(certificates);
        gpa.free(tp_copy);
        _ = c.PyErr_NoMemory();
        return null;
    };
    var resumption_identity: ?[]u8 = null;
    var resumption_psk: ?[32]u8 = null;
    if (resumption) |r| {
        resumption_identity = gpa.dupe(u8, r.identity) catch {
            freeCertificateChain(certificates);
            gpa.free(tp_copy);
            gpa.free(alpn);
            _ = c.PyErr_NoMemory();
            return null;
        };
        resumption_psk = r.psk;
    }
    return .{
        .certificates = certificates,
        .transport_params = tp_copy,
        .alpn = alpn,
        .resumption_identity = resumption_identity,
        .resumption_psk = resumption_psk,
        .signer = signer,
        .random = random,
        .ephemeral_seed = ephemeral_seed,
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
            _ = py.raiseRuntime("this is an HTTP/3 connection; send on a Stream (conn.stream(id) or the Stream returned by send_request)");
            return null;
        },
    }
}

fn receive_data(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    var data = py.BorrowedBuffer.init(arg) orelse return null;
    defer data.deinit();
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    switch (engine.*) {
        .h2 => |*e| {
            e.conn.feed(data.bytes) catch |err| {
                e.emitGoAwayIfOwed(); // a fatal feed (e.g. max_buffer flood) still owes a GOAWAY
                return exceptions.raiseH2(err);
            };
            return py.none();
        },
        .h1 => |*e| return e.receiveData(data.bytes, data.stable_owner),
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
            var addr_obj: ?*c.PyObject = null;
            if (c.PyArg_ParseTuple(args, "O|KO", &dgram_obj, &now, &addr_obj) == 0) return null;
            var dgram = py.BorrowedBuffer.init(dgram_obj) orelse return null;
            defer dgram.deinit();
            const peer_address = if (addr_obj != null and !py.isNone(addr_obj)) py.asBytes(addr_obj) orelse return null else null;
            return e.receiveDatagram(dgram.bytes, @intCast(now), peer_address);
        },
        else => return py.raiseRuntime("receive_datagram is only valid for an HTTP/3 connection"),
    }
}

fn h3_consume_data(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    var stream_id: c_ulonglong = 0;
    var length: c_ulonglong = 0;
    if (c.PyArg_ParseTuple(args, "KK", &stream_id, &length) == 0) return null;
    return e.consumeData(@intCast(stream_id), @intCast(length));
}

fn nextEventImpl(self_obj: ?*c.PyObject, eager_headers: bool) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    switch (engine.*) {
        .h3 => |*e| return e.nextEvent(),
        .h2 => |*e| {
            const ev = e.conn.nextEvent() catch |err| {
                e.emitGoAwayIfOwed(); // queue one GOAWAY for the next data_to_send
                return exceptions.raiseH2(err);
            };
            const handshake_sent = e.handshake_sent;
            e.autoRespond(ev) catch |err| {
                e.writer.clear();
                e.handshake_sent = handshake_sent;
                e.conn.poisonResourceFailure();
                e.emitGoAwayIfOwed();
                return h2RaiseWrite(err);
            };
            return events_obj.fromH2Event(ev);
        },
        .h1 => |*e| {
            while (true) {
                const ev = e.reader.nextEvent() catch |err| {
                    e.pending.clear();
                    // The response method survives start_next_cycle by design. Clear it ONLY
                    // when the failure is on a fresh request head (no request
                    // surfaced this cycle): otherwise an error response the app sends
                    // (e.g. send_response(400, content-length: ...)) would be framed
                    // on a stale HEAD/CONNECT method and wrongly forced bodyless. But
                    // if a request WAS already surfaced and its body then fails, the
                    // response to THAT request (a HEAD stays bodyless regardless of
                    // headers) still needs the method - keep it.
                    e.message.parseFailed();
                    return exceptions.raiseParse(err);
                };
                if (ev == .need_data and e.pending.hasData()) {
                    if (e.reader.backlogEmpty()) {
                        if (e.reader.bodyLengthRemaining() != null) return e.pending.emitBody(&e.reader);
                    }
                    // The stash cannot be consumed in place (chunked body,
                    // message done, or buffered bytes precede it): buffer it
                    // and ask the reader again.
                    e.pending.flushInto(&e.reader) catch |err| return exceptions.raiseParse(err);
                    continue;
                }
                if (ev == .request) {
                    if (!e.message.captureRequest(ev.request.method, e.reader.takeHeadInfo())) return null;
                } else if (ev == .response) {
                    e.message.captureResponse(e.reader.takeHeadInfo());
                }
                return if (eager_headers)
                    events_obj.fromH1Event(ev)
                else
                    events_obj.fromH1EventWithHeaderBlock(ev);
            }
        },
    }
}

fn next_event(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    return nextEventImpl(self_obj, false);
}

fn next_event_eager_for_benchmark(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    return nextEventImpl(self_obj, true);
}

/// Feed one HTTP/1 byte span and return its first available event in the same
/// extension call. Callers can continue with next_event() when this did not
/// return NEED_DATA, avoiding a container allocation on the one-event hot path.
fn receive_event(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    var data = py.BorrowedBuffer.init(arg) orelse return null;
    defer data.deinit();
    const engine = h1(self) orelse return null;
    if (!engine.feedData(data.bytes, data.stable_owner)) return null;
    return nextEventImpl(self_obj, false);
}

/// Headers borrowed (zero-copy) from a Python sequence of (name, value) bytes
/// pairs. Common ASGI lists fit in inline scratch storage. Exact tuple pairs of
/// exact bytes only retain the pair when their outer list is mutable; custom
/// sequences retain each synthesized name/value until the writer returns.
/// Header slices are valid only until `deinit`; every consumer must serialize
/// them synchronously before then. An exact outer tuple is immutable and remains
/// reachable from the active Python call arguments for that whole interval.
const BorrowedHeaders = struct {
    const inline_capacity = 16;

    inline_headers: [inline_capacity]events.Header = undefined,
    inline_refs: [inline_capacity * 2]py.Object = undefined,
    headers: []events.Header = &.{},
    refs: []py.Object = &.{},
    ref_count: usize = 0,
    heap_headers: ?[]events.Header = null,
    heap_refs: ?[]py.Object = null,

    fn exactType(obj: py.Object, tp: *c.PyTypeObject) bool {
        return @intFromPtr(c.Py_TYPE(obj)) == @intFromPtr(tp);
    }

    fn prepare(self: *BorrowedHeaders, count: usize) bool {
        if (count > std.math.maxInt(usize) / 2) {
            _ = c.PyErr_NoMemory();
            return false;
        }
        if (count <= inline_capacity) {
            self.headers = self.inline_headers[0..count];
            self.refs = self.inline_refs[0 .. count * 2];
            return true;
        }
        const headers = gpa.alloc(events.Header, count) catch {
            _ = c.PyErr_NoMemory();
            return false;
        };
        const refs = gpa.alloc(py.Object, count * 2) catch {
            gpa.free(headers);
            _ = c.PyErr_NoMemory();
            return false;
        };
        self.heap_headers = headers;
        self.heap_refs = refs;
        self.headers = headers;
        self.refs = refs;
        return true;
    }

    fn releaseRefs(self: *BorrowedHeaders) void {
        while (self.ref_count > 0) {
            self.ref_count -= 1;
            py.decref(self.refs[self.ref_count]);
        }
    }

    const ExactResult = union(enum) { success, fallback: usize, failure };

    /// Fast path for the list/tuple of bytes tuples emitted by ASGI apps. A
    /// mutable outer list yields owned pair references; an outer tuple and its
    /// inner tuples are immutable and already held by the call argument.
    fn borrowExact(self: *BorrowedHeaders, seq: py.Object, outer_tuple: bool) ExactResult {
        for (0..self.headers.len) |i| {
            const pair = if (outer_tuple)
                c.PyTuple_GetItem(seq, @intCast(i))
            else
                c.PySequence_GetItem(seq, @intCast(i));
            if (pair == null) return .failure;
            const pair_owned = !outer_tuple;
            if (!exactType(pair, py.data("PyTuple_Type")) or c.PyTuple_Size(pair) < 2) {
                if (pair_owned) py.decref(pair);
                return .{ .fallback = i };
            }

            const name = c.PyTuple_GetItem(pair, 0);
            const value = c.PyTuple_GetItem(pair, 1);
            if (!exactType(name, py.data("PyBytes_Type")) or !exactType(value, py.data("PyBytes_Type"))) {
                if (pair_owned) py.decref(pair);
                return .{ .fallback = i };
            }
            if (pair_owned) {
                self.refs[self.ref_count] = pair;
                self.ref_count += 1;
            }
            self.headers[i] = .{
                .name = py.asBytes(name).?,
                .value = py.asBytes(value).?,
            };
        }
        return .success;
    }

    fn borrowGeneric(self: *BorrowedHeaders, seq: py.Object, start: usize) bool {
        for (start..self.headers.len) |i| {
            const pair = c.PySequence_GetItem(seq, @intCast(i));
            if (pair == null) return false;
            const name = c.PySequence_GetItem(pair, 0);
            const value = c.PySequence_GetItem(pair, 1);
            py.decref(pair);
            if (name == null or value == null) {
                py.xdecref(name);
                py.xdecref(value);
                _ = py.raiseType("each header must be a (name, value) pair");
                return false;
            }
            const name_bytes = py.asBytes(name) orelse {
                py.decref(name);
                py.decref(value);
                return false;
            };
            const value_bytes = py.asBytes(value) orelse {
                py.decref(name);
                py.decref(value);
                return false;
            };
            self.refs[self.ref_count] = name;
            self.refs[self.ref_count + 1] = value;
            self.ref_count += 2;
            self.headers[i] = .{ .name = name_bytes, .value = value_bytes };
        }
        return true;
    }

    fn borrow(self: *BorrowedHeaders, seq: py.Object) bool {
        const n = c.PySequence_Size(seq);
        if (n < 0) {
            _ = py.raiseType("headers must be a sequence of (name, value) pairs");
            return false;
        }
        if (!self.prepare(@intCast(n))) return false;

        const outer_tuple = exactType(seq, py.data("PyTuple_Type"));
        if (outer_tuple or exactType(seq, py.data("PyList_Type"))) {
            switch (self.borrowExact(seq, outer_tuple)) {
                .success => return true,
                .failure => return false,
                .fallback => |start| return self.borrowGeneric(seq, start),
            }
        }
        return self.borrowGeneric(seq, 0);
    }

    fn deinit(self: *BorrowedHeaders) void {
        self.releaseRefs();
        if (self.heap_refs) |refs| gpa.free(refs);
        if (self.heap_headers) |headers| gpa.free(headers);
    }
};

// HTTP/2 send helpers -------------------------------------------------------

const asciiEqlIgnoreCase = core.ascii.eqIgnoreCase;

const AuthoritySplitError = error{LocalProtocol};

// Build the HTTP/2 regular-header list and pull out :authority. For a request the
// adapter derives :authority from a `host` (or `:authority`) field and drops it
// from the regular headers - HTTP/2 forbids `host` and carries it as a pseudo-
// header instead. `:scheme` defaults to https.
fn h2SplitAuthority(headers: []events.Header, out: *[]events.Header) AuthoritySplitError![]const u8 {
    var authority: []const u8 = "";
    var seen_authority = false;
    var n: usize = 0;
    for (headers) |h| {
        if (asciiEqlIgnoreCase(h.name, "host") or asciiEqlIgnoreCase(h.name, ":authority")) {
            if (seen_authority and !std.mem.eql(u8, authority, h.value)) return error.LocalProtocol;
            authority = h.value;
            seen_authority = true;
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

fn h3RaiseLocal(e: core.h3.connection.Error) py.Object {
    return switch (e) {
        error.OutOfMemory => c.PyErr_NoMemory(),
        error.H3Error, error.EventQueueFull, error.Blocked => py.raise(exceptions.LocalProtocolError, "invalid HTTP/3 send"),
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
    var hdrs = BorrowedHeaders{};
    defer hdrs.deinit();
    if (!hdrs.borrow(hdrs_seq)) return null;
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
            e.message.rememberRequest(mb);
            e.reader.setRequestMethod(mb);
            if (core.h1.connection.shouldClose(vb, hdrs.headers)) e.message.should_close = true;
            return py.none();
        },
        .h3 => |*e| {
            const id = e.sendRequest(mb, tb, &hdrs) orelse return null;
            return makeStream(self_obj, id);
        },
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
    var hdrs = BorrowedHeaders{};
    defer hdrs.deinit();
    if (!hdrs.borrow(hdrs_seq)) return null;
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

    var hdrs = BorrowedHeaders{};
    defer hdrs.deinit();
    if (hdrs_seq != null and !py.isNone(hdrs_seq)) {
        if (!hdrs.borrow(hdrs_seq)) return null;
    }

    var close_headers_inline: [BorrowedHeaders.inline_capacity + 1]events.Header = undefined;
    var close_headers_heap: ?[]events.Header = null;
    defer if (close_headers_heap) |headers| gpa.free(headers);
    var header_slice = hdrs.headers;
    if (e.message.should_close and !core.h1.connection.connectionHasClose(header_slice)) {
        const expanded = if (header_slice.len < close_headers_inline.len)
            close_headers_inline[0 .. header_slice.len + 1]
        else
            gpa.alloc(events.Header, header_slice.len + 1) catch {
                _ = c.PyErr_NoMemory();
                return null;
            };
        if (header_slice.len >= close_headers_inline.len) close_headers_heap = expanded;
        @memcpy(expanded[0..header_slice.len], header_slice);
        expanded[header_slice.len] = .{ .name = "Connection", .value = "close" };
        header_slice = expanded;
    }

    const rb = core.h1.writer.reasonPhrase(@intCast(status));
    const w = e.ensureWriter() orelse return null;
    w.sendResponse("1.1", @intCast(status), rb, header_slice, e.message.framingMethod()) catch |err| return raiseWrite(err);
    if (core.h1.connection.connectionHasClose(header_slice)) e.message.should_close = true;
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
        var hdrs = BorrowedHeaders{};
        defer hdrs.deinit();
        if (!hdrs.borrow(hdrs_seq)) return null;
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
        var hdrs = BorrowedHeaders{};
        defer hdrs.deinit();
        if (!hdrs.borrow(hdrs_seq)) return null;
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

fn h3_data_to_send_with_addresses(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    return switch (engine.*) {
        .h3 => |*e| e.dataToSendWithAddresses(),
        else => py.raiseRuntime("data_to_send_with_addresses is only valid for an HTTP/3 connection"),
    };
}

fn h3_set_endpoint_context(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    var server_obj: ?*c.PyObject = null;
    var original_obj: ?*c.PyObject = null;
    var address_validated: c_int = 0;
    if (c.PyArg_ParseTuple(args, "O|Op", &server_obj, &original_obj, &address_validated) == 0) return null;
    const server_cid = py.asBytes(server_obj) orelse return null;
    const original_dcid = if (original_obj != null and !py.isNone(original_obj))
        py.asBytes(original_obj) orelse return null
    else
        null;
    return switch (engine.*) {
        .h3 => |*e| e.setEndpointContext(server_cid, original_dcid, address_validated != 0),
        else => py.raiseRuntime("endpoint context is only valid for an HTTP/3 connection"),
    };
}

fn h3_endpoint_ready(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    return switch (engine.*) {
        .h3 => |*e| e.endpointReady(),
        else => py.raiseRuntime("endpoint readiness is only valid for an HTTP/3 connection"),
    };
}

fn h3_endpoint_connection_id_generation(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    return switch (engine.*) {
        .h3 => |*e| e.endpointConnectionIdGeneration(),
        else => py.raiseRuntime("endpoint connection ID generation is only valid for an HTTP/3 connection"),
    };
}

fn h3_endpoint_peer_address(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    return switch (engine.*) {
        .h3 => |*e| e.endpointPeerAddress(),
        else => py.raiseRuntime("_endpoint_peer_address is only valid for an HTTP/3 connection"),
    };
}

fn h3_challenge_path(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    var peer_obj: ?*c.PyObject = null;
    var data_obj: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "OO", &peer_obj, &data_obj) == 0) return null;
    const peer_address = py.asBytes(peer_obj) orelse return null;
    const data = py.asBytes(data_obj) orelse return null;
    return switch (engine.*) {
        .h3 => |*e| e.challengePath(peer_address, data),
        else => py.raiseRuntime("challenge_path is only valid for an HTTP/3 connection"),
    };
}

fn h3_use_peer_connection_id(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    const seq = c.PyLong_AsUnsignedLongLong(arg);
    if (seq == @as(c_ulonglong, @bitCast(@as(c_longlong, -1))) and c.PyErr_Occurred() != null) return null;
    return e.usePeerConnectionId(@intCast(seq));
}

fn h3_local_connection_ids(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    return e.localConnectionIds();
}

fn issue_connection_id(self_obj: ?*c.PyObject, args: ?*c.PyObject, endpoint: bool) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    var seq: c_ulonglong = 0;
    var cid_obj: ?*c.PyObject = null;
    var token_obj: ?*c.PyObject = null;
    var retire_prior_to: c_ulonglong = 0;
    if (c.PyArg_ParseTuple(args, "KOO|K", &seq, &cid_obj, &token_obj, &retire_prior_to) == 0) return null;
    const cid = py.asBytes(cid_obj) orelse return null;
    const token = py.asBytes(token_obj) orelse return null;
    return e.issueConnectionId(@intCast(seq), cid, token, @intCast(retire_prior_to), endpoint);
}

fn h3_issue_connection_id(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    return issue_connection_id(self_obj, args, false);
}

fn h3_endpoint_issue_connection_id(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    return issue_connection_id(self_obj, args, true);
}

fn h3_request_key_update(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    return e.requestKeyUpdate();
}

fn h3_close(self_obj: ?*c.PyObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    var app_obj: ?*c.PyObject = null;
    var code: c_ulonglong = 0;
    var reason_obj: ?*c.PyObject = null;
    var kwlist = [_][*c]u8{ @constCast("app"), @constCast("error_code"), @constCast("reason"), null };
    if (c.PyArg_ParseTupleAndKeywords(args, kwds, "|OKO", @ptrCast(&kwlist), &app_obj, &code, &reason_obj) == 0) return null;
    if (code >= (@as(c_ulonglong, 1) << 62)) return py.raiseValue("error_code must fit in QUIC's 62-bit integer range");
    var app = true;
    if (app_obj != null and !py.isNone(app_obj)) {
        const value = c.PyObject_IsTrue(app_obj);
        if (value < 0) return null;
        app = value != 0;
    }
    const reason = if (reason_obj != null and !py.isNone(reason_obj)) py.asBytes(reason_obj) orelse return null else @as([]const u8, &.{});
    return e.close(app, @intCast(code), reason);
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
    e.reader.reset() catch return py.raise(
        exceptions.LocalProtocolError,
        "cannot start the next cycle before the current message is complete",
    );
    e.message.startNextCycle();
    return py.none();
}

fn should_close(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const e = h1(self) orelse return null;
    return py.boolean(e.message.should_close);
}

fn upgrade(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const e = h1(self) orelse return null;
    const obj = e.message.upgrade_obj orelse return py.none();
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

fn h3_idle_timed_out(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    return py.boolean(e.idleTimedOut());
}

fn h3_close_info(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    return e.closeInfo();
}

fn h3_initiate(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    return e.initiate();
}

fn h3_send_session_ticket(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    var ticket_obj: py.Object = null;
    var lifetime: c_ulonglong = 0;
    var age_add: c_ulonglong = 0;
    var nonce_obj: py.Object = null;
    var extensions_obj: py.Object = null;
    var max_early_obj: py.Object = null;
    if (c.PyArg_ParseTuple(args, "O|KKOOO", &ticket_obj, &lifetime, &age_add, &nonce_obj, &extensions_obj, &max_early_obj) == 0) return null;
    if (lifetime > std.math.maxInt(u32) or age_add > std.math.maxInt(u32)) {
        return py.raiseValue("lifetime and age_add must fit in uint32");
    }
    const ticket = py.asBytes(ticket_obj) orelse return null;
    const nonce = if (nonce_obj != null and !py.isNone(nonce_obj)) py.asBytes(nonce_obj) orelse return null else @as([]const u8, &.{});
    const extensions = if (extensions_obj != null and !py.isNone(extensions_obj)) py.asBytes(extensions_obj) orelse return null else @as([]const u8, &.{});
    var max_early_data_size: ?u32 = null;
    if (max_early_obj != null and !py.isNone(max_early_obj)) {
        const value = c.PyLong_AsUnsignedLongLong(max_early_obj);
        if (value == @as(c_ulonglong, @bitCast(@as(c_longlong, -1))) and c.PyErr_Occurred() != null) return null;
        if (value > std.math.maxInt(u32)) return py.raiseValue("max_early_data_size must fit in uint32");
        max_early_data_size = @intCast(value);
    }
    return e.sendSessionTicket(@intCast(lifetime), @intCast(age_add), nonce, ticket, extensions, max_early_data_size);
}

fn h3_session_tickets(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    return e.sessionTickets();
}

fn h3_send_new_token(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    const token = py.asBytes(arg) orelse return null;
    return e.sendNewToken(token);
}

fn h3_validation_tokens(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const e = h3(@ptrCast(self_obj.?)) orelse return null;
    return e.validationTokens();
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
// Only `next_event()` is common to every transport. The read/write *byte* surface
// is transport-specific: HTTP/1.1 and HTTP/2 are byte streams (receive_data +
// data_to_send()->bytes); HTTP/3 rides UDP datagrams (receive_datagram +
// data_to_send()->list[bytes]). Keeping the byte surface off the base means
// H3Connection does not inherit an incompatible receive_data / data_to_send - the
// type hierarchy states exactly what each transport supports (see issue #113).
var base_methods = [_]py.MethodDef{
    .{ .ml_name = "next_event", .ml_meth = lockedConnectionMethod(next_event), .ml_flags = c.METH_NOARGS, .ml_doc = "Return the next parse event, or NEED_DATA." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

// HTTP/1.1: the byte-stream read/write surface plus the message-scoped send API and
// keep-alive / upgrade signals.
var h1_methods = [_]py.MethodDef{
    .{ .ml_name = "receive_data", .ml_meth = lockedConnectionMethod(receive_data), .ml_flags = c.METH_O, .ml_doc = "Append received bytes (empty bytes signals EOF)." },
    .{ .ml_name = "receive_event", .ml_meth = lockedConnectionMethod(receive_event), .ml_flags = c.METH_O, .ml_doc = "Feed received bytes and return the first available event, or NEED_DATA." },
    .{ .ml_name = "_next_event_eager_for_benchmark", .ml_meth = lockedConnectionMethod(next_event_eager_for_benchmark), .ml_flags = c.METH_NOARGS, .ml_doc = "Private benchmark control for comparing the legacy eager header list." },
    .{ .ml_name = "data_to_send", .ml_meth = lockedConnectionMethod(data_to_send), .ml_flags = c.METH_NOARGS, .ml_doc = "Return and clear the pending outgoing bytes." },
    .{ .ml_name = "start_next_cycle", .ml_meth = lockedConnectionMethod(next_message), .ml_flags = c.METH_NOARGS, .ml_doc = "Reset to read the next message on a keep-alive connection." },
    .{ .ml_name = "send_request", .ml_meth = lockedConnectionMethod(send_request), .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize a request head: send_request(method, target, version, headers)." },
    .{ .ml_name = "send_response", .ml_meth = lockedConnectionMethod(send_response), .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize a response head: send_response(status, headers=None). The reason phrase is derived from the status; the version is 1.1. Bodyless framing (HEAD / 204 / 304) is derived automatically." },
    .{ .ml_name = "send_informational", .ml_meth = lockedConnectionMethod(send_informational), .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize an interim 1xx response: send_informational(status, headers=None). The real response still follows on the same cycle." },
    .{ .ml_name = "send_data", .ml_meth = lockedConnectionMethod(send_data), .ml_flags = c.METH_O, .ml_doc = "Serialize a run of body bytes (chunk-framed if the head was chunked)." },
    .{ .ml_name = "end_message", .ml_meth = lockedConnectionMethod(end_message), .ml_flags = c.METH_VARARGS, .ml_doc = "End the outgoing message: end_message(trailers=None)." },
    .{ .ml_name = "should_close", .ml_meth = lockedConnectionMethod(should_close), .ml_flags = c.METH_NOARGS, .ml_doc = "Whether the connection must close after the last request/response (Connection: close / HTTP/1.0 / close-delimited response). Covers both the head parsed from the peer and one serialized locally." },
    .{ .ml_name = "upgrade", .ml_meth = lockedConnectionMethod(upgrade), .ml_flags = c.METH_NOARGS, .ml_doc = "The last request's Upgrade value if it asked to upgrade (Connection: upgrade), else None." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

// HTTP/2: everything is stream-scoped. The client originates a stream by sending
// a request (returns a Stream); the server reaches one with stream(id). There is
// no connection-level body send - that is what the Stream handle is for.
var h2_methods = [_]py.MethodDef{
    .{ .ml_name = "receive_data", .ml_meth = lockedConnectionMethod(receive_data), .ml_flags = c.METH_O, .ml_doc = "Append received bytes (empty bytes signals EOF)." },
    .{ .ml_name = "data_to_send", .ml_meth = lockedConnectionMethod(data_to_send), .ml_flags = c.METH_NOARGS, .ml_doc = "Return and clear the pending outgoing bytes." },
    .{ .ml_name = "initiate_connection", .ml_meth = lockedConnectionMethod(h2_initiate), .ml_flags = c.METH_NOARGS, .ml_doc = "Emit the connection preface (client preface + SETTINGS, or the server's SETTINGS) now, rather than lazily on the first send. Idempotent." },
    .{ .ml_name = "send_request", .ml_meth = lockedConnectionMethod(send_request), .ml_flags = c.METH_VARARGS, .ml_doc = "Open a request stream and return its Stream: send_request(method, target, version, headers). :authority is derived from a host header; the version arg is ignored." },
    .{ .ml_name = "initiate_upgrade_connection", .ml_meth = @ptrCast(lockedConnectionKeywordMethod(initiate_upgrade_connection)), .ml_flags = c.METH_VARARGS | c.METH_KEYWORDS, .ml_doc = "Initialise an h2c-upgraded connection: initiate_upgrade_connection(method, target, headers, settings_header=None). Seeds the already-parsed HTTP/1.1 request as stream 1 and applies the client's base64url HTTP2-Settings, returning the stream's Stream. Call on a fresh server connection before feeding the client's HTTP/2 preface; next_event() then yields the request." },
    .{ .ml_name = "stream", .ml_meth = lockedConnectionMethod(stream), .ml_flags = c.METH_O, .ml_doc = "Return a Stream handle for stream_id. The connection owns the stream state; the handle is a stream-scoped command surface (send_response / send_data / end_message)." },
    .{ .ml_name = "close", .ml_meth = lockedConnectionMethod(h2_close), .ml_flags = c.METH_VARARGS, .ml_doc = "Send GOAWAY to shut the connection down: close(error_code=NO_ERROR, last_stream_id=None). last_stream_id defaults to the highest peer stream processed." },
    .{ .ml_name = "has_pending_send", .ml_meth = lockedConnectionMethod(h2_has_pending_send), .ml_flags = c.METH_NOARGS, .ml_doc = "Whether any stream still has body bytes (or a FIN) parked waiting for the send window." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

var h2_getset = [_]c.PyGetSetDef{
    .{ .name = "send_window", .get = lockedConnectionGetter(h2_send_window_get), .set = null, .doc = "The connection-level send window: body bytes that may leave across all streams before a WINDOW_UPDATE (may be negative after a SETTINGS shrink).", .closure = null },
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
    .{ .ml_name = "receive_datagram", .ml_meth = lockedConnectionAndModuleMethod(receive_datagram), .ml_flags = c.METH_VARARGS, .ml_doc = "Feed one received UDP datagram: receive_datagram(datagram, now=0, peer_address=None). peer_address is an optional opaque bytes key for QUIC path validation and migration." },
    .{ .ml_name = "consume_data", .ml_meth = lockedConnectionMethod(h3_consume_data), .ml_flags = c.METH_VARARGS, .ml_doc = "Acknowledge HTTP/3 DATA payload bytes after the application consumes them: consume_data(stream_id, length)." },
    .{ .ml_name = "data_to_send", .ml_meth = lockedConnectionMethod(data_to_send), .ml_flags = c.METH_NOARGS, .ml_doc = "Return and clear the pending outgoing UDP datagrams as a list of bytes (one per datagram - QUIC datagram boundaries are semantic)." },
    .{ .ml_name = "data_to_send_with_addresses", .ml_meth = lockedConnectionMethod(h3_data_to_send_with_addresses), .ml_flags = c.METH_NOARGS, .ml_doc = "Return and clear pending HTTP/3 datagrams with their destination address keys." },
    .{ .ml_name = "_set_endpoint_context", .ml_meth = lockedConnectionMethod(h3_set_endpoint_context), .ml_flags = c.METH_VARARGS, .ml_doc = "Configure endpoint-selected connection IDs before receiving the first Initial." },
    .{ .ml_name = "_endpoint_ready", .ml_meth = lockedConnectionMethod(h3_endpoint_ready), .ml_flags = c.METH_NOARGS, .ml_doc = "Whether the endpoint connection authenticated its first Initial." },
    .{ .ml_name = "_endpoint_connection_id_generation", .ml_meth = lockedConnectionMethod(h3_endpoint_connection_id_generation), .ml_flags = c.METH_NOARGS, .ml_doc = "Return the active local connection ID generation." },
    .{ .ml_name = "_endpoint_peer_address", .ml_meth = lockedConnectionMethod(h3_endpoint_peer_address), .ml_flags = c.METH_NOARGS, .ml_doc = "Return the authenticated default peer address." },
    .{ .ml_name = "challenge_path", .ml_meth = lockedConnectionMethod(h3_challenge_path), .ml_flags = c.METH_VARARGS, .ml_doc = "Queue a QUIC PATH_CHALLENGE for a peer address: challenge_path(peer_address, data). data must be 8 unpredictable bytes. Drain with data_to_send_with_addresses." },
    .{ .ml_name = "use_peer_connection_id", .ml_meth = lockedConnectionMethod(h3_use_peer_connection_id), .ml_flags = c.METH_O, .ml_doc = "Switch future QUIC packets to a peer-issued NEW_CONNECTION_ID sequence: use_peer_connection_id(sequence_number)." },
    .{ .ml_name = "local_connection_ids", .ml_meth = lockedConnectionMethod(h3_local_connection_ids), .ml_flags = c.METH_NOARGS, .ml_doc = "Return every active local QUIC connection ID and sequence number." },
    .{ .ml_name = "issue_connection_id", .ml_meth = lockedConnectionMethod(h3_issue_connection_id), .ml_flags = c.METH_VARARGS, .ml_doc = "Queue a QUIC NEW_CONNECTION_ID for a local CID: issue_connection_id(sequence_number, connection_id, stateless_reset_token, retire_prior_to=0). Drain with data_to_send." },
    .{ .ml_name = "_endpoint_issue_connection_id", .ml_meth = lockedConnectionMethod(h3_endpoint_issue_connection_id), .ml_flags = c.METH_VARARGS, .ml_doc = "Queue a QUIC NEW_CONNECTION_ID owned by QuicEndpoint." },
    .{ .ml_name = "request_key_update", .ml_meth = lockedConnectionMethod(h3_request_key_update), .ml_flags = c.METH_NOARGS, .ml_doc = "Advance QUIC 1-RTT send keys. The next application packet carries the new key phase." },
    .{ .ml_name = "send_request", .ml_meth = lockedConnectionMethod(send_request), .ml_flags = c.METH_VARARGS, .ml_doc = "Open a request stream and return its Stream: send_request(method, target, version, headers). :authority is derived from a host header; the version arg is ignored." },
    .{ .ml_name = "stream", .ml_meth = lockedConnectionMethod(stream), .ml_flags = c.METH_O, .ml_doc = "Return a Stream handle for stream_id (the request's stream_id). The handle is the stream-scoped send surface: send_response / send_data / end_message." },
    .{ .ml_name = "next_timeout", .ml_meth = lockedConnectionMethod(h3_next_timeout), .ml_flags = c.METH_NOARGS, .ml_doc = "The next idle/loss/PTO deadline (same clock as now), or None if no timer is armed." },
    .{ .ml_name = "handle_timeout", .ml_meth = lockedConnectionMethod(h3_handle_timeout), .ml_flags = c.METH_O, .ml_doc = "Fire the timer at time now: handle_timeout(now). Closes on idle timeout or re-queues probes; drain them with data_to_send." },
    .{ .ml_name = "initiate_connection", .ml_meth = lockedConnectionMethod(h3_initiate), .ml_flags = c.METH_NOARGS, .ml_doc = "Open the control stream and send SETTINGS now (RFC 9114 6.2.1), rather than lazily on the first response. Idempotent. Drain it with data_to_send." },
    .{ .ml_name = "is_closed", .ml_meth = lockedConnectionMethod(h3_is_closed), .ml_flags = c.METH_NOARGS, .ml_doc = "Whether the connection has been closed (a peer CONNECTION_CLOSE, or the idle timeout fired)." },
    .{ .ml_name = "idle_timed_out", .ml_meth = lockedConnectionMethod(h3_idle_timed_out), .ml_flags = c.METH_NOARGS, .ml_doc = "Whether the connection was silently closed by the idle timeout (RFC 9000 10.1), as opposed to a CONNECTION_CLOSE." },
    .{ .ml_name = "send_session_ticket", .ml_meth = lockedConnectionMethod(h3_send_session_ticket), .ml_flags = c.METH_VARARGS, .ml_doc = "Queue a TLS NewSessionTicket on a confirmed HTTP/3 server connection and return its PSK when available: send_session_ticket(ticket, lifetime=0, age_add=0, nonce=b'', extensions=b'', max_early_data_size=None). Drain it with data_to_send." },
    .{ .ml_name = "send_new_token", .ml_meth = lockedConnectionMethod(h3_send_new_token), .ml_flags = c.METH_O, .ml_doc = "Queue a QUIC NEW_TOKEN address-validation token from a confirmed HTTP/3 server connection. Drain it with data_to_send." },
    .{ .ml_name = "session_tickets", .ml_meth = lockedConnectionMethod(h3_session_tickets), .ml_flags = c.METH_NOARGS, .ml_doc = "Return received TLS session tickets as a list of zttp.SessionTicket (fields: lifetime, age_add, nonce, ticket, extensions, max_early_data_size, psk)." },
    .{ .ml_name = "validation_tokens", .ml_meth = lockedConnectionMethod(h3_validation_tokens), .ml_flags = c.METH_NOARGS, .ml_doc = "Return NEW_TOKEN address-validation tokens received from the peer for use as validation_token on a future HTTP/3 client connection." },
    .{ .ml_name = "close", .ml_meth = @ptrCast(lockedConnectionKeywordMethod(h3_close)), .ml_flags = c.METH_VARARGS | c.METH_KEYWORDS, .ml_doc = "Send a QUIC CONNECTION_CLOSE: close(app=True, error_code=0, reason=b''). app=True sends an HTTP/3 application close once 1-RTT keys exist; app=False sends a transport close. Drain it with data_to_send." },
    .{ .ml_name = "close_info", .ml_meth = lockedConnectionMethod(h3_close_info), .ml_flags = c.METH_NOARGS, .ml_doc = "The peer's CONNECTION_CLOSE as a zttp.CloseInfo (fields: error_code, reason, is_application), or None if the peer has not closed." },
    .{ .ml_name = "peer_settings", .ml_meth = lockedConnectionMethod(h3_peer_settings), .ml_flags = c.METH_NOARGS, .ml_doc = "The peer's HTTP/3 SETTINGS as a dict (max_field_section_size, qpack_max_table_capacity, qpack_blocked_streams), or None until its SETTINGS frame has been received." },
    .{ .ml_name = "shutdown", .ml_meth = lockedConnectionMethod(h3_shutdown), .ml_flags = c.METH_O, .ml_doc = "Begin a graceful shutdown: send a GOAWAY. Servers announce the first request stream not processed; clients announce the first push ID not accepted (RFC 9114 5.2). A later GOAWAY may only lower the id. Drain it with data_to_send." },
    .{ .ml_name = "goaway_received", .ml_meth = lockedConnectionMethod(h3_goaway_received), .ml_flags = c.METH_NOARGS, .ml_doc = "The id of a GOAWAY received from the peer (RFC 9114 5.2), or None - the peer is shutting down and will not process streams at or above this id." },
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
    if (module_lock_object == null) module_lock_object = py.newRef(module);
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
