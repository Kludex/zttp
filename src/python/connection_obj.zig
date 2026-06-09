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

const gpa = std.heap.c_allocator;

const SERVER: c_long = 1;
const CLIENT: c_long = 2;
const HTTP1: c_long = 1;
const HTTP2: c_long = 2;

/// The HTTP/1.1 engine: the pull-API reader, the writer, and the per-connection
/// state the send path needs (the request method the next response answers, the
/// keep-alive / upgrade signals captured at parse time).
const H1Engine = struct {
    reader: *Reader,
    writer: *Writer,
    /// The method of the message the next response answers (server: the parsed
    /// request; client: the request we sent), so the connection auto-derives
    /// bodyless framing. Cleared per cycle by start_next_cycle.
    req_method: [16]u8 = undefined,
    req_method_len: usize = 0,
    /// Connection signals for the last parsed request, captured at event time so
    /// they outlive the head buffer. `upgrade_obj` is held Python bytes (or null).
    should_close: bool = false,
    upgrade_obj: py.Object = null,

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

    fn deinit(self: *H1Engine) void {
        self.reader.deinit();
        gpa.destroy(self.reader);
        self.writer.deinit();
        gpa.destroy(self.writer);
        py.xdecref(self.upgrade_obj);
    }
};

/// The HTTP/2 engine: the read-side connection plus the writer and the stream
/// bookkeeping the send path needs. `handshake_sent` gates the lazy preface;
/// `recv_stream` is the most recently parsed request's stream (so `send_response`
/// answers on the right one) and `send_stream` the current outgoing message's.
const H2Engine = struct {
    conn: *H2Connection,
    writer: *H2Writer,
    handshake_sent: bool = false,
    recv_stream: u32 = 0,
    send_stream: u32 = 0,

    fn ensureHandshake(self: *H2Engine) bool {
        if (self.handshake_sent) return true;
        self.writer.sendPreface(&.{}) catch {
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
        self.send_stream = id;
        return id;
    }

    fn sendResponse(self: *H2Engine, stream_id: u32, status: u16, hdrs: *BorrowedHeaders) py.Object {
        if (!self.ensureHandshake()) return null;
        self.writer.sendResponse(stream_id, status, hdrs.headers, false) catch |e| return h2RaiseWrite(e);
        self.conn.registerSendStream(stream_id) catch return c.PyErr_NoMemory();
        self.send_stream = stream_id;
        return py.none();
    }

    /// Queue body bytes on `id` through the flow-controlled send path: the core
    /// emits what the connection and stream send windows allow and parks the rest.
    fn sendData(self: *H2Engine, id: u32, data: []const u8) py.Object {
        self.conn.sendStreamData(self.writer, id, data, false) catch |e| return h2RaiseWrite(e);
        self.send_stream = id;
        return py.none();
    }

    fn endStream(self: *H2Engine, id: u32) py.Object {
        self.conn.sendStreamData(self.writer, id, &.{}, true) catch |e| return h2RaiseWrite(e);
        self.send_stream = id;
        return py.none();
    }

    /// Drain parked DATA that a freshly-parsed WINDOW_UPDATE / SETTINGS credit now
    /// permits. Called from next_event after such an event is produced.
    fn flushSendable(self: *H2Engine) void {
        self.conn.flushSendable(self.writer) catch {};
    }

    // Resolve the stream a body frame targets: an explicit `stream_id`, or the
    // current outgoing stream. Stream 0 is the connection-control stream and can
    // never carry DATA, so a missing selection is a local protocol error rather
    // than silently emitting an invalid frame.
    fn outgoingStream(self: *H2Engine, stream_id: c_long) ?u32 {
        if (stream_id > 0) return @intCast(stream_id);
        if (self.send_stream == 0) {
            _ = py.raise(exceptions.LocalProtocolError, "no HTTP/2 stream selected: send a request or response first, or pass stream_id");
            return null;
        }
        return self.send_stream;
    }

    fn deinit(self: *H2Engine) void {
        self.conn.deinit();
        gpa.destroy(self.conn);
        self.writer.deinit();
        gpa.destroy(self.writer);
    }
};

/// One Python Connection drives exactly one protocol engine, chosen at
/// construction. Modelling it as a tagged union (rather than a set of nullable
/// per-protocol fields) makes the "exactly one is live" invariant structural -
/// an illegal mix of H1 and H2 state cannot be represented - and lets each new
/// protocol slot in as another arm instead of another branch in every method.
const Engine = union(enum) {
    h1: H1Engine,
    h2: H2Engine,

    fn deinit(self: *Engine) void {
        switch (self.*) {
            inline else => |*e| e.deinit(),
        }
    }
};

const ConnectionObject = extern struct {
    ob_base: c.PyObject,
    engine: ?*Engine,
};

var connection_type: py.Object = null;
var stream_type: py.Object = null;

/// A handle to one HTTP/2 stream on a Connection. It is a borrowed view: the
/// Connection owns the stream state (the core's stream map); the handle holds the
/// stream id plus an owned reference to the Connection (so the connection cannot
/// be freed while a handle to it lives) and re-validates on every call. The send
/// window, pending-DATA buffer, and lifecycle all live in the core - the handle
/// is a command surface, never its own I/O buffer, so bytes still drain through
/// the Connection's single data_to_send.
const StreamObject = extern struct {
    ob_base: c.PyObject,
    conn: ?*c.PyObject, // owned reference to the ConnectionObject
    stream_id: u32,

    /// The H2 engine behind the handle, or a Python error if the connection was
    /// torn down or is not HTTP/2. (A Stream only ever wraps an H2 connection, but
    /// the connection object can outlive its engine.)
    fn engine(self: *StreamObject) ?*H2Engine {
        const conn_obj: *ConnectionObject = @ptrCast(self.conn orelse {
            _ = py.raiseRuntime("connection is closed");
            return null;
        });
        const eng = conn_obj.engine orelse {
            _ = py.raiseRuntime("connection is closed");
            return null;
        };
        switch (eng.*) {
            .h2 => |*h| return h,
            else => {
                _ = py.raiseRuntime("not an HTTP/2 connection");
                return null;
            },
        }
    }
};

/// Build a Stream handle for `stream_id` on `conn_obj` (a ConnectionObject). Holds
/// an owned reference to the connection. Returns null with a Python error set on
/// allocation failure. Public so events_obj can attach `event.stream`.
pub fn makeStream(conn_obj: ?*c.PyObject, stream_id: u32) py.Object {
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

fn stream_send_response(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    const e = self.engine() orelse return null;
    var status: c_long = 0;
    var hdrs_seq: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "l|O", &status, &hdrs_seq) == 0) return null;
    if (status < 0 or status > 999) return py.raiseValue("status code out of range");
    var hdrs: ?BorrowedHeaders = null;
    defer if (hdrs) |*h| h.deinit();
    if (hdrs_seq != null and !py.isNone(hdrs_seq)) {
        hdrs = borrowHeaders(hdrs_seq) orelse return null;
    }
    var h = hdrs orelse BorrowedHeaders{ .headers = &.{}, .refs = &.{} };
    return e.sendResponse(self.stream_id, @intCast(status), &h);
}

fn stream_send_data(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    const e = self.engine() orelse return null;
    const data = py.asBytes(arg) orelse return null;
    return e.sendData(self.stream_id, data);
}

fn stream_end_message(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    const e = self.engine() orelse return null;
    var hdrs_seq: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "|O", &hdrs_seq) == 0) return null;
    if (hdrs_seq != null and !py.isNone(hdrs_seq)) {
        return py.raise(exceptions.LocalProtocolError, "HTTP/2 send-side trailers are not supported yet");
    }
    return e.endStream(self.stream_id);
}

fn stream_id_get(self_obj: ?*c.PyObject, _: ?*anyopaque) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    return c.PyLong_FromUnsignedLong(self.stream_id);
}

fn stream_repr(self_obj: ?*c.PyObject) callconv(.c) py.Object {
    const self: *StreamObject = @ptrCast(self_obj.?);
    return c.PyUnicode_FromFormat("Stream(stream_id=%u)", self.stream_id);
}

var stream_methods = [_]py.MethodDef{
    .{ .ml_name = "send_response", .ml_meth = stream_send_response, .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize a response head on this stream: send_response(status, headers=None)." },
    .{ .ml_name = "send_data", .ml_meth = stream_send_data, .ml_flags = c.METH_O, .ml_doc = "Queue body bytes on this stream (flow-controlled; parked until the send window allows)." },
    .{ .ml_name = "end_message", .ml_meth = stream_end_message, .ml_flags = c.METH_VARARGS, .ml_doc = "End the outgoing message on this stream (empty END_STREAM DATA)." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

var stream_getset = [_]c.PyGetSetDef{
    .{ .name = "stream_id", .get = stream_id_get, .set = null, .doc = "The HTTP/2 stream id this handle addresses.", .closure = null },
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

fn new(tp: ?*c.PyTypeObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
    var role_val: c_long = 0;
    var protocol_val: c_long = HTTP1;
    // The kwlist parameter type differs across CPython versions (char** in 3.12,
    // const char* const* in 3.13+), so build a plain C-pointer array and ptrCast
    // it to whatever the translated signature expects.
    var kwlist = [_][*c]u8{ @constCast("role"), @constCast("protocol"), null };
    if (c.PyArg_ParseTupleAndKeywords(args, kwds, "l|l", @ptrCast(&kwlist), &role_val, &protocol_val) == 0) return null;
    const role: Role = switch (role_val) {
        SERVER => .server,
        CLIENT => .client,
        else => return py.raiseValue("role must be zttp.SERVER or zttp.CLIENT"),
    };
    if (protocol_val != HTTP1 and protocol_val != HTTP2) return py.raiseValue("protocol must be zttp.HTTP1 or zttp.HTTP2");

    const alloc = tp.?.tp_alloc.?;
    const obj = alloc(tp, 0);
    if (obj == null) return null;
    const self: *ConnectionObject = @ptrCast(obj);
    self.engine = null;

    const engine = buildEngine(role, protocol_val) orelse {
        py.decref(obj);
        return null;
    };
    self.engine = engine;
    return obj;
}

fn buildEngine(role: Role, protocol_val: c_long) ?*Engine {
    const engine = gpa.create(Engine) catch {
        _ = c.PyErr_NoMemory();
        return null;
    };

    if (protocol_val == HTTP2) {
        const conn = gpa.create(H2Connection) catch {
            gpa.destroy(engine);
            _ = c.PyErr_NoMemory();
            return null;
        };
        conn.* = H2Connection.init(gpa, if (role == .server) H2Role.server else H2Role.client);
        const writer = gpa.create(H2Writer) catch {
            conn.deinit();
            gpa.destroy(conn);
            gpa.destroy(engine);
            _ = c.PyErr_NoMemory();
            return null;
        };
        writer.* = H2Writer.init(gpa, if (role == .server) core.h2.writer.Role.server else core.h2.writer.Role.client);
        engine.* = .{ .h2 = .{ .conn = conn, .writer = writer } };
        return engine;
    }

    const reader = gpa.create(Reader) catch {
        gpa.destroy(engine);
        _ = c.PyErr_NoMemory();
        return null;
    };
    reader.* = Reader.init(gpa, role);
    const writer = gpa.create(Writer) catch {
        reader.deinit();
        gpa.destroy(reader);
        gpa.destroy(engine);
        _ = c.PyErr_NoMemory();
        return null;
    };
    writer.* = Writer.init(gpa);
    engine.* = .{ .h1 = .{ .reader = reader, .writer = writer } };
    return engine;
}

fn dealloc(self_obj: ?*c.PyObject) callconv(.c) void {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    if (self.engine) |engine| {
        engine.deinit();
        gpa.destroy(engine);
    }
    py.freeInstance(@ptrCast(self));
}

/// The H1 engine, or a "connection is closed" error when this is not an H1
/// connection or has been torn down. Used by H1-only API (keep-alive / upgrade).
fn h1(self: *ConnectionObject) ?*H1Engine {
    const engine = self.engine orelse {
        _ = py.raiseRuntime("connection is closed");
        return null;
    };
    switch (engine.*) {
        .h1 => |*e| return e,
        else => {
            _ = py.raiseRuntime("connection is closed");
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
            e.conn.feed(bytes) catch |err| return exceptions.raiseH2(err);
            return py.none();
        },
        .h1 => |*e| {
            e.reader.feed(bytes) catch |err| return exceptions.raiseParse(err); // MessageTooLong -> RemoteProtocolError
            return py.none();
        },
    }
}

fn next_event(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    switch (engine.*) {
        .h2 => |*e| {
            const ev = e.conn.nextEvent() catch |err| return exceptions.raiseH2(err);
            if (ev == .request) e.recv_stream = ev.request.stream_id;
            // A parsed WINDOW_UPDATE / SETTINGS may have credited a send window;
            // drain any DATA that was parked waiting for it. The bytes land in the
            // writer's buffer for the next data_to_send.
            if (ev == .window_update or ev == .settings) e.flushSendable();
            return events_obj.fromH2Event(ev);
        },
        .h1 => |*e| {
            const ev = e.reader.nextEvent() catch |err| return exceptions.raiseParse(err);
            if (ev == .request) {
                e.rememberMethod(ev.request.method);
                e.should_close = e.reader.shouldClose();
                py.xdecref(e.upgrade_obj);
                e.upgrade_obj = if (e.reader.upgrade()) |u| py.fromBytes(u) else null;
            }
            return events_obj.fromH1Event(ev);
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
        py.decref(item); // the pair tuple itself is not needed past this point
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

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        const lx = if (x >= 'A' and x <= 'Z') x + 32 else x;
        const ly = if (y >= 'A' and y <= 'Z') y + 32 else y;
        if (lx != ly) return false;
    }
    return true;
}

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
            continue; // dropped from the regular list
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
            e.writer.sendRequest(mb, tb, vb, hdrs.headers) catch |err| return raiseWrite(err);
            e.rememberMethod(mb);
            e.reader.setRequestMethod(mb);
            return py.none();
        },
    }
}

fn send_response(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    var status: c_long = 0;
    var hdrs_seq: ?*c.PyObject = null;
    var stream_id: c_long = -1; // HTTP/2 only; -1 means "the last parsed request"
    if (c.PyArg_ParseTuple(args, "l|Ol", &status, &hdrs_seq, &stream_id) == 0) return null;
    if (status < 0 or status > 999) return py.raiseValue("status code out of range");

    var hdrs: ?BorrowedHeaders = null;
    defer if (hdrs) |*h| h.deinit();
    if (hdrs_seq != null and !py.isNone(hdrs_seq)) {
        hdrs = borrowHeaders(hdrs_seq) orelse return null;
    }
    const header_slice = if (hdrs) |h| h.headers else &.{};

    switch (engine.*) {
        .h2 => |*e| {
            // HTTP/2: the response answers on `stream_id` if given - required when
            // several requests are outstanding - else the most recently parsed
            // request's stream (the single-request convenience).
            const id: u32 = if (stream_id >= 0) @intCast(stream_id) else e.recv_stream;
            var h = hdrs orelse BorrowedHeaders{ .headers = &.{}, .refs = &.{} };
            return e.sendResponse(id, @intCast(status), &h);
        },
        .h1 => |*e| {
            const rb = core.h1.writer.reasonPhrase(@intCast(status));
            e.writer.sendResponse("1.1", @intCast(status), rb, header_slice, e.method()) catch |err| return raiseWrite(err);
            return py.none();
        },
    }
}

fn send_informational(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const e = h1(self) orelse return null;
    var status: c_long = 0;
    var hdrs_seq: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "l|O", &status, &hdrs_seq) == 0) return null;
    if (status < 100 or status > 199) return py.raiseValue("informational status code must be in 100..199");
    if (status == 101) return py.raiseValue("101 Switching Protocols is a terminal upgrade response, not interim");
    if (hdrs_seq == null or py.isNone(hdrs_seq)) {
        e.writer.sendInformational(@intCast(status), &.{}) catch |err| return raiseWrite(err);
    } else {
        var hdrs = borrowHeaders(hdrs_seq) orelse return null;
        defer hdrs.deinit();
        e.writer.sendInformational(@intCast(status), hdrs.headers) catch |err| return raiseWrite(err);
    }
    return py.none();
}

fn send_data(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    var data_obj: ?*c.PyObject = null;
    var stream_id: c_long = -1; // HTTP/2 only
    if (c.PyArg_ParseTuple(args, "O|l", &data_obj, &stream_id) == 0) return null;
    const data = py.asBytes(data_obj) orelse return null;
    switch (engine.*) {
        .h2 => |*e| {
            const id = e.outgoingStream(stream_id) orelse return null;
            return e.sendData(id, data);
        },
        .h1 => |*e| {
            e.writer.sendData(data) catch |err| return raiseWrite(err);
            return py.none();
        },
    }
}

fn end_message(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    var hdrs_seq: ?*c.PyObject = null;
    var stream_id: c_long = -1; // HTTP/2 only
    if (c.PyArg_ParseTuple(args, "|Ol", &hdrs_seq, &stream_id) == 0) return null;
    switch (engine.*) {
        .h2 => |*e| {
            // HTTP/2 ends a message with an empty END_STREAM DATA frame. Trailers
            // are not yet supported on the send side.
            if (hdrs_seq != null and !py.isNone(hdrs_seq)) {
                return py.raise(exceptions.LocalProtocolError, "HTTP/2 send-side trailers are not supported yet");
            }
            const id = e.outgoingStream(stream_id) orelse return null;
            return e.endStream(id);
        },
        .h1 => |*e| {
            if (hdrs_seq == null or py.isNone(hdrs_seq)) {
                e.writer.endMessage(&.{}) catch |err| return raiseWrite(err);
            } else {
                var hdrs = borrowHeaders(hdrs_seq) orelse return null;
                defer hdrs.deinit();
                e.writer.endMessage(hdrs.headers) catch |err| return raiseWrite(err);
            }
            return py.none();
        },
    }
}

fn data_to_send(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const engine = self.engine orelse return py.raiseRuntime("connection is closed");
    const pending = switch (engine.*) {
        .h2 => |*e| e.writer.pending(),
        .h1 => |*e| e.writer.pending(),
    };
    const out = py.fromBytes(pending);
    if (out == null) return null;
    switch (engine.*) {
        .h2 => |*e| e.writer.clear(),
        .h1 => |*e| e.writer.clear(),
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
    switch (engine.*) {
        .h2 => {},
        else => return py.raiseRuntime("streams exist only on an HTTP/2 connection"),
    }
    const id = c.PyLong_AsLong(arg);
    if (id <= 0) {
        if (c.PyErr_Occurred() != null) return null;
        return py.raiseValue("stream_id must be a positive integer");
    }
    return makeStream(self_obj, @intCast(id));
}

var methods = [_]py.MethodDef{
    .{ .ml_name = "receive_data", .ml_meth = receive_data, .ml_flags = c.METH_O, .ml_doc = "Append received bytes (empty bytes signals EOF)." },
    .{ .ml_name = "stream", .ml_meth = stream, .ml_flags = c.METH_O, .ml_doc = "Return a Stream handle for stream_id on this HTTP/2 connection. The connection owns the stream state; the handle is a stream-scoped command surface (send_response / send_data / end_message)." },
    .{ .ml_name = "next_event", .ml_meth = next_event, .ml_flags = c.METH_NOARGS, .ml_doc = "Return the next parse event, or NEED_DATA." },
    .{ .ml_name = "start_next_cycle", .ml_meth = next_message, .ml_flags = c.METH_NOARGS, .ml_doc = "Reset to read the next message on a keep-alive connection." },
    .{ .ml_name = "send_request", .ml_meth = send_request, .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize a request head: send_request(method, target, version, headers)." },
    .{ .ml_name = "send_response", .ml_meth = send_response, .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize a response head: send_response(status, headers=None, stream_id=...). The reason phrase is derived from the status; the version is 1.1. Bodyless framing (HEAD / 204 / 304) is derived automatically. stream_id is HTTP/2 only." },
    .{ .ml_name = "send_informational", .ml_meth = send_informational, .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize an interim 1xx response: send_informational(status, headers=None). The real response still follows on the same cycle." },
    .{ .ml_name = "send_data", .ml_meth = send_data, .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize a run of body bytes: send_data(data, stream_id=...). stream_id is HTTP/2 only." },
    .{ .ml_name = "end_message", .ml_meth = end_message, .ml_flags = c.METH_VARARGS, .ml_doc = "End the outgoing message: end_message(trailers=None, stream_id=...). stream_id is HTTP/2 only." },
    .{ .ml_name = "data_to_send", .ml_meth = data_to_send, .ml_flags = c.METH_NOARGS, .ml_doc = "Return and clear the pending outgoing bytes." },
    .{ .ml_name = "should_close", .ml_meth = should_close, .ml_flags = c.METH_NOARGS, .ml_doc = "Whether the connection must close after the last request (Connection: close / HTTP/1.0)." },
    .{ .ml_name = "upgrade", .ml_meth = upgrade, .ml_flags = c.METH_NOARGS, .ml_doc = "The last request's Upgrade value if it asked to upgrade (Connection: upgrade), else None." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

var slots = [_]py.Slot{
    .{ .slot = c.Py_tp_new, .pfunc = @ptrCast(@constCast(&new)) },
    .{ .slot = c.Py_tp_dealloc, .pfunc = @ptrCast(@constCast(&dealloc)) },
    .{ .slot = c.Py_tp_methods, .pfunc = @ptrCast(&methods) },
    .{ .slot = 0, .pfunc = null },
};

var spec = py.Spec{
    .name = "zttp.Connection",
    .basicsize = @sizeOf(ConnectionObject),
    .itemsize = 0,
    .flags = c.Py_TPFLAGS_DEFAULT,
    .slots = &slots,
};

pub fn register(module: py.Object) bool {
    connection_type = py.typeFromSpec(&spec);
    if (connection_type == null) return false;
    stream_type = py.typeFromSpec(&stream_spec);
    if (stream_type == null) return false;
    _ = c.PyModule_AddObjectRef(module, "Connection", connection_type);
    _ = c.PyModule_AddObjectRef(module, "Stream", stream_type);
    _ = c.PyModule_AddIntConstant(module, "SERVER", SERVER);
    _ = c.PyModule_AddIntConstant(module, "CLIENT", CLIENT);
    _ = c.PyModule_AddIntConstant(module, "HTTP1", HTTP1);
    _ = c.PyModule_AddIntConstant(module, "HTTP2", HTTP2);
    return true;
}
