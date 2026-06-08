//! The Python `Connection` object: a thin wrapper over the core Reader exposing
//! the sans-IO pull API. `receive_data(bytes)` appends to the parse buffer;
//! `next_event()` returns the next Request/Response/Data/EndOfMessage event, or
//! the NEED_DATA singleton. The write side (send/data_to_send) is added on top.

const std = @import("std");
const py = @import("py.zig");
const c = py.c;
const core = @import("core");
const Reader = core.reader.Reader;
const Role = core.reader.Role;
const Writer = core.writer.Writer;
const events = core.events;
const events_obj = @import("events_obj.zig");
const exceptions = @import("exceptions.zig");

const H2Connection = core.h2.connection.Connection;
const H2Role = core.h2.connection.Role;

const gpa = std.heap.c_allocator;

const SERVER: c_long = 1;
const CLIENT: c_long = 2;
const HTTP1: c_long = 1;
const HTTP2: c_long = 2;

// One Python Connection backs either an HTTP/1.1 Reader+Writer or an HTTP/2
// engine, chosen by the `protocol` argument. The H1 path (reader/writer
// non-null, h2 null) is byte-for-byte the original; H2 leaves reader/writer null
// and drives `h2` instead. Methods dispatch on which is set.
const ConnectionObject = extern struct {
    ob_base: c.PyObject,
    reader: ?*Reader,
    writer: ?*Writer,
    h2: ?*H2Connection,
    /// The method of the message the next response answers (server: the parsed
    /// request; client: the request we sent), so the connection auto-derives
    /// bodyless framing. Cleared per cycle by start_next_cycle.
    req_method: [16]u8,
    req_method_len: usize,
    /// Connection signals for the last parsed request, captured at event time so
    /// they outlive the head buffer. `upgrade_obj` is held Python bytes (or null).
    should_close: bool,
    upgrade_obj: py.Object,
};

var connection_type: py.Object = null;

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
    self.reader = null;
    self.writer = null;
    self.h2 = null;
    self.req_method_len = 0;
    self.should_close = false;
    self.upgrade_obj = null;

    if (protocol_val == HTTP2) {
        const h = gpa.create(H2Connection) catch {
            py.decref(obj);
            return c.PyErr_NoMemory();
        };
        h.* = H2Connection.init(gpa, if (role == .server) H2Role.server else H2Role.client);
        self.h2 = h;
        return obj;
    }

    const r = gpa.create(Reader) catch {
        py.decref(obj);
        return c.PyErr_NoMemory();
    };
    r.* = Reader.init(gpa, role);
    self.reader = r;

    const wctx = gpa.create(Writer) catch {
        py.decref(obj);
        return c.PyErr_NoMemory();
    };
    wctx.* = Writer.init(gpa);
    self.writer = wctx;
    return obj;
}

fn dealloc(self_obj: ?*c.PyObject) callconv(.c) void {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    if (self.reader) |r| {
        r.deinit();
        gpa.destroy(r);
    }
    if (self.writer) |wc| {
        wc.deinit();
        gpa.destroy(wc);
    }
    if (self.h2) |h| {
        h.deinit();
        gpa.destroy(h);
    }
    py.xdecref(self.upgrade_obj);
    py.freeInstance(@ptrCast(self));
}

fn receive_data(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const bytes = py.asBytes(arg) orelse return null;
    if (self.h2) |h| {
        h.feed(bytes) catch |e| return exceptions.raiseH2(e);
        return py.none();
    }
    const r = self.reader orelse return py.raiseRuntime("connection is closed");
    r.feed(bytes) catch |e| return exceptions.raiseParse(e); // MessageTooLong -> RemoteProtocolError
    return py.none();
}

fn rememberMethod(self: *ConnectionObject, method: []const u8) void {
    if (method.len > self.req_method.len) {
        self.req_method_len = 0;
        return;
    }
    @memcpy(self.req_method[0..method.len], method);
    self.req_method_len = method.len;
}

fn next_event(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    if (self.h2) |h| {
        const ev = h.nextEvent() catch |e| return exceptions.raiseH2(e);
        return events_obj.fromH2Event(ev);
    }
    const r = self.reader orelse return py.raiseRuntime("connection is closed");
    const ev = r.nextEvent() catch |e| return exceptions.raiseParse(e);
    if (ev == .request) {
        rememberMethod(self, ev.request.method);
        self.should_close = r.shouldClose();
        py.xdecref(self.upgrade_obj);
        self.upgrade_obj = if (r.upgrade()) |u| py.fromBytes(u) else null;
    }
    return events_obj.fromH1Event(ev);
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

fn send_request(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const wc = self.writer orelse return py.raiseRuntime("connection is closed");
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
    wc.sendRequest(mb, tb, vb, hdrs.headers) catch |e| return raiseWrite(e);
    rememberMethod(self, mb);
    if (self.reader) |r| r.setRequestMethod(mb);
    return py.none();
}

fn send_response(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const wc = self.writer orelse return py.raiseRuntime("connection is closed");
    var version: ?*c.PyObject = null;
    var status: c_long = 0;
    var reason: ?*c.PyObject = null;
    var hdrs_seq: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "OlOO", &version, &status, &reason, &hdrs_seq) == 0) return null;
    if (status < 0 or status > 999) return py.raiseValue("status code out of range");
    const vb = py.asBytes(version) orelse return null;
    const rb = py.asBytes(reason) orelse return null;
    var hdrs = borrowHeaders(hdrs_seq) orelse return null;
    defer hdrs.deinit();
    const method = self.req_method[0..self.req_method_len];
    wc.sendResponse(vb, @intCast(status), rb, hdrs.headers, method) catch |e| return raiseWrite(e);
    return py.none();
}

fn send_data(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const wc = self.writer orelse return py.raiseRuntime("connection is closed");
    const data = py.asBytes(arg) orelse return null;
    wc.sendData(data) catch |e| return raiseWrite(e);
    return py.none();
}

fn end_message(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const wc = self.writer orelse return py.raiseRuntime("connection is closed");
    var hdrs_seq: ?*c.PyObject = null;
    if (c.PyArg_ParseTuple(args, "|O", &hdrs_seq) == 0) return null;
    if (hdrs_seq == null or py.isNone(hdrs_seq)) {
        wc.endMessage(&.{}) catch |e| return raiseWrite(e);
    } else {
        var hdrs = borrowHeaders(hdrs_seq) orelse return null;
        defer hdrs.deinit();
        wc.endMessage(hdrs.headers) catch |e| return raiseWrite(e);
    }
    return py.none();
}

fn data_to_send(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const wc = self.writer orelse return py.raiseRuntime("connection is closed");
    const out = py.fromBytes(wc.pending());
    if (out == null) return null;
    wc.clear();
    return out;
}

fn raiseWrite(e: core.writer.WriteError) py.Object {
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
    const r = self.reader orelse return py.raiseRuntime("connection is closed");
    r.reset();
    self.req_method_len = 0;
    self.should_close = false;
    py.xdecref(self.upgrade_obj);
    self.upgrade_obj = null;
    return py.none();
}

fn should_close(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    return py.boolean(self.should_close);
}

fn upgrade(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const obj = self.upgrade_obj orelse return py.none();
    py.incref(obj);
    return obj;
}

var methods = [_]py.MethodDef{
    .{ .ml_name = "receive_data", .ml_meth = receive_data, .ml_flags = c.METH_O, .ml_doc = "Append received bytes (empty bytes signals EOF)." },
    .{ .ml_name = "next_event", .ml_meth = next_event, .ml_flags = c.METH_NOARGS, .ml_doc = "Return the next parse event, or NEED_DATA." },
    .{ .ml_name = "start_next_cycle", .ml_meth = next_message, .ml_flags = c.METH_NOARGS, .ml_doc = "Reset to read the next message on a keep-alive connection." },
    .{ .ml_name = "send_request", .ml_meth = send_request, .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize a request head: send_request(method, target, version, headers)." },
    .{ .ml_name = "send_response", .ml_meth = send_response, .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize a response head: send_response(version, status, reason, headers). Bodyless framing (HEAD / 1xx / 204 / 304) is derived automatically." },
    .{ .ml_name = "send_data", .ml_meth = send_data, .ml_flags = c.METH_O, .ml_doc = "Serialize a run of body bytes (chunk-framed if the head was chunked)." },
    .{ .ml_name = "end_message", .ml_meth = end_message, .ml_flags = c.METH_VARARGS, .ml_doc = "End the outgoing message: end_message(trailers=None)." },
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
    _ = c.PyModule_AddObjectRef(module, "Connection", connection_type);
    _ = c.PyModule_AddIntConstant(module, "SERVER", SERVER);
    _ = c.PyModule_AddIntConstant(module, "CLIENT", CLIENT);
    _ = c.PyModule_AddIntConstant(module, "HTTP1", HTTP1);
    _ = c.PyModule_AddIntConstant(module, "HTTP2", HTTP2);
    return true;
}
