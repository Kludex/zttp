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

const gpa = std.heap.c_allocator;

const SERVER: c_long = 1;
const CLIENT: c_long = 2;

const ConnectionObject = extern struct {
    ob_base: c.PyObject,
    reader: ?*Reader,
    writer: ?*Writer,
};

var connection_type: py.Object = null;

fn new(tp: ?*c.PyTypeObject, args: ?*c.PyObject, kwds: ?*c.PyObject) callconv(.c) py.Object {
    _ = kwds;
    var role_val: c_long = 0;
    if (c.PyArg_ParseTuple(args, "l", &role_val) == 0) return null;
    const role: Role = switch (role_val) {
        SERVER => .server,
        CLIENT => .client,
        else => return py.raiseValue("role must be zhttp.SERVER or zhttp.CLIENT"),
    };

    const alloc = tp.?.tp_alloc.?;
    const obj = alloc(tp, 0);
    if (obj == null) return null;
    const self: *ConnectionObject = @ptrCast(obj);

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
    py.freeInstance(@ptrCast(self));
}

fn receive_data(self_obj: ?*c.PyObject, arg: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const r = self.reader orelse return py.raiseRuntime("connection is closed");
    const bytes = py.asBytes(arg) orelse return null;
    r.feed(bytes) catch return c.PyErr_NoMemory();
    return py.none();
}

fn next_event(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const r = self.reader orelse return py.raiseRuntime("connection is closed");
    const ev = r.nextEvent() catch |e| return exceptions.raiseParse(e);
    return events_obj.fromEvent(ev);
}

/// Borrow a list/tuple of (name, value) bytes pairs into a Zig Header slice.
/// The returned headers point into the Python bytes objects, which the caller's
/// sequence keeps alive for the duration of the send call. Caller frees `out`.
fn borrowHeaders(seq: py.Object, out: *[]events.Header) bool {
    const n = c.PySequence_Size(seq);
    if (n < 0) {
        _ = py.raiseType("headers must be a sequence of (name, value) pairs");
        return false;
    }
    const slice = gpa.alloc(events.Header, @intCast(n)) catch {
        _ = c.PyErr_NoMemory();
        return false;
    };
    var i: c.Py_ssize_t = 0;
    while (i < n) : (i += 1) {
        const item = c.PySequence_GetItem(seq, i); // new ref
        if (item == null) {
            gpa.free(slice);
            return false;
        }
        defer py.decref(item);
        const name = c.PySequence_GetItem(item, 0);
        const value = c.PySequence_GetItem(item, 1);
        defer py.xdecref(name);
        defer py.xdecref(value);
        if (name == null or value == null) {
            gpa.free(slice);
            _ = py.raiseType("each header must be a (name, value) pair");
            return false;
        }
        const nb = py.asBytes(name) orelse {
            gpa.free(slice);
            return false;
        };
        const vb = py.asBytes(value) orelse {
            gpa.free(slice);
            return false;
        };
        slice[@intCast(i)] = .{ .name = nb, .value = vb };
    }
    out.* = slice;
    return true;
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
    var hdrs: []events.Header = undefined;
    if (!borrowHeaders(hdrs_seq, &hdrs)) return null;
    defer gpa.free(hdrs);
    wc.sendRequest(mb, tb, vb, hdrs) catch |e| return raiseWrite(e);
    return py.none();
}

fn send_response(self_obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const wc = self.writer orelse return py.raiseRuntime("connection is closed");
    var version: ?*c.PyObject = null;
    var status: c_long = 0;
    var reason: ?*c.PyObject = null;
    var hdrs_seq: ?*c.PyObject = null;
    var bodyless: c_int = 0;
    if (c.PyArg_ParseTuple(args, "OlOO|p", &version, &status, &reason, &hdrs_seq, &bodyless) == 0) return null;
    if (status < 0 or status > 999) return py.raiseValue("status code out of range");
    const vb = py.asBytes(version) orelse return null;
    const rb = py.asBytes(reason) orelse return null;
    var hdrs: []events.Header = undefined;
    if (!borrowHeaders(hdrs_seq, &hdrs)) return null;
    defer gpa.free(hdrs);
    wc.sendResponse(vb, @intCast(status), rb, hdrs, bodyless != 0) catch |e| return raiseWrite(e);
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
        var hdrs: []events.Header = undefined;
        if (!borrowHeaders(hdrs_seq, &hdrs)) return null;
        defer gpa.free(hdrs);
        wc.endMessage(hdrs) catch |e| return raiseWrite(e);
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
    return switch (e) {
        error.OutOfMemory => c.PyErr_NoMemory(),
        error.LocalProtocol => py.raise(exceptions.LocalProtocolError, "invalid send for current connection state"),
    };
}

fn next_message(self_obj: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    // Convenience for keep-alive: reset the reader for the next request/response.
    const self: *ConnectionObject = @ptrCast(self_obj.?);
    const r = self.reader orelse return py.raiseRuntime("connection is closed");
    r.reset();
    return py.none();
}

var methods = [_]py.MethodDef{
    .{ .ml_name = "receive_data", .ml_meth = receive_data, .ml_flags = c.METH_O, .ml_doc = "Append received bytes (empty bytes signals EOF)." },
    .{ .ml_name = "next_event", .ml_meth = next_event, .ml_flags = c.METH_NOARGS, .ml_doc = "Return the next parse event, or NEED_DATA." },
    .{ .ml_name = "start_next_cycle", .ml_meth = next_message, .ml_flags = c.METH_NOARGS, .ml_doc = "Reset to read the next message on a keep-alive connection." },
    .{ .ml_name = "send_request", .ml_meth = send_request, .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize a request head: send_request(method, target, version, headers)." },
    .{ .ml_name = "send_response", .ml_meth = send_response, .ml_flags = c.METH_VARARGS, .ml_doc = "Serialize a response head: send_response(version, status, reason, headers, bodyless=False)." },
    .{ .ml_name = "send_data", .ml_meth = send_data, .ml_flags = c.METH_O, .ml_doc = "Serialize a run of body bytes (chunk-framed if the head was chunked)." },
    .{ .ml_name = "end_message", .ml_meth = end_message, .ml_flags = c.METH_VARARGS, .ml_doc = "End the outgoing message: end_message(trailers=None)." },
    .{ .ml_name = "data_to_send", .ml_meth = data_to_send, .ml_flags = c.METH_NOARGS, .ml_doc = "Return and clear the pending outgoing bytes." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

var slots = [_]py.Slot{
    .{ .slot = c.Py_tp_new, .pfunc = @ptrCast(@constCast(&new)) },
    .{ .slot = c.Py_tp_dealloc, .pfunc = @ptrCast(@constCast(&dealloc)) },
    .{ .slot = c.Py_tp_methods, .pfunc = @ptrCast(&methods) },
    .{ .slot = 0, .pfunc = null },
};

var spec = py.Spec{
    .name = "zhttp.Connection",
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
    return true;
}
