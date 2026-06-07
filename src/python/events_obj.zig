//! Python event objects mirroring the core's events: Request, Response, Data,
//! EndOfMessage, plus the NEED_DATA / PAUSED singletons. Each is a small heap
//! type whose attributes are plain Python objects materialised (copied) from the
//! core's buffer slices, so they outlive the next receive_data call.

const std = @import("std");
const py = @import("py.zig");
const c = py.c;
const core = @import("core");
const events = core.events;

const RequestObject = extern struct {
    ob_base: c.PyObject,
    method: py.Object,
    target: py.Object,
    http_version: py.Object,
    headers: py.Object,
};

const ResponseObject = extern struct {
    ob_base: c.PyObject,
    status_code: py.Object,
    reason: py.Object,
    http_version: py.Object,
    headers: py.Object,
};

const DataObject = extern struct {
    ob_base: c.PyObject,
    data: py.Object,
};

const EndOfMessageObject = extern struct {
    ob_base: c.PyObject,
    trailers: py.Object,
};

var request_type: py.Object = null;
var response_type: py.Object = null;
var data_type: py.Object = null;
var end_of_message_type: py.Object = null;
/// Singletons returned when no event is ready / read side is paused.
pub var need_data: py.Object = null;
pub var connection_closed: py.Object = null;

// -- members (read-only attribute exposure) -----------------------------------

fn member(comptime name: [*c]const u8, comptime offset: usize) py.MemberDef {
    return .{ .name = name, .type = c.Py_T_OBJECT_EX, .offset = @intCast(offset), .flags = c.Py_READONLY, .doc = null };
}

var request_members = [_]py.MemberDef{
    member("method", @offsetOf(RequestObject, "method")),
    member("target", @offsetOf(RequestObject, "target")),
    member("http_version", @offsetOf(RequestObject, "http_version")),
    member("headers", @offsetOf(RequestObject, "headers")),
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var response_members = [_]py.MemberDef{
    member("status_code", @offsetOf(ResponseObject, "status_code")),
    member("reason", @offsetOf(ResponseObject, "reason")),
    member("http_version", @offsetOf(ResponseObject, "http_version")),
    member("headers", @offsetOf(ResponseObject, "headers")),
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var data_members = [_]py.MemberDef{
    member("data", @offsetOf(DataObject, "data")),
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var eom_members = [_]py.MemberDef{
    member("trailers", @offsetOf(EndOfMessageObject, "trailers")),
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};

// -- dealloc ------------------------------------------------------------------

fn deallocRequest(o: ?*c.PyObject) callconv(.c) void {
    const s: *RequestObject = @ptrCast(o.?);
    py.gcUntrack(s);
    py.xdecref(s.method);
    py.xdecref(s.target);
    py.xdecref(s.http_version);
    py.xdecref(s.headers);
    py.freeInstance(@ptrCast(s));
}
fn deallocResponse(o: ?*c.PyObject) callconv(.c) void {
    const s: *ResponseObject = @ptrCast(o.?);
    py.gcUntrack(s);
    py.xdecref(s.status_code);
    py.xdecref(s.reason);
    py.xdecref(s.http_version);
    py.xdecref(s.headers);
    py.freeInstance(@ptrCast(s));
}
fn deallocData(o: ?*c.PyObject) callconv(.c) void {
    const s: *DataObject = @ptrCast(o.?);
    py.gcUntrack(s);
    py.xdecref(s.data);
    py.freeInstance(@ptrCast(s));
}
fn deallocEom(o: ?*c.PyObject) callconv(.c) void {
    const s: *EndOfMessageObject = @ptrCast(o.?);
    py.gcUntrack(s);
    py.xdecref(s.trailers);
    py.freeInstance(@ptrCast(s));
}

// -- GC support ---------------------------------------------------------------

// The event types hold strong references to Python objects (and Request/
// Response/EndOfMessage expose mutable header/trailer lists), so they must be
// GC types with traverse/clear; otherwise a cycle through them leaks. tp_alloc
// (PyType_GenericAlloc) already GC-tracks a HAVE_GC instance on creation, so we
// only untrack in dealloc; no explicit track is needed (and double-tracking
// trips an assertion in a debug build).

fn visitObj(obj: py.Object, visit: c.visitproc, arg: ?*anyopaque) c_int {
    if (obj != null) {
        const r = visit.?(obj, arg);
        if (r != 0) return r;
    }
    return 0;
}

fn traverseRequest(o: ?*c.PyObject, visit: c.visitproc, arg: ?*anyopaque) callconv(.c) c_int {
    const s: *RequestObject = @ptrCast(o.?);
    inline for (.{ s.method, s.target, s.http_version, s.headers }) |f| {
        const r = visitObj(f, visit, arg);
        if (r != 0) return r;
    }
    return 0;
}
fn clearRequest(o: ?*c.PyObject) callconv(.c) c_int {
    const s: *RequestObject = @ptrCast(o.?);
    py.clear(&s.method);
    py.clear(&s.target);
    py.clear(&s.http_version);
    py.clear(&s.headers);
    return 0;
}
fn traverseResponse(o: ?*c.PyObject, visit: c.visitproc, arg: ?*anyopaque) callconv(.c) c_int {
    const s: *ResponseObject = @ptrCast(o.?);
    inline for (.{ s.status_code, s.reason, s.http_version, s.headers }) |f| {
        const r = visitObj(f, visit, arg);
        if (r != 0) return r;
    }
    return 0;
}
fn clearResponse(o: ?*c.PyObject) callconv(.c) c_int {
    const s: *ResponseObject = @ptrCast(o.?);
    py.clear(&s.status_code);
    py.clear(&s.reason);
    py.clear(&s.http_version);
    py.clear(&s.headers);
    return 0;
}
fn traverseData(o: ?*c.PyObject, visit: c.visitproc, arg: ?*anyopaque) callconv(.c) c_int {
    const s: *DataObject = @ptrCast(o.?);
    return visitObj(s.data, visit, arg);
}
fn clearData(o: ?*c.PyObject) callconv(.c) c_int {
    const s: *DataObject = @ptrCast(o.?);
    py.clear(&s.data);
    return 0;
}
fn traverseEom(o: ?*c.PyObject, visit: c.visitproc, arg: ?*anyopaque) callconv(.c) c_int {
    const s: *EndOfMessageObject = @ptrCast(o.?);
    return visitObj(s.trailers, visit, arg);
}
fn clearEom(o: ?*c.PyObject) callconv(.c) c_int {
    const s: *EndOfMessageObject = @ptrCast(o.?);
    py.clear(&s.trailers);
    return 0;
}

// -- specs --------------------------------------------------------------------

fn slots(comptime dealloc: anytype, comptime members: anytype, comptime traverse: anytype, comptime clear_fn: anytype) [5]py.Slot {
    return .{
        .{ .slot = c.Py_tp_dealloc, .pfunc = @ptrCast(@constCast(&dealloc)) },
        .{ .slot = c.Py_tp_members, .pfunc = @ptrCast(members) },
        .{ .slot = c.Py_tp_traverse, .pfunc = @ptrCast(@constCast(&traverse)) },
        .{ .slot = c.Py_tp_clear, .pfunc = @ptrCast(@constCast(&clear_fn)) },
        .{ .slot = 0, .pfunc = null },
    };
}

var request_slots = slots(deallocRequest, &request_members, traverseRequest, clearRequest);
var response_slots = slots(deallocResponse, &response_members, traverseResponse, clearResponse);
var data_slots = slots(deallocData, &data_members, traverseData, clearData);
var eom_slots = slots(deallocEom, &eom_members, traverseEom, clearEom);

fn spec(comptime name: [*c]const u8, comptime size: usize, sl: anytype) py.Spec {
    return .{
        .name = name,
        .basicsize = @intCast(size),
        .itemsize = 0,
        .flags = c.Py_TPFLAGS_DEFAULT | c.Py_TPFLAGS_HAVE_GC,
        .slots = sl,
    };
}

var request_spec = spec("zhttp.Request", @sizeOf(RequestObject), &request_slots);
var response_spec = spec("zhttp.Response", @sizeOf(ResponseObject), &response_slots);
var data_spec = spec("zhttp.Data", @sizeOf(DataObject), &data_slots);
var eom_spec = spec("zhttp.EndOfMessage", @sizeOf(EndOfMessageObject), &eom_slots);

// -- header list materialisation ----------------------------------------------

/// Build a Python list of (name, value) bytes tuples from the core headers.
fn buildHeaders(hdrs: []const events.Header) py.Object {
    const list = py.newList(@intCast(hdrs.len));
    if (list == null) return null;
    for (hdrs, 0..) |h, i| {
        const name = py.fromBytes(h.name);
        const value = py.fromBytes(h.value);
        if (name == null or value == null) {
            py.xdecref(name);
            py.xdecref(value);
            py.decref(list);
            return null;
        }
        const tup = py.tupleNew(2);
        if (tup == null) {
            py.decref(name);
            py.decref(value);
            py.decref(list);
            return null;
        }
        py.tupleSet(tup, 0, name);
        py.tupleSet(tup, 1, value);
        py.listSet(list, @intCast(i), tup);
    }
    return list;
}

// -- constructors from core events --------------------------------------------

pub fn fromEvent(ev: events.Event) py.Object {
    return switch (ev) {
        .request => |r| makeRequest(r),
        .response => |r| makeResponse(r),
        .data => |d| makeData(d),
        .end_of_message => |e| makeEom(e),
        .need_data => py.newRef(need_data),
        .connection_closed => py.newRef(connection_closed),
    };
}

fn makeRequest(r: events.Request) py.Object {
    const o = py.allocInstance(request_type);
    if (o == null) return null;
    const s: *RequestObject = @ptrCast(o);
    s.method = py.fromBytes(r.method);
    s.target = py.fromBytes(r.target);
    s.http_version = py.fromBytes(r.http_version);
    s.headers = buildHeaders(r.headers);
    if (s.method == null or s.target == null or s.http_version == null or s.headers == null) {
        py.decref(o);
        return null;
    }
    return o;
}

fn makeResponse(r: events.Response) py.Object {
    const o = py.allocInstance(response_type);
    if (o == null) return null;
    const s: *ResponseObject = @ptrCast(o);
    s.status_code = py.fromU16(r.status_code);
    s.reason = py.fromBytes(r.reason);
    s.http_version = py.fromBytes(r.http_version);
    s.headers = buildHeaders(r.headers);
    if (s.status_code == null or s.reason == null or s.http_version == null or s.headers == null) {
        py.decref(o);
        return null;
    }
    return o;
}

fn makeData(d: events.Data) py.Object {
    const o = py.allocInstance(data_type);
    if (o == null) return null;
    const s: *DataObject = @ptrCast(o);
    s.data = py.fromBytes(d.data);
    if (s.data == null) {
        py.decref(o);
        return null;
    }
    return o;
}

fn makeEom(e: events.EndOfMessage) py.Object {
    const o = py.allocInstance(end_of_message_type);
    if (o == null) return null;
    const s: *EndOfMessageObject = @ptrCast(o);
    s.trailers = buildHeaders(e.trailers);
    if (s.trailers == null) {
        py.decref(o);
        return null;
    }
    return o;
}

// -- registration -------------------------------------------------------------

pub fn register(module: py.Object) bool {
    request_type = py.typeFromSpec(&request_spec);
    response_type = py.typeFromSpec(&response_spec);
    data_type = py.typeFromSpec(&data_spec);
    end_of_message_type = py.typeFromSpec(&eom_spec);
    if (request_type == null or response_type == null or data_type == null or end_of_message_type == null) {
        return false;
    }

    // NEED_DATA / ConnectionClosed are unique sentinel instances of bare types.
    need_data = makeSentinel("zhttp.NeedDataType");
    connection_closed = makeSentinel("zhttp.ConnectionClosedType");
    if (need_data == null or connection_closed == null) return false;

    _ = c.PyModule_AddObjectRef(module, "Request", request_type);
    _ = c.PyModule_AddObjectRef(module, "Response", response_type);
    _ = c.PyModule_AddObjectRef(module, "Data", data_type);
    _ = c.PyModule_AddObjectRef(module, "EndOfMessage", end_of_message_type);
    _ = c.PyModule_AddObjectRef(module, "NEED_DATA", need_data);
    _ = c.PyModule_AddObjectRef(module, "ConnectionClosed", connection_closed);
    return true;
}

var sentinel_slots = [_]py.Slot{.{ .slot = 0, .pfunc = null }};

fn makeSentinel(comptime name: [*c]const u8) py.Object {
    var sp = py.Spec{ .name = name, .basicsize = @sizeOf(c.PyObject), .itemsize = 0, .flags = c.Py_TPFLAGS_DEFAULT, .slots = &sentinel_slots };
    const tp = py.typeFromSpec(&sp);
    if (tp == null) return null;
    defer py.decref(tp);
    return py.allocInstance(tp);
}
