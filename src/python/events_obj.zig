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
    path: py.Object,
    query: py.Object,
    http_version: py.Object,
    headers: py.Object,
    expect_continue: c_char,
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
/// The two terminal sentinels: NEED_DATA (no event yet) and CONNECTION_CLOSED
/// (the peer closed). Each is a unique instance compared with `is`; its bare
/// type (NeedData / ConnectionClosed) is exposed so the Event union can name it.
var need_data_type: py.Object = null;
var connection_closed_type: py.Object = null;
pub var need_data: py.Object = null;
pub var connection_closed: py.Object = null;

// -- members (read-only attribute exposure) -----------------------------------

fn member(comptime name: [*c]const u8, comptime offset: usize) py.MemberDef {
    return .{ .name = name, .type = c.Py_T_OBJECT_EX, .offset = @intCast(offset), .flags = c.Py_READONLY, .doc = null };
}

var request_members = [_]py.MemberDef{
    member("method", @offsetOf(RequestObject, "method")),
    member("target", @offsetOf(RequestObject, "target")),
    member("path", @offsetOf(RequestObject, "path")),
    member("query", @offsetOf(RequestObject, "query")),
    member("http_version", @offsetOf(RequestObject, "http_version")),
    member("headers", @offsetOf(RequestObject, "headers")),
    .{ .name = "expect_continue", .type = c.Py_T_BOOL, .offset = @intCast(@offsetOf(RequestObject, "expect_continue")), .flags = c.Py_READONLY, .doc = null },
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
    py.xdecref(s.path);
    py.xdecref(s.query);
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
    inline for (.{ s.method, s.target, s.path, s.query, s.http_version, s.headers }) |f| {
        const r = visitObj(f, visit, arg);
        if (r != 0) return r;
    }
    return 0;
}
fn clearRequest(o: ?*c.PyObject) callconv(.c) c_int {
    const s: *RequestObject = @ptrCast(o.?);
    py.clear(&s.method);
    py.clear(&s.target);
    py.clear(&s.path);
    py.clear(&s.query);
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

// -- repr & equality ----------------------------------------------------------

// Events get a dataclass-like repr (e.g. Request(method=b'GET', target=b'/',
// http_version=b'1.1', headers=[...])) and value equality across all fields, so
// they read well in a REPL and compare cleanly in tests - matching h11.

/// The exposed object fields of an event type, as (python_name, struct_field).
fn FieldInfo(comptime T: type) type {
    return struct { name: []const u8, field: []const u8, _t: type = T };
}

fn reprFields(comptime T: type, comptime short_name: []const u8, comptime fields: anytype) fn (?*c.PyObject) callconv(.c) py.Object {
    return struct {
        fn repr(o: ?*c.PyObject) callconv(.c) py.Object {
            const s: *T = @ptrCast(o.?);
            var parts: py.Object = py.fromStr(short_name ++ "(");
            if (parts == null) return null;
            inline for (fields, 0..) |f, i| {
                const sep = if (i == 0) f.name ++ "=" else ", " ++ f.name ++ "=";
                appendStr(&parts, sep);
                appendRepr(&parts, @field(s, f.field));
            }
            appendStr(&parts, ")");
            return parts;
        }
    }.repr;
}

fn appendStr(acc: *py.Object, lit: []const u8) void {
    if (acc.* == null) return;
    const piece = py.fromStr(lit);
    concatInto(acc, piece);
}

fn appendRepr(acc: *py.Object, field: py.Object) void {
    if (acc.* == null) return;
    const r = if (field == null) py.fromStr("None") else c.PyObject_Repr(field);
    concatInto(acc, r);
}

fn concatInto(acc: *py.Object, piece: py.Object) void {
    if (piece == null) {
        py.clear(acc);
        return;
    }
    const joined = c.PyUnicode_Concat(acc.*, piece);
    py.decref(piece);
    py.decref(acc.*);
    acc.* = joined; // null on failure - propagated by the null guards above
}

fn richcompareFields(comptime T: type, comptime fields: anytype) fn (?*c.PyObject, ?*c.PyObject, c_int) callconv(.c) py.Object {
    return struct {
        fn cmp(a: ?*c.PyObject, b: ?*c.PyObject, op: c_int) callconv(.c) py.Object {
            if (op != c.Py_EQ and op != c.Py_NE) return py.newRef(c.Py_NotImplemented());
            // Only equal-typed events compare; otherwise defer (NotImplemented).
            if (c.Py_TYPE(a) != c.Py_TYPE(b)) return py.newRef(c.Py_NotImplemented());
            const sa: *T = @ptrCast(a.?);
            const sb: *T = @ptrCast(b.?);
            var equal = true;
            inline for (fields) |f| {
                const r = c.PyObject_RichCompareBool(@field(sa, f.field), @field(sb, f.field), c.Py_EQ);
                if (r < 0) return null;
                if (r == 0) {
                    equal = false;
                    break;
                }
            }
            const result = if (op == c.Py_EQ) equal else !equal;
            return py.boolean(result);
        }
    }.cmp;
}

const request_fields = .{
    FieldInfo(RequestObject){ .name = "method", .field = "method" },
    FieldInfo(RequestObject){ .name = "target", .field = "target" },
    FieldInfo(RequestObject){ .name = "http_version", .field = "http_version" },
    FieldInfo(RequestObject){ .name = "headers", .field = "headers" },
};
// path/query are derived from target, so they're excluded from repr/eq to keep
// the repr concise and equality non-redundant.
const response_fields = .{
    FieldInfo(ResponseObject){ .name = "status_code", .field = "status_code" },
    FieldInfo(ResponseObject){ .name = "reason", .field = "reason" },
    FieldInfo(ResponseObject){ .name = "http_version", .field = "http_version" },
    FieldInfo(ResponseObject){ .name = "headers", .field = "headers" },
};
const data_fields = .{FieldInfo(DataObject){ .name = "data", .field = "data" }};
const eom_fields = .{FieldInfo(EndOfMessageObject){ .name = "trailers", .field = "trailers" }};

const reprRequest = reprFields(RequestObject, "Request", request_fields);
const reprResponse = reprFields(ResponseObject, "Response", response_fields);
const reprData = reprFields(DataObject, "Data", data_fields);
const reprEom = reprFields(EndOfMessageObject, "EndOfMessage", eom_fields);

const cmpRequest = richcompareFields(RequestObject, request_fields);
const cmpResponse = richcompareFields(ResponseObject, response_fields);
const cmpData = richcompareFields(DataObject, data_fields);
const cmpEom = richcompareFields(EndOfMessageObject, eom_fields);

// -- specs --------------------------------------------------------------------

fn slots(comptime dealloc: anytype, comptime members: anytype, comptime traverse: anytype, comptime clear_fn: anytype, comptime repr: anytype, comptime cmp: anytype) [7]py.Slot {
    return .{
        .{ .slot = c.Py_tp_dealloc, .pfunc = @ptrCast(@constCast(&dealloc)) },
        .{ .slot = c.Py_tp_members, .pfunc = @ptrCast(members) },
        .{ .slot = c.Py_tp_traverse, .pfunc = @ptrCast(@constCast(&traverse)) },
        .{ .slot = c.Py_tp_clear, .pfunc = @ptrCast(@constCast(&clear_fn)) },
        .{ .slot = c.Py_tp_repr, .pfunc = @ptrCast(@constCast(&repr)) },
        .{ .slot = c.Py_tp_richcompare, .pfunc = @ptrCast(@constCast(&cmp)) },
        .{ .slot = 0, .pfunc = null },
    };
}

var request_slots = slots(deallocRequest, &request_members, traverseRequest, clearRequest, reprRequest, cmpRequest);
var response_slots = slots(deallocResponse, &response_members, traverseResponse, clearResponse, reprResponse, cmpResponse);
var data_slots = slots(deallocData, &data_members, traverseData, clearData, reprData, cmpData);
var eom_slots = slots(deallocEom, &eom_members, traverseEom, clearEom, reprEom, cmpEom);

fn spec(comptime name: [*c]const u8, comptime size: usize, sl: anytype) py.Spec {
    return .{
        .name = name,
        .basicsize = @intCast(size),
        .itemsize = 0,
        .flags = c.Py_TPFLAGS_DEFAULT | c.Py_TPFLAGS_HAVE_GC,
        .slots = sl,
    };
}

var request_spec = spec("zttp.Request", @sizeOf(RequestObject), &request_slots);
var response_spec = spec("zttp.Response", @sizeOf(ResponseObject), &response_slots);
var data_spec = spec("zttp.Data", @sizeOf(DataObject), &data_slots);
var eom_spec = spec("zttp.EndOfMessage", @sizeOf(EndOfMessageObject), &eom_slots);

// -- header-name interning ----------------------------------------------------

// Building a fresh PyBytes for every header name is the single biggest per-
// header cost. The common request header names are a small, fixed set, so we
// pre-build one PyBytes each at module init and hand back a new reference when a
// parsed name matches EXACTLY (wire casing included - so observable output is
// unchanged; a differently-cased name simply misses the cache and allocates).
const INTERNED_NAMES = [_][]const u8{
    "Host",
    "User-Agent",
    "Accept",
    "Accept-Encoding",
    "Accept-Language",
    "Connection",
    "Content-Type",
    "Content-Length",
    "Cookie",
    "Authorization",
    "Referer",
    "Cache-Control",
    "Origin",
    "Sec-Fetch-Site",
    "Sec-Fetch-Mode",
    "Sec-Fetch-Dest",
    "Upgrade-Insecure-Requests",
    "If-None-Match",
    "If-Modified-Since",
    "Range",
    "Pragma",
    "DNT",
    "X-Requested-With",
    "X-Forwarded-For",
    "X-Forwarded-Proto",
    "X-Real-IP",
    "Transfer-Encoding",
};

var interned: [INTERNED_NAMES.len]py.Object = @splat(null);

fn buildInternTable() bool {
    inline for (INTERNED_NAMES, 0..) |name, i| {
        interned[i] = py.fromBytes(name);
        if (interned[i] == null) return false;
    }
    return true;
}

/// A new reference to the cached PyBytes for `name` if it matches an interned
/// name exactly, else null (caller allocates a fresh one). Dispatches on length
/// via a comptime switch, so each call compares only against the interned names
/// that share `name`'s length - keeping both hit and miss paths cheap.
fn internName(name: []const u8) ?py.Object {
    switch (name.len) {
        inline 3...25 => |L| {
            inline for (INTERNED_NAMES, 0..) |cand, i| {
                if (comptime cand.len == L) {
                    if (name[0] == cand[0] and std.mem.eql(u8, name, cand)) return py.newRef(interned[i]);
                }
            }
            return null;
        },
        else => return null,
    }
}

// -- header list materialisation ----------------------------------------------

/// Build a Python list of (name, value) bytes tuples from the core headers.
fn buildHeaders(hdrs: []const events.Header) py.Object {
    const list = py.newList(@intCast(hdrs.len));
    if (list == null) return null;
    for (hdrs, 0..) |h, i| {
        const name = internName(h.name) orelse py.fromBytes(h.name);
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
    s.path = py.fromBytes(r.path);
    s.query = py.fromBytes(r.query);
    s.http_version = py.fromBytes(r.http_version);
    s.headers = buildHeaders(r.headers);
    s.expect_continue = @intFromBool(r.expect_continue);
    if (s.method == null or s.target == null or s.path == null or s.query == null or s.http_version == null or s.headers == null) {
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

    // NEED_DATA / CONNECTION_CLOSED are unique sentinel instances of bare types;
    // we keep both the instance (compared with `is`) and the type so the Event
    // union can name it.
    need_data_type = py.typeFromSpec(&need_data_spec);
    connection_closed_type = py.typeFromSpec(&connection_closed_spec);
    if (need_data_type == null or connection_closed_type == null) return false;
    need_data = py.allocInstance(need_data_type);
    connection_closed = py.allocInstance(connection_closed_type);
    if (need_data == null or connection_closed == null) return false;

    if (!buildInternTable()) return false;

    _ = c.PyModule_AddObjectRef(module, "Request", request_type);
    _ = c.PyModule_AddObjectRef(module, "Response", response_type);
    _ = c.PyModule_AddObjectRef(module, "Data", data_type);
    _ = c.PyModule_AddObjectRef(module, "EndOfMessage", end_of_message_type);
    _ = c.PyModule_AddObjectRef(module, "NEED_DATA", need_data);
    _ = c.PyModule_AddObjectRef(module, "NeedData", need_data_type);
    _ = c.PyModule_AddObjectRef(module, "CONNECTION_CLOSED", connection_closed);
    _ = c.PyModule_AddObjectRef(module, "ConnectionClosed", connection_closed_type);
    return true;
}

var need_data_slots = [_]py.Slot{.{ .slot = 0, .pfunc = null }};
var need_data_spec = py.Spec{ .name = "zttp.NeedData", .basicsize = @sizeOf(c.PyObject), .itemsize = 0, .flags = c.Py_TPFLAGS_DEFAULT, .slots = &need_data_slots };
var connection_closed_slots = [_]py.Slot{.{ .slot = 0, .pfunc = null }};
var connection_closed_spec = py.Spec{ .name = "zttp.ConnectionClosed", .basicsize = @sizeOf(c.PyObject), .itemsize = 0, .flags = c.Py_TPFLAGS_DEFAULT, .slots = &connection_closed_slots };
