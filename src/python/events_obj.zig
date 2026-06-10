//! Python event objects mirroring the core's events: Request, Response, Data,
//! EndOfMessage, plus the NEED_DATA / PAUSED singletons. Each is a small heap
//! type whose attributes are plain Python objects materialised (copied) from the
//! core's buffer slices, so they outlive the next receive_data call.

const std = @import("std");
const py = @import("py.zig");
const c = py.c;
const core = @import("core");
const events = core.events;

// stream_id is the HTTP/2 stream an event belongs to (0 for HTTP/1.1). It is
// exposed as a read-only member but DELIBERATELY excluded from each event's repr
// and equality field lists, so every existing HTTP/1.1 repr string and equality
// test is byte-for-byte unchanged.

const RequestObject = extern struct {
    ob_base: c.PyObject,
    method: py.Object,
    target: py.Object,
    path: py.Object,
    query: py.Object,
    http_version: py.Object,
    headers: py.Object,
    stream_id: py.Object,
    expect_continue: c_char,
};

const ResponseObject = extern struct {
    ob_base: c.PyObject,
    status_code: py.Object,
    reason: py.Object,
    http_version: py.Object,
    headers: py.Object,
    stream_id: py.Object,
};

const DataObject = extern struct {
    ob_base: c.PyObject,
    data: py.Object,
    stream_id: py.Object,
};

const EndOfMessageObject = extern struct {
    ob_base: c.PyObject,
    trailers: py.Object,
    stream_id: py.Object,
};

// The five HTTP/2 control events. Each holds plain Python ints/bytes.

const RstStreamObject = extern struct {
    ob_base: c.PyObject,
    stream_id: py.Object,
    error_code: py.Object,
};

const GoawayObject = extern struct {
    ob_base: c.PyObject,
    last_stream_id: py.Object,
    error_code: py.Object,
    debug: py.Object,
};

const SettingsEventObject = extern struct {
    ob_base: c.PyObject,
    params: py.Object, // list of (id, value) int tuples
};

const PingObject = extern struct {
    ob_base: c.PyObject,
    ack: py.Object,
    data: py.Object, // 8 opaque bytes
};

const WindowUpdateObject = extern struct {
    ob_base: c.PyObject,
    stream_id: py.Object,
    increment: py.Object,
};

var request_type: py.Object = null;
var response_type: py.Object = null;
var data_type: py.Object = null;
var end_of_message_type: py.Object = null;
var rst_stream_type: py.Object = null;
var goaway_type: py.Object = null;
var settings_type: py.Object = null;
var ping_type: py.Object = null;
var window_update_type: py.Object = null;
/// The two terminal sentinels: NEED_DATA (no event yet) and CONNECTION_CLOSED
/// (the peer closed). Each is a unique instance compared with `is`; its bare
/// type (NeedData / ConnectionClosed) is exposed so the Event union can name it.
var need_data_type: py.Object = null;
var connection_closed_type: py.Object = null;
pub var need_data: py.Object = null;
pub var connection_closed: py.Object = null;

// -- members (read-only attribute exposure) -----------------------------------

fn member(comptime name: [*c]const u8, comptime offset: usize) py.MemberDef {
    return .{ .name = name, .type = py.T_OBJECT_EX, .offset = @intCast(offset), .flags = py.READONLY, .doc = null };
}

var request_members = [_]py.MemberDef{
    member("method", @offsetOf(RequestObject, "method")),
    member("target", @offsetOf(RequestObject, "target")),
    member("path", @offsetOf(RequestObject, "path")),
    member("query", @offsetOf(RequestObject, "query")),
    member("http_version", @offsetOf(RequestObject, "http_version")),
    member("headers", @offsetOf(RequestObject, "headers")),
    member("stream_id", @offsetOf(RequestObject, "stream_id")),
    .{ .name = "expect_continue", .type = py.T_BOOL, .offset = @intCast(@offsetOf(RequestObject, "expect_continue")), .flags = py.READONLY, .doc = null },
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var response_members = [_]py.MemberDef{
    member("status_code", @offsetOf(ResponseObject, "status_code")),
    member("reason", @offsetOf(ResponseObject, "reason")),
    member("http_version", @offsetOf(ResponseObject, "http_version")),
    member("headers", @offsetOf(ResponseObject, "headers")),
    member("stream_id", @offsetOf(ResponseObject, "stream_id")),
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var data_members = [_]py.MemberDef{
    member("data", @offsetOf(DataObject, "data")),
    member("stream_id", @offsetOf(DataObject, "stream_id")),
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var eom_members = [_]py.MemberDef{
    member("trailers", @offsetOf(EndOfMessageObject, "trailers")),
    member("stream_id", @offsetOf(EndOfMessageObject, "stream_id")),
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var rst_stream_members = [_]py.MemberDef{
    member("stream_id", @offsetOf(RstStreamObject, "stream_id")),
    member("error_code", @offsetOf(RstStreamObject, "error_code")),
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var goaway_members = [_]py.MemberDef{
    member("last_stream_id", @offsetOf(GoawayObject, "last_stream_id")),
    member("error_code", @offsetOf(GoawayObject, "error_code")),
    member("debug", @offsetOf(GoawayObject, "debug")),
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var settings_members = [_]py.MemberDef{
    member("params", @offsetOf(SettingsEventObject, "params")),
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var ping_members = [_]py.MemberDef{
    member("ack", @offsetOf(PingObject, "ack")),
    member("data", @offsetOf(PingObject, "data")),
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var window_update_members = [_]py.MemberDef{
    member("stream_id", @offsetOf(WindowUpdateObject, "stream_id")),
    member("increment", @offsetOf(WindowUpdateObject, "increment")),
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};

// -- event shell cache ----------------------------------------------------------

// next_event allocates one event object that callers typically drop before the
// next call, so one cached shell per hot type recycles nearly every alloc/free
// pair. The slot is swapped atomically, so it stays correct on free-threaded
// builds; the dealloc path nulls every field before stashing.
var request_cache: py.Object = null;
var response_cache: py.Object = null;
var data_cache: py.Object = null;
var eom_cache: py.Object = null;

fn cacheTake(slot: *py.Object, tp: py.Object) py.Object {
    if (@atomicRmw(py.Object, slot, .Xchg, null, .acq_rel)) |shell| {
        c.Py_SET_REFCNT(shell, 1);
        py.gcTrack(shell);
        return shell;
    }
    return py.allocInstance(tp);
}

fn cacheStash(slot: *py.Object, o: py.Object) void {
    if (@atomicRmw(py.Object, slot, .Xchg, o, .acq_rel)) |evicted| {
        py.freeInstance(evicted);
    }
}

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
    py.xdecref(s.stream_id);
    s.method = null;
    s.target = null;
    s.path = null;
    s.query = null;
    s.http_version = null;
    s.headers = null;
    s.stream_id = null;
    s.expect_continue = 0;
    cacheStash(&request_cache, @ptrCast(s));
}
fn deallocResponse(o: ?*c.PyObject) callconv(.c) void {
    const s: *ResponseObject = @ptrCast(o.?);
    py.gcUntrack(s);
    py.xdecref(s.status_code);
    py.xdecref(s.reason);
    py.xdecref(s.http_version);
    py.xdecref(s.headers);
    py.xdecref(s.stream_id);
    s.status_code = null;
    s.reason = null;
    s.http_version = null;
    s.headers = null;
    s.stream_id = null;
    cacheStash(&response_cache, @ptrCast(s));
}
fn deallocData(o: ?*c.PyObject) callconv(.c) void {
    const s: *DataObject = @ptrCast(o.?);
    py.gcUntrack(s);
    py.xdecref(s.data);
    py.xdecref(s.stream_id);
    s.data = null;
    s.stream_id = null;
    cacheStash(&data_cache, @ptrCast(s));
}
fn deallocEom(o: ?*c.PyObject) callconv(.c) void {
    const s: *EndOfMessageObject = @ptrCast(o.?);
    py.gcUntrack(s);
    py.xdecref(s.trailers);
    py.xdecref(s.stream_id);
    s.trailers = null;
    s.stream_id = null;
    cacheStash(&eom_cache, @ptrCast(s));
}
fn deallocRstStream(o: ?*c.PyObject) callconv(.c) void {
    const s: *RstStreamObject = @ptrCast(o.?);
    py.gcUntrack(s);
    py.xdecref(s.stream_id);
    py.xdecref(s.error_code);
    py.freeInstance(@ptrCast(s));
}
fn deallocGoaway(o: ?*c.PyObject) callconv(.c) void {
    const s: *GoawayObject = @ptrCast(o.?);
    py.gcUntrack(s);
    py.xdecref(s.last_stream_id);
    py.xdecref(s.error_code);
    py.xdecref(s.debug);
    py.freeInstance(@ptrCast(s));
}
fn deallocSettings(o: ?*c.PyObject) callconv(.c) void {
    const s: *SettingsEventObject = @ptrCast(o.?);
    py.gcUntrack(s);
    py.xdecref(s.params);
    py.freeInstance(@ptrCast(s));
}
fn deallocPing(o: ?*c.PyObject) callconv(.c) void {
    const s: *PingObject = @ptrCast(o.?);
    py.gcUntrack(s);
    py.xdecref(s.ack);
    py.xdecref(s.data);
    py.freeInstance(@ptrCast(s));
}
fn deallocWindowUpdate(o: ?*c.PyObject) callconv(.c) void {
    const s: *WindowUpdateObject = @ptrCast(o.?);
    py.gcUntrack(s);
    py.xdecref(s.stream_id);
    py.xdecref(s.increment);
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
    inline for (.{ s.method, s.target, s.path, s.query, s.http_version, s.headers, s.stream_id }) |f| {
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
    py.clear(&s.stream_id);
    return 0;
}
fn traverseResponse(o: ?*c.PyObject, visit: c.visitproc, arg: ?*anyopaque) callconv(.c) c_int {
    const s: *ResponseObject = @ptrCast(o.?);
    inline for (.{ s.status_code, s.reason, s.http_version, s.headers, s.stream_id }) |f| {
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
    py.clear(&s.stream_id);
    return 0;
}
fn traverseData(o: ?*c.PyObject, visit: c.visitproc, arg: ?*anyopaque) callconv(.c) c_int {
    const s: *DataObject = @ptrCast(o.?);
    inline for (.{ s.data, s.stream_id }) |f| {
        const r = visitObj(f, visit, arg);
        if (r != 0) return r;
    }
    return 0;
}
fn clearData(o: ?*c.PyObject) callconv(.c) c_int {
    const s: *DataObject = @ptrCast(o.?);
    py.clear(&s.data);
    py.clear(&s.stream_id);
    return 0;
}
fn traverseEom(o: ?*c.PyObject, visit: c.visitproc, arg: ?*anyopaque) callconv(.c) c_int {
    const s: *EndOfMessageObject = @ptrCast(o.?);
    inline for (.{ s.trailers, s.stream_id }) |f| {
        const r = visitObj(f, visit, arg);
        if (r != 0) return r;
    }
    return 0;
}
fn clearEom(o: ?*c.PyObject) callconv(.c) c_int {
    const s: *EndOfMessageObject = @ptrCast(o.?);
    py.clear(&s.trailers);
    py.clear(&s.stream_id);
    return 0;
}
fn traverseRstStream(o: ?*c.PyObject, visit: c.visitproc, arg: ?*anyopaque) callconv(.c) c_int {
    const s: *RstStreamObject = @ptrCast(o.?);
    inline for (.{ s.stream_id, s.error_code }) |f| {
        const r = visitObj(f, visit, arg);
        if (r != 0) return r;
    }
    return 0;
}
fn clearRstStream(o: ?*c.PyObject) callconv(.c) c_int {
    const s: *RstStreamObject = @ptrCast(o.?);
    py.clear(&s.stream_id);
    py.clear(&s.error_code);
    return 0;
}
fn traverseGoaway(o: ?*c.PyObject, visit: c.visitproc, arg: ?*anyopaque) callconv(.c) c_int {
    const s: *GoawayObject = @ptrCast(o.?);
    inline for (.{ s.last_stream_id, s.error_code, s.debug }) |f| {
        const r = visitObj(f, visit, arg);
        if (r != 0) return r;
    }
    return 0;
}
fn clearGoaway(o: ?*c.PyObject) callconv(.c) c_int {
    const s: *GoawayObject = @ptrCast(o.?);
    py.clear(&s.last_stream_id);
    py.clear(&s.error_code);
    py.clear(&s.debug);
    return 0;
}
fn traverseSettings(o: ?*c.PyObject, visit: c.visitproc, arg: ?*anyopaque) callconv(.c) c_int {
    const s: *SettingsEventObject = @ptrCast(o.?);
    return visitObj(s.params, visit, arg);
}
fn clearSettings(o: ?*c.PyObject) callconv(.c) c_int {
    const s: *SettingsEventObject = @ptrCast(o.?);
    py.clear(&s.params);
    return 0;
}
fn traversePing(o: ?*c.PyObject, visit: c.visitproc, arg: ?*anyopaque) callconv(.c) c_int {
    const s: *PingObject = @ptrCast(o.?);
    inline for (.{ s.ack, s.data }) |f| {
        const r = visitObj(f, visit, arg);
        if (r != 0) return r;
    }
    return 0;
}
fn clearPing(o: ?*c.PyObject) callconv(.c) c_int {
    const s: *PingObject = @ptrCast(o.?);
    py.clear(&s.ack);
    py.clear(&s.data);
    return 0;
}
fn traverseWindowUpdate(o: ?*c.PyObject, visit: c.visitproc, arg: ?*anyopaque) callconv(.c) c_int {
    const s: *WindowUpdateObject = @ptrCast(o.?);
    inline for (.{ s.stream_id, s.increment }) |f| {
        const r = visitObj(f, visit, arg);
        if (r != 0) return r;
    }
    return 0;
}
fn clearWindowUpdate(o: ?*c.PyObject) callconv(.c) c_int {
    const s: *WindowUpdateObject = @ptrCast(o.?);
    py.clear(&s.stream_id);
    py.clear(&s.increment);
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

// The HTTP/2 control events include stream_id in their repr/equality (they are
// H2-only, so there is no H1 output to preserve).
const rst_stream_fields = .{
    FieldInfo(RstStreamObject){ .name = "stream_id", .field = "stream_id" },
    FieldInfo(RstStreamObject){ .name = "error_code", .field = "error_code" },
};
const goaway_fields = .{
    FieldInfo(GoawayObject){ .name = "last_stream_id", .field = "last_stream_id" },
    FieldInfo(GoawayObject){ .name = "error_code", .field = "error_code" },
    FieldInfo(GoawayObject){ .name = "debug", .field = "debug" },
};
const settings_fields = .{FieldInfo(SettingsEventObject){ .name = "params", .field = "params" }};
const ping_fields = .{
    FieldInfo(PingObject){ .name = "ack", .field = "ack" },
    FieldInfo(PingObject){ .name = "data", .field = "data" },
};
const window_update_fields = .{
    FieldInfo(WindowUpdateObject){ .name = "stream_id", .field = "stream_id" },
    FieldInfo(WindowUpdateObject){ .name = "increment", .field = "increment" },
};

const reprRequest = reprFields(RequestObject, "Request", request_fields);
const reprResponse = reprFields(ResponseObject, "Response", response_fields);
const reprData = reprFields(DataObject, "Data", data_fields);
const reprEom = reprFields(EndOfMessageObject, "EndOfMessage", eom_fields);
const reprRstStream = reprFields(RstStreamObject, "RstStream", rst_stream_fields);
const reprGoaway = reprFields(GoawayObject, "Goaway", goaway_fields);
const reprSettings = reprFields(SettingsEventObject, "Settings", settings_fields);
const reprPing = reprFields(PingObject, "Ping", ping_fields);
const reprWindowUpdate = reprFields(WindowUpdateObject, "WindowUpdate", window_update_fields);

const cmpRequest = richcompareFields(RequestObject, request_fields);
const cmpResponse = richcompareFields(ResponseObject, response_fields);
const cmpData = richcompareFields(DataObject, data_fields);
const cmpEom = richcompareFields(EndOfMessageObject, eom_fields);
const cmpRstStream = richcompareFields(RstStreamObject, rst_stream_fields);
const cmpGoaway = richcompareFields(GoawayObject, goaway_fields);
const cmpSettings = richcompareFields(SettingsEventObject, settings_fields);
const cmpPing = richcompareFields(PingObject, ping_fields);
const cmpWindowUpdate = richcompareFields(WindowUpdateObject, window_update_fields);

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
var rst_stream_slots = slots(deallocRstStream, &rst_stream_members, traverseRstStream, clearRstStream, reprRstStream, cmpRstStream);
var goaway_slots = slots(deallocGoaway, &goaway_members, traverseGoaway, clearGoaway, reprGoaway, cmpGoaway);
var settings_slots = slots(deallocSettings, &settings_members, traverseSettings, clearSettings, reprSettings, cmpSettings);
var ping_slots = slots(deallocPing, &ping_members, traversePing, clearPing, reprPing, cmpPing);
var window_update_slots = slots(deallocWindowUpdate, &window_update_members, traverseWindowUpdate, clearWindowUpdate, reprWindowUpdate, cmpWindowUpdate);

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
var rst_stream_spec = spec("zttp.RstStream", @sizeOf(RstStreamObject), &rst_stream_slots);
var goaway_spec = spec("zttp.Goaway", @sizeOf(GoawayObject), &goaway_slots);
var settings_spec = spec("zttp.Settings", @sizeOf(SettingsEventObject), &settings_slots);
var ping_spec = spec("zttp.Ping", @sizeOf(PingObject), &ping_slots);
var window_update_spec = spec("zttp.WindowUpdate", @sizeOf(WindowUpdateObject), &window_update_slots);

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

// The same trick for header values: the values of the connection-management
// and content-negotiation headers are drawn from a tiny fixed vocabulary, so
// the common ones get a pre-built PyBytes too (exact-bytes match only).
const INTERNED_VALUES = [_][]const u8{
    "1",
    "*/*",
    "cors",
    "none",
    "close",
    "empty",
    "https",
    "chunked",
    "Upgrade",
    "no-cache",
    "identity",
    "navigate",
    "document",
    "text/html",
    "websocket",
    "max-age=0",
    "keep-alive",
    "text/plain",
    "same-origin",
    "gzip, deflate",
    "en-US,en;q=0.9",
    "XMLHttpRequest",
    "application/json",
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "application/x-www-form-urlencoded",
};

var interned: [INTERNED_NAMES.len]py.Object = @splat(null);
var interned_values: [INTERNED_VALUES.len]py.Object = @splat(null);

fn buildInternTable() bool {
    inline for (INTERNED_NAMES, 0..) |name, i| {
        interned[i] = py.fromBytes(name);
        if (interned[i] == null) return false;
    }
    inline for (INTERNED_VALUES, 0..) |value, i| {
        interned_values[i] = py.fromBytes(value);
        if (interned_values[i] == null) return false;
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

fn internValue(value: []const u8) ?py.Object {
    switch (value.len) {
        inline 1...33 => |L| {
            inline for (INTERNED_VALUES, 0..) |cand, i| {
                if (comptime cand.len == L) {
                    if (value[0] == cand[0] and std.mem.eql(u8, value, cand)) return py.newRef(interned_values[i]);
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
        const value = internValue(h.value) orelse py.fromBytes(h.value);
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

pub fn fromH1Event(ev: events.H1Event) py.Object {
    return switch (ev) {
        .request => |r| makeRequest(r),
        .response => |r| makeResponse(r),
        .data => |d| makeData(d),
        .end_of_message => |e| makeEom(e),
        .need_data => py.newRef(need_data),
        .connection_closed => py.newRef(connection_closed),
    };
}

pub fn fromH2Event(ev: events.H2Event) py.Object {
    return switch (ev) {
        .request => |r| makeRequest(r),
        .response => |r| makeResponse(r),
        .data => |d| makeData(d),
        .end_of_message => |e| makeEom(e),
        .need_data => py.newRef(need_data),
        .rst_stream => |r| makeRstStream(r),
        .goaway => |g| makeGoaway(g),
        .settings => |s| makeSettings(s),
        .ping => |p| makePing(p),
        .window_update => |w| makeWindowUpdate(w),
    };
}

pub fn fromH3Event(ev: events.H3Event) py.Object {
    return switch (ev) {
        .request => |r| makeRequest(r),
        .response => |r| makeResponse(r),
        .data => |d| makeData(d),
        .end_of_message => |e| makeEom(e),
        .need_data => py.newRef(need_data),
        .settings => |s| makeSettings(s),
        .goaway => |g| makeGoaway(g),
    };
}

fn u32Obj(v: u32) py.Object {
    return c.PyLong_FromUnsignedLong(v);
}

fn makeRequest(r: events.Request) py.Object {
    const o = cacheTake(&request_cache, request_type);
    if (o == null) return null;
    const s: *RequestObject = @ptrCast(o);
    s.method = py.fromBytes(r.method);
    s.target = py.fromBytes(r.target);
    s.path = py.fromBytes(r.path);
    s.query = py.fromBytes(r.query);
    s.http_version = py.fromBytes(r.http_version);
    s.headers = buildHeaders(r.headers);
    s.stream_id = u32Obj(r.stream_id);
    s.expect_continue = @intFromBool(r.expect_continue);
    if (s.method == null or s.target == null or s.path == null or s.query == null or s.http_version == null or s.headers == null or s.stream_id == null) {
        py.decref(o);
        return null;
    }
    return o;
}

fn makeResponse(r: events.Response) py.Object {
    const o = cacheTake(&response_cache, response_type);
    if (o == null) return null;
    const s: *ResponseObject = @ptrCast(o);
    s.status_code = py.fromU16(r.status_code);
    s.reason = py.fromBytes(r.reason);
    s.http_version = py.fromBytes(r.http_version);
    s.headers = buildHeaders(r.headers);
    s.stream_id = u32Obj(r.stream_id);
    if (s.status_code == null or s.reason == null or s.http_version == null or s.headers == null or s.stream_id == null) {
        py.decref(o);
        return null;
    }
    return o;
}

fn makeData(d: events.Data) py.Object {
    const o = cacheTake(&data_cache, data_type);
    if (o == null) return null;
    const s: *DataObject = @ptrCast(o);
    s.data = py.fromBytes(d.data);
    s.stream_id = u32Obj(d.stream_id);
    if (s.data == null or s.stream_id == null) {
        py.decref(o);
        return null;
    }
    return o;
}

fn makeEom(e: events.EndOfMessage) py.Object {
    const o = cacheTake(&eom_cache, end_of_message_type);
    if (o == null) return null;
    const s: *EndOfMessageObject = @ptrCast(o);
    s.trailers = buildHeaders(e.trailers);
    s.stream_id = u32Obj(e.stream_id);
    if (s.trailers == null or s.stream_id == null) {
        py.decref(o);
        return null;
    }
    return o;
}

fn makeRstStream(r: events.RstStream) py.Object {
    const o = py.allocInstance(rst_stream_type);
    if (o == null) return null;
    const s: *RstStreamObject = @ptrCast(o);
    s.stream_id = u32Obj(r.stream_id);
    s.error_code = u32Obj(r.error_code);
    if (s.stream_id == null or s.error_code == null) {
        py.decref(o);
        return null;
    }
    return o;
}

fn makeGoaway(g: events.Goaway) py.Object {
    const o = py.allocInstance(goaway_type);
    if (o == null) return null;
    const s: *GoawayObject = @ptrCast(o);
    s.last_stream_id = u32Obj(g.last_stream_id);
    s.error_code = u32Obj(g.error_code);
    s.debug = py.fromBytes(g.debug);
    if (s.last_stream_id == null or s.error_code == null or s.debug == null) {
        py.decref(o);
        return null;
    }
    return o;
}

fn makeSettings(ev: events.SettingsEvent) py.Object {
    const o = py.allocInstance(settings_type);
    if (o == null) return null;
    const s: *SettingsEventObject = @ptrCast(o);
    const list = py.newList(@intCast(ev.params.len));
    if (list == null) {
        py.decref(o);
        return null;
    }
    for (ev.params, 0..) |p, i| {
        const id = u32Obj(p.id);
        const value = u32Obj(p.value);
        const tup = py.tupleNew(2);
        if (id == null or value == null or tup == null) {
            py.xdecref(id);
            py.xdecref(value);
            py.xdecref(tup);
            py.decref(list);
            py.decref(o);
            return null;
        }
        py.tupleSet(tup, 0, id);
        py.tupleSet(tup, 1, value);
        py.listSet(list, @intCast(i), tup);
    }
    s.params = list;
    return o;
}

fn makePing(p: events.Ping) py.Object {
    const o = py.allocInstance(ping_type);
    if (o == null) return null;
    const s: *PingObject = @ptrCast(o);
    s.ack = py.boolean(p.ack);
    s.data = py.fromBytes(&p.opaque_data);
    if (s.ack == null or s.data == null) {
        py.decref(o);
        return null;
    }
    return o;
}

fn makeWindowUpdate(w: events.WindowUpdate) py.Object {
    const o = py.allocInstance(window_update_type);
    if (o == null) return null;
    const s: *WindowUpdateObject = @ptrCast(o);
    s.stream_id = u32Obj(w.stream_id);
    s.increment = u32Obj(w.increment);
    if (s.stream_id == null or s.increment == null) {
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
    rst_stream_type = py.typeFromSpec(&rst_stream_spec);
    goaway_type = py.typeFromSpec(&goaway_spec);
    settings_type = py.typeFromSpec(&settings_spec);
    ping_type = py.typeFromSpec(&ping_spec);
    window_update_type = py.typeFromSpec(&window_update_spec);
    if (request_type == null or response_type == null or data_type == null or end_of_message_type == null) {
        return false;
    }
    if (rst_stream_type == null or goaway_type == null or settings_type == null or ping_type == null or window_update_type == null) {
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
    _ = c.PyModule_AddObjectRef(module, "RstStream", rst_stream_type);
    _ = c.PyModule_AddObjectRef(module, "Goaway", goaway_type);
    _ = c.PyModule_AddObjectRef(module, "Settings", settings_type);
    _ = c.PyModule_AddObjectRef(module, "Ping", ping_type);
    _ = c.PyModule_AddObjectRef(module, "WindowUpdate", window_update_type);
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
