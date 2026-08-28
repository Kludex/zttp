//! Python event objects mirroring the core's events: Request, Response, Data,
//! EndOfMessage, plus the NEED_DATA / PAUSED singletons. Each is a small heap
//! type whose attributes own copied data from the core's buffer slices, so they
//! outlive the next receive_data call. HTTP/1 heads use one packed HeaderBlock;
//! individual Python header pairs are materialised only when accessed.

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
    stream_id: c_ulonglong,
    expect_continue: c_char,
    end_stream: c_char,
};

const ResponseObject = extern struct {
    ob_base: c.PyObject,
    status_code: py.Object,
    reason: py.Object,
    http_version: py.Object,
    headers: py.Object,
    stream_id: c_ulonglong,
};

const DataObject = extern struct {
    ob_base: c.PyObject,
    data: py.Object,
    stream_id: c_ulonglong,
};

const EndOfMessageObject = extern struct {
    ob_base: c.PyObject,
    trailers: py.Object,
    stream_id: c_ulonglong,
};

/// Lazy header container. Compact native ranges and their bytes live together
/// in the variable-sized tail of this one Python object. Python bytes/tuples
/// are created only for fields the caller actually touches.
const HeaderBlockObject = extern struct {
    ob_base: c.PyVarObject,
    count: usize,
    data_len: usize,
};

const HeaderRange = extern struct {
    name_offset: u32,
    name_len: u32,
    value_offset: u32,
    value_len: u32,
    hash: u8,
};

// The five HTTP/2 control events. Each holds plain Python ints/bytes.

const RstStreamObject = extern struct {
    ob_base: c.PyObject,
    stream_id: py.Object,
    error_code: py.Object,
};

const GoAwayObject = extern struct {
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
var header_block_type: py.Object = null;
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
    .{ .name = "stream_id", .type = py.T_ULONGLONG, .offset = @intCast(@offsetOf(RequestObject, "stream_id")), .flags = py.READONLY, .doc = null },
    .{ .name = "expect_continue", .type = py.T_BOOL, .offset = @intCast(@offsetOf(RequestObject, "expect_continue")), .flags = py.READONLY, .doc = null },
    .{ .name = "end_stream", .type = py.T_BOOL, .offset = @intCast(@offsetOf(RequestObject, "end_stream")), .flags = py.READONLY, .doc = null },
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var response_members = [_]py.MemberDef{
    member("status_code", @offsetOf(ResponseObject, "status_code")),
    member("reason", @offsetOf(ResponseObject, "reason")),
    member("http_version", @offsetOf(ResponseObject, "http_version")),
    member("headers", @offsetOf(ResponseObject, "headers")),
    .{ .name = "stream_id", .type = py.T_ULONGLONG, .offset = @intCast(@offsetOf(ResponseObject, "stream_id")), .flags = py.READONLY, .doc = null },
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var data_members = [_]py.MemberDef{
    member("data", @offsetOf(DataObject, "data")),
    .{ .name = "stream_id", .type = py.T_ULONGLONG, .offset = @intCast(@offsetOf(DataObject, "stream_id")), .flags = py.READONLY, .doc = null },
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var eom_members = [_]py.MemberDef{
    member("trailers", @offsetOf(EndOfMessageObject, "trailers")),
    .{ .name = "stream_id", .type = py.T_ULONGLONG, .offset = @intCast(@offsetOf(EndOfMessageObject, "stream_id")), .flags = py.READONLY, .doc = null },
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var rst_stream_members = [_]py.MemberDef{
    member("stream_id", @offsetOf(RstStreamObject, "stream_id")),
    member("error_code", @offsetOf(RstStreamObject, "error_code")),
    .{ .name = null, .type = 0, .offset = 0, .flags = 0, .doc = null },
};
var goaway_members = [_]py.MemberDef{
    member("last_stream_id", @offsetOf(GoAwayObject, "last_stream_id")),
    member("error_code", @offsetOf(GoAwayObject, "error_code")),
    member("debug", @offsetOf(GoAwayObject, "debug")),
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

// -- GC support ---------------------------------------------------------------

// The event types hold strong references to Python objects (and Request/
// Response/EndOfMessage expose mutable header/trailer lists), so they must be
// GC types with dealloc/traverse/clear over every owned reference; otherwise a
// cycle through them leaks. tp_alloc (PyType_GenericAlloc) already GC-tracks a
// HAVE_GC instance on creation, so we only untrack in dealloc; no explicit track
// is needed (and double-tracking trips an assertion in a debug build).
//
// dealloc/traverse/clear are identical across the event types up to their field
// list, so gcOps generates the trio from the struct itself: it walks exactly the
// `py.Object`-typed fields, skipping `ob_base` and the plain-integer fields. This
// covers fields the repr/equality lists deliberately omit (Request's path/query),
// which is why it introspects the type rather than reusing the *_fields tuples.

fn visitObj(obj: py.Object, visit: c.visitproc, arg: ?*anyopaque) c_int {
    if (obj != null) {
        const r = visit.?(obj, arg);
        if (r != 0) return r;
    }
    return 0;
}

/// Names of the `py.Object`-typed fields of an event struct - the owned refs the
/// GC trio must walk.
fn objectFields(comptime T: type) []const []const u8 {
    comptime {
        var names: []const []const u8 = &.{};
        for (@typeInfo(T).@"struct".fields) |f| {
            if (f.type == py.Object) names = names ++ .{f.name};
        }
        return names;
    }
}

const GcOps = struct {
    dealloc: fn (?*c.PyObject) callconv(.c) void,
    traverse: fn (?*c.PyObject, c.visitproc, ?*anyopaque) callconv(.c) c_int,
    clear: fn (?*c.PyObject) callconv(.c) c_int,
};

fn gcOps(comptime T: type) GcOps {
    const fields = objectFields(T);
    return .{
        .dealloc = struct {
            fn dealloc(o: ?*c.PyObject) callconv(.c) void {
                const s: *T = @ptrCast(o.?);
                py.gcUntrack(s);
                inline for (fields) |name| py.xdecref(@field(s, name));
                py.freeInstance(@ptrCast(s));
            }
        }.dealloc,
        .traverse = struct {
            fn traverse(o: ?*c.PyObject, visit: c.visitproc, arg: ?*anyopaque) callconv(.c) c_int {
                const s: *T = @ptrCast(o.?);
                inline for (fields) |name| {
                    const r = visitObj(@field(s, name), visit, arg);
                    if (r != 0) return r;
                }
                return 0;
            }
        }.traverse,
        .clear = struct {
            fn clear(o: ?*c.PyObject) callconv(.c) c_int {
                const s: *T = @ptrCast(o.?);
                inline for (fields) |name| py.clear(&@field(s, name));
                return 0;
            }
        }.clear,
    };
}

const request_gc = gcOps(RequestObject);
const response_gc = gcOps(ResponseObject);
const data_gc = gcOps(DataObject);
const eom_gc = gcOps(EndOfMessageObject);
const rst_stream_gc = gcOps(RstStreamObject);
const goaway_gc = gcOps(GoAwayObject);
const settings_gc = gcOps(SettingsEventObject);
const ping_gc = gcOps(PingObject);
const window_update_gc = gcOps(WindowUpdateObject);

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
    FieldInfo(GoAwayObject){ .name = "last_stream_id", .field = "last_stream_id" },
    FieldInfo(GoAwayObject){ .name = "error_code", .field = "error_code" },
    FieldInfo(GoAwayObject){ .name = "debug", .field = "debug" },
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
const reprGoAway = reprFields(GoAwayObject, "GoAway", goaway_fields);
const reprSettings = reprFields(SettingsEventObject, "Settings", settings_fields);
const reprPing = reprFields(PingObject, "Ping", ping_fields);
const reprWindowUpdate = reprFields(WindowUpdateObject, "WindowUpdate", window_update_fields);

const cmpRequest = richcompareFields(RequestObject, request_fields);
const cmpResponse = richcompareFields(ResponseObject, response_fields);
const cmpData = richcompareFields(DataObject, data_fields);
const cmpEom = richcompareFields(EndOfMessageObject, eom_fields);
const cmpRstStream = richcompareFields(RstStreamObject, rst_stream_fields);
const cmpGoAway = richcompareFields(GoAwayObject, goaway_fields);
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

var request_slots = slots(request_gc.dealloc, &request_members, request_gc.traverse, request_gc.clear, reprRequest, cmpRequest);
var response_slots = slots(response_gc.dealloc, &response_members, response_gc.traverse, response_gc.clear, reprResponse, cmpResponse);
var data_slots = slots(data_gc.dealloc, &data_members, data_gc.traverse, data_gc.clear, reprData, cmpData);
var eom_slots = slots(eom_gc.dealloc, &eom_members, eom_gc.traverse, eom_gc.clear, reprEom, cmpEom);
var rst_stream_slots = slots(rst_stream_gc.dealloc, &rst_stream_members, rst_stream_gc.traverse, rst_stream_gc.clear, reprRstStream, cmpRstStream);
var goaway_slots = slots(goaway_gc.dealloc, &goaway_members, goaway_gc.traverse, goaway_gc.clear, reprGoAway, cmpGoAway);
var settings_slots = slots(settings_gc.dealloc, &settings_members, settings_gc.traverse, settings_gc.clear, reprSettings, cmpSettings);
var ping_slots = slots(ping_gc.dealloc, &ping_members, ping_gc.traverse, ping_gc.clear, reprPing, cmpPing);
var window_update_slots = slots(window_update_gc.dealloc, &window_update_members, window_update_gc.traverse, window_update_gc.clear, reprWindowUpdate, cmpWindowUpdate);

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
var goaway_spec = spec("zttp.GoAway", @sizeOf(GoAwayObject), &goaway_slots);
var settings_spec = spec("zttp.Settings", @sizeOf(SettingsEventObject), &settings_slots);
var ping_spec = spec("zttp.Ping", @sizeOf(PingObject), &ping_slots);
var window_update_spec = spec("zttp.WindowUpdate", @sizeOf(WindowUpdateObject), &window_update_slots);

// -- header-name interning ----------------------------------------------------

// Building a fresh PyBytes for every header name is the single biggest per-
// header cost. The common request header names are a small, fixed set, so we
// pre-build one PyBytes each at module init and hand back a new reference when a
// parsed name matches EXACTLY (wire casing included - so observable output is
// unchanged). HTTP/1 clients commonly send either conventional casing or all
// lowercase, so cache both spellings rather than making lowercase-heavy traffic
// pay for a fresh bytes allocation on every request.
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
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "connection",
    "content-type",
    "content-length",
    "cookie",
    "authorization",
    "referer",
    "cache-control",
    "origin",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "upgrade-insecure-requests",
    "if-none-match",
    "if-modified-since",
    "range",
    "pragma",
    "dnt",
    "x-requested-with",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-real-ip",
    "transfer-encoding",
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

// The request/status line draws from even smaller fixed sets: the standard
// methods, the two HTTP/1.x versions, and the stock reason phrases. Same deal -
// one PyBytes each at module init, returned on an exact-bytes match.
const INTERNED_METHODS = [_][]const u8{ "GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "QUERY" };
const INTERNED_VERSIONS = [_][]const u8{ "1.1", "1.0" };
const INTERNED_REASONS = [_][]const u8{
    "OK",
    "Created",
    "Accepted",
    "No Content",
    "Moved Permanently",
    "Found",
    "Not Modified",
    "Bad Request",
    "Unauthorized",
    "Forbidden",
    "Not Found",
    "Internal Server Error",
    "Service Unavailable",
};

var interned: [INTERNED_NAMES.len]py.Object = @splat(null);
var interned_values: [INTERNED_VALUES.len]py.Object = @splat(null);
var interned_methods: [INTERNED_METHODS.len]py.Object = @splat(null);
var interned_versions: [INTERNED_VERSIONS.len]py.Object = @splat(null);
var interned_reasons: [INTERNED_REASONS.len]py.Object = @splat(null);
var empty_bytes: py.Object = null;

fn buildInternTable() bool {
    inline for (INTERNED_NAMES, 0..) |name, i| {
        interned[i] = py.fromBytes(name);
        if (interned[i] == null) return false;
    }
    inline for (INTERNED_VALUES, 0..) |value, i| {
        interned_values[i] = py.fromBytes(value);
        if (interned_values[i] == null) return false;
    }
    inline for (INTERNED_METHODS, 0..) |m, i| {
        interned_methods[i] = py.fromBytes(m);
        if (interned_methods[i] == null) return false;
    }
    inline for (INTERNED_VERSIONS, 0..) |v, i| {
        interned_versions[i] = py.fromBytes(v);
        if (interned_versions[i] == null) return false;
    }
    inline for (INTERNED_REASONS, 0..) |r, i| {
        interned_reasons[i] = py.fromBytes(r);
        if (interned_reasons[i] == null) return false;
    }
    empty_bytes = py.fromBytes("");
    return empty_bytes != null;
}

/// A new reference to the cached PyBytes for `s` if it matches a table entry
/// exactly, else null. The tables are small enough that a length + first-byte
/// gated linear scan beats fancier dispatch.
fn internFrom(comptime table: []const []const u8, cache: *const [table.len]py.Object, s: []const u8) ?py.Object {
    if (s.len == 0) return null;
    inline for (table, 0..) |cand, i| {
        if (s.len == cand.len and s[0] == cand[0] and std.mem.eql(u8, s, cand)) return py.newRef(cache[i]);
    }
    return null;
}

/// A new reference to the cached PyBytes for `name` if it matches an interned
/// name exactly, else null (caller allocates a fresh one). Dispatches on length
/// via a comptime switch, so each call compares only against the interned names
/// that share `name`'s length - keeping both hit and miss paths cheap.
fn internName(name: []const u8) ?py.Object {
    @setEvalBranchQuota(3000);
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

// -- lazy header block -------------------------------------------------------

fn headerHash(name: []const u8) u8 {
    var hash: u8 = 0x9d;
    for (name) |ch| hash = hash *% 33 +% std.ascii.toLower(ch);
    return hash;
}

fn headerNameEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

fn headerNameIsLowercase(name: []const u8) bool {
    for (name) |ch| {
        if (std.ascii.isUpper(ch)) return false;
    }
    return true;
}

fn headerRanges(self: *HeaderBlockObject) [*]HeaderRange {
    return @ptrFromInt(@intFromPtr(self) + @sizeOf(HeaderBlockObject));
}

fn headerData(self: *HeaderBlockObject) []const u8 {
    const start = @intFromPtr(headerRanges(self)) + self.count * @sizeOf(HeaderRange);
    const ptr: [*]const u8 = @ptrFromInt(start);
    return ptr[0..self.data_len];
}

fn headerName(data: []const u8, range: HeaderRange) []const u8 {
    const start: usize = range.name_offset;
    return data[start .. start + range.name_len];
}

fn headerValue(data: []const u8, range: HeaderRange) []const u8 {
    const start: usize = range.value_offset;
    return data[start .. start + range.value_len];
}

fn lowerHeaderName(name: []const u8) py.Object {
    // Reuse the lowercase half of the common-name cache where possible.  ASGI
    // servers require lowercase names, so adapters can materialize their scope
    // without a Python callback and bytes.lower() call for every header.
    @setEvalBranchQuota(3000);
    switch (name.len) {
        inline 3...25 => |L| {
            inline for (INTERNED_NAMES, 0..) |candidate, i| {
                if (comptime candidate.len == L and headerNameIsLowercase(candidate)) {
                    if (headerNameEql(name, candidate)) return py.newRef(interned[i]);
                }
            }
        },
        else => {},
    }

    const result = c.PyBytes_FromStringAndSize(null, @intCast(name.len));
    if (result == null) return null;
    const dst: [*]u8 = @ptrCast(c.PyBytes_AsString(result));
    for (name, 0..) |ch, i| dst[i] = std.ascii.toLower(ch);
    return result;
}

fn headerPair(self: *HeaderBlockObject, idx: usize, lowercase_name: bool) py.Object {
    const data = headerData(self);
    const range = headerRanges(self)[idx];
    const name_bytes = headerName(data, range);
    const value_bytes = headerValue(data, range);
    const name = if (lowercase_name)
        lowerHeaderName(name_bytes)
    else
        internName(name_bytes) orelse py.fromBytes(name_bytes);
    const value = internValue(value_bytes) orelse py.fromBytes(value_bytes);
    if (name == null or value == null) {
        py.xdecref(name);
        py.xdecref(value);
        return null;
    }
    const pair = py.tupleNew(2);
    if (pair == null) {
        py.decref(name);
        py.decref(value);
        return null;
    }
    py.tupleSet(pair, 0, name);
    py.tupleSet(pair, 1, value);
    return pair;
}

fn materializeHeaderBlock(self: *HeaderBlockObject, lowercase_names: bool) py.Object {
    const list = py.newList(@intCast(self.count));
    if (list == null) return null;
    for (0..self.count) |i| {
        const pair = headerPair(self, i, lowercase_names);
        if (pair == null) {
            py.decref(list);
            return null;
        }
        py.listSet(list, @intCast(i), pair);
    }
    return list;
}

fn buildHeaderBlock(hdrs: []const events.Header) py.Object {
    var total: usize = 0;
    for (hdrs) |h| total += h.name.len + h.value.len;

    // tp_alloc sizes variable objects in HeaderRange units. Reserve enough
    // trailing units for the real ranges followed immediately by packed bytes;
    // at most one range unit is padding.
    const unit = @sizeOf(HeaderRange);
    const data_units = (total + unit - 1) / unit;
    const allocation_units = hdrs.len + data_units;
    const tp: [*c]c.PyTypeObject = @ptrCast(header_block_type);
    const obj = tp.*.tp_alloc.?(tp, @intCast(allocation_units));
    if (obj == null) return null;
    const self: *HeaderBlockObject = @ptrCast(obj);
    self.count = hdrs.len;
    self.data_len = total;

    const ranges = headerRanges(self);
    const dst: [*]u8 = @ptrFromInt(@intFromPtr(ranges) + hdrs.len * unit);
    var offset: usize = 0;
    for (hdrs, 0..) |h, i| {
        const name_offset = offset;
        @memcpy(dst[offset .. offset + h.name.len], h.name);
        offset += h.name.len;
        const value_offset = offset;
        @memcpy(dst[offset .. offset + h.value.len], h.value);
        offset += h.value.len;
        ranges[i] = .{
            .name_offset = @intCast(name_offset),
            .name_len = @intCast(h.name.len),
            .value_offset = @intCast(value_offset),
            .value_len = @intCast(h.value.len),
            .hash = headerHash(h.name),
        };
    }
    return obj;
}

fn headerBlockLen(obj: ?*c.PyObject) callconv(.c) py.ssize {
    const self: *HeaderBlockObject = @ptrCast(obj.?);
    return @intCast(self.count);
}

fn headerBlockItem(obj: ?*c.PyObject, raw_idx: py.ssize) callconv(.c) py.Object {
    const self: *HeaderBlockObject = @ptrCast(obj.?);
    var idx = raw_idx;
    if (idx < 0) idx += @intCast(self.count);
    if (idx < 0 or idx >= self.count) {
        c.PyErr_SetString(py.data("PyExc_IndexError").*, "header index out of range");
        return null;
    }
    return headerPair(self, @intCast(idx), false);
}

fn headerBlockIter(obj: ?*c.PyObject) callconv(.c) py.Object {
    return c.PySeqIter_New(obj);
}

fn headerBlockSubscript(obj: ?*c.PyObject, key: ?*c.PyObject) callconv(.c) py.Object {
    if (c.PyIndex_Check(key) != 0) {
        const index_obj = c.PyNumber_Index(key);
        if (index_obj == null) return null;
        defer py.decref(index_obj);
        const idx = c.PyLong_AsSsize_t(index_obj);
        if (idx == -1 and py.errOccurred()) return null;
        return headerBlockItem(obj, idx);
    }
    // PySlice_Check expands through _PyObject_CAST_CONST on CPython 3.10;
    // translate-c cannot lower that macro. Exact type comparison is sufficient
    // because slice is final and keeps the extension buildable on 3.10.
    if (@intFromPtr(c.Py_TYPE(key)) == @intFromPtr(py.data("PySlice_Type"))) {
        const self: *HeaderBlockObject = @ptrCast(obj.?);
        var start: py.ssize = 0;
        var stop: py.ssize = 0;
        var step: py.ssize = 0;
        if (c.PySlice_Unpack(key, &start, &stop, &step) != 0) return null;
        const slice_len = c.PySlice_AdjustIndices(@intCast(self.count), &start, &stop, step);
        const list = py.newList(slice_len);
        if (list == null) return null;
        var idx = start;
        for (0..@intCast(slice_len)) |out_idx| {
            const pair = headerPair(self, @intCast(idx), false);
            if (pair == null) {
                py.decref(list);
                return null;
            }
            py.listSet(list, @intCast(out_idx), pair);
            idx += step;
        }
        return list;
    }
    return py.raiseType("header indices must be integers or slices");
}

fn headerBlockGet(obj: ?*c.PyObject, args: ?*c.PyObject) callconv(.c) py.Object {
    const self: *HeaderBlockObject = @ptrCast(obj.?);
    var name_obj: py.Object = null;
    var default_obj: py.Object = null;
    if (c.PyArg_ParseTuple(args, "O|O", &name_obj, &default_obj) == 0) return null;
    const wanted = py.asBytes(name_obj) orelse return null;
    const wanted_hash = headerHash(wanted);
    const data = headerData(self);
    for (headerRanges(self)[0..self.count]) |range| {
        if (range.hash == wanted_hash and headerNameEql(headerName(data, range), wanted)) {
            const value = headerValue(data, range);
            return internValue(value) orelse py.fromBytes(value);
        }
    }
    return if (default_obj == null) py.none() else py.newRef(default_obj);
}

fn headerBlockGetAll(obj: ?*c.PyObject, name_obj: ?*c.PyObject) callconv(.c) py.Object {
    const self: *HeaderBlockObject = @ptrCast(obj.?);
    const wanted = py.asBytes(name_obj) orelse return null;
    const wanted_hash = headerHash(wanted);
    const data = headerData(self);
    var count: usize = 0;
    for (headerRanges(self)[0..self.count]) |range| {
        if (range.hash == wanted_hash and headerNameEql(headerName(data, range), wanted)) count += 1;
    }
    const list = py.newList(@intCast(count));
    if (list == null) return null;
    var out_idx: usize = 0;
    for (headerRanges(self)[0..self.count]) |range| {
        if (range.hash == wanted_hash and headerNameEql(headerName(data, range), wanted)) {
            const value = headerValue(data, range);
            const value_obj = internValue(value) orelse py.fromBytes(value);
            if (value_obj == null) {
                py.decref(list);
                return null;
            }
            py.listSet(list, @intCast(out_idx), value_obj);
            out_idx += 1;
        }
    }
    return list;
}

fn headerBlockToList(obj: ?*c.PyObject, args: ?*c.PyObject, kwargs: ?*c.PyObject) callconv(.c) py.Object {
    var lowercase_names: c_int = 0;
    var kwlist = [_][*c]u8{ @constCast("lowercase_names"), null };
    if (c.PyArg_ParseTupleAndKeywords(args, kwargs, "|$p", @ptrCast(&kwlist), &lowercase_names) == 0) return null;
    return materializeHeaderBlock(@ptrCast(obj.?), lowercase_names != 0);
}

fn headerBlockRepr(obj: ?*c.PyObject) callconv(.c) py.Object {
    const list = materializeHeaderBlock(@ptrCast(obj.?), false);
    if (list == null) return null;
    defer py.decref(list);
    return c.PyObject_Repr(list);
}

fn headerBlockCmp(a: ?*c.PyObject, b: ?*c.PyObject, op: c_int) callconv(.c) py.Object {
    if (op != c.Py_EQ and op != c.Py_NE) return py.newRef(c.Py_NotImplemented());
    const left = materializeHeaderBlock(@ptrCast(a.?), false);
    if (left == null) return null;
    defer py.decref(left);
    if (c.Py_TYPE(b) == @as([*c]c.PyTypeObject, @ptrCast(header_block_type))) {
        const right = materializeHeaderBlock(@ptrCast(b.?), false);
        if (right == null) return null;
        defer py.decref(right);
        return c.PyObject_RichCompare(left, right, op);
    }
    return c.PyObject_RichCompare(left, b, op);
}

fn headerBlockDealloc(obj: ?*c.PyObject) callconv(.c) void {
    py.freeInstance(obj.?);
}

fn headerBlockNew(_: ?*c.PyTypeObject, _: ?*c.PyObject, _: ?*c.PyObject) callconv(.c) py.Object {
    return py.raiseType("zttp.HeaderBlock objects are created by HTTP/1 parsing");
}

var header_block_methods = [_]py.MethodDef{
    .{ .ml_name = "get", .ml_meth = headerBlockGet, .ml_flags = c.METH_VARARGS, .ml_doc = "Return the first case-insensitive header value, or default." },
    .{ .ml_name = "getall", .ml_meth = headerBlockGetAll, .ml_flags = c.METH_O, .ml_doc = "Return all values for a case-insensitive header name." },
    .{ .ml_name = "to_list", .ml_meth = @ptrCast(&headerBlockToList), .ml_flags = c.METH_VARARGS | c.METH_KEYWORDS, .ml_doc = "Materialize the fields, optionally with lowercase names." },
    .{ .ml_name = null, .ml_meth = null, .ml_flags = 0, .ml_doc = null },
};

var header_block_slots = [_]py.Slot{
    .{ .slot = c.Py_tp_new, .pfunc = @ptrCast(@constCast(&headerBlockNew)) },
    .{ .slot = c.Py_tp_dealloc, .pfunc = @ptrCast(@constCast(&headerBlockDealloc)) },
    .{ .slot = c.Py_tp_methods, .pfunc = @ptrCast(&header_block_methods) },
    .{ .slot = c.Py_tp_repr, .pfunc = @ptrCast(@constCast(&headerBlockRepr)) },
    .{ .slot = c.Py_tp_richcompare, .pfunc = @ptrCast(@constCast(&headerBlockCmp)) },
    .{ .slot = c.Py_sq_length, .pfunc = @ptrCast(@constCast(&headerBlockLen)) },
    .{ .slot = c.Py_sq_item, .pfunc = @ptrCast(@constCast(&headerBlockItem)) },
    .{ .slot = c.Py_tp_iter, .pfunc = @ptrCast(@constCast(&headerBlockIter)) },
    .{ .slot = c.Py_mp_subscript, .pfunc = @ptrCast(@constCast(&headerBlockSubscript)) },
    .{ .slot = 0, .pfunc = null },
};

var header_block_spec = py.Spec{
    .name = "zttp.HeaderBlock",
    .basicsize = @sizeOf(HeaderBlockObject),
    .itemsize = @sizeOf(HeaderRange),
    .flags = c.Py_TPFLAGS_DEFAULT |
        (if (@hasDecl(c, "Py_TPFLAGS_ITEMS_AT_END")) c.Py_TPFLAGS_ITEMS_AT_END else 0),
    .slots = &header_block_slots,
};

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

/// HTTP/1 conversion path: request/response headers use the packed lazy
/// HeaderBlock while every other event keeps its normal shape.
pub fn fromH1EventWithHeaderBlock(ev: events.H1Event) py.Object {
    return switch (ev) {
        .request => |r| makeRequestImpl(r, true),
        .response => |r| makeResponseImpl(r, true),
        else => fromH1Event(ev),
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
        .goaway => |g| makeGoAway(g),
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
        .connection_closed => py.newRef(connection_closed),
        .need_data => py.newRef(need_data),
        .settings => |s| makeSettings(s),
        .goaway => |g| makeGoAway(g),
        .rst_stream => |r| makeH3RstStream(r),
    };
}

/// Build a RstStream event from an HTTP/3 peer reset. The same Python type as the H2
/// reset event (its fields are boxed ints), but the values are u64 (62-bit QUIC
/// stream id and error code), so they are not truncated.
fn makeH3RstStream(r: events.StreamReset) py.Object {
    const o = py.allocInstance(rst_stream_type);
    if (o == null) return null;
    const s: *RstStreamObject = @ptrCast(o);
    s.stream_id = c.PyLong_FromUnsignedLongLong(r.stream_id);
    s.error_code = c.PyLong_FromUnsignedLongLong(r.error_code);
    if (s.stream_id == null or s.error_code == null) {
        py.decref(o);
        return null;
    }
    return o;
}

fn u32Obj(v: u32) py.Object {
    return c.PyLong_FromUnsignedLong(v);
}

fn makeRequest(r: events.Request) py.Object {
    return makeRequestImpl(r, false);
}

fn makeRequestImpl(r: events.Request, lazy_headers: bool) py.Object {
    const o = py.allocInstance(request_type);
    if (o == null) return null;
    const s: *RequestObject = @ptrCast(o);
    s.method = internFrom(&INTERNED_METHODS, &interned_methods, r.method) orelse py.fromBytes(r.method);
    s.target = py.fromBytes(r.target);
    // With no query string the parser hands path and target as the same slice,
    // so the immutable target bytes can simply be shared.
    s.path = if (s.target != null and r.path.ptr == r.target.ptr and r.path.len == r.target.len)
        py.newRef(s.target)
    else
        py.fromBytes(r.path);
    s.query = if (r.query.len == 0) py.newRef(empty_bytes) else py.fromBytes(r.query);
    s.http_version = internFrom(&INTERNED_VERSIONS, &interned_versions, r.http_version) orelse py.fromBytes(r.http_version);
    s.headers = if (lazy_headers) buildHeaderBlock(r.headers) else buildHeaders(r.headers);
    s.stream_id = r.stream_id;
    s.expect_continue = @intFromBool(r.expect_continue);
    s.end_stream = @intFromBool(r.end_stream);
    if (s.method == null or s.target == null or s.path == null or s.query == null or s.http_version == null or s.headers == null) {
        py.decref(o);
        return null;
    }
    return o;
}

fn makeResponse(r: events.Response) py.Object {
    return makeResponseImpl(r, false);
}

fn makeResponseImpl(r: events.Response, lazy_headers: bool) py.Object {
    const o = py.allocInstance(response_type);
    if (o == null) return null;
    const s: *ResponseObject = @ptrCast(o);
    s.status_code = py.fromU16(r.status_code);
    s.reason = internFrom(&INTERNED_REASONS, &interned_reasons, r.reason) orelse py.fromBytes(r.reason);
    s.http_version = internFrom(&INTERNED_VERSIONS, &interned_versions, r.http_version) orelse py.fromBytes(r.http_version);
    s.headers = if (lazy_headers) buildHeaderBlock(r.headers) else buildHeaders(r.headers);
    s.stream_id = r.stream_id;
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
    s.stream_id = d.stream_id;
    if (s.data == null) {
        py.decref(o);
        return null;
    }
    return o;
}

/// Build an HTTP/1 Data event by retaining the exact immutable bytes object the
/// caller fed. The connection has already established that the whole object is
/// the emitted body span, so no slice or copy is needed.
pub fn makeH1DataFromBytes(data_obj: py.Object) py.Object {
    const o = py.allocInstance(data_type);
    if (o == null) return null;
    const s: *DataObject = @ptrCast(o);
    s.data = py.newRef(data_obj);
    s.stream_id = 0;
    return o;
}

fn makeEom(e: events.EndOfMessage) py.Object {
    const o = py.allocInstance(end_of_message_type);
    if (o == null) return null;
    const s: *EndOfMessageObject = @ptrCast(o);
    s.trailers = buildHeaders(e.trailers);
    s.stream_id = e.stream_id;
    if (s.trailers == null) {
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

fn makeGoAway(g: events.GoAway) py.Object {
    const o = py.allocInstance(goaway_type);
    if (o == null) return null;
    const s: *GoAwayObject = @ptrCast(o);
    s.last_stream_id = c.PyLong_FromUnsignedLongLong(g.last_stream_id);
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
        const id = c.PyLong_FromUnsignedLongLong(p.id);
        const value = c.PyLong_FromUnsignedLongLong(p.value);
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
    header_block_type = py.typeFromSpec(&header_block_spec);
    request_type = py.typeFromSpec(&request_spec);
    response_type = py.typeFromSpec(&response_spec);
    data_type = py.typeFromSpec(&data_spec);
    end_of_message_type = py.typeFromSpec(&eom_spec);
    rst_stream_type = py.typeFromSpec(&rst_stream_spec);
    goaway_type = py.typeFromSpec(&goaway_spec);
    settings_type = py.typeFromSpec(&settings_spec);
    ping_type = py.typeFromSpec(&ping_spec);
    window_update_type = py.typeFromSpec(&window_update_spec);
    if (header_block_type == null or request_type == null or response_type == null or data_type == null or end_of_message_type == null) {
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

    _ = c.PyModule_AddObjectRef(module, "HeaderBlock", header_block_type);
    _ = c.PyModule_AddObjectRef(module, "Request", request_type);
    _ = c.PyModule_AddObjectRef(module, "Response", response_type);
    _ = c.PyModule_AddObjectRef(module, "Data", data_type);
    _ = c.PyModule_AddObjectRef(module, "EndOfMessage", end_of_message_type);
    _ = c.PyModule_AddObjectRef(module, "RstStream", rst_stream_type);
    _ = c.PyModule_AddObjectRef(module, "GoAway", goaway_type);
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
