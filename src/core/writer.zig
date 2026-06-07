//! The write-side serializer: turn a request/response head, body data, and the
//! end-of-message into wire bytes. It is the mirror of the reader - sans-IO,
//! appending to a caller-owned buffer - and tracks just enough state to frame
//! the body correctly (Content-Length passthrough vs chunked encoding) and to
//! reject misuse (a body before a head, two heads in a row).

const std = @import("std");
const tables = @import("tables.zig");
const events = @import("events.zig");

const Header = events.Header;

pub const WriteError = error{
    /// A send was attempted in a state that does not allow it (e.g. data before
    /// the head, or a second head before the first message ended).
    LocalProtocol,
    /// A field (method/target/version/reason/header) contained bytes that would
    /// break the wire grammar - CR, LF, NUL or other controls. Serializing them
    /// verbatim would allow header/response-splitting injection.
    InvalidField,
    OutOfMemory,
};

/// A header field-name must be a non-empty token (RFC 9110 5.6.2).
fn validName(name: []const u8) WriteError!void {
    if (name.len == 0) return error.InvalidField;
    for (name) |ch| {
        if (!tables.is_tchar[ch]) return error.InvalidField;
    }
}

/// A header field-value may not contain CR, LF, NUL or other controls (except
/// HTAB). Matches the parser's field-vchar acceptance.
fn validValue(value: []const u8) WriteError!void {
    for (value) |ch| {
        if (!tables.is_field_vchar[ch]) return error.InvalidField;
    }
}

/// Normalize a caller-supplied HTTP version into the bare number (e.g. "1.1"),
/// accepting both "1.1" and "HTTP/1.1" so a value round-tripped from the read
/// side (which yields the bare "1.1") cannot double-prefix into "HTTP/HTTP/1.1".
/// The result must be exactly `DIGIT "." DIGIT`.
fn normalizeVersion(version: []const u8) WriteError![]const u8 {
    const v = if (version.len >= 5 and std.mem.eql(u8, version[0..5], "HTTP/")) version[5..] else version;
    if (v.len != 3 or v[0] < '0' or v[0] > '9' or v[1] != '.' or v[2] < '0' or v[2] > '9') {
        return error.InvalidField;
    }
    return v;
}

/// Request-line / status-line tokens (method, target, version, reason) must not
/// carry CR/LF or controls. Reason allows SP; the others should not contain SP,
/// but we only guard against the injection-relevant controls here.
fn validLineToken(s: []const u8, allow_sp: bool) WriteError!void {
    for (s) |ch| {
        if (ch == '\r' or ch == '\n' or ch == 0) return error.InvalidField;
        if (ch < 0x20 and !(allow_sp and ch == '\t')) return error.InvalidField;
        if (ch == 0x7F) return error.InvalidField;
        if (!allow_sp and ch == ' ') return error.InvalidField;
    }
}

fn validateHeaders(hdrs: []const Header) WriteError!void {
    for (hdrs) |h| {
        try validName(h.name);
        try validValue(h.value);
    }
    try validateFraming(hdrs);
}

/// Refuse to serialize ambiguous framing - the send-side mirror of the reader's
/// smuggling guards. A message carrying both Transfer-Encoding and
/// Content-Length, or conflicting duplicate Content-Lengths, would let a
/// downstream parser disagree about message boundaries (response splitting).
fn validateFraming(hdrs: []const Header) WriteError!void {
    var has_te = false;
    var content_length: ?[]const u8 = null;
    for (hdrs) |h| {
        if (eqIgnoreCase(h.name, "transfer-encoding")) {
            has_te = true;
        } else if (eqIgnoreCase(h.name, "content-length")) {
            const v = trimOws(h.value);
            for (v) |ch| if (ch < '0' or ch > '9') return error.InvalidField; // digits only
            if (content_length) |prev| {
                if (!eqIgnoreCase(prev, v)) return error.InvalidField; // conflicting duplicate
            }
            content_length = v;
        }
    }
    if (has_te and content_length != null) return error.InvalidField; // TE + CL
}

fn trimOws(s: []const u8) []const u8 {
    var start: usize = 0;
    var end = s.len;
    while (start < end and (s[start] == ' ' or s[start] == '\t')) start += 1;
    while (end > start and (s[end - 1] == ' ' or s[end - 1] == '\t')) end -= 1;
    return s[start..end];
}

const State = enum {
    /// No message in flight; the next send must be a head.
    idle,
    /// Head sent with a fixed Content-Length; body bytes pass through.
    body_length,
    /// Head sent with Transfer-Encoding: chunked; body bytes are chunk-framed.
    body_chunked,
    /// No body expected after the head (bodyless response / zero length).
    body_none,
};

pub const Writer = struct {
    gpa: std.mem.Allocator,
    out: std.ArrayList(u8) = .empty,
    state: State = .idle,

    pub fn init(gpa: std.mem.Allocator) Writer {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Writer) void {
        self.out.deinit(self.gpa);
    }

    /// Take the bytes produced so far, leaving the buffer empty for reuse.
    pub fn take(self: *Writer) []u8 {
        const owned = self.out.toOwnedSlice(self.gpa) catch return &.{};
        return owned;
    }

    /// The pending output without transferring ownership.
    pub fn pending(self: *const Writer) []const u8 {
        return self.out.items;
    }

    pub fn clear(self: *Writer) void {
        self.out.clearRetainingCapacity();
    }

    fn w(self: *Writer, s: []const u8) WriteError!void {
        try self.out.appendSlice(self.gpa, s);
    }

    /// Serialize a request-line + headers. `framing` decides body handling.
    pub fn sendRequest(self: *Writer, method: []const u8, target: []const u8, version: []const u8, hdrs: []const Header) WriteError!void {
        if (self.state != .idle) return error.LocalProtocol;
        try validLineToken(method, false);
        try validLineToken(target, false);
        const ver = try normalizeVersion(version);
        try validateHeaders(hdrs);
        try self.w(method);
        try self.w(" ");
        try self.w(target);
        try self.w(" HTTP/");
        try self.w(ver);
        try self.w("\r\n");
        try self.writeHeaders(hdrs);
        self.state = bodyStateFor(hdrs);
    }

    /// Serialize a status-line + headers.
    pub fn sendResponse(self: *Writer, version: []const u8, status: u16, reason: []const u8, hdrs: []const Header, bodyless: bool) WriteError!void {
        if (self.state != .idle) return error.LocalProtocol;
        const ver = try normalizeVersion(version);
        try validLineToken(reason, true); // reason-phrase may contain SP/HTAB
        try validateHeaders(hdrs);
        try self.w("HTTP/");
        try self.w(ver);
        try self.w(" ");
        var buf: [3]u8 = undefined;
        buf[0] = '0' + @as(u8, @intCast((status / 100) % 10));
        buf[1] = '0' + @as(u8, @intCast((status / 10) % 10));
        buf[2] = '0' + @as(u8, @intCast(status % 10));
        try self.w(&buf);
        try self.w(" ");
        try self.w(reason);
        try self.w("\r\n");
        try self.writeHeaders(hdrs);
        self.state = if (bodyless) .body_none else bodyStateFor(hdrs);
    }

    fn writeHeaders(self: *Writer, hdrs: []const Header) WriteError!void {
        for (hdrs) |h| {
            try self.w(h.name);
            try self.w(": ");
            try self.w(h.value);
            try self.w("\r\n");
        }
        try self.w("\r\n");
    }

    /// Serialize a run of body bytes, chunk-framing them if the head declared
    /// chunked transfer-coding.
    pub fn sendData(self: *Writer, data: []const u8) WriteError!void {
        switch (self.state) {
            .body_length => try self.w(data),
            .body_chunked => {
                if (data.len == 0) return; // empty write is not a terminator
                var size_buf: [18]u8 = undefined;
                const size = std.fmt.bufPrint(&size_buf, "{x}\r\n", .{data.len}) catch unreachable;
                try self.w(size);
                try self.w(data);
                try self.w("\r\n");
            },
            else => return error.LocalProtocol,
        }
    }

    /// Finish the message. For chunked, writes the terminating 0-chunk and any
    /// trailers; otherwise just resets to idle for the next message.
    pub fn endMessage(self: *Writer, trailers: []const Header) WriteError!void {
        switch (self.state) {
            .body_chunked => {
                try validateHeaders(trailers);
                try self.w("0\r\n");
                for (trailers) |tr| {
                    try self.w(tr.name);
                    try self.w(": ");
                    try self.w(tr.value);
                    try self.w("\r\n");
                }
                try self.w("\r\n");
            },
            .body_length, .body_none => {},
            .idle => return error.LocalProtocol,
        }
        self.state = .idle;
    }
};

fn eqIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (tables.to_lower[x] != tables.to_lower[y]) return false;
    return true;
}

/// Pick the body state from the headers the caller supplied: chunked if
/// Transfer-Encoding is present, else length if Content-Length is present, else
/// none. The caller is trusted to provide consistent framing headers.
fn bodyStateFor(hdrs: []const Header) State {
    for (hdrs) |h| {
        if (eqIgnoreCase(h.name, "transfer-encoding")) return .body_chunked;
    }
    for (hdrs) |h| {
        if (eqIgnoreCase(h.name, "content-length")) return .body_length;
    }
    return .body_none;
}

const t = std.testing;

test "serialize a simple response" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{
        .{ .name = "Content-Type", .value = "text/plain" },
        .{ .name = "Content-Length", .value = "5" },
    };
    try wr.sendResponse("1.1", 200, "OK", &hdrs, false);
    try wr.sendData("hello");
    try wr.endMessage(&.{});
    try t.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
        wr.pending(),
    );
}

test "serialize a request" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{.{ .name = "Host", .value = "example.com" }};
    try wr.sendRequest("GET", "/", "1.1", &hdrs);
    try wr.endMessage(&.{});
    try t.expectEqualStrings("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", wr.pending());
}

test "version accepts both bare and HTTP/-prefixed forms" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try wr.sendRequest("GET", "/", "HTTP/1.1", &.{}); // round-tripped form
    try wr.endMessage(&.{});
    try t.expectEqualStrings("GET / HTTP/1.1\r\n\r\n", wr.pending());
}

test "invalid version rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try t.expectError(error.InvalidField, wr.sendRequest("GET", "/", "1.1.1", &.{}));
    var wr2 = Writer.init(t.allocator);
    defer wr2.deinit();
    try t.expectError(error.InvalidField, wr2.sendResponse("garbage", 200, "OK", &.{}, true));
}

test "chunked response framing" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked" }};
    try wr.sendResponse("1.1", 200, "OK", &hdrs, false);
    try wr.sendData("Wiki");
    try wr.sendData("pedia");
    try wr.endMessage(&.{});
    try t.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        wr.pending(),
    );
}

test "chunked with trailers" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked" }};
    const trailers = [_]Header{.{ .name = "X-Checksum", .value = "abc" }};
    try wr.sendResponse("1.1", 200, "OK", &hdrs, false);
    try wr.sendData("data");
    try wr.endMessage(&trailers);
    try t.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\nX-Checksum: abc\r\n\r\n",
        wr.pending(),
    );
}

test "status code formatting" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try wr.sendResponse("1.1", 404, "Not Found", &.{}, true);
    try wr.endMessage(&.{});
    try t.expectEqualStrings("HTTP/1.1 404 Not Found\r\n\r\n", wr.pending());
}

test "data before head is rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try t.expectError(error.LocalProtocol, wr.sendData("x"));
}

test "two heads without ending is rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try wr.sendResponse("1.1", 200, "OK", &.{}, true);
    try t.expectError(error.LocalProtocol, wr.sendResponse("1.1", 200, "OK", &.{}, true));
}

test "take transfers ownership and empties" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try wr.sendResponse("1.1", 204, "No Content", &.{}, true);
    try wr.endMessage(&.{});
    const owned = wr.take();
    defer t.allocator.free(owned);
    try t.expectEqualStrings("HTTP/1.1 204 No Content\r\n\r\n", owned);
    try t.expectEqual(@as(usize, 0), wr.pending().len);
}

test "send-path injection: CRLF in reason rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK\r\nX-Evil: 1", &.{}, true));
}

test "send-path injection: CRLF in header value rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{.{ .name = "X", .value = "a\r\nInjected: yes" }};
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, true));
}

test "send-path injection: bad header name rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{.{ .name = "Bad Name", .value = "x" }};
    try t.expectError(error.InvalidField, wr.sendRequest("GET", "/", "1.1", &h));
}

test "send-path injection: CRLF in target rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try t.expectError(error.InvalidField, wr.sendRequest("GET", "/ HTTP/1.1\r\nX: y", "1.1", &.{}));
}

test "send-path injection: CRLF in trailer rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked" }};
    try wr.sendResponse("1.1", 200, "OK", &hdrs, false);
    const trailers = [_]Header{.{ .name = "X", .value = "v\r\nInjected: 1" }};
    try t.expectError(error.InvalidField, wr.endMessage(&trailers));
}

test "send rejects ambiguous framing (TE + CL)" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Content-Length", .value = "5" },
    };
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, false));
}

test "send rejects conflicting duplicate Content-Length" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{
        .{ .name = "Content-Length", .value = "5" },
        .{ .name = "Content-Length", .value = "6" },
    };
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, false));
}

test "send rejects non-digit Content-Length" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{.{ .name = "Content-Length", .value = "5x" }};
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, false));
}
