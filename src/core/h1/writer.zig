//! The write-side serializer: turn a request/response head, body data, and the
//! end-of-message into wire bytes. It is the mirror of the reader - sans-IO,
//! appending to a caller-owned buffer - and tracks just enough state to frame
//! the body correctly (Content-Length passthrough vs chunked encoding) and to
//! reject misuse (a body before a head, two heads in a row).

const std = @import("std");
const tables = @import("../tables.zig");
const ascii = @import("../ascii.zig");
const events = @import("../events.zig");
const framing = @import("framing.zig");
const headers_mod = @import("headers.zig");

const Header = events.Header;
const responseIsBodyless = framing.responseIsBodyless;
const responseForbidsTransferEncoding = framing.responseForbidsTransferEncoding;
const eqIgnoreCase = ascii.eqIgnoreCase;
const trimOws = ascii.trimOws;

pub const WriteError = error{
    /// A head was sent while a message was still in progress.
    MessageNotEnded,
    /// Body bytes were sent when none can be: before a head, or on a message
    /// whose framing carries no body.
    NoBodyAllowed,
    /// More body bytes were sent than the declared Content-Length allows.
    BodyTooLong,
    /// The message was ended before the declared Content-Length was reached.
    BodyTooShort,
    /// Trailers were passed to a message that cannot carry them - only a chunked
    /// body has a place for trailers on the wire.
    TrailersNotAllowed,
    /// The message was ended when none was in progress.
    NoMessageInProgress,
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
/// The result must be exactly `1 "." DIGIT`: this is the HTTP/1 serializer, so
/// emitting an `HTTP/2.0` or `HTTP/0.9` start line would create a version
/// differential with the reader.
fn normalizeVersion(version: []const u8) WriteError![]const u8 {
    const v = if (version.len >= 5 and std.mem.eql(u8, version[0..5], "HTTP/")) version[5..] else version;
    if (v.len != 3 or v[0] != '1' or v[1] != '.' or v[2] < '0' or v[2] > '9') {
        return error.InvalidField;
    }
    return v;
}

/// Methods are tokens on the wire, same grammar as field names.
fn validMethod(method: []const u8) WriteError!void {
    try validName(method);
}

/// Request targets use the same permissive-but-bounded class as the parser:
/// no controls, SP, DEL, or DQUOTE, and not empty.
fn validTarget(target: []const u8) WriteError!void {
    if (target.len == 0) return error.InvalidField;
    for (target) |ch| {
        if (!tables.is_target_char[ch]) return error.InvalidField;
    }
}

/// Reason phrases may contain SP/HTAB, but not CR/LF, NUL, DEL, or other
/// controls.
fn validReasonPhrase(reason: []const u8) WriteError!void {
    for (reason) |ch| {
        if (ch == '\r' or ch == '\n' or ch == 0) return error.InvalidField;
        if (ch < 0x20 and ch != '\t') return error.InvalidField;
        if (ch == 0x7F) return error.InvalidField;
    }
}

/// The IANA reason phrase for a status code. Unknown codes fall back to a
/// per-class generic phrase; the code is what carries meaning, the phrase is
/// advisory (RFC 9110 15.1), so callers may always override it.
pub fn reasonPhrase(status: u16) []const u8 {
    return switch (status) {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a Teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        else => switch (status / 100) {
            1 => "Informational",
            2 => "Success",
            3 => "Redirection",
            4 => "Client Error",
            5 => "Server Error",
            else => "Unknown",
        },
    };
}

fn validateHeaders(hdrs: []const Header) WriteError!void {
    for (hdrs) |h| {
        try validName(h.name);
        try validValue(h.value);
    }
    try validateFraming(hdrs);
}

fn hasHeader(hdrs: []const Header, name: []const u8) bool {
    for (hdrs) |h| if (eqIgnoreCase(h.name, name)) return true;
    return false;
}

/// Refuse to serialize ambiguous framing - the send-side mirror of the reader's
/// smuggling guards. A message carrying both Transfer-Encoding and
/// Content-Length, multiple Transfer-Encoding fields, unsupported TE codings, or
/// duplicate Content-Lengths would let a downstream parser disagree
/// about message boundaries (response splitting).
fn validateFraming(hdrs: []const Header) WriteError!void {
    var has_te = false;
    var content_length: ?[]const u8 = null;
    for (hdrs) |h| {
        if (eqIgnoreCase(h.name, "transfer-encoding")) {
            if (has_te) return error.InvalidField;
            has_te = true;
            // h11-style send policy: zttp only emits the `chunked` transfer
            // coding it implements, never unsupported metadata-only codings.
            if (!eqIgnoreCase(trimOws(h.value), "chunked")) return error.InvalidField;
        } else if (eqIgnoreCase(h.name, "content-length")) {
            const v = trimOws(h.value);
            if (ascii.parseDecimal(u64, v) == null) return error.InvalidField; // non-empty digits, no overflow
            if (content_length != null) return error.InvalidField;
            content_length = v;
        }
    }
    if (has_te and content_length != null) return error.InvalidField; // TE + CL
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
    /// Bytes still owed under a fixed Content-Length. Sending more than declared,
    /// or ending the message with bytes still owed, is a local protocol error -
    /// it would put a malformed message on the wire.
    body_remaining: u64 = 0,

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
        if (self.state != .idle) return error.MessageNotEnded;
        try validMethod(method);
        try validTarget(target);
        const ver = try normalizeVersion(version);
        try validateHeaders(hdrs);
        try self.w(method);
        try self.w(" ");
        try self.w(target);
        try self.w(" HTTP/");
        try self.w(ver);
        try self.w("\r\n");
        try self.writeHeaders(hdrs);
        const framing_ = bodyStateFor(hdrs);
        self.state = framing_.state;
        self.body_remaining = framing_.length;
    }

    /// Serialize a status-line + headers. `request_method` is the method this
    /// response answers; together with the status it decides whether the response
    /// is bodyless (RFC 9112 6.3), so the caller never tracks framing by hand.
    pub fn sendResponse(self: *Writer, version: []const u8, status: u16, reason: []const u8, hdrs: []const Header, request_method: []const u8) WriteError!void {
        if (self.state != .idle) return error.MessageNotEnded;
        if (responseForbidsTransferEncoding(request_method, status) and hasHeader(hdrs, "transfer-encoding")) return error.InvalidField;
        try self.writeStatusLine(try normalizeVersion(version), status, reason, hdrs);
        if (responseIsBodyless(request_method, status)) {
            self.state = .body_none;
            self.body_remaining = 0;
        } else {
            const framing_ = bodyStateFor(hdrs);
            self.state = framing_.state;
            self.body_remaining = framing_.length;
        }
    }

    /// Serialize an interim (1xx) response: a status-line + headers that precedes
    /// the final response on the same message cycle. Unlike `sendResponse` it does
    /// not consume the cycle - the writer stays idle, awaiting the real response.
    /// The reason phrase is derived from the status, and the version is always 1.1
    /// (1xx didn't exist in HTTP/1.0). Status must be 100..199, excluding 101:
    /// 101 Switching Protocols is terminal (the connection leaves HTTP afterwards),
    /// not interim, so it cannot be followed by a final response here.
    pub fn sendInformational(self: *Writer, status: u16, hdrs: []const Header) WriteError!void {
        if (self.state != .idle) return error.MessageNotEnded;
        if (status / 100 != 1 or status == 101) return error.InvalidField;
        if (hasHeader(hdrs, "transfer-encoding")) return error.InvalidField;
        try self.writeStatusLine("1.1", status, reasonPhrase(status), hdrs);
    }

    fn writeStatusLine(self: *Writer, version: []const u8, status: u16, reason: []const u8, hdrs: []const Header) WriteError!void {
        if (status < 100 or status > 599) return error.InvalidField;
        try validReasonPhrase(reason);
        try validateHeaders(hdrs);
        try self.w("HTTP/");
        try self.w(version);
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
            .body_length => {
                if (data.len > self.body_remaining) return error.BodyTooLong;
                try self.w(data);
                self.body_remaining -= data.len;
            },
            .body_chunked => {
                if (data.len == 0) return; // empty write is not a terminator
                var size_buf: [18]u8 = undefined;
                const size = std.fmt.bufPrint(&size_buf, "{x}\r\n", .{data.len}) catch unreachable;
                try self.w(size);
                try self.w(data);
                try self.w("\r\n");
            },
            else => return error.NoBodyAllowed,
        }
    }

    /// Finish the message. For chunked, writes the terminating 0-chunk and any
    /// trailers; otherwise just resets to idle for the next message. Trailers are
    /// only framable after a chunked body, so passing them with any other framing
    /// is a local protocol error - there is nowhere on the wire to put them.
    pub fn endMessage(self: *Writer, trailers: []const Header) WriteError!void {
        switch (self.state) {
            .body_chunked => {
                try validateHeaders(trailers);
                for (trailers) |tr| {
                    if (!headers_mod.trailerFieldAllowed(tr.name)) return error.InvalidField;
                }
                try self.w("0\r\n");
                for (trailers) |tr| {
                    try self.w(tr.name);
                    try self.w(": ");
                    try self.w(tr.value);
                    try self.w("\r\n");
                }
                try self.w("\r\n");
            },
            .body_length => {
                if (self.body_remaining != 0) return error.BodyTooShort;
                if (trailers.len != 0) return error.TrailersNotAllowed;
            },
            .body_none => {
                if (trailers.len != 0) return error.TrailersNotAllowed;
            },
            .idle => return error.NoMessageInProgress,
        }
        self.state = .idle;
    }
};

const BodyFraming = struct { state: State, length: u64 = 0 };

/// Pick the body state from the headers the caller supplied: chunked if
/// Transfer-Encoding is present, else length if Content-Length is present, else
/// none. For a fixed length, also returns the declared count so the writer can
/// hold the caller to it. The caller is trusted to provide consistent framing
/// headers (validateFraming already rejected the ambiguous combinations).
fn bodyStateFor(hdrs: []const Header) BodyFraming {
    for (hdrs) |h| {
        if (eqIgnoreCase(h.name, "transfer-encoding")) return .{ .state = .body_chunked };
    }
    for (hdrs) |h| {
        if (eqIgnoreCase(h.name, "content-length")) {
            const n = parseLength(trimOws(h.value));
            return if (n == 0) .{ .state = .body_none } else .{ .state = .body_length, .length = n };
        }
    }
    return .{ .state = .body_none };
}

/// Parse a Content-Length. validateFraming already rejected non-digit,
/// overflowing, and conflicting values, so this only sees an empty value (an
/// empty Content-Length frames no body) or a parseable one.
fn parseLength(v: []const u8) u64 {
    return ascii.parseDecimal(u64, v) orelse 0;
}

const t = std.testing;

test "serialize a simple response" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{
        .{ .name = "Content-Type", .value = "text/plain" },
        .{ .name = "Content-Length", .value = "5" },
    };
    try wr.sendResponse("1.1", 200, "OK", &hdrs, "GET");
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
    try t.expectError(error.InvalidField, wr2.sendResponse("garbage", 200, "OK", &.{}, "GET"));
}

test "non-HTTP/1 versions rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try t.expectError(error.InvalidField, wr.sendRequest("GET", "/", "HTTP/2.0", &.{}));
    try t.expectError(error.InvalidField, wr.sendResponse("0.9", 200, "OK", &.{}, "GET"));
}

test "chunked response framing" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked" }};
    try wr.sendResponse("1.1", 200, "OK", &hdrs, "GET");
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
    try wr.sendResponse("1.1", 200, "OK", &hdrs, "GET");
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
    try wr.sendResponse("1.1", 404, "Not Found", &.{}, "GET");
    try wr.endMessage(&.{});
    try t.expectEqualStrings("HTTP/1.1 404 Not Found\r\n\r\n", wr.pending());
}

test "status code range rejected before formatting" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 99, "Too Low", &.{}, "GET"));
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 600, "Too High", &.{}, "GET"));
    try t.expectEqualStrings("", wr.pending());
}

test "HEAD response is bodyless despite Content-Length" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{.{ .name = "Content-Length", .value = "1234" }};
    try wr.sendResponse("1.1", 200, "OK", &hdrs, "HEAD");
    try t.expectError(error.NoBodyAllowed, wr.sendData("x"));
    try wr.endMessage(&.{});
    try t.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n", wr.pending());
}

test "responses forbidden to carry Transfer-Encoding reject it before output" {
    const hdrs = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked" }};
    const cases = .{
        .{ @as(u16, 103), "Early Hints", "GET" },
        .{ @as(u16, 204), "No Content", "GET" },
        .{ @as(u16, 200), "OK", "CONNECT" },
    };
    inline for (cases) |case| {
        var wr = Writer.init(t.allocator);
        defer wr.deinit();
        try t.expectError(error.InvalidField, wr.sendResponse("1.1", case[0], case[1], &hdrs, case[2]));
        try t.expectEqualStrings("", wr.pending());
    }
}

test "informational response rejects Transfer-Encoding before output" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked" }};
    try t.expectError(error.InvalidField, wr.sendInformational(103, &hdrs));
    try t.expectEqualStrings("", wr.pending());
}

test "HEAD and 304 may describe chunked coding of corresponding body" {
    const hdrs = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked" }};
    const cases = .{
        .{ @as(u16, 200), "OK", "HEAD" },
        .{ @as(u16, 304), "Not Modified", "GET" },
    };
    inline for (cases) |case| {
        var wr = Writer.init(t.allocator);
        defer wr.deinit();
        try wr.sendResponse("1.1", case[0], case[1], &hdrs, case[2]);
        try t.expectError(error.NoBodyAllowed, wr.sendData("x"));
        try wr.endMessage(&.{});
    }
}

test "data before head is rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try t.expectError(error.NoBodyAllowed, wr.sendData("x"));
}

test "oversized body rejected against Content-Length" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{.{ .name = "Content-Length", .value = "5" }};
    try wr.sendResponse("1.1", 200, "OK", &hdrs, "GET");
    try t.expectError(error.BodyTooLong, wr.sendData("abcdef")); // 6 > 5
}

test "oversized body rejected across multiple writes" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{.{ .name = "Content-Length", .value = "5" }};
    try wr.sendResponse("1.1", 200, "OK", &hdrs, "GET");
    try wr.sendData("abc");
    try t.expectError(error.BodyTooLong, wr.sendData("def")); // 3 + 3 > 5
}

test "undersized body rejected at end_message" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{.{ .name = "Content-Length", .value = "5" }};
    try wr.sendResponse("1.1", 200, "OK", &hdrs, "GET");
    try wr.sendData("abc");
    try t.expectError(error.BodyTooShort, wr.endMessage(&.{})); // 2 bytes still owed
}

test "exact-length body is accepted" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{.{ .name = "Content-Length", .value = "5" }};
    try wr.sendResponse("1.1", 200, "OK", &hdrs, "GET");
    try wr.sendData("ab");
    try wr.sendData("cde");
    try wr.endMessage(&.{});
    try t.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde", wr.pending());
}

test "trailers rejected on a Content-Length body" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{.{ .name = "Content-Length", .value = "3" }};
    try wr.sendResponse("1.1", 200, "OK", &hdrs, "GET");
    try wr.sendData("abc");
    const trailers = [_]Header{.{ .name = "X-Checksum", .value = "abc" }};
    try t.expectError(error.TrailersNotAllowed, wr.endMessage(&trailers));
}

test "trailers rejected on a bodyless message" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try wr.sendResponse("1.1", 204, "No Content", &.{}, "GET");
    const trailers = [_]Header{.{ .name = "X-Checksum", .value = "abc" }};
    try t.expectError(error.TrailersNotAllowed, wr.endMessage(&trailers));
}

test "two heads without ending is rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try wr.sendResponse("1.1", 200, "OK", &.{}, "GET");
    try t.expectError(error.MessageNotEnded, wr.sendResponse("1.1", 200, "OK", &.{}, "GET"));
}

test "end_message with no message in progress is rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try t.expectError(error.NoMessageInProgress, wr.endMessage(&.{}));
}

test "take transfers ownership and empties" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try wr.sendResponse("1.1", 204, "No Content", &.{}, "GET");
    try wr.endMessage(&.{});
    const owned = wr.take();
    defer t.allocator.free(owned);
    try t.expectEqualStrings("HTTP/1.1 204 No Content\r\n\r\n", owned);
    try t.expectEqual(@as(usize, 0), wr.pending().len);
}

test "send-path injection: CRLF in reason rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK\r\nX-Evil: 1", &.{}, "GET"));
}

test "send-path injection: CRLF in header value rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{.{ .name = "X", .value = "a\r\nInjected: yes" }};
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, "GET"));
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

test "send rejects malformed request-line fields" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try t.expectError(error.InvalidField, wr.sendRequest("", "/", "1.1", &.{}));
    try t.expectError(error.InvalidField, wr.sendRequest("GE:T", "/", "1.1", &.{}));
    try t.expectError(error.InvalidField, wr.sendRequest("GET", "", "1.1", &.{}));
    try t.expectError(error.InvalidField, wr.sendRequest("GET", "\"bad\"", "1.1", &.{}));
    try t.expectEqualStrings("", wr.pending());
}

test "send validates reason phrase controls" {
    inline for (.{ "O\x00K", "O\x07K", "O\x7fK" }) |reason| {
        var wr = Writer.init(t.allocator);
        defer wr.deinit();
        try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, reason, &.{}, "GET"));
        try t.expectEqualStrings("", wr.pending());
    }

    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    try wr.sendResponse("1.1", 200, "O\tK", &.{}, "GET");
    try wr.endMessage(&.{});
    try t.expectEqualStrings("HTTP/1.1 200 O\tK\r\n\r\n", wr.pending());
}

test "send-path injection: CRLF in trailer rejected" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const hdrs = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked" }};
    try wr.sendResponse("1.1", 200, "OK", &hdrs, "GET");
    const trailers = [_]Header{.{ .name = "X", .value = "v\r\nInjected: 1" }};
    try t.expectError(error.InvalidField, wr.endMessage(&trailers));
}

test "send rejects prohibited trailers" {
    inline for (.{ "Transfer-Encoding", "Trailer", "Content-Type" }) |name| {
        var wr = Writer.init(t.allocator);
        defer wr.deinit();
        const hdrs = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked" }};
        try wr.sendResponse("1.1", 200, "OK", &hdrs, "GET");
        const trailers = [_]Header{.{ .name = name, .value = "x" }};
        try t.expectError(error.InvalidField, wr.endMessage(&trailers));
    }
}

test "send rejects non-chunked transfer-encoding" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{.{ .name = "Transfer-Encoding", .value = "gzip" }};
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, "GET"));
}

test "send rejects non-final transfer-encoding chunked" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked, gzip" }};
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, "GET"));
}

test "send rejects duplicate transfer-encoding chunked" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked, chunked" }};
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, "GET"));
}

test "send rejects unsupported transfer-encoding comma list" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{.{ .name = "Transfer-Encoding", .value = "gzip, chunked" }};
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, "GET"));
}

test "send rejects multiple transfer-encoding fields" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{
        .{ .name = "Transfer-Encoding", .value = "gzip" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
    };
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, "GET"));
}

test "send rejects ambiguous framing (TE + CL)" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Content-Length", .value = "5" },
    };
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, "GET"));
}

test "send rejects conflicting duplicate Content-Length" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{
        .{ .name = "Content-Length", .value = "5" },
        .{ .name = "Content-Length", .value = "6" },
    };
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, "GET"));
}

test "send rejects identical duplicate Content-Length" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{
        .{ .name = "Content-Length", .value = "5" },
        .{ .name = "Content-Length", .value = "5" },
    };
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, "GET"));
}

test "send rejects non-digit Content-Length" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const h = [_]Header{.{ .name = "Content-Length", .value = "5x" }};
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &h, "GET"));
}

test "send rejects empty Content-Length" {
    var wr = Writer.init(t.allocator);
    defer wr.deinit();
    const empty = [_]Header{.{ .name = "Content-Length", .value = "" }};
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &empty, "GET"));

    const whitespace = [_]Header{.{ .name = "Content-Length", .value = "   " }};
    try t.expectError(error.InvalidField, wr.sendResponse("1.1", 200, "OK", &whitespace, "GET"));
}
