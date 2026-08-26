//! Parse a header block (the field-lines up to the terminating blank line) into
//! a list of `Header` slices, and parse a single request- or status-line. All
//! results slice into the fed buffer; the only allocation is the growable list
//! of (name, value) pairs, which the caller owns.

const std = @import("std");
const tables = @import("../tables.zig");
const events = @import("../events.zig");
const fields = @import("../fields.zig");
const scanner = @import("../scanner.zig");
const Scanner = scanner.Scanner;
const trimTrailingOws = scanner.trimTrailingOws;
const ParseError = @import("../errors.zig").ParseError;

const Header = events.Header;

pub const RequestLine = struct {
    method: []const u8,
    target: []const u8,
    path: []const u8,
    query: []const u8,
    http_version: []const u8,
};

pub const StatusLine = struct {
    http_version: []const u8,
    status_code: u16,
    reason: []const u8,
};

/// Parse the request-line `method SP request-target SP HTTP-version`.
/// RFC 9112 3. Exactly one SP between tokens; no leading whitespace.
pub fn parseRequestLine(line: []const u8) ParseError!RequestLine {
    var sc = Scanner.init(line);
    const method = sc.span(tables.is_tchar);
    if (method.len == 0 or sc.peek() != ' ') return error.InvalidLine;
    _ = sc.take(1);

    const target = sc.spanTarget();
    if (target.len == 0 or sc.peek() != ' ') return error.InvalidLine;
    _ = sc.take(1);

    const version = try parseVersion(sc.remaining());
    const q = std.mem.indexOfScalar(u8, target, '?');
    const path = if (q) |i| target[0..i] else target;
    const query = if (q) |i| target[i + 1 ..] else target[target.len..];
    return .{ .method = method, .target = target, .path = path, .query = query, .http_version = version };
}

/// Parse the status-line `HTTP-version SP status-code SP [ reason-phrase ]`.
/// RFC 9112 4. The reason phrase may be empty.
pub fn parseStatusLine(line: []const u8) ParseError!StatusLine {
    var sc = Scanner.init(line);
    const sp = std.mem.indexOfScalar(u8, line, ' ') orelse return error.InvalidLine;
    const version = try parseVersion(line[0..sp]);
    sc.pos = sp + 1;

    if (sc.buf.len - sc.pos < 3) return error.InvalidLine;
    const digits = sc.take(3);
    var code: u16 = 0;
    for (digits) |d| {
        if (d < '0' or d > '9') return error.InvalidLine;
        code = code * 10 + (d - '0');
    }
    if (code < 100 or code > 599) return error.InvalidLine;
    // A space and reason phrase are optional after the code.
    var reason: []const u8 = "";
    if (sc.peek() == ' ') {
        _ = sc.take(1);
        reason = sc.remaining();
    } else if (!sc.isEmpty()) {
        return error.InvalidLine;
    }
    // reason-phrase = *( HTAB / SP / VCHAR / obs-text ); reject other controls
    // (CR/LF can't appear - it's a single line - but NUL and the rest can).
    for (reason) |ch| {
        if (ch != '\t' and ch < 0x20) return error.InvalidLine;
        if (ch == 0x7F) return error.InvalidLine;
    }
    return .{ .http_version = version, .status_code = code, .reason = reason };
}

/// Validate and strip the `HTTP/` prefix, returning just the version number
/// (e.g. "1.1"). This is an HTTP/1.x parser, so the major version must be `1`:
/// accepting `HTTP/0.9` or `HTTP/2.0` here would be a version-confusion
/// differential (the request would be framed by 1.1 rules under a wrong banner).
fn parseVersion(tok: []const u8) ParseError![]const u8 {
    if (tok.len != 8) return error.InvalidLine;
    if (!std.mem.eql(u8, tok[0..5], "HTTP/")) return error.InvalidLine;
    const num = tok[5..];
    if (num[0] != '1' or num[1] != '.' or num[2] < '0' or num[2] > '9') {
        return error.InvalidLine;
    }
    return num;
}

/// Whether a field-name is allowed in a chunked trailer section.
pub const trailerFieldAllowed = fields.trailerFieldAllowed;

/// Parse one header field-line into a (name, value) pair. The name is the raw
/// token (case preserved); the value has surrounding OWS stripped. A line with
/// leading whitespace is obs-fold (RFC 9112 5.2) and is rejected.
pub fn parseHeaderLine(line: []const u8) ParseError!Header {
    if (line.len == 0) return error.InvalidHeader;
    if (line[0] == ' ' or line[0] == '\t') return error.InvalidHeader; // obs-fold

    var sc = Scanner.init(line);
    const name = sc.span(tables.is_tchar);
    if (name.len == 0 or sc.peek() != ':') return error.InvalidHeader;
    _ = sc.take(1);
    sc.skipOws();

    const rest = sc.remaining();
    if (!scanner.validFieldValue(rest)) return error.InvalidHeader;
    return .{ .name = name, .value = trimTrailingOws(rest) };
}

test "parseRequestLine" {
    const r = try parseRequestLine("GET /path?q=1 HTTP/1.1");
    try std.testing.expectEqualStrings("GET", r.method);
    try std.testing.expectEqualStrings("/path?q=1", r.target);
    try std.testing.expectEqualStrings("/path", r.path);
    try std.testing.expectEqualStrings("q=1", r.query);
    try std.testing.expectEqualStrings("1.1", r.http_version);
}

test "parseRequestLine splits target with no query" {
    const r = try parseRequestLine("GET /path HTTP/1.1");
    try std.testing.expectEqualStrings("/path", r.path);
    try std.testing.expectEqualStrings("", r.query);
}

test "parseRequestLine empty query after bare question mark" {
    const r = try parseRequestLine("GET /path? HTTP/1.1");
    try std.testing.expectEqualStrings("/path", r.path);
    try std.testing.expectEqualStrings("", r.query);
}

test "parseRequestLine rejects malformed" {
    try std.testing.expectError(error.InvalidLine, parseRequestLine("GET  /  HTTP/1.1"));
    try std.testing.expectError(error.InvalidLine, parseRequestLine("GET /"));
    try std.testing.expectError(error.InvalidLine, parseRequestLine("GET / HTTP/1"));
    try std.testing.expectError(error.InvalidLine, parseRequestLine(" GET / HTTP/1.1"));
    try std.testing.expectError(error.InvalidLine, parseRequestLine("GET / FTP/1.1"));
}

test "parseStatusLine" {
    const s = try parseStatusLine("HTTP/1.1 200 OK");
    try std.testing.expectEqualStrings("1.1", s.http_version);
    try std.testing.expectEqual(@as(u16, 200), s.status_code);
    try std.testing.expectEqualStrings("OK", s.reason);
}

test "parseStatusLine empty reason" {
    const s = try parseStatusLine("HTTP/1.1 204 ");
    try std.testing.expectEqual(@as(u16, 204), s.status_code);
    try std.testing.expectEqualStrings("", s.reason);
    const s2 = try parseStatusLine("HTTP/1.0 404");
    try std.testing.expectEqual(@as(u16, 404), s2.status_code);
    try std.testing.expectEqualStrings("", s2.reason);
}

test "parseStatusLine rejects bad code" {
    try std.testing.expectError(error.InvalidLine, parseStatusLine("HTTP/1.1 20 OK"));
    try std.testing.expectError(error.InvalidLine, parseStatusLine("HTTP/1.1 2xx OK"));
}

test "version restricted to HTTP/1.x" {
    try std.testing.expectEqualStrings("1.0", (try parseRequestLine("GET / HTTP/1.0")).http_version);
    try std.testing.expectEqualStrings("1.1", (try parseRequestLine("GET / HTTP/1.1")).http_version);
    // non-1.x major versions are a version-confusion differential -> rejected
    try std.testing.expectError(error.InvalidLine, parseRequestLine("GET / HTTP/0.9"));
    try std.testing.expectError(error.InvalidLine, parseRequestLine("GET / HTTP/2.0"));
    try std.testing.expectError(error.InvalidLine, parseStatusLine("HTTP/2.0 200 OK"));
}

test "reason phrase rejects control bytes" {
    try std.testing.expectError(error.InvalidLine, parseStatusLine("HTTP/1.1 200 O\x00K"));
    try std.testing.expectError(error.InvalidLine, parseStatusLine("HTTP/1.1 200 O\x07K"));
    // SP and HTAB are allowed in the reason phrase
    try std.testing.expectEqualStrings("O K\t", (try parseStatusLine("HTTP/1.1 200 O K\t")).reason);
}

test "parseHeaderLine" {
    const h = try parseHeaderLine("Content-Type:  text/html  ");
    try std.testing.expectEqualStrings("Content-Type", h.name);
    try std.testing.expectEqualStrings("text/html", h.value);
}

test "parseHeaderLine empty value" {
    const h = try parseHeaderLine("X-Empty:");
    try std.testing.expectEqualStrings("X-Empty", h.name);
    try std.testing.expectEqualStrings("", h.value);
}

test "parseHeaderLine rejects obs-fold and bad names" {
    try std.testing.expectError(error.InvalidHeader, parseHeaderLine(" continuation"));
    try std.testing.expectError(error.InvalidHeader, parseHeaderLine("No colon here"));
    try std.testing.expectError(error.InvalidHeader, parseHeaderLine(":empty-name"));
    try std.testing.expectError(error.InvalidHeader, parseHeaderLine("Bad Name: x"));
}

test "parseHeaderLine rejects control chars in value" {
    try std.testing.expectError(error.InvalidHeader, parseHeaderLine("X: a\x00b"));
}

test "trailerFieldAllowed rejects prohibited fields" {
    try std.testing.expect(!trailerFieldAllowed("Content-Length"));
    try std.testing.expect(!trailerFieldAllowed("Transfer-Encoding"));
    try std.testing.expect(!trailerFieldAllowed("Trailer"));
    try std.testing.expect(!trailerFieldAllowed("Connection"));
    try std.testing.expect(!trailerFieldAllowed("Content-Encoding"));
    try std.testing.expect(!trailerFieldAllowed("Content-Type"));
    try std.testing.expect(!trailerFieldAllowed("Content-Range"));
    try std.testing.expect(trailerFieldAllowed("X-Checksum"));
}
