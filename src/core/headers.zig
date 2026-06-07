//! Parse a header block (the field-lines up to the terminating blank line) into
//! a list of `Header` slices, and parse a single request- or status-line. All
//! results slice into the fed buffer; the only allocation is the growable list
//! of (name, value) pairs, which the caller owns.

const std = @import("std");
const tables = @import("tables.zig");
const events = @import("events.zig");
const Scanner = @import("scanner.zig").Scanner;
const trimTrailingOws = @import("scanner.zig").trimTrailingOws;
const ParseError = @import("errors.zig").ParseError;

const Header = events.Header;

pub const RequestLine = struct {
    method: []const u8,
    target: []const u8,
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

    const target = sc.span(tables.is_target_char);
    if (target.len == 0 or sc.peek() != ' ') return error.InvalidLine;
    _ = sc.take(1);

    const version = try parseVersion(sc.remaining());
    return .{ .method = method, .target = target, .http_version = version };
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
    // A space and reason phrase are optional after the code.
    var reason: []const u8 = "";
    if (sc.peek() == ' ') {
        _ = sc.take(1);
        reason = sc.remaining();
    } else if (!sc.isEmpty()) {
        return error.InvalidLine;
    }
    return .{ .http_version = version, .status_code = code, .reason = reason };
}

/// Validate and strip the `HTTP/` prefix, returning just the version number
/// (e.g. "1.1"). Only HTTP/1.x major versions reach this 1.1 parser; "1.0" and
/// "1.1" are the expected values, but we accept any `1.DIGIT` and let the
/// connection layer decide semantics.
fn parseVersion(tok: []const u8) ParseError![]const u8 {
    if (tok.len != 8) return error.InvalidLine;
    if (!std.mem.eql(u8, tok[0..5], "HTTP/")) return error.InvalidLine;
    const num = tok[5..];
    if (num[0] < '0' or num[0] > '9' or num[1] != '.' or num[2] < '0' or num[2] > '9') {
        return error.InvalidLine;
    }
    return num;
}

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
    for (rest) |ch| {
        if (!tables.is_field_vchar[ch]) return error.InvalidHeader;
    }
    return .{ .name = name, .value = trimTrailingOws(rest) };
}

test "parseRequestLine" {
    const r = try parseRequestLine("GET /path?q=1 HTTP/1.1");
    try std.testing.expectEqualStrings("GET", r.method);
    try std.testing.expectEqualStrings("/path?q=1", r.target);
    try std.testing.expectEqualStrings("1.1", r.http_version);
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
