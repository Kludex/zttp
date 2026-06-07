//! Decide how a message body is delimited, from its headers, per RFC 9112 6.
//! This is the request-smuggling defense: when Transfer-Encoding and
//! Content-Length are both present, or Content-Length is duplicated with
//! conflicting values, we reject rather than guess.

const std = @import("std");
const tables = @import("tables.zig");
const events = @import("events.zig");
const ParseError = @import("errors.zig").ParseError;

const Header = events.Header;

pub const Framing = union(enum) {
    /// No body. The message is complete once headers end.
    none,
    /// Exactly `len` body bytes follow.
    content_length: u64,
    /// chunked transfer-coding; length is implicit in the chunk framing.
    chunked,
    /// Body runs until the connection closes (responses only; RFC 9112 6.3).
    until_close,
};

fn eqIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (tables.to_lower[x] != tables.to_lower[y]) return false;
    }
    return true;
}

/// True if the comma-separated `Transfer-Encoding` value list ends in `chunked`
/// (the only coding RFC 9112 lets us frame). A `chunked` that is not final is a
/// framing error.
fn transferEncodingChunked(value: []const u8) ParseError!bool {
    var last: []const u8 = "";
    var saw_chunked_not_last = false;
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |raw| {
        const coding = std.mem.trim(u8, raw, " \t");
        if (coding.len == 0) continue;
        if (saw_chunked_not_last) return error.InvalidFraming;
        if (eqIgnoreCase(coding, "chunked")) {
            saw_chunked_not_last = true;
        } else {
            saw_chunked_not_last = false;
        }
        last = coding;
    }
    return eqIgnoreCase(last, "chunked");
}

fn parseContentLength(value: []const u8) ParseError!u64 {
    const v = std.mem.trim(u8, value, " \t");
    if (v.len == 0) return error.InvalidFraming;
    var n: u64 = 0;
    for (v) |ch| {
        if (ch < '0' or ch > '9') return error.InvalidFraming;
        n = std.math.mul(u64, n, 10) catch return error.InvalidFraming;
        n = std.math.add(u64, n, ch - '0') catch return error.InvalidFraming;
    }
    return n;
}

pub const FramingOptions = struct {
    /// Responses to HEAD, 1xx/204/304, and the connect side have no body
    /// regardless of headers (RFC 9112 6.3). The connection layer sets this.
    bodyless: bool = false,
    /// Whether absence of length info means "read until close". True for
    /// responses, false for requests (a request without length has no body).
    until_close_default: bool = false,
};

/// Inspect the parsed headers and return the body framing. Enforces the
/// CL/TE conflict and duplicate-Content-Length rules.
pub fn determine(headers: []const Header, opts: FramingOptions) ParseError!Framing {
    var te_chunked = false;
    var has_te = false;
    var content_length: ?u64 = null;

    for (headers) |h| {
        if (eqIgnoreCase(h.name, "transfer-encoding")) {
            has_te = true;
            if (try transferEncodingChunked(h.value)) te_chunked = true;
        } else if (eqIgnoreCase(h.name, "content-length")) {
            const n = try parseContentLength(h.value);
            if (content_length) |prev| {
                if (prev != n) return error.InvalidFraming; // conflicting duplicates
            }
            content_length = n;
        }
    }

    // RFC 9112 6.1: if both are present, Transfer-Encoding overrides, but this
    // is a smuggling vector - reject outright (what secure parsers do).
    if (has_te and content_length != null) return error.InvalidFraming;

    if (opts.bodyless) return .none;

    if (has_te) {
        // A Transfer-Encoding that is not (or does not end in) chunked is
        // unframeable for a request; treat as error to avoid smuggling.
        if (!te_chunked) return error.InvalidFraming;
        return .chunked;
    }
    if (content_length) |n| {
        return if (n == 0) .none else .{ .content_length = n };
    }
    return if (opts.until_close_default) .until_close else .none;
}

test "no body" {
    const h = [_]Header{.{ .name = "Host", .value = "x" }};
    try std.testing.expectEqual(Framing.none, try determine(&h, .{}));
}

test "content-length" {
    const h = [_]Header{.{ .name = "Content-Length", .value = " 42 " }};
    const f = try determine(&h, .{});
    try std.testing.expectEqual(@as(u64, 42), f.content_length);
}

test "zero content-length is none" {
    const h = [_]Header{.{ .name = "content-length", .value = "0" }};
    try std.testing.expectEqual(Framing.none, try determine(&h, .{}));
}

test "chunked" {
    const h = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked" }};
    try std.testing.expectEqual(Framing.chunked, try determine(&h, .{}));
}

test "chunked with preceding coding" {
    const h = [_]Header{.{ .name = "Transfer-Encoding", .value = "gzip, chunked" }};
    try std.testing.expectEqual(Framing.chunked, try determine(&h, .{}));
}

test "te and cl together is rejected (smuggling)" {
    const h = [_]Header{
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Content-Length", .value = "10" },
    };
    try std.testing.expectError(error.InvalidFraming, determine(&h, .{}));
}

test "conflicting duplicate content-length rejected" {
    const h = [_]Header{
        .{ .name = "Content-Length", .value = "10" },
        .{ .name = "Content-Length", .value = "20" },
    };
    try std.testing.expectError(error.InvalidFraming, determine(&h, .{}));
}

test "identical duplicate content-length allowed" {
    const h = [_]Header{
        .{ .name = "Content-Length", .value = "10" },
        .{ .name = "Content-Length", .value = "10" },
    };
    try std.testing.expectEqual(@as(u64, 10), (try determine(&h, .{})).content_length);
}

test "non-final chunked rejected" {
    const h = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked, gzip" }};
    try std.testing.expectError(error.InvalidFraming, determine(&h, .{}));
}

test "te without chunked rejected for request" {
    const h = [_]Header{.{ .name = "Transfer-Encoding", .value = "gzip" }};
    try std.testing.expectError(error.InvalidFraming, determine(&h, .{}));
}

test "bad content-length rejected" {
    const h = [_]Header{.{ .name = "Content-Length", .value = "12a" }};
    try std.testing.expectError(error.InvalidFraming, determine(&h, .{}));
}

test "bodyless forces none" {
    const h = [_]Header{.{ .name = "Content-Length", .value = "100" }};
    try std.testing.expectEqual(Framing.none, try determine(&h, .{ .bodyless = true }));
}

test "until_close default for response without length" {
    const h = [_]Header{.{ .name = "Server", .value = "x" }};
    try std.testing.expectEqual(Framing.until_close, try determine(&h, .{ .until_close_default = true }));
}
