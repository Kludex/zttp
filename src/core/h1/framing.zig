//! Decide how a message body is delimited, from its headers, per RFC 9112 6.
//! This is the request-smuggling defense: when Transfer-Encoding and
//! Content-Length are both present, or Content-Length is duplicated with
//! conflicting values, we reject rather than guess.

const std = @import("std");
const ascii = @import("../ascii.zig");
const events = @import("../events.zig");
const tables = @import("../tables.zig");
const ParseError = @import("../errors.zig").ParseError;

const Header = events.Header;
const eqIgnoreCase = ascii.eqIgnoreCase;

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

/// Accumulates Transfer-Encoding codings across (possibly multiple) field-lines,
/// which RFC 9112 6.1 requires to be treated as a single ordered comma list. The
/// only framing we accept is `chunked` appearing exactly once and as the final
/// coding overall; anything else (chunked not last, chunked twice, malformed
/// list/parameter grammar) is a framing error - the request-smuggling guard.
const TransferEncoding = struct {
    saw_chunked: bool = false,
    /// True once any coding has been seen after a `chunked` coding (illegal).
    coding_after_chunked: bool = false,

    fn skipOws(value: []const u8, i: *usize) void {
        while (i.* < value.len and (value[i.*] == ' ' or value[i.*] == '\t')) i.* += 1;
    }

    fn takeToken(value: []const u8, i: *usize) ?[]const u8 {
        const start = i.*;
        while (i.* < value.len and tables.is_tchar[value[i.*]]) i.* += 1;
        return if (i.* == start) null else value[start..i.*];
    }

    /// quoted-string / quoted-pair (RFC 9110 5.6.4). The surrounding field-value
    /// check already rejects CR/LF/NUL, but this enforces the narrower grammar.
    fn takeQuotedString(value: []const u8, i: *usize) bool {
        if (i.* >= value.len or value[i.*] != '"') return false;
        i.* += 1;
        while (i.* < value.len) {
            const ch = value[i.*];
            i.* += 1;
            if (ch == '"') return true;
            if (ch == '\\') {
                if (i.* >= value.len) return false;
                const escaped = value[i.*];
                i.* += 1;
                if (!(escaped == '\t' or escaped == ' ' or (escaped >= 0x21 and escaped <= 0x7E) or escaped >= 0x80)) return false;
            } else if (!(ch == '\t' or ch == ' ' or ch == 0x21 or (ch >= 0x23 and ch <= 0x5B) or (ch >= 0x5D and ch <= 0x7E) or ch >= 0x80)) {
                return false;
            }
        }
        return false;
    }

    fn noteCoding(self: *TransferEncoding, coding: []const u8) bool {
        if (self.saw_chunked) self.coding_after_chunked = true;
        const is_chunked = eqIgnoreCase(coding, "chunked");
        if (is_chunked) self.saw_chunked = true;
        return is_chunked;
    }

    /// Fold one field-line's `#transfer-coding` value into the accumulator,
    /// validating token names, parameters, quoted strings, and list separators.
    /// RFC 9110 5.6.1 forbids senders from generating empty list elements but
    /// requires recipients to ignore a reasonable number, hence the policy flag.
    fn add(self: *TransferEncoding, value: []const u8, allow_empty_members: bool) ParseError!void {
        var i: usize = 0;
        skipOws(value, &i);
        if (i == value.len) {
            if (allow_empty_members) return;
            return error.InvalidFraming;
        }

        while (true) {
            if (value[i] == ',') {
                if (!allow_empty_members) return error.InvalidFraming;
                i += 1;
                skipOws(value, &i);
                if (i == value.len) return;
                continue;
            }

            const coding = takeToken(value, &i) orelse return error.InvalidFraming;
            const is_chunked = self.noteCoding(coding);
            skipOws(value, &i);

            // `chunked` defines no parameters. Keeping it exact also preserves
            // the reader's pre-existing rejection of `chunked;anything`.
            if (is_chunked and i < value.len and value[i] == ';') return error.InvalidFraming;
            while (i < value.len and value[i] == ';') {
                i += 1;
                skipOws(value, &i);
                _ = takeToken(value, &i) orelse return error.InvalidFraming;
                skipOws(value, &i);
                if (i == value.len or value[i] != '=') return error.InvalidFraming;
                i += 1;
                skipOws(value, &i);
                if (i < value.len and value[i] == '"') {
                    if (!takeQuotedString(value, &i)) return error.InvalidFraming;
                } else {
                    _ = takeToken(value, &i) orelse return error.InvalidFraming;
                }
                skipOws(value, &i);
            }

            if (i == value.len) return;
            if (value[i] != ',') return error.InvalidFraming;
            i += 1;
            skipOws(value, &i);
            if (i == value.len) {
                if (allow_empty_members) return;
                return error.InvalidFraming;
            }
        }
    }

    /// Resolve to chunked framing, or reject. Only valid when chunked is present
    /// once and last; a non-chunked-terminated TE is unframeable -> reject.
    fn resolve(self: TransferEncoding) ParseError!bool {
        if (!self.saw_chunked) return error.InvalidFraming;
        if (self.coding_after_chunked) return error.InvalidFraming;
        return true;
    }
};

pub const TransferEncodingMode = enum {
    /// Recipients ignore empty list members (RFC 9110 5.6.1).
    receive,
    /// Senders must not generate empty list members.
    send,
};

/// Validate Transfer-Encoding across all field-lines as one ordered comma list.
/// Returns whether the message declared Transfer-Encoding. The caller owns any
/// codings before `chunked`; this layer only requires the framing coding it can
/// decode/emit: `chunked` exactly once and last (RFC 9112 6.1, 7.1).
pub fn validateTransferEncoding(headers: []const Header, mode: TransferEncodingMode) ParseError!bool {
    var te = TransferEncoding{};
    var has_te = false;
    for (headers) |h| {
        if (eqIgnoreCase(h.name, "transfer-encoding")) {
            has_te = true;
            try te.add(h.value, mode == .receive);
        }
    }
    if (has_te) _ = try te.resolve();
    return has_te;
}

fn parseContentLength(value: []const u8) ParseError!u64 {
    const v = ascii.trimOws(value);
    return ascii.parseDecimal(u64, v) orelse error.InvalidFraming;
}

/// A response carries no body regardless of its headers when it answers a HEAD,
/// is 1xx/204/304, or is a 2xx to a CONNECT (RFC 9112 6.3). Shared by the read
/// and write paths so framing is decided identically in both directions.
pub fn responseIsBodyless(method: []const u8, status: u16) bool {
    if (status / 100 == 1 or status == 204 or status == 304) return true;
    if (eqIgnoreCase(method, "HEAD")) return true;
    if (eqIgnoreCase(method, "CONNECT") and status >= 200 and status < 300) return true;
    return false;
}

/// RFC 9112 6.1 forbids Transfer-Encoding on 1xx/204 and successful CONNECT
/// responses. HEAD and 304 are also bodyless, but may carry the coding that
/// would have applied to the corresponding body (RFC 9110 8.6, 15.4.5).
pub fn responseForbidsTransferEncoding(method: []const u8, status: u16) bool {
    if (status / 100 == 1 or status == 204) return true;
    return eqIgnoreCase(method, "CONNECT") and status >= 200 and status < 300;
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
    const has_te = try validateTransferEncoding(headers, .receive);
    var content_length: ?u64 = null;

    for (headers) |h| {
        if (eqIgnoreCase(h.name, "content-length")) {
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

    if (has_te) return .chunked;
    if (content_length) |n| {
        return if (n == 0) .none else .{ .content_length = n };
    }
    return if (opts.until_close_default) .until_close else .none;
}

test "responseIsBodyless rule" {
    try std.testing.expect(responseIsBodyless("HEAD", 200));
    try std.testing.expect(responseIsBodyless("head", 200));
    try std.testing.expect(responseIsBodyless("GET", 204));
    try std.testing.expect(responseIsBodyless("GET", 304));
    try std.testing.expect(responseIsBodyless("GET", 100));
    try std.testing.expect(responseIsBodyless("CONNECT", 200));
    try std.testing.expect(!responseIsBodyless("CONNECT", 404));
    try std.testing.expect(!responseIsBodyless("GET", 200));
    try std.testing.expect(!responseIsBodyless("POST", 201));
}

test "responseForbidsTransferEncoding rule" {
    try std.testing.expect(responseForbidsTransferEncoding("GET", 103));
    try std.testing.expect(responseForbidsTransferEncoding("GET", 204));
    try std.testing.expect(responseForbidsTransferEncoding("CONNECT", 200));
    try std.testing.expect(!responseForbidsTransferEncoding("HEAD", 200));
    try std.testing.expect(!responseForbidsTransferEncoding("GET", 304));
    try std.testing.expect(!responseForbidsTransferEncoding("CONNECT", 404));
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

test "transfer coding parameters and quoted commas" {
    const h = [_]Header{.{ .name = "Transfer-Encoding", .value = "gzip ; level = 1 ; note = \"a,b\\\"c\", chunked" }};
    try std.testing.expectEqual(Framing.chunked, try determine(&h, .{}));
}

test "receiver ignores empty transfer coding list members" {
    inline for (.{ ",chunked", "chunked,", "gzip,,chunked", ",,gzip,,chunked,," }) |value| {
        const h = [_]Header{.{ .name = "Transfer-Encoding", .value = value }};
        try std.testing.expectEqual(Framing.chunked, try determine(&h, .{}));
    }
}

test "malformed transfer coding grammar rejected" {
    inline for (.{
        "",
        ";bad, chunked",
        "gzip;flag, chunked",
        "gzip;=value, chunked",
        "gzip;level=, chunked",
        "gzip;note=\"unterminated, chunked",
        "gzip;note=\"bad\\\", chunked",
    }) |value| {
        const h = [_]Header{.{ .name = "Transfer-Encoding", .value = value }};
        try std.testing.expectError(error.InvalidFraming, determine(&h, .{}));
    }
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

test "H-3: split TE chunked then identity rejected" {
    const h = [_]Header{
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Transfer-Encoding", .value = "identity" },
    };
    try std.testing.expectError(error.InvalidFraming, determine(&h, .{}));
}

test "H-3: split TE chunked then gzip rejected" {
    const h = [_]Header{
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Transfer-Encoding", .value = "gzip" },
    };
    try std.testing.expectError(error.InvalidFraming, determine(&h, .{}));
}

test "H-3: split TE gzip then chunked accepted as chunked" {
    const h = [_]Header{
        .{ .name = "Transfer-Encoding", .value = "gzip" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
    };
    try std.testing.expectEqual(Framing.chunked, try determine(&h, .{}));
}

test "H-3: split TE chunked twice rejected" {
    const h = [_]Header{
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
    };
    try std.testing.expectError(error.InvalidFraming, determine(&h, .{}));
}

test "H-3: single line gzip, chunked still accepted" {
    const h = [_]Header{.{ .name = "Transfer-Encoding", .value = "gzip, chunked" }};
    try std.testing.expectEqual(Framing.chunked, try determine(&h, .{}));
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
