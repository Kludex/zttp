//! Decide how a message body is delimited, from its headers, per RFC 9112 6.
//! This is the request-smuggling defense: when Transfer-Encoding and
//! Content-Length are both present, or Content-Length is duplicated with
//! conflicting values, we reject rather than guess.

const std = @import("std");
const ascii = @import("../ascii.zig");
const events = @import("../events.zig");
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
/// coding overall; anything else (chunked not last, chunked twice, an unknown
/// coding after chunked) is a framing error - the request-smuggling guard.
const TransferEncoding = struct {
    saw_chunked: bool = false,
    /// True once any coding has been seen after a `chunked` coding (illegal).
    coding_after_chunked: bool = false,

    /// Fold one field-line value's comma-separated codings into the accumulator.
    fn add(self: *TransferEncoding, value: []const u8) void {
        var it = std.mem.splitScalar(u8, value, ',');
        while (it.next()) |raw| {
            const coding = std.mem.trim(u8, raw, " \t");
            if (coding.len == 0) continue;
            if (self.saw_chunked) self.coding_after_chunked = true;
            if (eqIgnoreCase(coding, "chunked")) self.saw_chunked = true;
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
/// responses. HEAD and 304 are also bodyless, but may carry `chunked` metadata
/// for the corresponding body (RFC 9110 8.6, 15.4.5).
pub fn responseForbidsTransferEncoding(method: []const u8, status: u16) bool {
    if (status / 100 == 1 or status == 204) return true;
    return eqIgnoreCase(method, "CONNECT") and status >= 200 and status < 300;
}

pub const FramingOptions = struct {
    /// Responses to HEAD, 1xx/204/304, and the connect side have no body
    /// regardless of headers (RFC 9112 6.3). The connection layer sets this.
    bodyless: bool = false,
    /// 1xx/204 and successful CONNECT responses forbid Transfer-Encoding.
    /// Separate from bodyless because HEAD and 304 may carry TE metadata.
    forbid_transfer_encoding: bool = false,
    /// Whether absence of length info means "read until close". True for
    /// responses, false for requests (a request without length has no body).
    until_close_default: bool = false,
};

/// Incrementally collect the framing fields while the caller parses the header
/// block. Keeping this state beside the header parser lets connection-level
/// metadata share the same pass instead of repeatedly walking the completed
/// header list.
pub const Analyzer = struct {
    transfer_encoding: TransferEncoding = .{},
    has_transfer_encoding: bool = false,
    content_length: ?u64 = null,
    content_length_value: ?[]const u8 = null,

    pub fn add(self: *Analyzer, h: Header) ParseError!void {
        if (eqIgnoreCase(h.name, "transfer-encoding")) {
            self.has_transfer_encoding = true;
            self.transfer_encoding.add(h.value);
        } else if (eqIgnoreCase(h.name, "content-length")) {
            const n = try parseContentLength(h.value);
            if (self.content_length_value) |previous| {
                if (!std.mem.eql(u8, previous, h.value)) return error.InvalidFraming;
            }
            self.content_length = n;
            self.content_length_value = h.value;
        }
    }

    /// Whether the head carries framing metadata at all. Informational
    /// responses use this to reject Content-Length and Transfer-Encoding before
    /// a final response is parsed.
    pub fn hasFramingHeader(self: Analyzer) bool {
        return self.has_transfer_encoding or self.content_length != null;
    }

    pub fn finish(self: Analyzer, opts: FramingOptions) ParseError!Framing {
        // RFC 9112 6.1: if both are present, Transfer-Encoding overrides, but
        // this is a smuggling vector - reject outright (what secure parsers do).
        if (self.has_transfer_encoding and self.content_length != null) return error.InvalidFraming;
        if (self.has_transfer_encoding and opts.forbid_transfer_encoding) return error.InvalidFraming;

        if (opts.bodyless) return .none;

        if (self.has_transfer_encoding) {
            // chunked must be the sole/final coding across ALL field-lines;
            // resolve rejects non-final or unframeable Transfer-Encodings.
            _ = try self.transfer_encoding.resolve();
            return .chunked;
        }
        if (self.content_length) |n| {
            return if (n == 0) .none else .{ .content_length = n };
        }
        return if (opts.until_close_default) .until_close else .none;
    }
};

/// Inspect the parsed headers and return the body framing. Enforces the
/// CL/TE conflict and duplicate-Content-Length rules.
pub fn determine(headers: []const Header, opts: FramingOptions) ParseError!Framing {
    var analyzer = Analyzer{};
    for (headers) |h| try analyzer.add(h);
    return analyzer.finish(opts);
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

test "numerically equal content-length values must match textually" {
    const h = [_]Header{
        .{ .name = "Content-Length", .value = "010" },
        .{ .name = "Content-Length", .value = "10" },
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

test "forbidden Transfer-Encoding is rejected before bodyless framing" {
    const h = [_]Header{.{ .name = "Transfer-Encoding", .value = "chunked" }};
    try std.testing.expectError(error.InvalidFraming, determine(&h, .{
        .bodyless = true,
        .forbid_transfer_encoding = true,
    }));
    // HEAD/304 use bodyless without the forbidden flag and may describe the
    // chunked coding that would have applied to their corresponding body.
    try std.testing.expectEqual(Framing.none, try determine(&h, .{ .bodyless = true }));
}

test "until_close default for response without length" {
    const h = [_]Header{.{ .name = "Server", .value = "x" }};
    try std.testing.expectEqual(Framing.until_close, try determine(&h, .{ .until_close_default = true }));
}
