//! The events a parsed HTTP message yields. These are the pure-Zig analogue of
//! the Python-facing event objects (Request, Data, EndOfMessage). They reference
//! bytes by `[]const u8` slices that point INTO the buffer the caller fed; the
//! caller must materialise (copy) anything it wants to outlive the next
//! `receiveData` call. The core never copies.

const std = @import("std");

/// One `field-name: field-value` pair, both pointing into the fed buffer. The
/// name is the raw (un-lowercased) bytes; case-folding for matching is the
/// adapter's concern, mirroring h11 which preserves the wire casing in events.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// The start of a request: method, target, HTTP version, and the full header
/// block. Emitted once, after the blank line that terminates the headers.
pub const Request = struct {
    method: []const u8,
    target: []const u8,
    /// The version number only, e.g. "1.1" or "1.0" (the "HTTP/" is stripped).
    http_version: []const u8,
    headers: []const Header,
};

/// The start of a response (client role): status code, reason phrase, version,
/// and headers.
pub const Response = struct {
    status_code: u16,
    reason: []const u8,
    http_version: []const u8,
    headers: []const Header,
};

/// A run of body bytes. For chunked bodies one Data event is emitted per chunk
/// (or per buffered span); for Content-Length bodies, per fed span.
pub const Data = struct {
    data: []const u8,
};

/// The message body has ended. Carries any trailer headers seen after the final
/// chunk of a chunked body (empty otherwise).
pub const EndOfMessage = struct {
    trailers: []const Header = &.{},
};

/// The tagged union the state machine produces. `need_data` is the sentinel
/// meaning "no complete event is available; feed more bytes" - it is a real
/// variant here rather than an optional so the Python adapter can map it onto
/// the NEED_DATA singleton without an extra branch.
pub const Event = union(enum) {
    request: Request,
    response: Response,
    data: Data,
    end_of_message: EndOfMessage,
    /// The peer closed the connection (half-close on the read side).
    connection_closed,
    /// Not enough buffered bytes to produce the next event yet.
    need_data,
};

test "event union round-trips a request" {
    const hdrs = [_]Header{.{ .name = "Host", .value = "example.com" }};
    const ev = Event{ .request = .{
        .method = "GET",
        .target = "/",
        .http_version = "1.1",
        .headers = &hdrs,
    } };
    try std.testing.expectEqualStrings("GET", ev.request.method);
    try std.testing.expectEqualStrings("example.com", ev.request.headers[0].value);
}
