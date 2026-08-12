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
/// `stream_id` is 0 for HTTP/1.1 (the field is omitted at every H1 construction
/// site and never surfaced); HTTP/2 sets the 31-bit stream the request arrived on,
/// HTTP/3 the 62-bit QUIC stream id (hence u64).
pub const Request = struct {
    method: []const u8,
    target: []const u8,
    /// The target split at the first `?`: `path` excludes it, `query` excludes the
    /// `?` (empty when absent). Both verbatim - no percent-decoding. For the usual
    /// origin-form target (`/p?x=1`) this is the only split a consumer needs.
    path: []const u8,
    query: []const u8,
    /// The version number only, e.g. "1.1" or "1.0" (the "HTTP/" is stripped).
    http_version: []const u8,
    headers: []const Header,
    stream_id: u64 = 0,
    /// Whether the request carried `Expect: 100-continue`. Per-request (a stream
    /// property under HTTP/2), so it rides the event rather than the connection.
    expect_continue: bool = false,
    /// The peer ended the request stream with this head. No Data or
    /// EndOfMessage event follows when this is true.
    end_stream: bool = false,
};

/// The start of a response (client role): status code, reason phrase, version,
/// and headers.
pub const Response = struct {
    status_code: u16,
    reason: []const u8,
    http_version: []const u8,
    headers: []const Header,
    stream_id: u64 = 0,
};

/// A run of body bytes. For chunked bodies one Data event is emitted per chunk
/// (or per buffered span); for Content-Length bodies, per fed span.
pub const Data = struct {
    data: []const u8,
    stream_id: u64 = 0,
};

/// The message body has ended. Carries any trailer headers seen after the final
/// chunk of a chunked body (empty otherwise).
pub const EndOfMessage = struct {
    trailers: []const Header = &.{},
    stream_id: u64 = 0,
};

/// One peer setting (id, value), surfaced verbatim so the integrator can react.
pub const SettingPair = struct {
    /// HTTP/2 settings fit in 16/32 bits; HTTP/3 settings are QUIC varints. Keep
    /// the shared event shape wide enough for both protocols.
    id: u64,
    value: u64,
};

/// A stream was reset by the peer (RFC 9113 6.4). HTTP/2 only.
pub const RstStream = struct {
    stream_id: u32,
    error_code: u32,
};

/// A peer reset (RESET_STREAM) or asked us to stop sending (STOP_SENDING) on an
/// HTTP/3 request stream (RFC 9114 4.4): the request/response is cancelled. The id
/// and code are 62-bit/u64, so this is the H3 analogue of the (u32) H2 RstStream.
pub const StreamReset = struct {
    stream_id: u64,
    error_code: u64,
};

/// The peer is shutting the connection down: HTTP/2 GOAWAY (RFC 9113 6.8) or
/// HTTP/3 GOAWAY (RFC 9114 5.2). `last_stream_id` is u64 to hold the HTTP/3
/// 62-bit id losslessly; HTTP/2's 31-bit id fits the same field.
pub const GoAway = struct {
    last_stream_id: u64,
    error_code: u32,
    debug: []const u8 = &.{},
};

/// The peer announced its settings (RFC 9113 6.5 / RFC 9114 7.2.4). HTTP/2
/// SETTINGS need an ACK; HTTP/3 SETTINGS are not acknowledged at the H3 layer.
pub const SettingsEvent = struct {
    params: []const SettingPair,
};

/// A PING (RFC 9113 6.7); if `ack` is false a PING-ACK echoing `opaque_data` is
/// owed. HTTP/2 only.
pub const Ping = struct {
    ack: bool,
    opaque_data: [8]u8,
};

/// A flow-control window increment (RFC 9113 6.9). stream_id 0 is the connection
/// window. HTTP/2 only.
pub const WindowUpdate = struct {
    stream_id: u32,
    increment: u32,
};

/// The events the HTTP/1.1 state machine produces. The payload structs above are
/// shared with HTTP/2, but each protocol has its OWN event union so a consumer's
/// type is exactly as wide as that protocol's reality - an H1 connection can
/// never yield a `ping`, and the type system says so (no `unreachable` arms).
/// `need_data` is the sentinel meaning "no complete event yet; feed more bytes" -
/// a real variant rather than an optional so the adapter maps it onto the
/// NEED_DATA singleton without an extra branch.
pub const H1Event = union(enum) {
    request: Request,
    response: Response,
    data: Data,
    end_of_message: EndOfMessage,
    /// The peer closed the connection (half-close on the read side).
    connection_closed,
    need_data,
};

/// The events the HTTP/2 engine produces. It shares the request/response/data/
/// end-of-message payloads with H1 but adds the connection- and stream-control
/// frames, and has no `connection_closed` (HTTP/2 signals shutdown with goaway).
pub const H2Event = union(enum) {
    request: Request,
    response: Response,
    data: Data,
    end_of_message: EndOfMessage,
    need_data,
    rst_stream: RstStream,
    goaway: GoAway,
    settings: SettingsEvent,
    ping: Ping,
    window_update: WindowUpdate,
};

/// The events the HTTP/3 engine produces. It shares the request/response/data/
/// end-of-message payloads with H1 and H2, and like H2 has its own union: HTTP/3
/// keeps only the control events it actually has (`settings`, `goaway`) - flow
/// control and PING live down in QUIC, not in the HTTP/3 framing. A QUIC
/// CONNECTION_CLOSE maps to `connection_closed`, matching the shared pull API.
/// The `stream_id` on the shared payloads carries the 62-bit QUIC request-stream id.
pub const H3Event = union(enum) {
    request: Request,
    response: Response,
    data: Data,
    end_of_message: EndOfMessage,
    connection_closed,
    need_data,
    settings: SettingsEvent,
    goaway: GoAway,
    rst_stream: StreamReset,
};

test "H1 event union round-trips a request" {
    const hdrs = [_]Header{.{ .name = "Host", .value = "example.com" }};
    const ev = H1Event{ .request = .{
        .method = "GET",
        .target = "/",
        .path = "/",
        .query = "",
        .http_version = "1.1",
        .headers = &hdrs,
    } };
    try std.testing.expectEqualStrings("GET", ev.request.method);
    try std.testing.expectEqualStrings("example.com", ev.request.headers[0].value);
}

test "H2 event union carries a stream-tagged request" {
    const ev = H2Event{ .request = .{
        .method = "GET",
        .target = "/",
        .path = "/",
        .query = "",
        .http_version = "2",
        .headers = &.{},
        .stream_id = 3,
    } };
    try std.testing.expectEqual(@as(u64, 3), ev.request.stream_id);
}
