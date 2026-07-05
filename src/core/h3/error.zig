//! HTTP/3 error codes (RFC 9114 8.1 and RFC 9204 6). An HTTP/3 error is reported
//! to the peer in a QUIC CONNECTION_CLOSE (application variant) or RESET_STREAM,
//! carrying one of these codes, so a peer learns *which* rule was broken rather
//! than just that the connection ended.

/// The codes the server actually emits today; the full RFC set is enumerated so
/// the values are pinned even where not yet used. `_` keeps it non-exhaustive for
/// the reserved/greased space.
pub const ErrorCode = enum(u64) {
    no_error = 0x0100,
    general_protocol_error = 0x0101,
    internal_error = 0x0102,
    stream_creation_error = 0x0103,
    closed_critical_stream = 0x0104,
    frame_unexpected = 0x0105,
    frame_error = 0x0106,
    excessive_load = 0x0107,
    id_error = 0x0108,
    settings_error = 0x0109,
    missing_settings = 0x010a,
    request_rejected = 0x010b,
    request_cancelled = 0x010c,
    request_incomplete = 0x010d,
    message_error = 0x010e,
    connect_error = 0x010f,
    version_fallback = 0x0110,
    qpack_decompression_failed = 0x0200,
    qpack_encoder_stream_error = 0x0201,
    qpack_decoder_stream_error = 0x0202,
    _,
};

test "the codes match the RFC 9114 registry" {
    const std = @import("std");
    try std.testing.expectEqual(@as(u64, 0x010a), @intFromEnum(ErrorCode.missing_settings));
    try std.testing.expectEqual(@as(u64, 0x0105), @intFromEnum(ErrorCode.frame_unexpected));
    try std.testing.expectEqual(@as(u64, 0x0200), @intFromEnum(ErrorCode.qpack_decompression_failed));
    try std.testing.expectEqual(@as(u64, 0x0201), @intFromEnum(ErrorCode.qpack_encoder_stream_error));
    try std.testing.expectEqual(@as(u64, 0x0202), @intFromEnum(ErrorCode.qpack_decoder_stream_error));
}
