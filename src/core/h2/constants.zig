//! HTTP/2 wire constants (RFC 9113 + RFC 7541): frame types, flags, settings,
//! error codes, the client preface, and the per-frame-type length rules. The
//! single source of truth, mirroring tables.zig's role for HTTP/1.1. Pure leaf:
//! no state, no allocation.

const std = @import("std");

/// The 9-octet frame header: Length(24) Type(8) Flags(8) R(1)+StreamId(31).
pub const FRAME_HEADER_LEN: usize = 9;

/// Client connection preface (RFC 9113 3.4): the exact 24 octets the client
/// sends before its first SETTINGS frame.
pub const CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

comptime {
    std.debug.assert(CLIENT_PREFACE.len == 24);
}

/// SETTINGS_MAX_FRAME_SIZE default and bounds (RFC 9113 4.2 / 6.5.2). The
/// default is also the minimum any endpoint may advertise.
pub const DEFAULT_FRAME_SIZE: u32 = 16384; // 2^14
pub const MAX_FRAME_SIZE_LIMIT: u32 = 16777215; // 2^24 - 1

/// Flow-control window default and ceiling (RFC 9113 6.5.2 / 6.9.1).
pub const DEFAULT_WINDOW_SIZE: i32 = 65535; // 2^16 - 1
pub const MAX_WINDOW_SIZE: i32 = 2147483647; // 2^31 - 1

/// Default HPACK dynamic table size (RFC 7541 4.2 / RFC 9113 6.5.2).
pub const DEFAULT_HEADER_TABLE_SIZE: u32 = 4096;

/// Frame types (RFC 9113 section 6). The non-exhaustive tag (`_`) lets us parse
/// unknown/extension types and discard them per RFC 9113 4.1 rather than reject.
pub const FrameType = enum(u8) {
    data = 0x00,
    headers = 0x01,
    priority = 0x02,
    rst_stream = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    ping = 0x06,
    goaway = 0x07,
    window_update = 0x08,
    continuation = 0x09,
    _,
};

/// Frame flags (RFC 9113 section 6). A flag's bit position is reused across
/// frame types, so each constant is just a mask; the meaning is per-type.
pub const Flags = struct {
    pub const ack: u8 = 0x01; // SETTINGS, PING
    pub const end_stream: u8 = 0x01; // DATA, HEADERS
    pub const end_headers: u8 = 0x04; // HEADERS, PUSH_PROMISE, CONTINUATION
    pub const padded: u8 = 0x08; // DATA, HEADERS, PUSH_PROMISE
    pub const priority: u8 = 0x20; // HEADERS

    pub fn has(flags: u8, mask: u8) bool {
        return flags & mask != 0;
    }
};

/// SETTINGS parameter identifiers (RFC 9113 6.5.2). Unknown ids are ignored.
pub const SettingId = enum(u16) {
    header_table_size = 0x01,
    enable_push = 0x02,
    max_concurrent_streams = 0x03,
    initial_window_size = 0x04,
    max_frame_size = 0x05,
    max_header_list_size = 0x06,
    _,
};

/// HTTP/2 error codes (RFC 9113 7). Used in RST_STREAM and GOAWAY.
pub const ErrorCode = enum(u32) {
    no_error = 0x00,
    protocol_error = 0x01,
    internal_error = 0x02,
    flow_control_error = 0x03,
    settings_timeout = 0x04,
    stream_closed = 0x05,
    frame_size_error = 0x06,
    refused_stream = 0x07,
    cancel = 0x08,
    compression_error = 0x09,
    connect_error = 0x0a,
    enhance_your_calm = 0x0b,
    inadequate_security = 0x0c,
    http_1_1_required = 0x0d,
    _,
};

test "frame type tags match the wire codes" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(FrameType.data));
    try std.testing.expectEqual(@as(u8, 9), @intFromEnum(FrameType.continuation));
    try std.testing.expectEqual(FrameType.settings, @as(FrameType, @enumFromInt(4)));
    // Unknown/extension type round-trips through the non-exhaustive tag.
    try std.testing.expectEqual(@as(u8, 0xFE), @intFromEnum(@as(FrameType, @enumFromInt(0xFE))));
}

test "flags helper masks bits" {
    try std.testing.expect(Flags.has(0x05, Flags.ack));
    try std.testing.expect(Flags.has(0x05, Flags.end_headers));
    try std.testing.expect(!Flags.has(0x05, Flags.padded));
}

test "error codes match the wire values" {
    try std.testing.expectEqual(@as(u32, 0), @intFromEnum(ErrorCode.no_error));
    try std.testing.expectEqual(@as(u32, 0x0b), @intFromEnum(ErrorCode.enhance_your_calm));
    try std.testing.expectEqual(@as(u32, 0x0d), @intFromEnum(ErrorCode.http_1_1_required));
}

test "client preface is the exact 24-octet magic" {
    try std.testing.expectEqualStrings("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", CLIENT_PREFACE);
}
