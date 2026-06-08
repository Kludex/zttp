//! QUIC wire constants (RFC 9000): packet types, frame types, transport error
//! codes, and the protocol limits the transport enforces. The single source of
//! truth for the QUIC layer, mirroring h2/constants.zig's role for HTTP/2. Pure
//! leaf: no state, no allocation.

const std = @import("std");

/// The QUIC version this implementation speaks (RFC 9000 version 1).
pub const VERSION_1: u32 = 0x0000_0001;

/// The maximum length of a connection id (RFC 9000 17.2: 0-20 octets in v1).
pub const MAX_CID_LEN: usize = 20;

/// The smallest UDP payload an Initial-carrying datagram may have (RFC 9000
/// 14.1). A client MUST pad its Initials to at least this; a server MUST drop a
/// short Initial. It is the anti-amplification floor.
pub const MIN_INITIAL_DATAGRAM: usize = 1200;

/// The address-validation amplification factor (RFC 9000 8.1): before validating
/// the peer's address a server may send at most this many times what it received.
pub const AMPLIFICATION_FACTOR: usize = 3;

/// Long-header packet types (RFC 9000 17.2), the two bits after the fixed bit.
pub const LongType = enum(u2) {
    initial = 0x0,
    zero_rtt = 0x1,
    handshake = 0x2,
    retry = 0x3,
};

/// The form bit (RFC 9000 17.1): set for long-header packets, clear for short.
pub const HEADER_FORM_LONG: u8 = 0x80;
/// The fixed bit (RFC 9000 17.2): MUST be 1 in every v1 packet not subject to
/// Greasing the QUIC Bit (RFC 9287); a 0 here is a parse-time reject.
pub const FIXED_BIT: u8 = 0x40;

/// QUIC frame types (RFC 9000 section 19). Non-exhaustive so unknown types are a
/// connection error (FRAME_ENCODING_ERROR) rather than a translate-time panic;
/// the connection layer decides. STREAM is a range 0x08-0x0f whose low 3 bits are
/// the OFF/LEN/FIN flags, so only its base is named here.
pub const FrameType = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    stream = 0x08, // 0x08-0x0f, low 3 bits are flags
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c, // transport error
    connection_close_app = 0x1d, // application error
    handshake_done = 0x1e,
    _,
};

/// The STREAM frame type flags carried in the low 3 bits of types 0x08-0x0f.
pub const STREAM_BASE: u64 = 0x08;
pub const STREAM_FIN: u64 = 0x01;
pub const STREAM_LEN: u64 = 0x02;
pub const STREAM_OFF: u64 = 0x04;

/// Transport error codes (RFC 9000 20.1) carried in a CONNECTION_CLOSE frame.
pub const TransportError = enum(u64) {
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
    _,
};

/// The packet-number spaces (RFC 9002 section 3): each has independent ack
/// tracking and its own packet-number counter.
pub const Space = enum(u2) {
    initial = 0,
    handshake = 1,
    application = 2,
};

test "long types cover the four RFC 9000 17.2 values" {
    try std.testing.expectEqual(@as(u2, 0), @intFromEnum(LongType.initial));
    try std.testing.expectEqual(@as(u2, 3), @intFromEnum(LongType.retry));
}

test "stream flag bits are the low three of the type" {
    try std.testing.expectEqual(@as(u64, 0x08), STREAM_BASE);
    try std.testing.expectEqual(@as(u64, 0x0f), STREAM_BASE | STREAM_FIN | STREAM_LEN | STREAM_OFF);
}
