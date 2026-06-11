//! QUIC transport parameters (RFC 9000 18.2): a peer advertises its limits in the
//! TLS quic_transport_parameters extension as a sequence of (id, length, value)
//! triples, each field a QUIC varint. The server reads the client's to learn the
//! flow-control grants, stream limits, and timers it must honour. Only the
//! integer-valued parameters this stack acts on are surfaced; unknown ids (and the
//! reserved GREASE ids) are skipped, as RFC 9000 18.1 requires.

const std = @import("std");
const varint = @import("varint.zig");

pub const Error = error{
    /// A parameter ran past the buffer, a length was malformed, a parameter that
    /// must be an integer was not a single varint, or a parameter appeared twice
    /// (RFC 9000 7.4: a duplicate is a TRANSPORT_PARAMETER_ERROR).
    Malformed,
};

/// RFC 9000 18.2 caps max_ack_delay at 2^14 ms; clamp here so the us conversion
/// (x1000) downstream cannot overflow on a hostile value.
const MAX_ACK_DELAY_MS_CAP: u64 = 1 << 14;

/// The parameters this stack reads. Each defaults to the RFC 9000 18.2 default for
/// an absent parameter, so a parsed value is always usable directly.
pub const TransportParameters = struct {
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    max_idle_timeout_ms: u64 = 0, // 0 = no idle timeout
    max_ack_delay_ms: u64 = 25, // RFC 9000 18.2 default
    active_connection_id_limit: u64 = 2, // RFC 9000 18.2 default
};

const Id = enum(u64) {
    max_idle_timeout = 0x01,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    max_ack_delay = 0x0b,
    active_connection_id_limit = 0x0e,
    _,
};

/// Parse the client's transport-parameter list. Unknown ids are skipped; a known
/// id appearing twice is a TRANSPORT_PARAMETER_ERROR (RFC 9000 7.4).
pub fn parse(buf: []const u8) Error!TransportParameters {
    var tp = TransportParameters{};
    var seen: [64]u64 = undefined; // the ids seen so far; a real list is tiny
    var seen_n: usize = 0;
    var pos: usize = 0;
    while (pos < buf.len) {
        const id = take(buf, &pos) catch return error.Malformed;
        const len = take(buf, &pos) catch return error.Malformed;
        if (pos + len > buf.len) return error.Malformed;
        const value = buf[pos .. pos + @as(usize, @intCast(len))];
        pos += @intCast(len);
        // RFC 9000 7.4.2: a parameter MUST NOT appear more than once.
        for (seen[0..seen_n]) |s| if (s == id) return error.Malformed;
        if (seen_n == seen.len) return error.Malformed; // absurdly many parameters
        seen[seen_n] = id;
        seen_n += 1;
        switch (@as(Id, @enumFromInt(id))) {
            .max_idle_timeout => tp.max_idle_timeout_ms = try intParam(value),
            .initial_max_data => tp.initial_max_data = try intParam(value),
            .initial_max_stream_data_bidi_local => tp.initial_max_stream_data_bidi_local = try intParam(value),
            .initial_max_stream_data_bidi_remote => tp.initial_max_stream_data_bidi_remote = try intParam(value),
            .initial_max_stream_data_uni => tp.initial_max_stream_data_uni = try intParam(value),
            .initial_max_streams_bidi => tp.initial_max_streams_bidi = try intParam(value),
            .initial_max_streams_uni => tp.initial_max_streams_uni = try intParam(value),
            .max_ack_delay => tp.max_ack_delay_ms = @min(try intParam(value), MAX_ACK_DELAY_MS_CAP),
            .active_connection_id_limit => tp.active_connection_id_limit = try intParam(value),
            _ => {}, // unknown / GREASE: skip (RFC 9000 18.1)
        }
    }
    return tp;
}

/// An integer-valued parameter is exactly one varint filling its value (RFC 9000 18.2).
fn intParam(value: []const u8) Error!u64 {
    const d = varint.decode(value) catch return error.Malformed;
    if (d.len != value.len) return error.Malformed; // trailing bytes are illegal
    return d.value;
}

fn take(buf: []const u8, pos: *usize) varint.Error!u64 {
    const d = try varint.decode(buf[pos.*..]);
    pos.* += d.len;
    return d.value;
}

const testing = std.testing;

test "parses the integer parameters and skips unknown ids" {
    // id 0x04 (initial_max_data) len 4 value 0x80010000 (varint 65536); then an
    // unknown id 0x21 len 1 value 0x05 (skipped); then 0x0b (max_ack_delay) len 1 value 20.
    const buf = [_]u8{
        0x04, 0x04, 0x80, 0x01, 0x00, 0x00, // initial_max_data = 65536
        0x21, 0x01, 0x05, // unknown id, skipped
        0x0b, 0x01, 0x14, // max_ack_delay = 20
        0x08, 0x01, 0x03, // initial_max_streams_bidi = 3
    };
    const tp = try parse(&buf);
    try testing.expectEqual(@as(u64, 65536), tp.initial_max_data);
    try testing.expectEqual(@as(u64, 20), tp.max_ack_delay_ms);
    try testing.expectEqual(@as(u64, 3), tp.initial_max_streams_bidi);
    try testing.expectEqual(@as(u64, 2), tp.active_connection_id_limit); // unset -> default
}

test "absent parameters keep their RFC defaults" {
    const tp = try parse(&.{});
    try testing.expectEqual(@as(u64, 0), tp.initial_max_data);
    try testing.expectEqual(@as(u64, 25), tp.max_ack_delay_ms);
    try testing.expectEqual(@as(u64, 2), tp.active_connection_id_limit);
}

test "a parameter running past the buffer is malformed" {
    try testing.expectError(error.Malformed, parse(&[_]u8{ 0x04, 0x08, 0x00 })); // len 8, only 1 byte
}

test "an integer parameter with trailing bytes is malformed" {
    try testing.expectError(error.Malformed, parse(&[_]u8{ 0x04, 0x02, 0x01, 0x02 })); // 2 bytes, two varints
}

test "a duplicate parameter is rejected (RFC 9000 7.4.2)" {
    try testing.expectError(error.Malformed, parse(&[_]u8{ 0x04, 0x01, 0x01, 0x04, 0x01, 0x02 })); // 0x04 twice
}

test "max_ack_delay is clamped so the us conversion cannot overflow" {
    // 0x0b len 8, value the max 62-bit varint (0x3fff...ff) -> a huge ms value; clamped.
    const buf = [_]u8{ 0x0b, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const tp = try parse(&buf);
    try testing.expectEqual(MAX_ACK_DELAY_MS_CAP, tp.max_ack_delay_ms);
}
