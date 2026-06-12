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
    /// must be an integer was not a single varint, a connection id exceeded the 20
    /// bytes QUIC v1 allows, or a parameter appeared twice (RFC 9000 7.4: a
    /// duplicate is a TRANSPORT_PARAMETER_ERROR).
    Malformed,
};

/// A connection id carried in a transport parameter (RFC 9000 18.2): at most 20
/// bytes in QUIC version 1 (RFC 9000 17.2).
pub const ConnectionId = struct {
    buf: [20]u8 = undefined,
    len: u8 = 0,

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.buf[0..self.len];
    }
};

/// RFC 9000 18.2 caps max_ack_delay at 2^14 ms; clamp here so the us conversion
/// (x1000) downstream cannot overflow on a hostile value.
const MAX_ACK_DELAY_MS_CAP: u64 = 1 << 14;

/// max_idle_timeout has no RFC ceiling, but the timer code converts ms to us (x1000),
/// which a hostile 62-bit varint would overflow. ~49 days is far longer than any real
/// idle timeout, so clamp here - a connection that quiet is closed by other means.
const MAX_IDLE_TIMEOUT_MS_CAP: u64 = 1 << 32;

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
    /// The sender's initial_source_connection_id (RFC 9000 7.3): both endpoints MUST
    /// send it, and the receiver MUST check it against the Source Connection ID of
    /// the peer's first packet. Null when absent - the caller decides whether that
    /// is fatal (it is, for a peer's parameters).
    initial_scid: ?ConnectionId = null,
    /// A parameter only a server may send appeared (RFC 9000 18.2:
    /// original_destination_connection_id, stateless_reset_token, preferred_address,
    /// or retry_source_connection_id). A server MUST reject a client list carrying
    /// any of these as a TRANSPORT_PARAMETER_ERROR.
    has_server_only_param: bool = false,
    /// A connection-id parameter the server derives per-connection and appends itself
    /// (original_destination_connection_id or initial_source_connection_id) appeared.
    /// A server's base configuration blob carrying one would duplicate it on the
    /// wire; unlike the broader server-only set, stateless_reset_token and
    /// preferred_address are NOT flagged - a server may legitimately advertise those.
    has_injected_cid_param: bool = false,
};

const Id = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    max_ack_delay = 0x0b,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
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
            .max_idle_timeout => tp.max_idle_timeout_ms = @min(try intParam(value), MAX_IDLE_TIMEOUT_MS_CAP),
            .initial_max_data => tp.initial_max_data = try intParam(value),
            .initial_max_stream_data_bidi_local => tp.initial_max_stream_data_bidi_local = try intParam(value),
            .initial_max_stream_data_bidi_remote => tp.initial_max_stream_data_bidi_remote = try intParam(value),
            .initial_max_stream_data_uni => tp.initial_max_stream_data_uni = try intParam(value),
            .initial_max_streams_bidi => tp.initial_max_streams_bidi = try intParam(value),
            .initial_max_streams_uni => tp.initial_max_streams_uni = try intParam(value),
            .max_ack_delay => tp.max_ack_delay_ms = @min(try intParam(value), MAX_ACK_DELAY_MS_CAP),
            .active_connection_id_limit => tp.active_connection_id_limit = try intParam(value),
            .initial_source_connection_id => {
                if (value.len > 20) return error.Malformed; // RFC 9000 17.2: at most 20 bytes in v1
                var cid = ConnectionId{ .len = @intCast(value.len) };
                @memcpy(cid.buf[0..value.len], value);
                tp.initial_scid = cid;
                tp.has_injected_cid_param = true; // 0x0f: a server appends this itself
            },
            .original_destination_connection_id => {
                tp.has_server_only_param = true;
                tp.has_injected_cid_param = true; // 0x00: a server appends this itself
            },
            .stateless_reset_token,
            .preferred_address,
            .retry_source_connection_id,
            => tp.has_server_only_param = true,
            _ => {}, // unknown / GREASE: skip (RFC 9000 18.1)
        }
    }
    return tp;
}

/// Append one transport parameter with a raw byte value (RFC 9000 18.1): varint id,
/// varint length, then the bytes - the encoding the connection-id parameters use.
/// Ids and lengths here are always far inside the varint range, so the only real
/// failure is allocation.
pub fn appendBytesParam(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, id: u64, value: []const u8) error{OutOfMemory}!void {
    varint.append(out, gpa, id) catch return error.OutOfMemory;
    varint.append(out, gpa, value.len) catch return error.OutOfMemory;
    try out.appendSlice(gpa, value);
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

test "max_idle_timeout is clamped so the us conversion cannot overflow" {
    // 0x01 len 8, value the max 62-bit varint -> a huge ms value the idle timer would
    // overflow when multiplying by 1000; clamped to the cap.
    const buf = [_]u8{ 0x01, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const tp = try parse(&buf);
    try testing.expectEqual(MAX_IDLE_TIMEOUT_MS_CAP, tp.max_idle_timeout_ms);
}

test "appendBytesParam round-trips a connection id through parse" {
    const gpa = testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try appendBytesParam(&out, gpa, 0x0f, &[_]u8{ 0xaa, 0xbb, 0xcc });
    const tp = try parse(out.items);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc }, tp.initial_scid.?.slice());
}

test "an empty initial_source_connection_id is present, not absent" {
    // A zero-length connection id is legal (RFC 9000 17.2); the parameter being
    // present-with-empty must be distinguishable from the parameter missing.
    const tp = try parse(&[_]u8{ 0x0f, 0x00 });
    try testing.expectEqual(@as(usize, 0), tp.initial_scid.?.slice().len);
    try testing.expectEqual(@as(?ConnectionId, null), (try parse(&.{})).initial_scid);
}

test "a connection id past 20 bytes is malformed" {
    var buf = [_]u8{ 0x0f, 21 } ++ [_]u8{0xaa} ** 21;
    try testing.expectError(error.Malformed, parse(&buf));
}

test "a server-only parameter is flagged" {
    // ODCID (0x00) from a peer that must not send it; the caller rejects on the flag.
    const tp = try parse(&[_]u8{ 0x00, 0x02, 0x11, 0x22 });
    try testing.expect(tp.has_server_only_param);
    try testing.expect(!(try parse(&[_]u8{ 0x0f, 0x00 })).has_server_only_param);
}

test "only the injected connection-id parameters are flagged for a server base blob" {
    // The two ids the server appends itself (0x00 ODCID, 0x0f initial_scid) are
    // flagged so a base blob carrying one is caught as a duplicate...
    try testing.expect((try parse(&[_]u8{ 0x00, 0x01, 0xaa })).has_injected_cid_param);
    try testing.expect((try parse(&[_]u8{ 0x0f, 0x00 })).has_injected_cid_param);
    // ...but a stateless_reset_token (0x02) or preferred_address (0x0d) is a server's
    // own to advertise, so it is NOT an injected-id conflict.
    try testing.expect(!(try parse(&[_]u8{0x02} ++ [_]u8{0x10} ++ [_]u8{0xcc} ** 16)).has_injected_cid_param);
    try testing.expect((try parse(&[_]u8{0x02} ++ [_]u8{0x10} ++ [_]u8{0xcc} ** 16)).has_server_only_param);
}
