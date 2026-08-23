//! QUIC transport parameters (RFC 9000 18.2): a peer advertises its limits in the
//! TLS quic_transport_parameters extension as a sequence of (id, length, value)
//! triples, each field a QUIC varint. The server reads the client's to learn the
//! flow-control grants, stream limits, timers, and migration constraints it must
//! honour. Unknown ids (and the reserved GREASE ids) are skipped, as RFC 9000
//! 18.1 requires.

const std = @import("std");
const varint = @import("varint.zig");

pub const Error = error{
    /// A parameter ran past the buffer, a length was malformed, a parameter that
    /// must be an integer was not a single varint, a connection id exceeded the 20
    /// bytes QUIC v1 allows, or a parameter appeared twice (RFC 9000 7.4: a
    /// duplicate is a TRANSPORT_PARAMETER_ERROR).
    Malformed,
};

/// RFC 9000 18.2 caps max_ack_delay at 2^14 ms; clamp here so the us conversion
/// (x1000) downstream cannot overflow on a hostile value.
const MAX_ACK_DELAY_MS_CAP: u64 = 1 << 14;
/// ack_delay_exponent values above 20 are invalid (RFC 9000 18.2).
const MAX_ACK_DELAY_EXPONENT: u64 = 20;
const MAX_CID_LEN: usize = 20;
/// Stream-count parameters cannot exceed 2^60, otherwise the implied largest
/// stream ID would not fit in a QUIC varint (RFC 9000 4.6 and 19.11).
pub const MAX_STREAM_COUNT: u64 = 1 << 60;

pub const ConnectionId = struct {
    bytes: [MAX_CID_LEN]u8 = [_]u8{0} ** MAX_CID_LEN,
    len: u8 = 0,

    pub fn init(value: []const u8) Error!ConnectionId {
        if (value.len > MAX_CID_LEN) return error.Malformed;
        var cid = ConnectionId{ .len = @intCast(value.len) };
        @memcpy(cid.bytes[0..value.len], value);
        return cid;
    }

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// max_idle_timeout has no RFC ceiling, but the timer code converts ms to us (x1000),
/// which a hostile 62-bit varint would overflow. ~49 days is far longer than any real
/// idle timeout, so clamp here - a connection that quiet is closed by other means.
const MAX_IDLE_TIMEOUT_MS_CAP: u64 = 1 << 32;

/// The parameters this stack reads. Each defaults to the RFC 9000 18.2 default for
/// an absent parameter, so a parsed value is always usable directly.
pub const TransportParameters = struct {
    original_destination_connection_id: ?ConnectionId = null,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    max_idle_timeout_ms: u64 = 0, // 0 = no idle timeout
    max_udp_payload_size: u64 = 65527, // RFC 9000 18.2 default
    stateless_reset_token: ?[16]u8 = null,
    ack_delay_exponent: u64 = 3, // RFC 9000 18.2 default
    max_ack_delay_ms: u64 = 25, // RFC 9000 18.2 default
    disable_active_migration: bool = false,
    active_connection_id_limit: u64 = 2, // RFC 9000 18.2 default
    initial_source_connection_id: ?ConnectionId = null,
    retry_source_connection_id: ?ConnectionId = null,
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

/// Caller-configurable transport parameters. Connection ID fields injected by
/// the QUIC connection are deliberately omitted.
pub const Configuration = struct {
    max_idle_timeout: ?u64 = null,
    stateless_reset_token: ?[16]u8 = null,
    max_udp_payload_size: ?u64 = null,
    initial_max_data: ?u64 = null,
    initial_max_stream_data_bidi_local: ?u64 = null,
    initial_max_stream_data_bidi_remote: ?u64 = null,
    initial_max_stream_data_uni: ?u64 = null,
    initial_max_streams_bidi: ?u64 = null,
    initial_max_streams_uni: ?u64 = null,
    ack_delay_exponent: ?u64 = null,
    max_ack_delay: ?u64 = null,
    disable_active_migration: bool = false,
    active_connection_id_limit: ?u64 = null,
};

const Id = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    _,
};

/// Encode caller configuration with canonical QUIC varints.
pub fn encodeConfiguration(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    configuration: Configuration,
) error{ Malformed, OutOfMemory }!void {
    if (configuration.max_idle_timeout) |value| {
        if (value > MAX_IDLE_TIMEOUT_MS_CAP) return error.Malformed;
        try appendIntegerParam(out, gpa, .max_idle_timeout, value);
    }
    if (configuration.stateless_reset_token) |token| {
        try appendBytesParam(out, gpa, @intFromEnum(Id.stateless_reset_token), &token);
    }
    if (configuration.max_udp_payload_size) |value| {
        if (value < 1200 or value > 65527) return error.Malformed;
        try appendIntegerParam(out, gpa, .max_udp_payload_size, value);
    }
    if (configuration.initial_max_data) |value| try appendIntegerParam(out, gpa, .initial_max_data, value);
    if (configuration.initial_max_stream_data_bidi_local) |value| {
        try appendIntegerParam(out, gpa, .initial_max_stream_data_bidi_local, value);
    }
    if (configuration.initial_max_stream_data_bidi_remote) |value| {
        try appendIntegerParam(out, gpa, .initial_max_stream_data_bidi_remote, value);
    }
    if (configuration.initial_max_stream_data_uni) |value| {
        try appendIntegerParam(out, gpa, .initial_max_stream_data_uni, value);
    }
    if (configuration.initial_max_streams_bidi) |value| {
        if (value > MAX_STREAM_COUNT) return error.Malformed;
        try appendIntegerParam(out, gpa, .initial_max_streams_bidi, value);
    }
    if (configuration.initial_max_streams_uni) |value| {
        if (value > MAX_STREAM_COUNT) return error.Malformed;
        try appendIntegerParam(out, gpa, .initial_max_streams_uni, value);
    }
    if (configuration.ack_delay_exponent) |value| {
        if (value > MAX_ACK_DELAY_EXPONENT) return error.Malformed;
        try appendIntegerParam(out, gpa, .ack_delay_exponent, value);
    }
    if (configuration.max_ack_delay) |value| {
        if (value >= MAX_ACK_DELAY_MS_CAP) return error.Malformed;
        try appendIntegerParam(out, gpa, .max_ack_delay, value);
    }
    if (configuration.disable_active_migration) {
        try appendBytesParam(out, gpa, @intFromEnum(Id.disable_active_migration), &.{});
    }
    if (configuration.active_connection_id_limit) |value| {
        if (value < 2) return error.Malformed;
        try appendIntegerParam(out, gpa, .active_connection_id_limit, value);
    }
}

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
            .original_destination_connection_id => {
                tp.original_destination_connection_id = try cidParam(value);
                tp.has_server_only_param = true;
                tp.has_injected_cid_param = true;
            },
            .max_idle_timeout => tp.max_idle_timeout_ms = @min(try intParam(value), MAX_IDLE_TIMEOUT_MS_CAP),
            .stateless_reset_token => {
                if (value.len != 16) return error.Malformed;
                tp.stateless_reset_token = value[0..16].*;
                tp.has_server_only_param = true;
            },
            .max_udp_payload_size => {
                tp.max_udp_payload_size = try intParam(value);
                if (tp.max_udp_payload_size < 1200) return error.Malformed;
            },
            .initial_max_data => tp.initial_max_data = try intParam(value),
            .initial_max_stream_data_bidi_local => tp.initial_max_stream_data_bidi_local = try intParam(value),
            .initial_max_stream_data_bidi_remote => tp.initial_max_stream_data_bidi_remote = try intParam(value),
            .initial_max_stream_data_uni => tp.initial_max_stream_data_uni = try intParam(value),
            .initial_max_streams_bidi => tp.initial_max_streams_bidi = try streamCountParam(value),
            .initial_max_streams_uni => tp.initial_max_streams_uni = try streamCountParam(value),
            .ack_delay_exponent => {
                tp.ack_delay_exponent = try intParam(value);
                if (tp.ack_delay_exponent > MAX_ACK_DELAY_EXPONENT) return error.Malformed;
            },
            .max_ack_delay => tp.max_ack_delay_ms = @min(try intParam(value), MAX_ACK_DELAY_MS_CAP),
            .active_connection_id_limit => {
                tp.active_connection_id_limit = try intParam(value);
                if (tp.active_connection_id_limit < 2) return error.Malformed;
            },
            .disable_active_migration => {
                if (value.len != 0) return error.Malformed;
                tp.disable_active_migration = true;
            },
            .initial_source_connection_id => {
                tp.initial_source_connection_id = try cidParam(value);
                tp.has_injected_cid_param = true;
            },
            .retry_source_connection_id => {
                tp.retry_source_connection_id = try cidParam(value);
                tp.has_server_only_param = true;
            },
            .preferred_address => tp.has_server_only_param = true,
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

fn appendIntegerParam(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    id: Id,
    value: u64,
) error{ Malformed, OutOfMemory }!void {
    var scratch: [8]u8 = undefined;
    const encoded = varint.encode(&scratch, value) catch return error.Malformed;
    try appendBytesParam(out, gpa, @intFromEnum(id), encoded);
}

/// An integer-valued parameter is exactly one varint filling its value (RFC 9000 18.2).
fn intParam(value: []const u8) Error!u64 {
    const d = varint.decode(value) catch return error.Malformed;
    if (d.len != value.len) return error.Malformed; // trailing bytes are illegal
    return d.value;
}

fn streamCountParam(value: []const u8) Error!u64 {
    const n = try intParam(value);
    if (n > MAX_STREAM_COUNT) return error.Malformed;
    return n;
}

fn cidParam(value: []const u8) Error!ConnectionId {
    return ConnectionId.init(value);
}

fn appendCidParam(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, id: Id, cid: []const u8) !void {
    try varint.append(out, gpa, @intFromEnum(id));
    try varint.append(out, gpa, cid.len);
    try out.appendSlice(gpa, cid);
}

pub fn appendOriginalDestinationConnectionId(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, cid: []const u8) !void {
    try appendCidParam(out, gpa, .original_destination_connection_id, cid);
}

pub fn appendInitialSourceConnectionId(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, cid: []const u8) !void {
    try appendCidParam(out, gpa, .initial_source_connection_id, cid);
}

pub fn appendRetrySourceConnectionId(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, cid: []const u8) !void {
    try appendCidParam(out, gpa, .retry_source_connection_id, cid);
}

fn take(buf: []const u8, pos: *usize) varint.Error!u64 {
    const d = try varint.decode(buf[pos.*..]);
    pos.* += d.len;
    return d.value;
}

const testing = std.testing;

test "configuration encodes canonical transport parameters" {
    const gpa = testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try encodeConfiguration(&out, gpa, .{
        .max_idle_timeout = 63,
        .stateless_reset_token = [_]u8{'r'} ** 16,
        .max_udp_payload_size = 1200,
        .initial_max_data = 64,
        .initial_max_stream_data_bidi_local = 16383,
        .initial_max_stream_data_bidi_remote = 16384,
        .initial_max_stream_data_uni = 1 << 30,
        .initial_max_streams_bidi = 4,
        .initial_max_streams_uni = 5,
        .ack_delay_exponent = 3,
        .max_ack_delay = 25,
        .disable_active_migration = true,
        .active_connection_id_limit = 2,
    });
    const expected = [_]u8{
        0x01, 0x01, 0x3f,
        0x02, 0x10,
    } ++ [_]u8{'r'} ** 16 ++ [_]u8{
        0x03, 0x02, 0x44, 0xb0,
        0x04, 0x02, 0x40, 0x40,
        0x05, 0x02, 0x7f, 0xff,
        0x06, 0x04, 0x80, 0x00,
        0x40, 0x00, 0x07, 0x08,
        0xc0, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00,
        0x08, 0x01, 0x04, 0x09,
        0x01, 0x05, 0x0a, 0x01,
        0x03, 0x0b, 0x01, 0x19,
        0x0c, 0x00, 0x0e, 0x01,
        0x02,
    };
    try testing.expectEqualSlices(u8, &expected, out.items);
}

test "configuration rejects values outside transport parameter ranges" {
    const gpa = testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try testing.expectError(error.Malformed, encodeConfiguration(&out, gpa, .{ .max_idle_timeout = (1 << 32) + 1 }));
    try testing.expectError(error.Malformed, encodeConfiguration(&out, gpa, .{ .max_udp_payload_size = 1199 }));
    try testing.expectError(error.Malformed, encodeConfiguration(&out, gpa, .{ .initial_max_data = varint.MAX + 1 }));
    try testing.expectError(error.Malformed, encodeConfiguration(&out, gpa, .{ .initial_max_streams_bidi = MAX_STREAM_COUNT + 1 }));
    try testing.expectError(error.Malformed, encodeConfiguration(&out, gpa, .{ .initial_max_streams_uni = MAX_STREAM_COUNT + 1 }));
    try testing.expectError(error.Malformed, encodeConfiguration(&out, gpa, .{ .ack_delay_exponent = 21 }));
    try testing.expectError(error.Malformed, encodeConfiguration(&out, gpa, .{ .max_ack_delay = 1 << 14 }));
    try testing.expectError(error.Malformed, encodeConfiguration(&out, gpa, .{ .active_connection_id_limit = 1 }));
}

test "parses the integer parameters and skips unknown ids" {
    // id 0x04 (initial_max_data) len 4 value 0x80010000 (varint 65536); then an
    // unknown id 0x21 len 1 value 0x05 (skipped); then 0x0b (max_ack_delay) len 1 value 20.
    const buf = [_]u8{
        0x00, 0x04, 'o', 'd', 'c', 'i', // original_destination_connection_id
        0x04, 0x04, 0x80, 0x01, 0x00, 0x00, // initial_max_data = 65536
        0x21, 0x01, 0x05, // unknown id, skipped
        0x02, 0x10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, // stateless_reset_token
        0x03, 0x02, 0x44, 0xb0, // max_udp_payload_size = 1200
        0x0a, 0x01, 0x04, // ack_delay_exponent = 4
        0x0b, 0x01, 0x14, // max_ack_delay = 20
        0x0c, 0x00, // disable_active_migration
        0x08, 0x01, 0x03, // initial_max_streams_bidi = 3
        0x0f, 0x03, 'i', 's', 'c', // initial_source_connection_id
        0x10, 0x03, 'r', 's', 'c', // retry_source_connection_id
    };
    const tp = try parse(&buf);
    try testing.expectEqualStrings("odci", tp.original_destination_connection_id.?.slice());
    try testing.expectEqual(@as(u64, 65536), tp.initial_max_data);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, &tp.stateless_reset_token.?);
    try testing.expectEqual(@as(u64, 1200), tp.max_udp_payload_size);
    try testing.expectEqual(@as(u64, 4), tp.ack_delay_exponent);
    try testing.expectEqual(@as(u64, 20), tp.max_ack_delay_ms);
    try testing.expect(tp.disable_active_migration);
    try testing.expectEqual(@as(u64, 3), tp.initial_max_streams_bidi);
    try testing.expectEqual(@as(u64, 2), tp.active_connection_id_limit); // unset -> default
    try testing.expectEqualStrings("isc", tp.initial_source_connection_id.?.slice());
    try testing.expectEqualStrings("rsc", tp.retry_source_connection_id.?.slice());
}

test "absent parameters keep their RFC defaults" {
    const tp = try parse(&.{});
    try testing.expect(tp.original_destination_connection_id == null);
    try testing.expectEqual(@as(u64, 0), tp.initial_max_data);
    try testing.expect(tp.stateless_reset_token == null);
    try testing.expectEqual(@as(u64, 65527), tp.max_udp_payload_size);
    try testing.expectEqual(@as(u64, 3), tp.ack_delay_exponent);
    try testing.expectEqual(@as(u64, 25), tp.max_ack_delay_ms);
    try testing.expect(!tp.disable_active_migration);
    try testing.expectEqual(@as(u64, 2), tp.active_connection_id_limit);
    try testing.expect(tp.initial_source_connection_id == null);
    try testing.expect(tp.retry_source_connection_id == null);
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
    try testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc }, tp.initial_source_connection_id.?.slice());
}

test "an empty initial_source_connection_id is present, not absent" {
    // A zero-length connection id is legal (RFC 9000 17.2); the parameter being
    // present-with-empty must be distinguishable from the parameter missing.
    const tp = try parse(&[_]u8{ 0x0f, 0x00 });
    try testing.expectEqual(@as(usize, 0), tp.initial_source_connection_id.?.slice().len);
    try testing.expectEqual(@as(?ConnectionId, null), (try parse(&.{})).initial_source_connection_id);
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

test "active_connection_id_limit below two is malformed" {
    try testing.expectError(error.Malformed, parse(&[_]u8{ 0x0e, 0x01, 0x01 }));
}

test "initial max streams above the stream-id range is malformed" {
    try testing.expectError(error.Malformed, parse(&[_]u8{
        0x08, 0x08, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    }));
    try testing.expectError(error.Malformed, parse(&[_]u8{
        0x09, 0x08, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    }));
}

test "ack_delay_exponent above twenty is malformed" {
    try testing.expectError(error.Malformed, parse(&[_]u8{ 0x0a, 0x01, 0x15 }));
}

test "max_udp_payload_size below 1200 is malformed" {
    try testing.expectError(error.Malformed, parse(&[_]u8{ 0x03, 0x02, 0x44, 0xaf }));
}

test "disable_active_migration must be empty" {
    try testing.expectError(error.Malformed, parse(&[_]u8{ 0x0c, 0x01, 0x00 }));
}

test "stateless_reset_token must be exactly sixteen bytes" {
    try testing.expectError(error.Malformed, parse(&[_]u8{ 0x02, 0x0f, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }));
}

test "connection id parameters are capped at twenty bytes" {
    try testing.expectError(error.Malformed, parse(&[_]u8{
        0x0f, 0x15,
        0,    1,
        2,    3,
        4,    5,
        6,    7,
        8,    9,
        10,   11,
        12,   13,
        14,   15,
        16,   17,
        18,   19,
        20,
    }));
}
