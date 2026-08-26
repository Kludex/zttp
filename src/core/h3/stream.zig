//! HTTP/3 stream typing and SETTINGS (RFC 9114 sections 6 and 7.2.4). A QUIC
//! bidirectional stream carries a request/response; a unidirectional stream
//! announces its role with a varint type as its very first bytes. This decodes
//! that prefix and the SETTINGS frame payload. Pure leaf: no allocation, slices
//! borrow from the fed bytes.

const std = @import("std");
const varint = @import("../quic/varint.zig");

/// Unidirectional stream types (RFC 9114 6.2 and 11.2.3). The first varint on a
/// uni stream selects its role; unknown types are abandoned (the stream is reset
/// or its data discarded).
pub const UniStreamType = enum(u64) {
    control = 0x00,
    push = 0x01,
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,
    _,
};

/// Decode the uni-stream type prefix. Returns the type and how many octets it
/// consumed (the rest of the stream is that type's content).
pub fn decodeUniType(buf: []const u8) ?struct { utype: UniStreamType, len: usize } {
    const d = varint.decode(buf) catch return null;
    return .{ .utype = @enumFromInt(d.value), .len = d.len };
}

/// SETTINGS identifiers the read path cares about (RFC 9114 7.2.4.1 and RFC 9204
/// 5). Others are ignored (RFC 9114 7.2.4: an unknown setting MUST be ignored).
pub const SettingId = enum(u64) {
    qpack_max_table_capacity = 0x01,
    max_field_section_size = 0x06,
    qpack_blocked_streams = 0x07,
    _,
};

/// The settings the peer advertised, with RFC defaults for anything unset.
/// `seen` records which known identifiers were actually present so the event
/// surfaced to the integrator reflects the wire, not the defaults.
pub const Settings = struct {
    qpack_max_table_capacity: u64 = 0,
    max_field_section_size: u64 = std.math.maxInt(u64),
    qpack_blocked_streams: u64 = 0,
    seen_cap: bool = false,
    seen_size: bool = false,
    seen_blocked: bool = false,
};

pub const Error = error{
    /// A SETTINGS payload is truncated or a setting id is repeated (RFC 9114
    /// 7.2.4: a duplicate identifier is a connection error).
    SettingsError,
};

/// Parse a SETTINGS frame payload (a sequence of id/value varint pairs) into a
/// `Settings`. A repeated identifier is a connection error (RFC 9114 7.2.4);
/// unknown settings are ignored after duplicate and resource-limit checks.
pub fn parseSettings(payload: []const u8) Error!Settings {
    var s = Settings{};
    var seen: [128]u64 = undefined;
    var seen_len: usize = 0;
    var pos: usize = 0;
    while (pos < payload.len) {
        const id = varint.decode(payload[pos..]) catch return error.SettingsError;
        pos += id.len;
        const val = varint.decode(payload[pos..]) catch return error.SettingsError;
        pos += val.len;
        for (seen[0..seen_len]) |previous| {
            if (previous == id.value) return error.SettingsError;
        }
        if (seen_len == seen.len) return error.SettingsError;
        seen[seen_len] = id.value;
        seen_len += 1;
        // The HTTP/2 setting ids 0x02-0x05 are reserved in HTTP/3 and their receipt
        // MUST be a connection error (RFC 9114 7.2.4.1), not ignored as unknown.
        if (id.value >= 0x02 and id.value <= 0x05) return error.SettingsError;
        switch (@as(SettingId, @enumFromInt(id.value))) {
            .qpack_max_table_capacity => {
                if (s.seen_cap) return error.SettingsError;
                s.seen_cap = true;
                s.qpack_max_table_capacity = val.value;
            },
            .max_field_section_size => {
                if (s.seen_size) return error.SettingsError;
                s.seen_size = true;
                s.max_field_section_size = val.value;
            },
            .qpack_blocked_streams => {
                if (s.seen_blocked) return error.SettingsError;
                s.seen_blocked = true;
                s.qpack_blocked_streams = val.value;
            },
            _ => {}, // unknown setting: ignored
        }
    }
    return s;
}

test "decode the uni-stream type prefixes" {
    try std.testing.expectEqual(UniStreamType.control, decodeUniType(&.{0x00}).?.utype);
    try std.testing.expectEqual(UniStreamType.qpack_encoder, decodeUniType(&.{0x02}).?.utype);
    try std.testing.expectEqual(UniStreamType.qpack_decoder, decodeUniType(&.{0x03}).?.utype);
}

test "parse a SETTINGS payload" {
    // max_field_section_size (0x06) = 0x4000 (varint 0x80,0x00,0x40,0x00)
    const s = try parseSettings(&.{ 0x06, 0x80, 0x00, 0x40, 0x00, 0x01, 0x10 });
    try std.testing.expectEqual(@as(u64, 0x4000), s.max_field_section_size);
    try std.testing.expectEqual(@as(u64, 0x10), s.qpack_max_table_capacity);
}

test "an unknown setting is ignored" {
    const s = try parseSettings(&.{ 0x21, 0x05 }); // reserved id, value 5
    try std.testing.expectEqual(@as(u64, 0), s.qpack_max_table_capacity);
}

test "a repeated setting is an error" {
    try std.testing.expectError(error.SettingsError, parseSettings(&.{ 0x01, 0x10, 0x01, 0x20 }));
}

test "a truncated SETTINGS payload is an error" {
    try std.testing.expectError(error.SettingsError, parseSettings(&.{0x06}));
    try std.testing.expectError(error.SettingsError, parseSettings(&.{0x40}));
    try std.testing.expectError(error.SettingsError, parseSettings(&.{ 0x06, 0x40 }));
}

test "many distinct unknown settings are accepted" {
    // Unknown ids are ignored and not capped (RFC 9114 7.2.4).
    const s = try parseSettings(&.{ 0x21, 0x00, 0x22, 0x00, 0x23, 0x00, 0x24, 0x00, 0x25, 0x00 });
    try std.testing.expectEqual(@as(u64, 0), s.qpack_max_table_capacity);
}

test "settings count is bounded" {
    var payload: std.ArrayListUnmanaged(u8) = .empty;
    defer payload.deinit(std.testing.allocator);
    for (0..128) |index| {
        try varint.append(&payload, std.testing.allocator, 0x21 + index);
        try varint.append(&payload, std.testing.allocator, 0);
    }
    _ = try parseSettings(payload.items);

    try varint.append(&payload, std.testing.allocator, 0x21 + 128);
    try varint.append(&payload, std.testing.allocator, 0);
    try std.testing.expectError(error.SettingsError, parseSettings(payload.items));
}

test "a repeated unknown setting is an error" {
    try std.testing.expectError(error.SettingsError, parseSettings(&.{ 0x21, 0x00, 0x21, 0x01 }));
}

test "a reserved HTTP/2 setting id is a connection error" {
    // 0x02-0x05 are reserved in HTTP/3 and MUST be rejected (RFC 9114 7.2.4.1).
    for ([_]u8{ 0x02, 0x03, 0x04, 0x05 }) |id| {
        try std.testing.expectError(error.SettingsError, parseSettings(&.{ id, 0x00 }));
    }
}
