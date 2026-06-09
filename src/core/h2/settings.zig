//! HTTP/2 SETTINGS (RFC 9113 6.5): parse a SETTINGS payload into one direction's
//! negotiated parameters and validate each value's range. Pure leaf - the
//! connection layer owns the connection window and applies an INITIAL_WINDOW_SIZE
//! change to per-stream windows; settings.zig only parses and validates.

const std = @import("std");
const constants = @import("constants.zig");

const SettingId = constants.SettingId;

pub const SettingsError = error{
    /// A value out of its defined range (ENABLE_PUSH not 0/1, MAX_FRAME_SIZE
    /// outside [16384, 2^24-1]). Connection error PROTOCOL_ERROR.
    ProtocolError,
    /// INITIAL_WINDOW_SIZE above 2^31-1. Connection error FLOW_CONTROL_ERROR.
    FlowControlError,
    /// Payload length not a multiple of 6. Connection error FRAME_SIZE_ERROR.
    FrameSizeError,
};

/// One direction's settings, seeded with the protocol defaults (RFC 9113 6.5.2).
/// initial_window_size is i32 because it feeds signed per-stream window math;
/// it is never negative here (validated <= 2^31-1) but stream windows can go
/// negative after a reduction.
pub const Settings = struct {
    header_table_size: u32 = constants.DEFAULT_HEADER_TABLE_SIZE,
    enable_push: bool = true,
    max_concurrent_streams: ?u32 = null, // unlimited until advertised
    initial_window_size: i32 = constants.DEFAULT_WINDOW_SIZE,
    max_frame_size: u32 = constants.DEFAULT_FRAME_SIZE,
    max_header_list_size: ?u32 = null, // unlimited until advertised

    /// Apply a validated SETTINGS payload (already length-checked as a multiple
    /// of 6 by frame.checkLength, re-checked here). Unknown ids are ignored.
    /// Returns the new initial_window_size only if it changed, so the caller can
    /// retroactively adjust per-stream windows by the delta (RFC 9113 6.9.2).
    pub fn apply(self: *Settings, payload: []const u8) SettingsError!?i32 {
        if (payload.len % 6 != 0) return error.FrameSizeError;
        var old_initial: ?i32 = null;
        var i: usize = 0;
        while (i < payload.len) : (i += 6) {
            const id = std.mem.readInt(u16, payload[i..][0..2], .big);
            const value = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
            switch (@as(SettingId, @enumFromInt(id))) {
                .header_table_size => self.header_table_size = value,
                .enable_push => {
                    if (value > 1) return error.ProtocolError;
                    self.enable_push = value == 1;
                },
                .max_concurrent_streams => self.max_concurrent_streams = value,
                .initial_window_size => {
                    if (value > @as(u32, @intCast(constants.MAX_WINDOW_SIZE))) return error.FlowControlError;
                    if (old_initial == null) old_initial = self.initial_window_size;
                    self.initial_window_size = @intCast(value);
                },
                .max_frame_size => {
                    if (value < constants.DEFAULT_FRAME_SIZE or value > constants.MAX_FRAME_SIZE_LIMIT) return error.ProtocolError;
                    self.max_frame_size = value;
                },
                .max_header_list_size => self.max_header_list_size = value,
                _ => {}, // unknown setting: ignore (RFC 9113 6.5.2)
            }
        }
        if (old_initial) |old| {
            if (old != self.initial_window_size) return self.initial_window_size - old;
        }
        return null;
    }
};

const testing = std.testing;

fn entry(id: u16, value: u32) [6]u8 {
    var b: [6]u8 = undefined;
    std.mem.writeInt(u16, b[0..2], id, .big);
    std.mem.writeInt(u32, b[2..6], value, .big);
    return b;
}

test "defaults match RFC 9113 6.5.2" {
    const s = Settings{};
    try testing.expectEqual(@as(u32, 4096), s.header_table_size);
    try testing.expect(s.enable_push);
    try testing.expectEqual(@as(?u32, null), s.max_concurrent_streams);
    try testing.expectEqual(@as(i32, 65535), s.initial_window_size);
    try testing.expectEqual(@as(u32, 16384), s.max_frame_size);
}

test "apply updates known settings and ignores unknown ids" {
    var s = Settings{};
    const payload = entry(0x03, 100) ++ entry(0x05, 32768) ++ entry(0xFF, 999);
    _ = try s.apply(&payload);
    try testing.expectEqual(@as(?u32, 100), s.max_concurrent_streams);
    try testing.expectEqual(@as(u32, 32768), s.max_frame_size);
}

test "apply reports the initial-window-size delta" {
    var s = Settings{};
    const delta = try s.apply(&entry(0x04, 100000));
    try testing.expectEqual(@as(?i32, 100000 - 65535), delta);
    try testing.expectEqual(@as(i32, 100000), s.initial_window_size);
}

test "apply rejects enable_push other than 0 or 1" {
    var s = Settings{};
    try testing.expectError(error.ProtocolError, s.apply(&entry(0x02, 2)));
}

test "apply rejects max_frame_size out of range" {
    var s = Settings{};
    try testing.expectError(error.ProtocolError, s.apply(&entry(0x05, 16383))); // below min
    try testing.expectError(error.ProtocolError, s.apply(&entry(0x05, 16777216))); // above max
}

test "apply rejects initial_window_size above 2^31-1" {
    var s = Settings{};
    try testing.expectError(error.FlowControlError, s.apply(&entry(0x04, 0x80000000)));
}

test "apply rejects a payload not a multiple of six" {
    var s = Settings{};
    try testing.expectError(error.FrameSizeError, s.apply(&[_]u8{ 0, 1, 2, 3, 4 }));
}

test "apply accepts the boundary max_frame_size values" {
    var s = Settings{};
    _ = try s.apply(&entry(0x05, 16384));
    try testing.expectEqual(@as(u32, 16384), s.max_frame_size);
    _ = try s.apply(&entry(0x05, 16777215));
    try testing.expectEqual(@as(u32, 16777215), s.max_frame_size);
}
