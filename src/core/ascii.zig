//! Small ASCII helpers shared by the read and write paths: case-insensitive
//! field-name comparison, OWS trimming, and overflow-safe decimal parsing. Kept
//! as a leaf module (only `tables.zig` and `std`) so both directions fold case
//! and frame lengths identically.

const std = @import("std");
const tables = @import("tables.zig");

/// Case-insensitive ASCII compare, folding A-Z via the `to_lower` table. Used to
/// match field-names and tokens, which HTTP treats case-insensitively.
pub fn eqIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (tables.to_lower[x] != tables.to_lower[y]) return false;
    return true;
}

/// Strip leading and trailing OWS (SP / HTAB) from a field-value (RFC 9110 5.6.3).
pub fn trimOws(s: []const u8) []const u8 {
    var start: usize = 0;
    var end = s.len;
    while (start < end and (s[start] == ' ' or s[start] == '\t')) start += 1;
    while (end > start and (s[end - 1] == ' ' or s[end - 1] == '\t')) end -= 1;
    return s[start..end];
}

/// Parse a base-10 unsigned integer, rejecting (returning null) an empty string,
/// any non-digit byte, or a value that overflows `T`. The overflow-safe form used
/// for Content-Length so a 30-nines length can never wrap to a small body size.
pub fn parseDecimal(comptime T: type, s: []const u8) ?T {
    if (s.len == 0) return null;
    var n: T = 0;
    for (s) |ch| {
        if (ch < '0' or ch > '9') return null;
        n = std.math.mul(T, n, 10) catch return null;
        n = std.math.add(T, n, ch - '0') catch return null;
    }
    return n;
}

test "eqIgnoreCase folds case" {
    try std.testing.expect(eqIgnoreCase("Connection", "connection"));
    try std.testing.expect(eqIgnoreCase("HEAD", "head"));
    try std.testing.expect(!eqIgnoreCase("close", "keep-alive"));
    try std.testing.expect(!eqIgnoreCase("a", "ab"));
}

test "trimOws strips SP and HTAB" {
    try std.testing.expectEqualStrings("x", trimOws(" \tx\t "));
    try std.testing.expectEqualStrings("a b", trimOws("  a b  "));
    try std.testing.expectEqualStrings("", trimOws(" \t \t"));
    try std.testing.expectEqualStrings("y", trimOws("y"));
}

test "parseDecimal accepts digits and rejects bad/overflow" {
    try std.testing.expectEqual(@as(?u64, 42), parseDecimal(u64, "42"));
    try std.testing.expectEqual(@as(?u64, 0), parseDecimal(u64, "0"));
    try std.testing.expectEqual(@as(?u64, null), parseDecimal(u64, ""));
    try std.testing.expectEqual(@as(?u64, null), parseDecimal(u64, "12a"));
    try std.testing.expectEqual(@as(?u64, null), parseDecimal(u64, "99999999999999999999999999999"));
}
