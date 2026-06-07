//! The HPACK static table (RFC 7541 Appendix A): 61 predefined header entries,
//! indexed 1..61. Stored as comptime literals with static lifetime, so a lookup
//! returns zero-copy slices that never move - exactly like tables.zig's char
//! classes. Index 0 is invalid (the index space starts at 1).

const std = @import("std");

pub const Entry = struct { name: []const u8, value: []const u8 };

pub const LENGTH: usize = 61;

pub const TABLE = [LENGTH]Entry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

/// Look up a 1-based static index, or null if out of range. The returned slices
/// have static lifetime.
pub fn lookup(index: usize) ?Entry {
    if (index < 1 or index > LENGTH) return null;
    return TABLE[index - 1];
}

const testing = std.testing;

test "static table has exactly 61 entries" {
    try testing.expectEqual(@as(usize, 61), TABLE.len);
}

test "lookup resolves known indices to RFC 7541 values" {
    try testing.expectEqualStrings(":authority", lookup(1).?.name);
    try testing.expectEqualStrings("GET", lookup(2).?.value);
    try testing.expectEqualStrings("POST", lookup(3).?.value);
    try testing.expectEqualStrings(":status", lookup(8).?.name);
    try testing.expectEqualStrings("200", lookup(8).?.value);
    try testing.expectEqualStrings("accept-encoding", lookup(16).?.name);
    try testing.expectEqualStrings("gzip, deflate", lookup(16).?.value);
    try testing.expectEqualStrings("www-authenticate", lookup(61).?.name);
}

test "lookup rejects out-of-range indices" {
    try testing.expectEqual(@as(?Entry, null), lookup(0));
    try testing.expectEqual(@as(?Entry, null), lookup(62));
}
