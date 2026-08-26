//! The QPACK static table (RFC 9204 appendix A): 99 fixed (name, value) entries
//! a field line can reference by index instead of spelling out. Distinct from
//! HPACK's 61-entry table - different entries and order - so it lives here rather
//! than being shared with h2/hpack. Pure leaf data.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Entry = struct { name: []const u8, value: []const u8 };

/// RFC 9204 appendix A, indices 0-98.
pub const TABLE = [_]Entry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":path", .value = "/" },
    .{ .name = "age", .value = "0" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-length", .value = "0" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = ":method", .value = "CONNECT" },
    .{ .name = ":method", .value = "DELETE" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "HEAD" },
    .{ .name = ":method", .value = "OPTIONS" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":method", .value = "PUT" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "103" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "503" },
    .{ .name = "accept", .value = "*/*" },
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
    .{ .name = "accept-ranges", .value = "bytes" },
    .{ .name = "access-control-allow-headers", .value = "cache-control" },
    .{ .name = "access-control-allow-headers", .value = "content-type" },
    .{ .name = "access-control-allow-origin", .value = "*" },
    .{ .name = "cache-control", .value = "max-age=0" },
    .{ .name = "cache-control", .value = "max-age=2592000" },
    .{ .name = "cache-control", .value = "max-age=604800" },
    .{ .name = "cache-control", .value = "no-cache" },
    .{ .name = "cache-control", .value = "no-store" },
    .{ .name = "cache-control", .value = "public, max-age=31536000" },
    .{ .name = "content-encoding", .value = "br" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "content-type", .value = "application/dns-message" },
    .{ .name = "content-type", .value = "application/javascript" },
    .{ .name = "content-type", .value = "application/json" },
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
    .{ .name = "content-type", .value = "image/gif" },
    .{ .name = "content-type", .value = "image/jpeg" },
    .{ .name = "content-type", .value = "image/png" },
    .{ .name = "content-type", .value = "text/css" },
    .{ .name = "content-type", .value = "text/html; charset=utf-8" },
    .{ .name = "content-type", .value = "text/plain" },
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" },
    .{ .name = "range", .value = "bytes=0-" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" },
    .{ .name = "vary", .value = "accept-encoding" },
    .{ .name = "vary", .value = "origin" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "x-xss-protection", .value = "1; mode=block" },
    .{ .name = ":status", .value = "100" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "302" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "403" },
    .{ .name = ":status", .value = "421" },
    .{ .name = ":status", .value = "425" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "access-control-allow-credentials", .value = "FALSE" },
    .{ .name = "access-control-allow-credentials", .value = "TRUE" },
    .{ .name = "access-control-allow-headers", .value = "*" },
    .{ .name = "access-control-allow-methods", .value = "get" },
    .{ .name = "access-control-allow-methods", .value = "get, post, options" },
    .{ .name = "access-control-allow-methods", .value = "options" },
    .{ .name = "access-control-expose-headers", .value = "content-length" },
    .{ .name = "access-control-request-headers", .value = "content-type" },
    .{ .name = "access-control-request-method", .value = "get" },
    .{ .name = "access-control-request-method", .value = "post" },
    .{ .name = "alt-svc", .value = "clear" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" },
    .{ .name = "early-data", .value = "1" },
    .{ .name = "expect-ct", .value = "" },
    .{ .name = "forwarded", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "origin", .value = "" },
    .{ .name = "purpose", .value = "prefetch" },
    .{ .name = "server", .value = "" },
    .{ .name = "timing-allow-origin", .value = "*" },
    .{ .name = "upgrade-insecure-requests", .value = "1" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "x-forwarded-for", .value = "" },
    .{ .name = "x-frame-options", .value = "deny" },
    .{ .name = "x-frame-options", .value = "sameorigin" },
};

pub fn get(index: u64) ?Entry {
    if (index >= TABLE.len) return null;
    return TABLE[@intCast(index)];
}

/// The index whose name AND value both equal `name`/`value`, for an indexed
/// field line, or null if none. The lowest matching index wins.
pub fn nameValueIndex(name: []const u8, value: []const u8) ?usize {
    for (TABLE, 0..) |e, i| {
        if (std.mem.eql(u8, e.name, name) and std.mem.eql(u8, e.value, value)) return i;
    }
    return null;
}

/// The index whose name equals `name`, for a literal with a static name
/// reference, or null if none. The lowest matching index wins.
pub fn nameIndex(name: []const u8) ?usize {
    for (TABLE, 0..) |e, i| {
        if (std.mem.eql(u8, e.name, name)) return i;
    }
    return null;
}

test "static table matches RFC 9204 appendix A" {
    // Entries are serialized in index order as name + NUL + value + NUL.
    const expected = [_]u8{
        0x2f, 0x57, 0x57, 0xc3, 0x7c, 0xec, 0x2b, 0xf4,
        0x6c, 0x4d, 0x9d, 0x85, 0x69, 0xfc, 0x52, 0xa3,
        0x89, 0x41, 0x42, 0xfe, 0x31, 0x1d, 0x07, 0xdc,
        0xf6, 0xbd, 0x20, 0xcd, 0x17, 0xf0, 0x4d, 0x3e,
    };
    var hasher = Sha256.init(.{});
    for (TABLE) |entry| {
        hasher.update(entry.name);
        hasher.update(&.{0});
        hasher.update(entry.value);
        hasher.update(&.{0});
    }
    var actual: [Sha256.digest_length]u8 = undefined;
    hasher.final(&actual);

    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "the table has the RFC 9204 appendix A length" {
    try std.testing.expectEqual(@as(usize, 99), TABLE.len);
}

test "known indices resolve" {
    try std.testing.expectEqualStrings(":path", get(1).?.name);
    try std.testing.expectEqualStrings("GET", get(17).?.value);
    try std.testing.expectEqualStrings(":status", get(25).?.name);
    try std.testing.expectEqualStrings("200", get(25).?.value);
    try std.testing.expect(get(99) == null);
}
