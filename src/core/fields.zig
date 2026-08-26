//! RFC 9110 field validation shared by HTTP/2 and HTTP/3 (RFC 9114 4.2 inherits
//! the HTTP/2 rules), so every path agrees on which field names and
//! connection-specific fields are legal. The value-body check intentionally lives
//! in each path: the read side (`validValue`) follows RFC 9110 field-vchar and
//! allows inner HTAB, while the write side is stricter and rejects it.

const std = @import("std");
const ascii = @import("ascii.zig");
const tables = @import("tables.zig");

/// Return whether `value` is a non-empty RFC 9110 token.
pub fn isValidToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |ch| {
        if (!tables.is_tchar[ch]) return false;
    }
    return true;
}

/// A valid HTTP/2 field name: a non-empty RFC 9110 token (so no SP, NUL, ':',
/// or other separators) with no uppercase ASCII (RFC 9113 8.2.1). `:` is
/// excluded here, so this is only applied to regular (non-pseudo) names.
pub fn isValidFieldName(name: []const u8) bool {
    if (!isValidToken(name)) return false;
    for (name) |ch| {
        if (ch >= 'A' and ch <= 'Z') return false;
    }
    return true;
}

/// A legal field value (RFC 9113 8.2.1): no CR/LF/NUL or other control and no
/// DEL (obs-text 0x80-0xFF and inner SP/HTAB are allowed), and no leading or
/// trailing whitespace. This is the read-side rule; the write side is stricter.
pub fn validValue(value: []const u8) bool {
    for (value) |ch| {
        if (!tables.is_field_vchar[ch]) return false;
    }
    if (value.len > 0) {
        const first = value[0];
        const last = value[value.len - 1];
        if (first == ' ' or first == '\t' or last == ' ' or last == '\t') return false;
    }
    return true;
}

/// The connection-specific fields forbidden in HTTP/2 (RFC 9113 8.2.2).
pub fn isConnectionSpecific(name: []const u8) bool {
    const forbidden = [_][]const u8{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" };
    for (forbidden) |f| {
        if (std.mem.eql(u8, name, f)) return true;
    }
    return false;
}

/// Return whether a field may appear in a trailer section (RFC 9110 6.5.1).
pub fn trailerFieldAllowed(name: []const u8) bool {
    inline for (.{
        "content-length",
        "transfer-encoding",
        "trailer",
        "host",
        "connection",
        "upgrade",
        "te",
        "content-encoding",
        "content-type",
        "content-range",
    }) |forbidden| {
        if (ascii.eqIgnoreCase(name, forbidden)) return false;
    }
    return true;
}

test "trailerFieldAllowed rejects framing, routing, and payload metadata" {
    for ([_][]const u8{
        "content-length",
        "transfer-encoding",
        "trailer",
        "host",
        "connection",
        "upgrade",
        "te",
        "content-encoding",
        "content-type",
        "content-range",
    }) |name| {
        try std.testing.expect(!trailerFieldAllowed(name));
    }
    try std.testing.expect(trailerFieldAllowed("x-checksum"));
}

test "isValidFieldName accepts lowercase token, rejects uppercase and empty" {
    try std.testing.expect(isValidFieldName("content-type"));
    try std.testing.expect(!isValidFieldName("Content-Type"));
    try std.testing.expect(!isValidFieldName(""));
    try std.testing.expect(!isValidFieldName("bad name"));
}

test "validValue rejects leading space, control, and DEL" {
    try std.testing.expect(validValue("text/plain"));
    try std.testing.expect(!validValue(" x"));
    try std.testing.expect(!validValue("x "));
    try std.testing.expect(!validValue("a\rb"));
    try std.testing.expect(!validValue("a\x00b"));
    try std.testing.expect(!validValue("a\x7Fb"));
}

test "isConnectionSpecific detects each forbidden name" {
    for ([_][]const u8{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" }) |name| {
        try std.testing.expect(isConnectionSpecific(name));
    }
    try std.testing.expect(!isConnectionSpecific("content-type"));
}
