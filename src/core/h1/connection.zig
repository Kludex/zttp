//! Connection-level signals derived from a parsed HTTP/1.1 head: whether the
//! peer wants the connection closed, whether it is requesting a protocol
//! upgrade, and whether it expects an interim 100-continue. These mirror the
//! decisions an integrator (e.g. a server loop) must make per message, computed
//! once from headers the reader has already parsed rather than re-scanned by the
//! caller.

const std = @import("std");
const ascii = @import("../ascii.zig");
const events = @import("../events.zig");

const Header = events.Header;
const eqIgnoreCase = ascii.eqIgnoreCase;
const trimOws = ascii.trimOws;

/// True if any comma-separated token in `value` equals `token` (case-insensitive,
/// surrounding whitespace ignored). Used for the `Connection` header's token list.
fn listContains(value: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |raw| {
        if (eqIgnoreCase(trimOws(raw), token)) return true;
    }
    return false;
}

/// Whether a `Connection` header carries the `close` token, across any number of
/// `Connection` field-lines. Applies to a head in either direction: a peer's, or
/// one the caller is about to serialize.
pub fn connectionHasClose(headers: []const Header) bool {
    for (headers) |h| {
        if (eqIgnoreCase(h.name, "connection") and listContains(h.value, "close")) return true;
    }
    return false;
}

/// Whether the request `Connection` header carries the `keep-alive` token.
fn connectionHasKeepAlive(headers: []const Header) bool {
    for (headers) |h| {
        if (eqIgnoreCase(h.name, "connection") and listContains(h.value, "keep-alive")) return true;
    }
    return false;
}

/// Whether the connection must close after this message: an explicit
/// `Connection: close`, or HTTP/1.0 without an explicit `Connection: keep-alive`
/// (RFC 9112 9.3). `http_version` is the bare number, e.g. "1.1" / "1.0".
pub fn shouldClose(http_version: []const u8, headers: []const Header) bool {
    if (connectionHasClose(headers)) return true;
    if (eqIgnoreCase(http_version, "1.0")) return !connectionHasKeepAlive(headers);
    return false;
}

/// The `Upgrade` header value iff the `Connection` header lists the `upgrade`
/// token (RFC 9110 7.8); otherwise null. The integrator compares it to e.g.
/// "websocket".
pub fn upgrade(headers: []const Header) ?[]const u8 {
    var has_upgrade_token = false;
    var upgrade_value: ?[]const u8 = null;
    for (headers) |h| {
        if (eqIgnoreCase(h.name, "connection")) {
            if (listContains(h.value, "upgrade")) has_upgrade_token = true;
        } else if (eqIgnoreCase(h.name, "upgrade")) {
            upgrade_value = h.value;
        }
    }
    return if (has_upgrade_token) upgrade_value else null;
}

/// Whether the request carries `Expect: 100-continue` (RFC 9110 10.1.1).
pub fn expectsContinue(headers: []const Header) bool {
    for (headers) |h| {
        if (eqIgnoreCase(h.name, "expect") and eqIgnoreCase(trimOws(h.value), "100-continue")) return true;
    }
    return false;
}

const t = std.testing;

test "shouldClose: explicit close" {
    const h = [_]Header{.{ .name = "Connection", .value = "close" }};
    try t.expect(shouldClose("1.1", &h));
}

test "shouldClose: keep-alive default for 1.1" {
    const h = [_]Header{.{ .name = "Host", .value = "x" }};
    try t.expect(!shouldClose("1.1", &h));
}

test "shouldClose: 1.0 closes by default" {
    const h = [_]Header{.{ .name = "Host", .value = "x" }};
    try t.expect(shouldClose("1.0", &h));
}

test "shouldClose: 1.0 with keep-alive stays open" {
    const h = [_]Header{.{ .name = "Connection", .value = "keep-alive" }};
    try t.expect(!shouldClose("1.0", &h));
}

test "shouldClose: token in a list" {
    const h = [_]Header{.{ .name = "Connection", .value = "keep-alive, close" }};
    try t.expect(shouldClose("1.1", &h));
}

test "upgrade: websocket" {
    const h = [_]Header{
        .{ .name = "Connection", .value = "Upgrade" },
        .{ .name = "Upgrade", .value = "websocket" },
    };
    try t.expectEqualStrings("websocket", upgrade(&h).?);
}

test "upgrade: header present but not in Connection token list" {
    const h = [_]Header{.{ .name = "Upgrade", .value = "websocket" }};
    try t.expect(upgrade(&h) == null);
}

test "upgrade: Connection lists upgrade but no Upgrade header" {
    const h = [_]Header{.{ .name = "Connection", .value = "upgrade" }};
    try t.expect(upgrade(&h) == null);
}

test "expectsContinue" {
    const h = [_]Header{.{ .name = "Expect", .value = "100-continue" }};
    try t.expect(expectsContinue(&h));
    const h2 = [_]Header{.{ .name = "Expect", .value = "100-Continue" }};
    try t.expect(expectsContinue(&h2));
    const h3 = [_]Header{.{ .name = "Host", .value = "x" }};
    try t.expect(!expectsContinue(&h3));
}
