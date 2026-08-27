//! Connection-level signals derived from a parsed HTTP/1.1 head: whether the
//! peer wants the connection closed, whether it is requesting a protocol
//! upgrade, and whether it expects an interim 100-continue. These mirror the
//! decisions an integrator (e.g. a server loop) must make per message, computed
//! once from headers the reader has already parsed rather than re-scanned by the
//! caller.

const std = @import("std");
const ascii = @import("../ascii.zig");
const events = @import("../events.zig");
const framing = @import("framing.zig");
const ParseError = @import("../errors.zig").ParseError;

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

/// All semantics derived from an HTTP/1 head while its fields are parsed. The
/// reader feeds each header exactly once, then finalizes framing and connection
/// state after parsing the request/status line.
pub const HeadSemantics = struct {
    framing: framing.Analyzer = .{},
    has_close: bool = false,
    has_keep_alive: bool = false,
    has_upgrade_token: bool = false,
    upgrade_value: ?[]const u8 = null,
    expect_continue: bool = false,
    host_count: usize = 0,

    pub fn add(self: *HeadSemantics, h: Header) ParseError!void {
        try self.framing.add(h);

        if (eqIgnoreCase(h.name, "host")) {
            self.host_count += 1;
        } else if (eqIgnoreCase(h.name, "connection")) {
            var it = std.mem.splitScalar(u8, h.value, ',');
            while (it.next()) |raw| {
                const token = trimOws(raw);
                if (eqIgnoreCase(token, "close")) {
                    self.has_close = true;
                } else if (eqIgnoreCase(token, "keep-alive")) {
                    self.has_keep_alive = true;
                } else if (eqIgnoreCase(token, "upgrade")) {
                    self.has_upgrade_token = true;
                }
            }
        } else if (eqIgnoreCase(h.name, "upgrade")) {
            self.upgrade_value = h.value;
        } else if (eqIgnoreCase(h.name, "expect") and listContains(h.value, "100-continue")) {
            self.expect_continue = true;
        }
    }

    pub fn shouldClose(self: HeadSemantics, http_version: []const u8) bool {
        if (self.has_close) return true;
        return eqIgnoreCase(http_version, "1.0") and !self.has_keep_alive;
    }

    /// Reject HTTP/1.1 requests without exactly one Host field (RFC 9112 3.2).
    pub fn validateRequestHost(self: HeadSemantics, http_version: []const u8) ParseError!void {
        if (eqIgnoreCase(http_version, "1.1") and self.host_count != 1) return error.InvalidHeader;
    }

    pub fn upgrade(self: HeadSemantics) ?[]const u8 {
        return if (self.has_upgrade_token) self.upgrade_value else null;
    }
};

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
/// "websocket". This standalone scan remains part of the public core API for
/// integrations that receive an already-complete header slice instead of
/// feeding fields through `HeadSemantics` while parsing.
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

/// Whether the request carries `Expect: 100-continue` (RFC 9110 10.1.1). This
/// standalone scan remains part of the public core API for integrations that
/// did not build `HeadSemantics` incrementally.
pub fn expectsContinue(headers: []const Header) bool {
    for (headers) |h| {
        if (eqIgnoreCase(h.name, "expect") and listContains(h.value, "100-continue")) return true;
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
    const h3 = [_]Header{.{ .name = "Expect", .value = "something, 100-Continue" }};
    try t.expect(expectsContinue(&h3));
    const h4 = [_]Header{.{ .name = "Host", .value = "x" }};
    try t.expect(!expectsContinue(&h4));
}

test "head semantics collects framing and connection metadata in one pass" {
    const headers = [_]Header{
        .{ .name = "Content-Length", .value = "5" },
        .{ .name = "Connection", .value = "keep-alive, Upgrade" },
        .{ .name = "Upgrade", .value = "websocket" },
        .{ .name = "Expect", .value = "something, 100-Continue" },
    };
    var semantics = HeadSemantics{};
    for (headers) |h| try semantics.add(h);

    try t.expectEqual(@as(u64, 5), (try semantics.framing.finish(.{})).content_length);
    try t.expect(!semantics.shouldClose("1.0"));
    try t.expectEqualStrings("websocket", semantics.upgrade().?);
    try t.expect(semantics.expect_continue);
}
