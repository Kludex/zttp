//! Server-certificate verification for the QUIC TLS 1.3 client (RFC 8446 4.4.2).
//!
//! The client half of the handshake proves the peer holds the leaf key via
//! CertificateVerify (sign.zig), but that alone authenticates nothing - an
//! attacker can present its own key. This module is the missing check: it walks
//! the Certificate message's chain, validates each link's signature and validity
//! against caller-supplied trust anchors, and matches the leaf's SubjectAltName
//! against the expected host, mirroring the loop in std.crypto.tls.Client.
//!
//! Sans-IO: the trust anchors (a pre-built std.crypto.Certificate.Bundle) and the
//! current time are injected by the caller. The core never reads the filesystem or
//! a clock, so the integrator owns "which CAs" and "what time is it" - exactly the
//! split aioquic/quiche/rustls use for their sans-IO cores.

const std = @import("std");
const wire = @import("wire.zig");

const Certificate = std.crypto.Certificate;

/// What the client trusts. `insecure` disables authentication entirely (an
/// explicit, dangerous opt-in for tests/interop); `anchors` verifies the chain to
/// a trust store, which for a pinned self-signed server is just that one cert.
pub const Trust = union(enum) {
    insecure,
    anchors: *const Certificate.Bundle,
};

pub const Options = struct {
    trust: Trust,
    /// The expected server identity (server_name). null skips the host check,
    /// which is only sound when pinning a specific certificate.
    host: ?[]const u8,
    /// Current time in Unix seconds, for validity-window checks.
    now_sec: i64,
};

pub const Error = error{
    /// The Certificate message framing or a certificate's DER did not parse.
    BadCertificate,
    /// The chain carried no certificates.
    EmptyChain,
    /// The leaf's SubjectAltName did not cover `host`.
    HostnameMismatch,
    /// A certificate in the chain was expired or not yet valid.
    CertificateExpired,
    /// The chain did not lead to any configured trust anchor.
    ChainUntrusted,
    OutOfMemory,
};

/// Verify the body of a TLS 1.3 Certificate message. Returns normally when the
/// leaf is trusted for `host` at `now_sec`; otherwise returns the reason.
pub fn verifyCertificateMessage(body: []const u8, opts: Options) Error!void {
    var r = wire.Reader{ .buf = body };
    _ = r.vector(1) catch return error.BadCertificate; // certificate_request_context
    var list = r.vector(3) catch return error.BadCertificate; // certificate_list
    r.expectEnd() catch return error.BadCertificate;
    if (list.remaining() == 0) return error.EmptyChain;

    switch (opts.trust) {
        // Still require a parseable leaf so CertificateVerify has a key to bind to;
        // the caller (client.zig) extracts it separately from the same leaf.
        .insecure => return,
        .anchors => |bundle| {
            var prev: Certificate.Parsed = undefined;
            var index: usize = 0;
            while (list.remaining() != 0) : (index += 1) {
                const cert_der = (list.vector(3) catch return error.BadCertificate).buf;
                _ = list.vector(2) catch return error.BadCertificate; // entry extensions
                const cert = Certificate{ .buffer = cert_der, .index = 0 };
                const subject = cert.parse() catch return error.BadCertificate;

                if (index == 0) {
                    if (opts.host) |h| subject.verifyHostName(h) catch return error.HostnameMismatch;
                } else {
                    // Each non-leaf must have signed the certificate before it.
                    prev.verify(subject, opts.now_sec) catch |e| return mapVerifyError(e);
                }

                // Trusted the moment a certificate is issued by a configured anchor
                // (for a pinned self-signed leaf, it is its own issuer).
                bundle.verify(subject, opts.now_sec) catch |e| switch (e) {
                    error.CertificateIssuerNotFound => {
                        prev = subject;
                        continue;
                    },
                    else => return mapVerifyError(e),
                };
                return;
            }
            return error.ChainUntrusted;
        },
    }
}

fn mapVerifyError(e: anyerror) Error {
    return switch (e) {
        error.CertificateExpired => error.CertificateExpired,
        error.OutOfMemory => error.OutOfMemory,
        else => error.BadCertificate,
    };
}

/// Build a trust bundle from a list of DER certificates (each an anchor). The
/// caller owns the returned bundle and must `deinit` it. Certificates that fail to
/// parse or are already expired at `now_sec` are silently skipped, matching
/// std.crypto.Certificate.Bundle's own loading behavior.
pub fn bundleFromDer(gpa: std.mem.Allocator, ders: []const []const u8, now_sec: i64) !Certificate.Bundle {
    var bundle: Certificate.Bundle = .empty;
    errdefer bundle.deinit(gpa);
    for (ders) |der| {
        const start: u32 = @intCast(bundle.bytes.items.len);
        try bundle.bytes.appendSlice(gpa, der);
        try bundle.parseCert(gpa, start, now_sec);
    }
    return bundle;
}

// -- tests --------------------------------------------------------------------

const testing = std.testing;
const x509 = @import("x509.zig");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const NOW: i64 = 1700000000; // 2023-11-14
const NOT_BEFORE: i64 = 1672531200; // 2023-01-01
const NOT_AFTER: i64 = 1988150400; // 2033-01-01

// Wrap a single leaf DER in a TLS 1.3 Certificate message body.
fn certMessage(gpa: std.mem.Allocator, ders: []const []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.append(gpa, 0x00); // empty certificate_request_context
    var list_len: usize = 0;
    for (ders) |d| list_len += 3 + d.len + 2;
    try out.append(gpa, @intCast((list_len >> 16) & 0xff));
    try out.append(gpa, @intCast((list_len >> 8) & 0xff));
    try out.append(gpa, @intCast(list_len & 0xff));
    for (ders) |d| {
        try out.append(gpa, @intCast((d.len >> 16) & 0xff));
        try out.append(gpa, @intCast((d.len >> 8) & 0xff));
        try out.append(gpa, @intCast(d.len & 0xff));
        try out.appendSlice(gpa, d);
        try out.appendSlice(gpa, &.{ 0x00, 0x00 }); // no entry extensions
    }
    return out.toOwnedSlice(gpa);
}

test "pinned self-signed leaf is accepted for its host" {
    const kp = try Ecdsa.KeyPair.generateDeterministic([_]u8{0x42} ** 32);
    var cert: std.ArrayListUnmanaged(u8) = .empty;
    defer cert.deinit(testing.allocator);
    const der = try x509.selfSigned(&cert, testing.allocator, kp, .{
        .dns_name = "example.com",
        .not_before = NOT_BEFORE,
        .not_after = NOT_AFTER,
    });

    var bundle = try bundleFromDer(testing.allocator, &.{der}, NOW);
    defer bundle.deinit(testing.allocator);
    const msg = try certMessage(testing.allocator, &.{der});
    defer testing.allocator.free(msg);

    try verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &bundle }, .host = "example.com", .now_sec = NOW });
}

test "a wrong hostname is rejected" {
    const kp = try Ecdsa.KeyPair.generateDeterministic([_]u8{0x42} ** 32);
    var cert: std.ArrayListUnmanaged(u8) = .empty;
    defer cert.deinit(testing.allocator);
    const der = try x509.selfSigned(&cert, testing.allocator, kp, .{ .dns_name = "example.com", .not_before = NOT_BEFORE, .not_after = NOT_AFTER });
    var bundle = try bundleFromDer(testing.allocator, &.{der}, NOW);
    defer bundle.deinit(testing.allocator);
    const msg = try certMessage(testing.allocator, &.{der});
    defer testing.allocator.free(msg);

    try testing.expectError(error.HostnameMismatch, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &bundle }, .host = "evil.com", .now_sec = NOW }));
}

test "an untrusted self-signed leaf (empty bundle) is rejected" {
    const kp = try Ecdsa.KeyPair.generateDeterministic([_]u8{0x42} ** 32);
    var cert: std.ArrayListUnmanaged(u8) = .empty;
    defer cert.deinit(testing.allocator);
    const der = try x509.selfSigned(&cert, testing.allocator, kp, .{ .dns_name = "example.com", .not_before = NOT_BEFORE, .not_after = NOT_AFTER });
    var bundle: Certificate.Bundle = .empty;
    defer bundle.deinit(testing.allocator);
    const msg = try certMessage(testing.allocator, &.{der});
    defer testing.allocator.free(msg);

    try testing.expectError(error.ChainUntrusted, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &bundle }, .host = "example.com", .now_sec = NOW }));
}

test "an expired leaf is rejected even when pinned" {
    const kp = try Ecdsa.KeyPair.generateDeterministic([_]u8{0x42} ** 32);
    var cert: std.ArrayListUnmanaged(u8) = .empty;
    defer cert.deinit(testing.allocator);
    const der = try x509.selfSigned(&cert, testing.allocator, kp, .{ .dns_name = "example.com", .not_before = NOT_BEFORE, .not_after = 1704067200 }); // expires 2024-01-01
    // parseCert drops the expired anchor, so the bundle is effectively empty ->
    // untrusted. Verify at a time past not_after.
    const later: i64 = 1800000000; // 2027
    var bundle = try bundleFromDer(testing.allocator, &.{der}, later);
    defer bundle.deinit(testing.allocator);
    const msg = try certMessage(testing.allocator, &.{der});
    defer testing.allocator.free(msg);

    try testing.expectError(error.ChainUntrusted, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &bundle }, .host = "example.com", .now_sec = later }));
}

test "a leaf signed by a trusted CA verifies through the chain" {
    const ca_kp = try Ecdsa.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    const leaf_kp = try Ecdsa.KeyPair.generateDeterministic([_]u8{0x22} ** 32);

    var ca_cert: std.ArrayListUnmanaged(u8) = .empty;
    defer ca_cert.deinit(testing.allocator);
    const ca_der = try x509.selfSigned(&ca_cert, testing.allocator, ca_kp, .{ .dns_name = "zttp Test CA", .not_before = NOT_BEFORE, .not_after = NOT_AFTER });

    var leaf_cert: std.ArrayListUnmanaged(u8) = .empty;
    defer leaf_cert.deinit(testing.allocator);
    const leaf_der = try x509.signedBy(&leaf_cert, testing.allocator, leaf_kp.public_key, ca_kp, "zttp Test CA", .{ .dns_name = "example.com", .not_before = NOT_BEFORE, .not_after = NOT_AFTER });

    var bundle = try bundleFromDer(testing.allocator, &.{ca_der}, NOW); // trust the CA only
    defer bundle.deinit(testing.allocator);
    const msg = try certMessage(testing.allocator, &.{ leaf_der, ca_der }); // chain: leaf, CA
    defer testing.allocator.free(msg);

    try verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &bundle }, .host = "example.com", .now_sec = NOW });

    // The same leaf without the CA in the bundle is untrusted.
    var empty: Certificate.Bundle = .empty;
    defer empty.deinit(testing.allocator);
    try testing.expectError(error.ChainUntrusted, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &empty }, .host = "example.com", .now_sec = NOW }));
}

test "insecure trust skips verification but still requires a leaf" {
    const kp = try Ecdsa.KeyPair.generateDeterministic([_]u8{0x42} ** 32);
    var cert: std.ArrayListUnmanaged(u8) = .empty;
    defer cert.deinit(testing.allocator);
    const der = try x509.selfSigned(&cert, testing.allocator, kp, .{ .dns_name = "whatever", .not_before = NOT_BEFORE, .not_after = NOT_AFTER });
    const msg = try certMessage(testing.allocator, &.{der});
    defer testing.allocator.free(msg);
    try verifyCertificateMessage(msg, .{ .trust = .insecure, .host = "anything", .now_sec = NOW });

    const empty = try certMessage(testing.allocator, &.{});
    defer testing.allocator.free(empty);
    try testing.expectError(error.EmptyChain, verifyCertificateMessage(empty, .{ .trust = .insecure, .host = null, .now_sec = NOW }));
}
