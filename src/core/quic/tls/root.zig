//! The TLS 1.3 server handshake, sans-IO: a bytes-in/bytes-out state machine
//! driven by QUIC CRYPTO frames (RFC 9001 4). It derives the Handshake and
//! Application packet-protection secrets the QUIC transport installs per space.
//! Aggregates the submodules, pulls their tests, and holds the cross-module
//! integration tests (the ones spanning parse + build + the crypto core) here,
//! since this is the one module that sees the whole codec assembled.

const std = @import("std");

pub const transcript = @import("transcript.zig");
pub const schedule = @import("schedule.zig");
pub const keyshare = @import("keyshare.zig");
pub const sign = @import("sign.zig");
pub const finished = @import("finished.zig");
pub const wire = @import("wire.zig");
pub const extension = @import("extension.zig");
pub const handshake = @import("handshake.zig");
pub const client_hello = @import("client_hello.zig");
pub const client = @import("client.zig");
pub const flight = @import("flight.zig");
pub const server = @import("server.zig");

test {
    _ = transcript;
    _ = schedule;
    _ = keyshare;
    _ = sign;
    _ = finished;
    _ = wire;
    _ = extension;
    _ = handshake;
    _ = client_hello;
    _ = client;
    _ = flight;
    _ = server;
}

// End-to-end codec tests, pinned where possible to the RFC 8448 section 3 trace.
// The RFC trace is TLS-over-TCP, so its ClientHello carries record_size_limit /
// psk_key_exchange_modes instead of the quic_transport_parameters this QUIC server
// requires; we therefore pin the LOAD-BEARING integration values (the published
// x25519 client key_share, which drives the published ECDHE secret) inside a
// QUIC-valid ClientHello, and round-trip the server flight. The crypto-core vectors
// (ECDHE 8bd4054f..., the handshake secrets) are the same ones schedule.zig and
// keyshare.zig already pin, so a green test here proves the codec surfaces byte-exact
// inputs to that validated core.

const testing = std.testing;
const hex = std.fmt.hexToBytes;

// The RFC 8448 section 3 client x25519 public key (its key_share), the same value
// keyshare.zig pins; feeding it to the RFC server private key yields ECDHE 8bd4054f...
const RFC_CLIENT_PUBKEY = "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c";
const RFC_SERVER_PRIVKEY = "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e";
const RFC_ECDHE = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";

/// Build a minimal but fully valid QUIC ClientHello carrying `pubkey` as its
/// x25519 key_share. Offers TLS_AES_128_GCM_SHA256, supported_versions=1.3,
/// supported_groups=x25519, signature_algorithms=ecdsa_secp256r1_sha256, and a
/// quic_transport_parameters - everything the server's policy requires.
fn buildClientHello(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, pubkey: [32]u8) !void {
    return buildClientHelloFull(out, gpa, pubkey, false, &.{});
}

fn buildClientHelloWithExtras(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, pubkey: [32]u8, extras: []const u8) !void {
    return buildClientHelloFull(out, gpa, pubkey, false, extras);
}

fn emitKeyShare(w: wire.Writer, pubkey: [32]u8) !void {
    try w.u16v(0x0033);
    const ks = try w.open(2);
    const ksl = try w.open(2);
    try w.u16v(0x001d);
    const pt = try w.open(2);
    try w.bytes(&pubkey);
    try w.close(pt);
    try w.close(ksl);
    try w.close(ks);
}

fn buildClientHelloFull(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, pubkey: [32]u8, dup_key_share: bool, extras: []const u8) !void {
    const w = wire.Writer{ .out = out, .gpa = gpa };
    try w.u8v(0x01); // client_hello
    const msg = try w.open(3);
    try w.u16v(0x0303); // legacy_version
    try w.bytes(&[_]u8{0x11} ** 32); // random
    try w.u8v(0x00); // legacy_session_id: empty
    const suites = try w.open(2);
    try w.u16v(0x1301); // TLS_AES_128_GCM_SHA256
    try w.close(suites);
    const comp = try w.open(1);
    try w.u8v(0x00); // null compression
    try w.close(comp);
    const exts = try w.open(2);
    // supported_groups = [x25519]
    try w.u16v(0x000a);
    const sg = try w.open(2);
    const sgl = try w.open(2);
    try w.u16v(0x001d);
    try w.close(sgl);
    try w.close(sg);
    // signature_algorithms = [ecdsa_secp256r1_sha256]
    try w.u16v(0x000d);
    const sa = try w.open(2);
    const sal = try w.open(2);
    try w.u16v(0x0403);
    try w.close(sal);
    try w.close(sa);
    // supported_versions = [TLS 1.3]
    try w.u16v(0x002b);
    const sv = try w.open(2);
    const svl = try w.open(1);
    try w.u16v(0x0304);
    try w.close(svl);
    try w.close(sv);
    try emitKeyShare(w, pubkey);
    if (dup_key_share) try emitKeyShare(w, pubkey);
    // quic_transport_parameters: a non-empty body, the realistic case
    try w.u16v(0x0039);
    const qtp = try w.open(2);
    try w.bytes(&[_]u8{ 0x01, 0x02, 0x40, 0x01 });
    try w.close(qtp);
    try w.bytes(extras); // raw extra extension bytes, for adversarial tests
    try w.close(exts);
    try w.close(msg);
}

test "parse surfaces the byte-exact x25519 key_share that drives the RFC ECDHE secret" {
    var pubkey: [32]u8 = undefined;
    _ = try hex(&pubkey, RFC_CLIENT_PUBKEY);
    var buf = std.ArrayListUnmanaged(u8).empty;
    defer buf.deinit(testing.allocator);
    try buildClientHello(&buf, testing.allocator, pubkey);

    const d = try client_hello.parse(buf.items);
    try testing.expectEqual(buf.items.len, d.len);
    try testing.expectEqualSlices(u8, &pubkey, &d.value.client_key_share);
    try testing.expectEqual(@as(u16, 0x001d), d.value.key_share_group);
    // A non-empty quic_transport_parameters body must survive parsing intact.
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x40, 0x01 }, d.value.quic_transport_parameters);

    // The decisive integration check: the parsed key plus the RFC server private
    // key reproduce the published ECDHE secret keyshare/schedule are pinned to.
    var server_sk: [32]u8 = undefined;
    _ = try hex(&server_sk, RFC_SERVER_PRIVKEY);
    const server_kp = keyshare.KeyShare{ .public_key = undefined, .secret_key = server_sk };
    const secret = try server_kp.shared(d.value.client_key_share);
    var want: [32]u8 = undefined;
    _ = try hex(&want, RFC_ECDHE);
    try testing.expectEqualSlices(u8, &want, &secret);
}

test "build emits a parseable ServerHello whose key_share round-trips to a shared secret" {
    var client_pub: [32]u8 = undefined;
    _ = try hex(&client_pub, RFC_CLIENT_PUBKEY);

    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(testing.allocator);
    var t = transcript.Transcript{};

    const signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32);
    const cfg = flight.Config{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = signer,
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &[_]u8{ 0x00, 0x01 },
    };
    const view = flight.ClientHelloView{ .legacy_session_id = &.{}, .client_key_share = client_pub };
    const built = try flight.build(&out, testing.allocator, &t, view, cfg);

    // The first emitted message is a ServerHello with both required extensions.
    const sh = handshake.peek(out.items).?;
    try testing.expectEqual(handshake.MsgType.server_hello, sh.msg_type);

    // The server's ephemeral public key, recovered from the ServerHello, must reach
    // the same ECDHE secret as the server computed against the client key.
    const server_ks = try keyshare.KeyShare.ephemeral(cfg.ephemeral_seed);
    const from_server = try server_ks.shared(client_pub);
    // The handshake secrets are non-empty (schedule ran) and the application secrets
    // differ from them (a later derivation point).
    try testing.expect(!std.mem.eql(u8, &built.handshake_secrets.server, &built.application_secrets.server));
    try testing.expectEqual(@as(usize, 32), from_server.len);
}

test "a ClientHello lacking supported_versions is rejected (anti-downgrade)" {
    var pubkey: [32]u8 = undefined;
    _ = try hex(&pubkey, RFC_CLIENT_PUBKEY);
    var buf = std.ArrayListUnmanaged(u8).empty;
    defer buf.deinit(testing.allocator);
    try buildClientHello(&buf, testing.allocator, pubkey);
    // Corrupt the supported_versions extension type (0x002b -> 0x9999) so TLS 1.3
    // is never signalled; the parser must reject the downgrade. The extension on the
    // wire is 00 2b 00 03 02 03 04 (type, len 3, list len 2, [TLS 1.3]).
    const idx = std.mem.indexOf(u8, buf.items, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 }).?;
    buf.items[idx] = 0x99;
    buf.items[idx + 1] = 0x99;
    try testing.expectError(error.EncodingError, client_hello.parse(buf.items));
}

test "a duplicate key_share extension is rejected" {
    var pubkey: [32]u8 = undefined;
    _ = try hex(&pubkey, RFC_CLIENT_PUBKEY);
    var buf = std.ArrayListUnmanaged(u8).empty;
    defer buf.deinit(testing.allocator);
    try buildClientHelloFull(&buf, testing.allocator, pubkey, true, &.{}); // emit key_share twice
    try testing.expectError(error.EncodingError, client_hello.parse(buf.items));
}

test "a duplicate unknown extension is rejected (RFC 8446 4.2, all types)" {
    var pubkey: [32]u8 = undefined;
    _ = try hex(&pubkey, RFC_CLIENT_PUBKEY);
    var buf = std.ArrayListUnmanaged(u8).empty;
    defer buf.deinit(testing.allocator);
    // A valid CH plus two copies of the same unrecognized extension (type 0xABCD).
    try buildClientHelloWithExtras(&buf, testing.allocator, pubkey, &.{
        0xAB, 0xCD, 0x00, 0x00, // unknown ext, empty body
        0xAB, 0xCD, 0x00, 0x00, // the duplicate
    });
    try testing.expectError(error.EncodingError, client_hello.parse(buf.items));
}

test "trailing garbage after the extensions block is rejected" {
    var pubkey: [32]u8 = undefined;
    _ = try hex(&pubkey, RFC_CLIENT_PUBKEY);
    var buf = std.ArrayListUnmanaged(u8).empty;
    defer buf.deinit(testing.allocator);
    try buildClientHello(&buf, testing.allocator, pubkey);
    // Append one stray byte inside the message body (bump the u24 message length).
    try buf.append(testing.allocator, 0xFF);
    const mlen = (@as(u32, buf.items[1]) << 16) | (@as(u32, buf.items[2]) << 8) | buf.items[3];
    const nm = mlen + 1;
    buf.items[1] = @intCast(nm >> 16);
    buf.items[2] = @truncate(nm >> 8);
    buf.items[3] = @truncate(nm);
    try testing.expectError(error.EncodingError, client_hello.parse(buf.items));
}

test "a key_share group absent from supported_groups is rejected" {
    var pubkey: [32]u8 = undefined;
    _ = try hex(&pubkey, RFC_CLIENT_PUBKEY);
    var buf = std.ArrayListUnmanaged(u8).empty;
    defer buf.deinit(testing.allocator);
    try buildClientHello(&buf, testing.allocator, pubkey);
    // Rewrite supported_groups to list secp256r1 (0x0017) instead of x25519, while
    // the key_share stays x25519: the server must not key on an unadvertised group.
    const sg = std.mem.indexOf(u8, buf.items, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d }).?;
    buf.items[sg + 7] = 0x17; // x25519 (0x001d) -> secp256r1 (0x0017) in the group list
    try testing.expectError(error.EncodingError, client_hello.parse(buf.items));
}

test "a ClientHello whose cipher_suites omit TLS_AES_128_GCM_SHA256 is rejected" {
    var pubkey: [32]u8 = undefined;
    _ = try hex(&pubkey, RFC_CLIENT_PUBKEY);
    var buf = std.ArrayListUnmanaged(u8).empty;
    defer buf.deinit(testing.allocator);
    try buildClientHello(&buf, testing.allocator, pubkey);
    // The cipher_suites vector is 00 02 13 01 right after the 32-byte random +
    // empty session_id; flip 0x1301 to 0x1302 (an unsupported suite).
    const cs = std.mem.indexOf(u8, buf.items, &.{ 0x00, 0x02, 0x13, 0x01 }).?;
    buf.items[cs + 3] = 0x02;
    try testing.expectError(error.EncodingError, client_hello.parse(buf.items));
}

test "a truncated ClientHello is Truncated, not a wild read" {
    var pubkey: [32]u8 = undefined;
    _ = try hex(&pubkey, RFC_CLIENT_PUBKEY);
    var buf = std.ArrayListUnmanaged(u8).empty;
    defer buf.deinit(testing.allocator);
    try buildClientHello(&buf, testing.allocator, pubkey);
    try testing.expectError(error.Truncated, client_hello.parse(buf.items[0 .. buf.items.len - 10]));
}
