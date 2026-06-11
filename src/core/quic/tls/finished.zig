//! The TLS 1.3 Finished verify_data (RFC 8446 4.4.4). Each side proves it holds
//! the handshake traffic secret by sending an HMAC over the transcript hash up to
//! that point, keyed by a secret-specific finished_key. The server builds its own
//! and verifies the client's in constant time. The HMAC itself lives in
//! schedule.verifyData; this module is the build/verify seam over it.

const std = @import("std");
const schedule = @import("schedule.zig");

pub const LEN = schedule.SECRET_LEN;

/// The server's Finished verify_data over the transcript through CertificateVerify
/// (RFC 8446 4.4.4), keyed by the server handshake traffic secret.
pub fn build(traffic_secret: [LEN]u8, transcript_hash: [LEN]u8) [LEN]u8 {
    return schedule.verifyData(traffic_secret, transcript_hash);
}

/// Verify a peer's Finished in constant time (RFC 8446 4.4.4), keyed by that
/// peer's handshake traffic secret over the transcript through the server's
/// Finished. Returns DecryptError on mismatch, the TLS alert a bad MAC raises.
pub fn verify(traffic_secret: [LEN]u8, transcript_hash: [LEN]u8, received: [LEN]u8) error{DecryptError}!void {
    const expected = schedule.verifyData(traffic_secret, transcript_hash);
    if (!std.crypto.timing_safe.eql([LEN]u8, expected, received)) return error.DecryptError;
}

const testing = std.testing;

test "a Finished verifies against its own build" {
    const secret = [_]u8{0x07} ** LEN;
    const th = [_]u8{0x5A} ** LEN;
    const mac = build(secret, th);
    try verify(secret, th, mac);
}

test "a tampered Finished is rejected" {
    const secret = [_]u8{0x07} ** LEN;
    const th = [_]u8{0x5A} ** LEN;
    var mac = build(secret, th);
    mac[0] ^= 0xFF;
    try testing.expectError(error.DecryptError, verify(secret, th, mac));
}

test "the wrong transcript is rejected" {
    const secret = [_]u8{0x07} ** LEN;
    const mac = build(secret, [_]u8{0x5A} ** LEN);
    try testing.expectError(error.DecryptError, verify(secret, [_]u8{0x5B} ** LEN, mac));
}
