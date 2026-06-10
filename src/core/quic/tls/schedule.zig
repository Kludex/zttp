//! The TLS 1.3 key schedule (RFC 8446 section 7.1), the part QUIC reuses to key
//! its Handshake and Application packet-number spaces. The chain is:
//!
//!   0 -> Early Secret = HKDF-Extract(salt=0, IKM=0)
//!   Early -> derived = Derive-Secret(Early, "derived", "")
//!   derived + ECDHE -> Handshake Secret = HKDF-Extract(salt=derived, IKM=ecdhe)
//!   Handshake -> c/s hs traffic = Derive-Secret(HS, "c/s hs traffic", transcript)
//!   Handshake -> derived2 = Derive-Secret(HS, "derived", "")
//!   derived2 + 0 -> Master Secret = HKDF-Extract(salt=derived2, IKM=0)
//!   Master -> c/s ap traffic = Derive-Secret(MS, "c/s ap traffic", transcript)
//!
//! Derive-Secret(secret, label, msgs) == HKDF-Expand-Label(secret, label,
//! Transcript-Hash(msgs), Hash.length) - which is crypto.expandLabel over the
//! transcript hash. The handshake traffic secrets are taken with the transcript
//! through ServerHello; the application traffic secrets with the transcript
//! through the server's Finished (RFC 8446 7.1, the "Messages" column).

const std = @import("std");
const crypto = @import("../crypto.zig");
const transcript = @import("transcript.zig");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const SECRET_LEN = 32;
const zeros = [_]u8{0} ** SECRET_LEN;

/// The SHA-256 of the empty string - Derive-Secret(_, "derived", "") reads the
/// hash of no messages.
fn emptyHash() [SECRET_LEN]u8 {
    var h: [SECRET_LEN]u8 = undefined;
    Sha256.hash("", &h, .{});
    return h;
}

/// Derive-Secret(secret, label, transcript_hash) (RFC 8446 7.1).
fn deriveSecret(secret: [SECRET_LEN]u8, comptime label: []const u8, msg_hash: [SECRET_LEN]u8) [SECRET_LEN]u8 {
    var out: [SECRET_LEN]u8 = undefined;
    crypto.expandLabel(&out, secret, label, &msg_hash);
    return out;
}

/// One direction's traffic secret pair plus the derived QUIC keys.
pub const Secrets = struct {
    client: [SECRET_LEN]u8,
    server: [SECRET_LEN]u8,

    pub fn clientKeys(self: Secrets) crypto.Keys {
        return crypto.Keys.fromSecret(self.client);
    }
    pub fn serverKeys(self: Secrets) crypto.Keys {
        return crypto.Keys.fromSecret(self.server);
    }
};

/// The running key schedule. Built by feeding the ECDHE shared secret and the
/// transcript at the two read points.
pub const Schedule = struct {
    handshake_secret: [SECRET_LEN]u8 = undefined,
    master_secret: [SECRET_LEN]u8 = undefined,

    /// Derive the handshake traffic secrets from the ECDHE shared secret and the
    /// transcript hash through ServerHello (RFC 8446 7.1). Stores the handshake
    /// and master secrets for the later application step.
    pub fn deriveHandshake(ecdhe: [32]u8, transcript_through_sh: [SECRET_LEN]u8) struct { schedule: Schedule, secrets: Secrets } {
        const early = Hkdf.extract(&zeros, &zeros); // salt 0, IKM 0
        const derived = deriveSecret(early, "derived", emptyHash());
        const handshake_secret = Hkdf.extract(&derived, &ecdhe);
        const c = deriveSecret(handshake_secret, "c hs traffic", transcript_through_sh);
        const s = deriveSecret(handshake_secret, "s hs traffic", transcript_through_sh);
        const derived2 = deriveSecret(handshake_secret, "derived", emptyHash());
        const master_secret = Hkdf.extract(&derived2, &zeros);
        return .{
            .schedule = .{ .handshake_secret = handshake_secret, .master_secret = master_secret },
            .secrets = .{ .client = c, .server = s },
        };
    }

    /// Derive the application (1-RTT) traffic secrets from the transcript hash
    /// through the server's Finished (RFC 8446 7.1).
    pub fn deriveApplication(self: Schedule, transcript_through_server_fin: [SECRET_LEN]u8) Secrets {
        const c = deriveSecret(self.master_secret, "c ap traffic", transcript_through_server_fin);
        const s = deriveSecret(self.master_secret, "s ap traffic", transcript_through_server_fin);
        return .{ .client = c, .server = s };
    }
};

/// The Finished MAC key for a traffic secret (RFC 8446 4.4.4):
/// finished_key = HKDF-Expand-Label(secret, "finished", "", Hash.length).
pub fn finishedKey(secret: [SECRET_LEN]u8) [SECRET_LEN]u8 {
    var out: [SECRET_LEN]u8 = undefined;
    crypto.expandLabel(&out, secret, "finished", "");
    return out;
}

/// The Finished verify_data: HMAC(finished_key, transcript_hash) (RFC 8446 4.4.4).
pub fn verifyData(secret: [SECRET_LEN]u8, transcript_hash: [SECRET_LEN]u8) [SECRET_LEN]u8 {
    var out: [SECRET_LEN]u8 = undefined;
    HmacSha256.create(&out, &transcript_hash, &finishedKey(secret));
    return out;
}

const testing = std.testing;

// RFC 8448 section 3 ("Simple 1-RTT Handshake") canonical trace. These pin the
// schedule against the published TLS 1.3 vectors - the same discipline crypto.zig
// uses for the RFC 9001 Initial keys.
const hex = std.fmt.hexToBytes;

test "RFC 8448: handshake traffic secrets match the published trace" {
    // The ECDHE shared secret and the transcript hash through ServerHello, from
    // RFC 8448 section 3.
    var ecdhe: [32]u8 = undefined;
    _ = try hex(&ecdhe, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    var th: [32]u8 = undefined;
    _ = try hex(&th, "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");

    const d = Schedule.deriveHandshake(ecdhe, th);
    var want_c: [32]u8 = undefined;
    _ = try hex(&want_c, "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
    var want_s: [32]u8 = undefined;
    _ = try hex(&want_s, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    try testing.expectEqualSlices(u8, &want_c, &d.secrets.client);
    try testing.expectEqualSlices(u8, &want_s, &d.secrets.server);
}

test "RFC 8448: application traffic secrets match the published trace" {
    var ecdhe: [32]u8 = undefined;
    _ = try hex(&ecdhe, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    var th_sh: [32]u8 = undefined;
    _ = try hex(&th_sh, "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    const d = Schedule.deriveHandshake(ecdhe, th_sh);

    // Transcript hash through the server's Finished (RFC 8448 section 3).
    var th_fin: [32]u8 = undefined;
    _ = try hex(&th_fin, "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    const app = d.schedule.deriveApplication(th_fin);
    var want_c: [32]u8 = undefined;
    _ = try hex(&want_c, "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
    var want_s: [32]u8 = undefined;
    _ = try hex(&want_s, "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");
    try testing.expectEqualSlices(u8, &want_c, &app.client);
    try testing.expectEqualSlices(u8, &want_s, &app.server);
}

test "verifyData is a stable HMAC over the transcript" {
    const secret = [_]u8{0xAB} ** 32;
    const th = [_]u8{0xCD} ** 32;
    const a = verifyData(secret, th);
    const b = verifyData(secret, th);
    try testing.expectEqualSlices(u8, &a, &b); // deterministic
    // A different transcript yields a different MAC.
    const c = verifyData(secret, [_]u8{0xCE} ** 32);
    try testing.expect(!std.mem.eql(u8, &a, &c));
}
