//! The TLS 1.3 (EC)DHE key exchange over the x25519 group (RFC 8446 4.2.8). The
//! server picks an ephemeral key pair, sends its public key in the ServerHello
//! key_share, and multiplies its private key by the client's public key to reach
//! the shared secret that seeds the handshake key schedule. Sans-IO: the ephemeral
//! seed is injected so the whole exchange is a pure function of its inputs.

const std = @import("std");

const X25519 = std.crypto.dh.X25519;

pub const PUBLIC_LEN = X25519.public_length;
pub const SHARED_LEN = X25519.shared_length;

pub const KeyShare = struct {
    public_key: [PUBLIC_LEN]u8,
    secret_key: [X25519.secret_length]u8,

    /// The server's ephemeral key pair, derived from an injected 32-byte seed so
    /// the exchange stays deterministic for a given seed (the one source of
    /// nondeterminism a sans-IO handshake takes from its caller).
    pub fn ephemeral(seed: [X25519.seed_length]u8) !KeyShare {
        const kp = try X25519.KeyPair.generateDeterministic(seed);
        return .{ .public_key = kp.public_key, .secret_key = kp.secret_key };
    }

    /// The ECDHE shared secret: our private key times the client's public key
    /// (RFC 8446 7.4.2). Feeds HKDF-Extract as the IKM for the Handshake Secret.
    pub fn shared(self: KeyShare, client_public: [PUBLIC_LEN]u8) ![SHARED_LEN]u8 {
        return X25519.scalarmult(self.secret_key, client_public);
    }
};

const testing = std.testing;
const hex = std.fmt.hexToBytes;

test "both sides reach the same x25519 shared secret" {
    const server = try KeyShare.ephemeral([_]u8{0x11} ** 32);
    const client = try KeyShare.ephemeral([_]u8{0x22} ** 32);
    const from_server = try server.shared(client.public_key);
    const from_client = try client.shared(server.public_key);
    try testing.expectEqualSlices(u8, &from_server, &from_client);
}

test "RFC 7748 x25519 vector" {
    // RFC 7748 section 6.1: Alice's private + Bob's public yields the published
    // shared secret. We load the scalars directly to pin scalarmult.
    var alice_sk: [32]u8 = undefined;
    _ = try hex(&alice_sk, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    var bob_pk: [32]u8 = undefined;
    _ = try hex(&bob_pk, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const k = try X25519.scalarmult(alice_sk, bob_pk);
    var want: [32]u8 = undefined;
    _ = try hex(&want, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    try testing.expectEqualSlices(u8, &want, &k);
}

test "RFC 8448 ECDHE: the server's key share yields the schedule's shared secret" {
    // RFC 8448 section 3: server ephemeral private key times client public key is
    // the ECDHE secret the handshake schedule extracts. The published private key
    // is the clamped scalar, so we load it directly rather than through a seed.
    var server_sk: [32]u8 = undefined;
    _ = try hex(&server_sk, "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e");
    var client_pk: [32]u8 = undefined;
    _ = try hex(&client_pk, "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c");
    const server = KeyShare{ .public_key = undefined, .secret_key = server_sk };
    const secret = try server.shared(client_pk);
    var want: [32]u8 = undefined;
    _ = try hex(&want, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    try testing.expectEqualSlices(u8, &want, &secret);
}
