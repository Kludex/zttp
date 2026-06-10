//! The TLS 1.3 CertificateVerify signature (RFC 8446 4.4.3). The server proves it
//! holds the certificate's private key by signing a context string concatenated
//! with the handshake transcript hash. We use ecdsa_secp256r1_sha256, the QUIC
//! mandatory-to-implement scheme. Sans-IO: the signing key is integrator config
//! and the signature is deterministic (RFC 6979), so no entropy is consumed.

const std = @import("std");
const transcript = @import("transcript.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// SignatureScheme ecdsa_secp256r1_sha256 (RFC 8446 4.2.3).
pub const SCHEME: u16 = 0x0403;

/// The 64 spaces + context label + separator prefixed to the transcript hash
/// before signing (RFC 8446 4.4.3). "server" side, hence the server label.
const SERVER_CONTEXT = (" " ** 64) ++ "TLS 1.3, server CertificateVerify" ++ "\x00";

pub const Signer = struct {
    key_pair: Ecdsa.KeyPair,

    /// Derive a signing key from an injected 32-byte seed - a test/sans-IO hook.
    /// Production wires in a real certificate key via `fromSeed` over its scalar.
    pub fn fromSeed(seed: [Ecdsa.KeyPair.seed_length]u8) !Signer {
        return .{ .key_pair = try Ecdsa.KeyPair.generateDeterministic(seed) };
    }

    /// The SEC1-uncompressed public point (0x04 || X || Y), what a server
    /// Certificate message carries for ecdsa_secp256r1.
    pub fn publicKeySec1(self: Signer) [Ecdsa.PublicKey.uncompressed_sec1_encoded_length]u8 {
        return self.key_pair.public_key.toUncompressedSec1();
    }

    /// Sign the CertificateVerify content for a transcript hash, returning the
    /// DER-encoded ECDSA signature the message carries (RFC 8446 4.4.3). The
    /// caller copies the returned slice; it points into `buf`.
    pub fn sign(self: Signer, transcript_hash: [transcript.LEN]u8, buf: *[Ecdsa.Signature.der_encoded_length_max]u8) ![]u8 {
        const sig = try self.key_pair.sign(&content(transcript_hash), null);
        return sig.toDer(buf);
    }
};

/// Verify a DER CertificateVerify signature against a SEC1 public key and the
/// transcript hash (RFC 8446 4.4.3) - the client's side, used in round-trip tests.
pub fn verify(public_sec1: []const u8, transcript_hash: [transcript.LEN]u8, der_sig: []const u8) !void {
    const pk = try Ecdsa.PublicKey.fromSec1(public_sec1);
    const sig = try Ecdsa.Signature.fromDer(der_sig);
    try sig.verify(&content(transcript_hash), pk);
}

/// The signed octet string (RFC 8446 4.4.3): the context prefix then the hash.
fn content(transcript_hash: [transcript.LEN]u8) [SERVER_CONTEXT.len + transcript.LEN]u8 {
    var out: [SERVER_CONTEXT.len + transcript.LEN]u8 = undefined;
    @memcpy(out[0..SERVER_CONTEXT.len], SERVER_CONTEXT);
    @memcpy(out[SERVER_CONTEXT.len..], &transcript_hash);
    return out;
}

const testing = std.testing;

test "CertificateVerify round-trips through the client's verify" {
    const signer = try Signer.fromSeed([_]u8{0x42} ** 32);
    const th = [_]u8{0xAB} ** 32;
    var buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const der = try signer.sign(th, &buf);
    try verify(&signer.publicKeySec1(), th, der);
}

test "a tampered transcript hash fails verification" {
    const signer = try Signer.fromSeed([_]u8{0x42} ** 32);
    const th = [_]u8{0xAB} ** 32;
    var buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const der = try signer.sign(th, &buf);
    const other = [_]u8{0xAC} ** 32;
    try testing.expectError(error.SignatureVerificationFailed, verify(&signer.publicKeySec1(), other, der));
}
