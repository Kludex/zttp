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

/// The widest DER ECDSA signature, the scratch a builder sizes for `sign`.
pub const SIG_DER_MAX = Ecdsa.Signature.der_encoded_length_max;

/// The SEC1-uncompressed public point length (0x04 || X || Y), what a Certificate
/// message carries for ecdsa_secp256r1.
pub const PUBLIC_SEC1_LEN = Ecdsa.PublicKey.uncompressed_sec1_encoded_length;

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

    /// Load the raw big-endian P-256 private scalar used by an existing certificate.
    pub fn fromPrivateKey(private_key: [Ecdsa.SecretKey.encoded_length]u8) !Signer {
        const secret_key = try Ecdsa.SecretKey.fromBytes(private_key);
        return .{ .key_pair = try Ecdsa.KeyPair.fromSecretKey(secret_key) };
    }

    /// The SEC1-uncompressed public point (0x04 || X || Y), what a server
    /// Certificate message carries for ecdsa_secp256r1.
    pub fn publicKeySec1(self: Signer) [PUBLIC_SEC1_LEN]u8 {
        return self.key_pair.public_key.toUncompressedSec1();
    }

    /// Sign the CertificateVerify content for a transcript hash, returning the
    /// DER-encoded ECDSA signature the message carries (RFC 8446 4.4.3). The
    /// caller copies the returned slice; it points into `buf`.
    pub fn sign(self: Signer, transcript_hash: [transcript.LEN]u8, buf: *[SIG_DER_MAX]u8) ![]u8 {
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

/// Extract the P-256 SEC1 public key from the Certificate message's first
/// certificate. zttp's test/raw-public-key form is already SEC1; X.509 DER is
/// accepted when it carries an id-ecPublicKey prime256v1 SubjectPublicKeyInfo.
pub fn certificatePublicKeySec1(cert: []const u8) ![]const u8 {
    if (cert.len == PUBLIC_SEC1_LEN) {
        _ = try Ecdsa.PublicKey.fromSec1(cert);
        return cert;
    }

    const ec_p256_algorithm = [_]u8{
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1
    };
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, cert, search_from, &ec_p256_algorithm)) |alg_pos| {
        var pos = alg_pos + ec_p256_algorithm.len;
        if (pos >= cert.len or cert[pos] != 0x03) {
            search_from = alg_pos + 1;
            continue;
        }
        pos += 1;
        const bit_string_len = derLength(cert, &pos) catch {
            search_from = alg_pos + 1;
            continue;
        };
        if (bit_string_len == PUBLIC_SEC1_LEN + 1 and
            pos + bit_string_len <= cert.len and
            cert[pos] == 0x00 and
            cert[pos + 1] == 0x04)
        {
            const public_sec1 = cert[pos + 1 .. pos + 1 + PUBLIC_SEC1_LEN];
            _ = try Ecdsa.PublicKey.fromSec1(public_sec1);
            return public_sec1;
        }
        search_from = alg_pos + 1;
    }
    return error.UnsupportedCertificate;
}

fn derLength(buf: []const u8, pos: *usize) !usize {
    if (pos.* >= buf.len) return error.InvalidDer;
    const first = buf[pos.*];
    pos.* += 1;
    if ((first & 0x80) == 0) return first;

    const n = first & 0x7f;
    if (n == 0 or n > @sizeOf(usize) or pos.* + n > buf.len) return error.InvalidDer;
    var len: usize = 0;
    for (buf[pos.* .. pos.* + n]) |b| {
        len = (len << 8) | b;
    }
    pos.* += n;
    return len;
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

test "Signer loads a raw private scalar" {
    const private_key = [_]u8{0x42} ** Ecdsa.SecretKey.encoded_length;
    const signer = try Signer.fromPrivateKey(private_key);
    const expected = (try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(private_key))).public_key;
    try testing.expectEqualSlices(u8, &expected.toUncompressedSec1(), &signer.publicKeySec1());
}

test "certificatePublicKeySec1 extracts a P-256 key from DER SubjectPublicKeyInfo" {
    const signer = try Signer.fromSeed([_]u8{0x42} ** 32);
    const public_key = signer.publicKeySec1();
    const prefix = [_]u8{
        0x30, 0x59, // SubjectPublicKeyInfo SEQUENCE
        0x30, 0x13, // AlgorithmIdentifier SEQUENCE
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1
        0x03, 0x42, 0x00, // subjectPublicKey BIT STRING, no unused bits
    };
    var der: [prefix.len + PUBLIC_SEC1_LEN]u8 = undefined;
    @memcpy(der[0..prefix.len], &prefix);
    @memcpy(der[prefix.len..], &public_key);

    try testing.expectEqualSlices(u8, &public_key, try certificatePublicKeySec1(&der));
    try testing.expectError(error.UnsupportedCertificate, certificatePublicKeySec1(&[_]u8{0xcc} ** 48));
}

test "a tampered transcript hash fails verification" {
    const signer = try Signer.fromSeed([_]u8{0x42} ** 32);
    const th = [_]u8{0xAB} ** 32;
    var buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const der = try signer.sign(th, &buf);
    const other = [_]u8{0xAC} ** 32;
    try testing.expectError(error.SignatureVerificationFailed, verify(&signer.publicKeySec1(), other, der));
}
