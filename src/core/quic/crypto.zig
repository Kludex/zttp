//! QUIC packet protection (RFC 9001): the key schedule and the AEAD that turn a
//! cleartext packet into a protected one and back. It builds on the vetted
//! primitives in `std.crypto` (AES-128-GCM, HKDF-SHA256, raw AES for header
//! protection) rather than hand-rolling cryptography - the QUIC-specific parts
//! are the HKDF-Expand-Label key schedule, the Initial-secret derivation, the
//! nonce construction, and header protection. Keeping those here, on top of the
//! standard library, is what makes this both safe and dependency-free.
//!
//! Scope: the AES-128-GCM / SHA-256 cipher suite, which is the mandatory-to-
//! implement suite (RFC 9001 5.3) and the one used for every Initial packet.

const std = @import("std");

const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128 = std.crypto.core.aes.Aes128;

pub const KEY_LEN = Aead.key_length; // 16
pub const IV_LEN = Aead.nonce_length; // 12
pub const TAG_LEN = Aead.tag_length; // 16
pub const HP_LEN = 16; // header-protection key length (an AES-128 key)
const SAMPLE_LEN = 16; // header-protection sample length

const RETRY_KEY = [_]u8{ 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };
const RETRY_NONCE = [_]u8{ 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };

/// The version-1 Initial salt (RFC 9001 5.2): the fixed input that, mixed with
/// the client's destination connection id, seeds both Initial secrets.
pub const INITIAL_SALT_V1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

pub const Error = error{
    /// The AEAD tag did not verify: the packet was forged or tampered with, and
    /// is dropped, not parsed (RFC 9001 9.5).
    DecryptFailed,
    /// The sample needed for header protection runs past the packet end.
    Truncated,
};

/// One direction's protection keys: the AEAD key, the IV the nonce is built from,
/// and the header-protection key. Derived from a traffic secret via `fromSecret`.
pub const Keys = struct {
    key: [KEY_LEN]u8,
    iv: [IV_LEN]u8,
    hp: [HP_LEN]u8,

    /// Derive the packet-protection keys from a traffic secret (RFC 9001 5.1):
    /// key = Expand-Label(secret, "quic key"), iv = "quic iv", hp = "quic hp".
    pub fn fromSecret(secret: [32]u8) Keys {
        var k: Keys = undefined;
        expandLabel(&k.key, secret, "quic key", "");
        expandLabel(&k.iv, secret, "quic iv", "");
        expandLabel(&k.hp, secret, "quic hp", "");
        return k;
    }

    /// QUIC key update advances only the packet-protection key and IV. Header
    /// protection keys remain fixed for the connection phase (RFC 9001 6).
    pub fn fromUpdatedSecret(secret: [32]u8, current_hp: [HP_LEN]u8) Keys {
        var k: Keys = undefined;
        expandLabel(&k.key, secret, "quic key", "");
        expandLabel(&k.iv, secret, "quic iv", "");
        k.hp = current_hp;
        return k;
    }
};

/// QUIC 1-RTT key update (RFC 9001 6): the next traffic secret is
/// HKDF-Expand-Label(current, "quic ku", "", Hash.length). Packet keys for that
/// phase are then derived with the normal QUIC key/iv/hp labels.
pub fn nextTrafficSecret(secret: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    expandLabel(&out, secret, "quic ku", "");
    return out;
}

/// Both directions' Initial keys, plus the secrets they came from. The client
/// protects with `client` and the server with `server`; a receiver uses the
/// opposite of what it sends.
pub const InitialKeys = struct {
    client: Keys,
    server: Keys,

    /// Derive the Initial keys from the client's destination connection id
    /// (RFC 9001 5.2). Both endpoints compute the same pair from the same dcid.
    pub fn derive(client_dcid: []const u8) InitialKeys {
        const initial_secret = Hkdf.extract(&INITIAL_SALT_V1, client_dcid);
        var client_secret: [32]u8 = undefined;
        var server_secret: [32]u8 = undefined;
        expandLabelPrk(&client_secret, initial_secret, "client in", "");
        expandLabelPrk(&server_secret, initial_secret, "server in", "");
        return .{ .client = Keys.fromSecret(client_secret), .server = Keys.fromSecret(server_secret) };
    }
};

/// HKDF-Expand-Label (RFC 8446 7.1) over a SHA-256 PRK, the TLS 1.3 / QUIC label
/// construction: the info is length-prefixed "tls13 "+label and context. Public so
/// the TLS 1.3 key schedule (tls/) shares this one label construction.
pub fn expandLabelPrk(out: []u8, prk: [Hkdf.prk_length]u8, comptime label: []const u8, context: []const u8) void {
    var info: [2 + 1 + 255 + 1 + 255]u8 = undefined; // the maximum legal HkdfLabel (RFC 8446 7.1)
    const full_label = "tls13 " ++ label;
    comptime std.debug.assert(full_label.len <= 255);
    var i: usize = 0;
    info[i] = @intCast(out.len >> 8);
    info[i + 1] = @intCast(out.len & 0xff);
    i += 2;
    info[i] = @intCast(full_label.len);
    i += 1;
    @memcpy(info[i .. i + full_label.len], full_label);
    i += full_label.len;
    info[i] = @intCast(context.len);
    i += 1;
    @memcpy(info[i .. i + context.len], context);
    i += context.len;
    Hkdf.expand(out, info[0..i], prk);
}

/// Expand-Label over a 32-byte secret (the common case): re-extract is not
/// needed because a traffic secret already has PRK length. Public so the TLS 1.3
/// key schedule's Derive-Secret (Expand-Label over the transcript hash) reuses it.
pub fn expandLabel(out: []u8, secret: [32]u8, comptime label: []const u8, context: []const u8) void {
    expandLabelPrk(out, secret, label, context);
}

/// Build the AEAD nonce for `pn`: the 62-bit packet number, left-padded to the
/// IV length and XORed with the IV (RFC 9001 5.3).
fn nonce(iv: [IV_LEN]u8, pn: u64) [IV_LEN]u8 {
    var n = iv;
    var pn_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &pn_bytes, pn, .big);
    inline for (0..8) |j| n[IV_LEN - 8 + j] ^= pn_bytes[j];
    return n;
}

/// Encrypt a packet payload in place into `out` (which must hold
/// plaintext.len + TAG_LEN). `header` is the authenticated associated data (the
/// packet header through the packet number). Returns the ciphertext+tag slice.
pub fn seal(keys: Keys, pn: u64, header: []const u8, plaintext: []const u8, out: []u8) []u8 {
    std.debug.assert(out.len >= plaintext.len + TAG_LEN);
    const ct = out[0..plaintext.len];
    const tag = out[plaintext.len .. plaintext.len + TAG_LEN];
    Aead.encrypt(ct, tag[0..TAG_LEN], plaintext, header, nonce(keys.iv, pn), keys.key);
    return out[0 .. plaintext.len + TAG_LEN];
}

/// Decrypt a packet payload (ciphertext followed by its 16-octet tag) into `out`
/// (which must hold ciphertext.len - TAG_LEN). Returns DecryptFailed on a bad
/// tag - the packet is then silently dropped.
pub fn open(keys: Keys, pn: u64, header: []const u8, ciphertext: []const u8, out: []u8) Error![]u8 {
    if (ciphertext.len < TAG_LEN) return error.DecryptFailed;
    const ct = ciphertext[0 .. ciphertext.len - TAG_LEN];
    const tag = ciphertext[ciphertext.len - TAG_LEN ..][0..TAG_LEN].*;
    std.debug.assert(out.len >= ct.len);
    Aead.decrypt(out[0..ct.len], ct, tag, header, nonce(keys.iv, pn), keys.key) catch return error.DecryptFailed;
    return out[0..ct.len];
}

/// QUIC v1 Retry integrity tag (RFC 9001 5.8): AES-128-GCM with fixed
/// key/nonce, empty plaintext, and the Retry pseudo-packet as associated data.
pub fn retryIntegrityTag(aad: []const u8) [TAG_LEN]u8 {
    var tag: [TAG_LEN]u8 = undefined;
    Aead.encrypt(&.{}, &tag, &.{}, aad, RETRY_NONCE, RETRY_KEY);
    return tag;
}

/// The header-protection mask for a sample (RFC 9001 5.4.3, AES form): encrypt
/// the 16-octet sample with the hp key; the first 5 output octets are the mask.
pub fn headerMask(hp: [HP_LEN]u8, sample: []const u8) Error![5]u8 {
    if (sample.len < SAMPLE_LEN) return error.Truncated;
    const ctx = Aes128.initEnc(hp);
    var block: [16]u8 = undefined;
    ctx.encrypt(&block, sample[0..SAMPLE_LEN]);
    return block[0..5].*;
}

fn lowMask(long: bool) u8 {
    return if (long) 0x0f else 0x1f;
}

/// Apply header protection at the sender (RFC 9001 5.4.1). The packet-number
/// length is already encoded in the cleartext first byte's low 2 bits, so it is
/// known before masking. The sample is taken at `pn_offset + 4` regardless of the
/// real pn length.
pub fn protectHeader(hp: [HP_LEN]u8, packet: []u8, pn_offset: usize, long: bool) Error!void {
    const sample_offset = pn_offset + 4;
    if (sample_offset + SAMPLE_LEN > packet.len) return error.Truncated;
    const mask = try headerMask(hp, packet[sample_offset .. sample_offset + SAMPLE_LEN]);
    const pn_len = (packet[0] & 0x03) + 1;
    packet[0] ^= mask[0] & lowMask(long);
    for (0..pn_len) |j| packet[pn_offset + j] ^= mask[1 + j];
}

/// Remove header protection at the receiver (RFC 9001 5.4.1) and return the now-
/// revealed packet-number length. The first byte is unmasked first to recover the
/// length, then exactly that many pn octets are unmasked.
pub fn unprotectHeader(hp: [HP_LEN]u8, packet: []u8, pn_offset: usize, long: bool) Error!usize {
    const sample_offset = pn_offset + 4;
    if (sample_offset + SAMPLE_LEN > packet.len) return error.Truncated;
    const mask = try headerMask(hp, packet[sample_offset .. sample_offset + SAMPLE_LEN]);
    packet[0] ^= mask[0] & lowMask(long);
    const pn_len = (packet[0] & 0x03) + 1;
    for (0..pn_len) |j| packet[pn_offset + j] ^= mask[1 + j];
    return pn_len;
}

test "Initial keys match RFC 9001 appendix A vectors" {
    // The client dcid from RFC 9001 A.1.
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = InitialKeys.derive(&dcid);
    // RFC 9001 A.1 expected client Initial key / iv / hp.
    const want_key = [_]u8{ 0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d };
    const want_iv = [_]u8{ 0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c };
    const want_hp = [_]u8{ 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };
    try std.testing.expectEqualSlices(u8, &want_key, &keys.client.key);
    try std.testing.expectEqualSlices(u8, &want_iv, &keys.client.iv);
    try std.testing.expectEqualSlices(u8, &want_hp, &keys.client.hp);
}

test "server Initial secret matches RFC 9001 appendix A" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = InitialKeys.derive(&dcid);
    const want_key = [_]u8{ 0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37 };
    try std.testing.expectEqualSlices(u8, &want_key, &keys.server.key);
}

test "seal then open round-trips" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = InitialKeys.derive(&dcid).client;
    const header = "header-as-aad";
    const plaintext = "the quick brown fox";
    var sealed: [plaintext.len + TAG_LEN]u8 = undefined;
    const ct = seal(keys, 0, header, plaintext, &sealed);
    var opened: [plaintext.len]u8 = undefined;
    const pt = try open(keys, 0, header, ct, &opened);
    try std.testing.expectEqualStrings(plaintext, pt);
}

test "open rejects a tampered tag" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = InitialKeys.derive(&dcid).client;
    var sealed: [3 + TAG_LEN]u8 = undefined;
    const ct = seal(keys, 7, "h", "abc", &sealed);
    sealed[sealed.len - 1] ^= 0x01; // flip a tag bit
    var opened: [3]u8 = undefined;
    try std.testing.expectError(error.DecryptFailed, open(keys, 7, "h", ct, &opened));
}

test "wrong packet number fails to open" {
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const keys = InitialKeys.derive(&dcid).client;
    var sealed: [3 + TAG_LEN]u8 = undefined;
    const ct = seal(keys, 1, "h", "abc", &sealed);
    var opened: [3]u8 = undefined;
    try std.testing.expectError(error.DecryptFailed, open(keys, 2, "h", ct, &opened));
}

test "Retry integrity tag matches RFC 9001 sample" {
    const aad = [_]u8{ 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 } ++
        [_]u8{ 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e };
    const want = [_]u8{ 0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba };
    try std.testing.expectEqualSlices(u8, &want, &retryIntegrityTag(&aad));
}

test "protect then unprotect round-trips and recovers pn_len" {
    const hp = [_]u8{0x11} ** HP_LEN;
    var packet: [40]u8 = undefined;
    for (&packet, 0..) |*b, j| b.* = @intCast(j);
    packet[0] = 0xC3; // long header, pn_len bits = 3 -> 4-byte pn
    const before = packet;
    try protectHeader(hp, &packet, 4, true);
    try std.testing.expect(!std.mem.eql(u8, &before, &packet));
    const pn_len = try unprotectHeader(hp, &packet, 4, true);
    try std.testing.expectEqual(@as(usize, 4), pn_len);
    try std.testing.expectEqualSlices(u8, &before, &packet);
}
