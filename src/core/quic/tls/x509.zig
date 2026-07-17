//! A minimal self-signed X.509 certificate builder for the QUIC server identity.
//!
//! zttp's TLS 1.3 stack authenticates with ecdsa_secp256r1_sha256 (see sign.zig),
//! so the certificate it presents must carry a prime256v1 key and be signed with
//! ecdsa-with-SHA256. Zig's std.crypto.Certificate can parse and verify X.509 but
//! cannot emit it, so we hand-encode just enough DER for a self-signed leaf: v3,
//! a single dNSName SubjectAltName, a validity window, and the SEC1 public point.
//! The output is round-tripped through std.crypto.Certificate.parse/verify in the
//! tests, which is the real contract - a verifying client (verify.zig) must accept
//! what this produces.
//!
//! Sans-IO: the serial, validity bounds, and signing key are all injected; nothing
//! here reads a clock or entropy source.

const std = @import("std");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const PUBLIC_SEC1_LEN = Ecdsa.PublicKey.uncompressed_sec1_encoded_length;

// ecdsa-with-SHA256 (RFC 5758) - both the tbsCertificate.signature and the outer
// signatureAlgorithm.
const OID_ECDSA_SHA256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
// id-ecPublicKey (RFC 5480) and the prime256v1 named curve.
const OID_EC_PUBLIC_KEY = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const OID_PRIME256V1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const OID_COMMON_NAME = [_]u8{ 0x55, 0x04, 0x03 };
const OID_SUBJECT_ALT_NAME = [_]u8{ 0x55, 0x1d, 0x11 };

pub const SECONDS_PER_DAY: i64 = 24 * 60 * 60;

pub const Params = struct {
    /// The subject/issuer dNSName and commonName. A verifying client matches this
    /// against its expected server_name.
    dns_name: []const u8,
    /// notBefore/notAfter as Unix seconds; the caller owns the clock.
    not_before: i64,
    not_after: i64,
    /// A positive serial number; DER encodes it minimally.
    serial: u64 = 1,
};

pub const Error = error{ OutOfMemory, InvalidName };

/// Emit a self-signed prime256v1 certificate for `key_pair` into `out`, returning
/// the DER bytes just written (a slice of `out`).
pub fn selfSigned(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    key_pair: Ecdsa.KeyPair,
    params: Params,
) Error![]const u8 {
    return build(out, gpa, key_pair.public_key, key_pair, params.dns_name, params);
}

/// Emit a prime256v1 leaf whose SubjectAltName/subject is `params.dns_name`,
/// signed by `issuer_key` under issuer name `issuer_dns`. Used for chain tests and
/// any future intermediate/leaf split.
pub fn signedBy(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    subject_key: Ecdsa.PublicKey,
    issuer_key: Ecdsa.KeyPair,
    issuer_dns: []const u8,
    params: Params,
) Error![]const u8 {
    return build(out, gpa, subject_key, issuer_key, issuer_dns, params);
}

fn build(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    subject_key: Ecdsa.PublicKey,
    issuer_key: Ecdsa.KeyPair,
    issuer_dns: []const u8,
    params: Params,
) Error![]const u8 {
    if (params.dns_name.len == 0 or params.dns_name.len > 0xffff) return error.InvalidName;
    if (issuer_dns.len == 0 or issuer_dns.len > 0xffff) return error.InvalidName;

    var tbs: std.ArrayListUnmanaged(u8) = .empty;
    defer tbs.deinit(gpa);
    try buildTbs(&tbs, gpa, subject_key, issuer_dns, params);

    const sig = issuer_key.sign(tbs.items, null) catch return error.OutOfMemory;
    var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&der_buf);

    const start = out.items.len;
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    var body: std.ArrayListUnmanaged(u8) = .empty;
    defer body.deinit(gpa);
    try body.appendSlice(gpa, tbs.items);
    try algorithmIdentifier(&body, gpa);
    // signatureValue BIT STRING: one "unused bits" octet (0) then the DER signature.
    var sig_bits: std.ArrayListUnmanaged(u8) = .empty;
    defer sig_bits.deinit(gpa);
    try sig_bits.append(gpa, 0x00);
    try sig_bits.appendSlice(gpa, sig_der);
    try element(&body, gpa, 0x03, sig_bits.items);

    try element(out, gpa, 0x30, body.items);
    return out.items[start..];
}

fn buildTbs(
    tbs: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    public_key: Ecdsa.PublicKey,
    issuer_dns: []const u8,
    params: Params,
) Error!void {
    var inner: std.ArrayListUnmanaged(u8) = .empty;
    defer inner.deinit(gpa);

    // version [0] EXPLICIT INTEGER { v3(2) }
    var version_int: std.ArrayListUnmanaged(u8) = .empty;
    defer version_int.deinit(gpa);
    try element(&version_int, gpa, 0x02, &[_]u8{0x02});
    try element(&inner, gpa, 0xa0, version_int.items);

    // serialNumber INTEGER (positive, minimal encoding, high-bit-safe)
    try integer(&inner, gpa, params.serial);

    // signature AlgorithmIdentifier (must equal the outer signatureAlgorithm)
    try algorithmIdentifier(&inner, gpa);

    // issuer: a single CN=issuer_dns RDN (== subject for a self-signed cert).
    try name(&inner, gpa, issuer_dns);

    // validity SEQUENCE { notBefore UTCTime, notAfter UTCTime }
    var validity: std.ArrayListUnmanaged(u8) = .empty;
    defer validity.deinit(gpa);
    try utcTime(&validity, gpa, params.not_before);
    try utcTime(&validity, gpa, params.not_after);
    try element(&inner, gpa, 0x30, validity.items);

    // subject
    try name(&inner, gpa, params.dns_name);

    // subjectPublicKeyInfo
    try subjectPublicKeyInfo(&inner, gpa, public_key);

    // extensions [3] EXPLICIT SEQUENCE OF Extension { subjectAltName }
    try extensions(&inner, gpa, params.dns_name);

    try element(tbs, gpa, 0x30, inner.items);
}

fn algorithmIdentifier(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator) Error!void {
    var seq: std.ArrayListUnmanaged(u8) = .empty;
    defer seq.deinit(gpa);
    try element(&seq, gpa, 0x06, &OID_ECDSA_SHA256); // no parameters for ecdsa-with-SHA256
    try element(out, gpa, 0x30, seq.items);
}

fn name(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, cn: []const u8) Error!void {
    // Name ::= SEQUENCE OF RelativeDistinguishedName (SET OF AttributeTypeAndValue)
    var atav: std.ArrayListUnmanaged(u8) = .empty;
    defer atav.deinit(gpa);
    try element(&atav, gpa, 0x06, &OID_COMMON_NAME);
    try element(&atav, gpa, 0x0c, cn); // UTF8String

    var atav_seq: std.ArrayListUnmanaged(u8) = .empty;
    defer atav_seq.deinit(gpa);
    try element(&atav_seq, gpa, 0x30, atav.items);

    var rdn: std.ArrayListUnmanaged(u8) = .empty;
    defer rdn.deinit(gpa);
    try element(&rdn, gpa, 0x31, atav_seq.items); // SET

    try element(out, gpa, 0x30, rdn.items);
}

fn subjectPublicKeyInfo(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, public_key: Ecdsa.PublicKey) Error!void {
    var algo: std.ArrayListUnmanaged(u8) = .empty;
    defer algo.deinit(gpa);
    try element(&algo, gpa, 0x06, &OID_EC_PUBLIC_KEY);
    try element(&algo, gpa, 0x06, &OID_PRIME256V1);

    var spki: std.ArrayListUnmanaged(u8) = .empty;
    defer spki.deinit(gpa);
    try element(&spki, gpa, 0x30, algo.items);

    const sec1 = public_key.toUncompressedSec1();
    var key_bits: std.ArrayListUnmanaged(u8) = .empty;
    defer key_bits.deinit(gpa);
    try key_bits.append(gpa, 0x00); // unused bits
    try key_bits.appendSlice(gpa, &sec1);
    try element(&spki, gpa, 0x03, key_bits.items);

    try element(out, gpa, 0x30, spki.items);
}

fn extensions(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, dns_name: []const u8) Error!void {
    // GeneralNames ::= SEQUENCE OF GeneralName; dNSName [2] IA5String.
    var general_names: std.ArrayListUnmanaged(u8) = .empty;
    defer general_names.deinit(gpa);
    try element(&general_names, gpa, 0x82, dns_name); // [2] IA5String, implicit

    var san_seq: std.ArrayListUnmanaged(u8) = .empty;
    defer san_seq.deinit(gpa);
    try element(&san_seq, gpa, 0x30, general_names.items);

    var ext: std.ArrayListUnmanaged(u8) = .empty;
    defer ext.deinit(gpa);
    try element(&ext, gpa, 0x06, &OID_SUBJECT_ALT_NAME);
    try element(&ext, gpa, 0x04, san_seq.items); // extnValue OCTET STRING

    var one_ext: std.ArrayListUnmanaged(u8) = .empty;
    defer one_ext.deinit(gpa);
    try element(&one_ext, gpa, 0x30, ext.items);

    var ext_list: std.ArrayListUnmanaged(u8) = .empty;
    defer ext_list.deinit(gpa);
    try element(&ext_list, gpa, 0x30, one_ext.items); // Extensions SEQUENCE OF

    try element(out, gpa, 0xa3, ext_list.items); // [3] EXPLICIT
}

fn integer(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, value: u64) Error!void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .big);
    var i: usize = 0;
    while (i < buf.len - 1 and buf[i] == 0) i += 1; // strip leading zero octets
    var contents: std.ArrayListUnmanaged(u8) = .empty;
    defer contents.deinit(gpa);
    if (buf[i] & 0x80 != 0) try contents.append(gpa, 0x00); // keep it positive
    try contents.appendSlice(gpa, buf[i..]);
    try element(out, gpa, 0x02, contents.items);
}

fn utcTime(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, unix_seconds: i64) Error!void {
    const c = civilFromDays(@divFloor(unix_seconds, SECONDS_PER_DAY));
    const rem = @mod(unix_seconds, SECONDS_PER_DAY);
    const hour: u64 = @intCast(@divFloor(rem, 3600));
    const minute: u64 = @intCast(@divFloor(@mod(rem, 3600), 60));
    const second: u64 = @intCast(@mod(rem, 60));
    var text: [13]u8 = undefined;
    // UTCTime YYMMDDHHMMSSZ; std.crypto reads the year as 2000+YY (valid to 2099).
    _ = std.fmt.bufPrint(&text, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
        @as(u64, @intCast(@mod(c.year, 100))),
        c.month,
        c.day,
        hour,
        minute,
        second,
    }) catch unreachable;
    try element(out, gpa, 0x17, &text);
}

const Civil = struct { year: i64, month: u64, day: u64 };

// days since 1970-01-01 -> civil date (Howard Hinnant's algorithm).
fn civilFromDays(z_in: i64) Civil {
    const z = z_in + 719468;
    const era = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: i64 = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    return .{ .year = if (m <= 2) y + 1 else y, .month = @intCast(m), .day = @intCast(d) };
}

fn element(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, tag: u8, contents: []const u8) Error!void {
    try out.append(gpa, tag);
    try length(out, gpa, contents.len);
    try out.appendSlice(gpa, contents);
}

fn length(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, len: usize) Error!void {
    if (len < 0x80) {
        try out.append(gpa, @intCast(len));
        return;
    }
    var buf: [8]u8 = undefined;
    var n: usize = 0;
    var v = len;
    while (v != 0) : (v >>= 8) {
        buf[n] = @intCast(v & 0xff);
        n += 1;
    }
    try out.append(gpa, @as(u8, 0x80) | @as(u8, @intCast(n)));
    while (n != 0) {
        n -= 1;
        try out.append(gpa, buf[n]);
    }
}

const testing = std.testing;
const Certificate = std.crypto.Certificate;

test "selfSigned emits a certificate std.crypto.Certificate accepts" {
    const kp = try Ecdsa.KeyPair.generateDeterministic([_]u8{0x42} ** 32);
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(testing.allocator);
    // 2023-01-01T00:00:00Z .. 2033-01-01T00:00:00Z
    const der = try selfSigned(&out, testing.allocator, kp, .{
        .dns_name = "example.com",
        .not_before = 1672531200,
        .not_after = 1988150400,
        .serial = 0x0102,
    });

    const cert = Certificate{ .buffer = der, .index = 0 };
    const parsed = try cert.parse();
    try testing.expectEqual(Certificate.Version.v3, parsed.version);
    try testing.expectEqual(Certificate.Algorithm.ecdsa_with_SHA256, parsed.signature_algorithm);
    try testing.expectEqual(@as(u64, 1672531200), parsed.validity.not_before);
    try testing.expectEqual(@as(u64, 1988150400), parsed.validity.not_after);
    try testing.expectEqualStrings("example.com", parsed.commonName());
    // The embedded SEC1 point matches the signing key.
    try testing.expectEqualSlices(u8, &kp.public_key.toUncompressedSec1(), parsed.pubKey());
    // Self-signature verifies, and the SAN matches (and mismatches).
    try parsed.verify(parsed, 1700000000);
    try parsed.verifyHostName("example.com");
    try testing.expectError(error.CertificateHostMismatch, parsed.verifyHostName("evil.com"));
}

test "selfSigned certificate is rejected outside its validity window" {
    const kp = try Ecdsa.KeyPair.generateDeterministic([_]u8{0x7c} ** 32);
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(testing.allocator);
    const der = try selfSigned(&out, testing.allocator, kp, .{
        .dns_name = "host.test",
        .not_before = 1672531200,
        .not_after = 1704067200, // 2024-01-01
    });
    const cert = Certificate{ .buffer = der, .index = 0 };
    const parsed = try cert.parse();
    try testing.expectError(error.CertificateExpired, parsed.verify(parsed, 1800000000));
}

test "selfSigned rejects an empty name" {
    const kp = try Ecdsa.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(testing.allocator);
    try testing.expectError(error.InvalidName, selfSigned(&out, testing.allocator, kp, .{
        .dns_name = "",
        .not_before = 0,
        .not_after = 1,
    }));
}
