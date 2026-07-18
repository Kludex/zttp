//! Server-certificate verification for the QUIC TLS 1.3 client (RFC 8446 4.4.2),
//! parsed the way the rest of zttp parses hostile bytes: a bounded, no-panic DER
//! reader. std.crypto.Certificate.parse indexes without bounds checks and traps on
//! malformed input - unacceptable for a certificate that arrives over the wire from
//! an untrusted peer - so we do the ASN.1 walk here and lean on std.crypto only for
//! the vetted signature math. The reader returns null on any truncation, length lie,
//! or over-deep nesting, so a crafted certificate is a clean verification failure,
//! not a crash.
//!
//! Sans-IO: the trust anchors and the current time are injected. zttp never reads a
//! trust store or a clock; the caller provides both.
//!
//! Signature coverage is the full real-world set: ECDSA P-256/P-384 and RSA
//! (PKCS#1 v1.5 and RSASSA-PSS) with SHA-256/384/512, so an ordinary chain - an
//! ECDSA or RSA leaf under RSA certificate authorities - verifies. std.crypto's own
//! DER-parsing RSA/ECDSA key loaders would reintroduce the panic, so keys are parsed
//! by the bounded reader and only the raw big-integer/point bytes reach std's math.

const std = @import("std");
const wire = @import("wire.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const rsa = std.crypto.Certificate.rsa; // the RSA math only; we do the DER ourselves
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const Trust = union(enum) {
    insecure,
    anchors: *const AnchorSet,
};

pub const Options = struct {
    trust: Trust,
    host: ?[]const u8,
    now_sec: i64,
};

pub const Error = error{
    BadCertificate,
    EmptyChain,
    HostnameMismatch,
    CertificateExpired,
    ChainUntrusted,
    OutOfMemory,
};

// -- bounded DER reader -------------------------------------------------------

// DER tags used by X.509 (RFC 5280 / X.690).
const TAG_INTEGER = 0x02;
const TAG_BITSTRING = 0x03;
const TAG_OCTETSTRING = 0x04;
const TAG_OID = 0x06;
const TAG_UTCTIME = 0x17;
const TAG_GENERALIZEDTIME = 0x18;
const TAG_SEQUENCE = 0x30;
const TAG_CONTEXT0 = 0xa0; // [0] version
const TAG_CONTEXT3 = 0xa3; // [3] extensions
const TAG_DNSNAME = 0x82; // [2] dNSName in a GeneralName

const Element = struct {
    tag: u8,
    content: []const u8, // the value bytes
    raw: []const u8, // tag + length + value, for capturing signed spans / names
};

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn atEnd(self: *const Reader) bool {
        return self.pos >= self.buf.len;
    }

    /// The next TLV element, or null on any truncation or length overflow.
    fn next(self: *Reader) ?Element {
        const start = self.pos;
        if (self.pos + 2 > self.buf.len) return null; // tag + first length octet
        const tag = self.buf[self.pos];
        self.pos += 1;
        const size_byte = self.buf[self.pos];
        self.pos += 1;
        var len: usize = size_byte;
        if (size_byte & 0x80 != 0) {
            const n: usize = size_byte & 0x7f;
            if (n == 0 or n > @sizeOf(usize) or self.pos + n > self.buf.len) return null;
            len = 0;
            for (self.buf[self.pos .. self.pos + n]) |b| len = (len << 8) | b;
            self.pos += n;
        }
        if (self.pos + len > self.buf.len) return null;
        const content = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return .{ .tag = tag, .content = content, .raw = self.buf[start..self.pos] };
    }

    fn expect(self: *Reader, tag: u8) ?Element {
        const e = self.next() orelse return null;
        if (e.tag != tag) return null;
        return e;
    }
};

// -- certificate model --------------------------------------------------------

const Curve = enum { p256, p384 };
const Hash = enum { sha256, sha384, sha512 };
const SigAlgo = union(enum) {
    ecdsa: Hash,
    rsa_pkcs1: Hash,
    rsa_pss: Hash,
};

/// A certificate's public key: whichever an issuer signs with.
const PublicKey = union(enum) {
    ecdsa: struct { curve: Curve, point: []const u8 }, // SEC1 point (0x04 || X || Y)
    rsa: struct { modulus: []const u8, exponent: []const u8 }, // big-endian, no leading zeros
};

// id-ecPublicKey / rsaEncryption, the named curves, the SubjectAltName extension,
// and the signature-algorithm OIDs (RFC 5758, RFC 8017, RFC 5480).
const OID_EC_PUBLIC_KEY = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const OID_RSA_ENCRYPTION = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
const OID_PRIME256V1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const OID_SECP384R1 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
const OID_SUBJECT_ALT_NAME = [_]u8{ 0x55, 0x1d, 0x11 };
const OID_ECDSA_SHA256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const OID_ECDSA_SHA384 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
const OID_RSA_SHA256 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
const OID_RSA_SHA384 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c };
const OID_RSA_SHA512 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d };
const OID_RSASSA_PSS = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a };
const OID_SHA256 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
const OID_SHA384 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
const OID_SHA512 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };

const Cert = struct {
    tbs: []const u8, // raw TBSCertificate: the bytes the signature covers
    issuer: []const u8, // raw issuer Name, matched against an anchor's subject
    subject: []const u8, // raw subject Name
    not_before: i64,
    not_after: i64,
    key: PublicKey,
    san: []const u8, // raw SubjectAltName GeneralNames (empty if absent)
    sig_algo: SigAlgo,
    sig: []const u8, // signatureValue: DER ECDSA-Sig-Value, or raw RSA signature

    fn validAt(self: *const Cert, now_sec: i64) bool {
        return now_sec >= self.not_before and now_sec <= self.not_after;
    }
};

fn parseCert(der: []const u8) ?Cert {
    var top = Reader{ .buf = der };
    const cert_elem = top.expect(TAG_SEQUENCE) orelse return null;
    if (!top.atEnd()) return null; // exactly one element, no trailing bytes
    var cert = Reader{ .buf = cert_elem.content };

    const tbs_elem = cert.expect(TAG_SEQUENCE) orelse return null;
    var tbs = Reader{ .buf = tbs_elem.content };

    // version [0] EXPLICIT (optional), then serialNumber.
    var e = tbs.next() orelse return null;
    if (e.tag == TAG_CONTEXT0) e = tbs.next() orelse return null;
    if (e.tag != TAG_INTEGER) return null; // serialNumber

    _ = tbs.expect(TAG_SEQUENCE) orelse return null; // signature AlgorithmIdentifier
    const issuer = tbs.expect(TAG_SEQUENCE) orelse return null;

    const validity_elem = tbs.expect(TAG_SEQUENCE) orelse return null;
    var validity = Reader{ .buf = validity_elem.content };
    const not_before = parseTime(validity.next() orelse return null) orelse return null;
    const not_after = parseTime(validity.next() orelse return null) orelse return null;

    const subject = tbs.expect(TAG_SEQUENCE) orelse return null;
    const spki = parseSpki(tbs.expect(TAG_SEQUENCE) orelse return null) orelse return null;

    // Optional extensions [3] EXPLICIT; pull the SubjectAltName if present.
    var san: []const u8 = &.{};
    while (tbs.next()) |ext_wrap| {
        if (ext_wrap.tag == TAG_CONTEXT3) san = parseSanFromExtensions(ext_wrap.content) orelse &.{};
    }

    const sig_algo = parseSigAlgo(cert.expect(TAG_SEQUENCE) orelse return null) orelse return null;
    const sig_bits = cert.expect(TAG_BITSTRING) orelse return null;
    if (sig_bits.content.len < 1 or sig_bits.content[0] != 0x00) return null; // unused-bits must be 0
    if (!cert.atEnd()) return null;

    return .{
        .tbs = tbs_elem.raw,
        .issuer = issuer.raw,
        .subject = subject.raw,
        .not_before = not_before,
        .not_after = not_after,
        .key = spki,
        .san = san,
        .sig_algo = sig_algo,
        .sig = sig_bits.content[1..],
    };
}

fn parseSpki(spki_elem: Element) ?PublicKey {
    var spki = Reader{ .buf = spki_elem.content };
    var algo = Reader{ .buf = (spki.expect(TAG_SEQUENCE) orelse return null).content };
    const algo_oid = algo.expect(TAG_OID) orelse return null;

    if (std.mem.eql(u8, algo_oid.content, &OID_EC_PUBLIC_KEY)) {
        const curve_oid = algo.expect(TAG_OID) orelse return null;
        const curve: Curve = if (std.mem.eql(u8, curve_oid.content, &OID_PRIME256V1))
            .p256
        else if (std.mem.eql(u8, curve_oid.content, &OID_SECP384R1))
            .p384
        else
            return null;
        const key_bits = spki.expect(TAG_BITSTRING) orelse return null;
        // BITSTRING: leading unused-bits octet (0), then 0x04 || X || Y.
        if (key_bits.content.len < 2 or key_bits.content[0] != 0x00 or key_bits.content[1] != 0x04) return null;
        return .{ .ecdsa = .{ .curve = curve, .point = key_bits.content[1..] } };
    }

    if (std.mem.eql(u8, algo_oid.content, &OID_RSA_ENCRYPTION)) {
        const key_bits = spki.expect(TAG_BITSTRING) orelse return null;
        if (key_bits.content.len < 1 or key_bits.content[0] != 0x00) return null; // unused bits = 0
        // The BIT STRING wraps RSAPublicKey ::= SEQUENCE { modulus, publicExponent }.
        var key = Reader{ .buf = key_bits.content[1..] };
        var rsa_seq = Reader{ .buf = (key.expect(TAG_SEQUENCE) orelse return null).content };
        const modulus = trimLeadingZeros((rsa_seq.expect(TAG_INTEGER) orelse return null).content);
        const exponent = trimLeadingZeros((rsa_seq.expect(TAG_INTEGER) orelse return null).content);
        if (modulus.len == 0 or exponent.len == 0) return null;
        return .{ .rsa = .{ .modulus = modulus, .exponent = exponent } };
    }

    return null;
}

// DER encodes a positive INTEGER with a leading 0x00 when the high bit is set;
// std's RSA math wants the raw big-endian magnitude, so strip those.
fn trimLeadingZeros(s: []const u8) []const u8 {
    var i: usize = 0;
    while (i < s.len and s[i] == 0) i += 1;
    return s[i..];
}

fn parseSigAlgo(algo_elem: Element) ?SigAlgo {
    var algo = Reader{ .buf = algo_elem.content };
    const oid = algo.expect(TAG_OID) orelse return null;
    if (std.mem.eql(u8, oid.content, &OID_ECDSA_SHA256)) return .{ .ecdsa = .sha256 };
    if (std.mem.eql(u8, oid.content, &OID_ECDSA_SHA384)) return .{ .ecdsa = .sha384 };
    if (std.mem.eql(u8, oid.content, &OID_RSA_SHA256)) return .{ .rsa_pkcs1 = .sha256 };
    if (std.mem.eql(u8, oid.content, &OID_RSA_SHA384)) return .{ .rsa_pkcs1 = .sha384 };
    if (std.mem.eql(u8, oid.content, &OID_RSA_SHA512)) return .{ .rsa_pkcs1 = .sha512 };
    if (std.mem.eql(u8, oid.content, &OID_RSASSA_PSS)) {
        // RSASSA-PSS-params carries the hash in its parameters, not the OID; the
        // MGF hash and salt length are recovered by std's PSS verify.
        const params = algo.expect(TAG_SEQUENCE) orelse return null;
        return .{ .rsa_pss = pssHash(params.content) orelse return null };
    }
    return null;
}

// The hashAlgorithm from RSASSA-PSS-params ([0] AlgorithmIdentifier), default SHA-1
// per RFC 8017 - which we do not accept, so an absent hash is a rejection.
fn pssHash(params_content: []const u8) ?Hash {
    var params = Reader{ .buf = params_content };
    while (params.next()) |field| {
        if (field.tag != TAG_CONTEXT0) continue; // [0] hashAlgorithm
        var h = Reader{ .buf = field.content };
        const oid = (h.expect(TAG_SEQUENCE) orelse return null);
        var inner = Reader{ .buf = oid.content };
        const hash_oid = inner.expect(TAG_OID) orelse return null;
        if (std.mem.eql(u8, hash_oid.content, &OID_SHA256)) return .sha256;
        if (std.mem.eql(u8, hash_oid.content, &OID_SHA384)) return .sha384;
        if (std.mem.eql(u8, hash_oid.content, &OID_SHA512)) return .sha512;
        return null;
    }
    return null;
}

// extensions [3] content is a SEQUENCE OF Extension { extnID OID, critical BOOL?,
// extnValue OCTETSTRING }. Return the SubjectAltName GeneralNames bytes, or null.
fn parseSanFromExtensions(ext_content: []const u8) ?[]const u8 {
    var outer = Reader{ .buf = ext_content };
    var list = Reader{ .buf = (outer.expect(TAG_SEQUENCE) orelse return null).content };
    while (list.next()) |ext| {
        if (ext.tag != TAG_SEQUENCE) continue;
        var one = Reader{ .buf = ext.content };
        const oid = one.expect(TAG_OID) orelse continue;
        var value = one.next() orelse continue;
        if (value.tag == 0x01) value = one.next() orelse continue; // skip critical BOOLEAN
        if (value.tag != TAG_OCTETSTRING) continue;
        if (!std.mem.eql(u8, oid.content, &OID_SUBJECT_ALT_NAME)) continue;
        // extnValue wraps a SEQUENCE OF GeneralName; return that content.
        var wrap = Reader{ .buf = value.content };
        const names = wrap.expect(TAG_SEQUENCE) orelse return null;
        return names.content;
    }
    return null;
}

// -- time ---------------------------------------------------------------------

fn parseTime(elem: Element) ?i64 {
    const b = elem.content;
    var year: i64 = undefined;
    var rest: []const u8 = undefined;
    switch (elem.tag) {
        TAG_UTCTIME => {
            if (b.len != 13 or b[12] != 'Z') return null; // YYMMDDHHMMSSZ
            const yy = twoDigit(b[0..2]) orelse return null;
            year = 2000 + @as(i64, yy); // RFC 5280: 2-digit years are 20YY (valid through 2049)
            rest = b[2..12];
        },
        TAG_GENERALIZEDTIME => {
            if (b.len != 15 or b[14] != 'Z') return null; // YYYYMMDDHHMMSSZ
            const y = fourDigit(b[0..4]) orelse return null;
            year = y;
            rest = b[4..14];
        },
        else => return null,
    }
    const month = twoDigit(rest[0..2]) orelse return null;
    const day = twoDigit(rest[2..4]) orelse return null;
    const hour = twoDigit(rest[4..6]) orelse return null;
    const minute = twoDigit(rest[6..8]) orelse return null;
    const second = twoDigit(rest[8..10]) orelse return null;
    if (month < 1 or month > 12 or day < 1 or day > 31 or hour > 23 or minute > 59 or second > 60) return null;
    return civilToUnix(year, month, day, hour, minute, second);
}

fn twoDigit(s: *const [2]u8) ?u8 {
    if (s[0] < '0' or s[0] > '9' or s[1] < '0' or s[1] > '9') return null;
    return (s[0] - '0') * 10 + (s[1] - '0');
}

fn fourDigit(s: *const [4]u8) ?i64 {
    var v: i64 = 0;
    for (s) |ch| {
        if (ch < '0' or ch > '9') return null;
        v = v * 10 + (ch - '0');
    }
    return v;
}

// Howard Hinnant's days_from_civil, then seconds. Valid for the whole X.509 range.
fn civilToUnix(year: i64, month: u8, day: u8, hour: u8, minute: u8, second: u8) i64 {
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe = y - era * 400;
    const m: i64 = month;
    const doy = @divFloor(153 * (if (m > 2) m - 3 else m + 9) + 2, 5) + @as(i64, day) - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
}

// -- signature + hostname -----------------------------------------------------

// Verify `sig` over `tbs` with the issuer's key, per `algo`. All parse/verify
// errors collapse to false; a crafted signature or key is a rejection, not a trap.
fn verifySignature(tbs: []const u8, algo: SigAlgo, sig: []const u8, issuer_key: PublicKey) bool {
    switch (algo) {
        .ecdsa => |hash| {
            const ec = switch (issuer_key) {
                .ecdsa => |e| e,
                else => return false,
            };
            switch (hash) {
                .sha256 => {
                    if (ec.curve != .p256) return false;
                    const pk = EcdsaP256.PublicKey.fromSec1(ec.point) catch return false;
                    const s = EcdsaP256.Signature.fromDer(sig) catch return false;
                    s.verify(tbs, pk) catch return false;
                    return true;
                },
                .sha384 => {
                    if (ec.curve != .p384) return false;
                    const pk = EcdsaP384.PublicKey.fromSec1(ec.point) catch return false;
                    const s = EcdsaP384.Signature.fromDer(sig) catch return false;
                    s.verify(tbs, pk) catch return false;
                    return true;
                },
                .sha512 => return false, // no ECDSA P-521
            }
        },
        .rsa_pkcs1 => |hash| return rsaVerify(.pkcs1, hash, tbs, sig, issuer_key),
        .rsa_pss => |hash| return rsaVerify(.pss, hash, tbs, sig, issuer_key),
    }
}

const RsaPad = enum { pkcs1, pss };

fn rsaVerify(pad: RsaPad, hash: Hash, tbs: []const u8, sig: []const u8, issuer_key: PublicKey) bool {
    const key = switch (issuer_key) {
        .rsa => |k| k,
        else => return false,
    };
    // std's RSA verify is generic over the modulus length at comptime; support the
    // standard 1024/2048/3072/4096-bit sizes.
    return switch (key.modulus.len) {
        inline 128, 256, 384, 512 => |mlen| blk: {
            if (sig.len != mlen) break :blk false;
            const pk = rsa.PublicKey.fromBytes(key.exponent, key.modulus) catch break :blk false;
            const sig_arr: [mlen]u8 = sig[0..mlen].*;
            (switch (pad) {
                .pkcs1 => switch (hash) {
                    .sha256 => rsa.PKCS1v1_5Signature.verify(mlen, sig_arr, tbs, pk, Sha256),
                    .sha384 => rsa.PKCS1v1_5Signature.verify(mlen, sig_arr, tbs, pk, Sha384),
                    .sha512 => rsa.PKCS1v1_5Signature.verify(mlen, sig_arr, tbs, pk, Sha512),
                },
                .pss => switch (hash) {
                    .sha256 => rsa.PSSSignature.verify(mlen, sig_arr, tbs, pk, Sha256),
                    .sha384 => rsa.PSSSignature.verify(mlen, sig_arr, tbs, pk, Sha384),
                    .sha512 => rsa.PSSSignature.verify(mlen, sig_arr, tbs, pk, Sha512),
                },
            }) catch break :blk false;
            break :blk true;
        },
        else => false,
    };
}

// RFC 6125 hostname match against the leaf's dNSName SANs: case-insensitive, with a
// single leftmost-label wildcard (*.example.com matches a.example.com, not b.a...).
fn hostMatchesSan(san: []const u8, host: []const u8) bool {
    var names = Reader{ .buf = san };
    while (names.next()) |name| {
        if (name.tag != TAG_DNSNAME) continue;
        if (dnsNameMatches(name.content, host)) return true;
    }
    return false;
}

fn dnsNameMatches(pattern: []const u8, host: []const u8) bool {
    if (pattern.len >= 2 and pattern[0] == '*' and pattern[1] == '.') {
        const suffix = pattern[1..]; // ".example.com"
        const dot = std.mem.indexOfScalar(u8, host, '.') orelse return false;
        return host.len > dot and asciiEqlIgnoreCase(host[dot..], suffix);
    }
    return asciiEqlIgnoreCase(pattern, host);
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

// -- trust anchors ------------------------------------------------------------

pub const AnchorSet = struct {
    ders: std.ArrayListUnmanaged([]u8) = .empty,

    pub const empty: AnchorSet = .{};

    /// Copy a DER certificate in as a trust anchor. Rejects anything that does not
    /// parse, so the set only ever holds usable anchors.
    pub fn addDer(self: *AnchorSet, gpa: std.mem.Allocator, der: []const u8) !void {
        if (parseCert(der) == null) return error.BadCertificate;
        const owned = try gpa.dupe(u8, der);
        errdefer gpa.free(owned);
        try self.ders.append(gpa, owned);
    }

    pub fn deinit(self: *AnchorSet, gpa: std.mem.Allocator) void {
        for (self.ders.items) |d| gpa.free(d);
        self.ders.deinit(gpa);
        self.* = undefined;
    }

    pub fn count(self: *const AnchorSet) usize {
        return self.ders.items.len;
    }

    // Whether some anchor issued `subject`: its subject name matches, it is in date,
    // and it verifies `subject`'s signature.
    fn issuerOf(self: *const AnchorSet, subject: *const Cert, now_sec: i64) bool {
        for (self.ders.items) |der| {
            const anchor = parseCert(der) orelse continue;
            if (!std.mem.eql(u8, anchor.subject, subject.issuer)) continue;
            if (!anchor.validAt(now_sec)) continue;
            if (verifySignature(subject.tbs, subject.sig_algo, subject.sig, anchor.key)) return true;
        }
        return false;
    }
};

// -- entry point --------------------------------------------------------------

/// Verify the body of a TLS 1.3 Certificate message: the leaf must be trusted for
/// `host` at `now_sec`. Mirrors std.crypto.tls.Client's walk - hostname on the
/// leaf, each link signed by the next, up to a configured anchor.
pub fn verifyCertificateMessage(body: []const u8, opts: Options) Error!void {
    var r = wire.Reader{ .buf = body };
    _ = r.vector(1) catch return error.BadCertificate; // certificate_request_context
    var list = r.vector(3) catch return error.BadCertificate; // certificate_list
    r.expectEnd() catch return error.BadCertificate;
    if (list.remaining() == 0) return error.EmptyChain;

    switch (opts.trust) {
        .insecure => return,
        .anchors => |anchors| {
            var prev: Cert = undefined;
            var index: usize = 0;
            while (list.remaining() != 0) : (index += 1) {
                const cert_der = (list.vector(3) catch return error.BadCertificate).buf;
                _ = list.vector(2) catch return error.BadCertificate; // entry extensions
                const cert = parseCert(cert_der) orelse return error.BadCertificate;
                if (!cert.validAt(opts.now_sec)) return error.CertificateExpired;

                if (index == 0) {
                    if (opts.host) |h| {
                        if (!hostMatchesSan(cert.san, h)) return error.HostnameMismatch;
                    }
                } else if (!verifySignature(prev.tbs, prev.sig_algo, prev.sig, cert.key)) {
                    return error.BadCertificate;
                }

                if (anchors.issuerOf(&cert, opts.now_sec)) return; // reached a trust anchor
                prev = cert;
            }
            return error.ChainUntrusted;
        },
    }
}

// -- tests --------------------------------------------------------------------

const testing = std.testing;
const x509 = @import("x509.zig");

const NOW: i64 = 1700000000; // 2023-11-14
const NOT_BEFORE: i64 = 1672531200; // 2023-01-01
const NOT_AFTER: i64 = 1988150400; // 2033-01-01

fn certMessage(gpa: std.mem.Allocator, ders: []const []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.append(gpa, 0x00);
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
        try out.appendSlice(gpa, &.{ 0x00, 0x00 });
    }
    return out.toOwnedSlice(gpa);
}

fn selfSigned(gpa: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), seed: [32]u8, dns: []const u8, na: i64) ![]const u8 {
    const kp = try EcdsaP256.KeyPair.generateDeterministic(seed);
    return x509.selfSigned(buf, gpa, kp, .{ .dns_name = dns, .not_before = NOT_BEFORE, .not_after = na });
}

test "parseCert extracts the fields x509.selfSigned wrote" {
    const gpa = testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    const der = try selfSigned(gpa, &buf, [_]u8{0x42} ** 32, "example.com", NOT_AFTER);
    const cert = parseCert(der) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(i64, NOT_BEFORE), cert.not_before);
    try testing.expectEqual(@as(i64, NOT_AFTER), cert.not_after);
    try testing.expectEqual(Curve.p256, cert.key.ecdsa.curve);
    try testing.expect(hostMatchesSan(cert.san, "example.com"));
    try testing.expect(!hostMatchesSan(cert.san, "evil.com"));
    try testing.expect(std.mem.eql(u8, cert.issuer, cert.subject)); // self-signed
}

test "pinned self-signed leaf is accepted for its host, rejected otherwise" {
    const gpa = testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    const der = try selfSigned(gpa, &buf, [_]u8{0x42} ** 32, "example.com", NOT_AFTER);
    var anchors = AnchorSet.empty;
    defer anchors.deinit(gpa);
    try anchors.addDer(gpa, der);
    const msg = try certMessage(gpa, &.{der});
    defer gpa.free(msg);

    try verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &anchors }, .host = "example.com", .now_sec = NOW });
    try testing.expectError(error.HostnameMismatch, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &anchors }, .host = "evil.com", .now_sec = NOW }));
}

test "an untrusted (empty-anchor) leaf is rejected" {
    const gpa = testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    const der = try selfSigned(gpa, &buf, [_]u8{0x42} ** 32, "example.com", NOT_AFTER);
    var anchors = AnchorSet.empty;
    defer anchors.deinit(gpa);
    const msg = try certMessage(gpa, &.{der});
    defer gpa.free(msg);
    try testing.expectError(error.ChainUntrusted, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &anchors }, .host = "example.com", .now_sec = NOW }));
}

test "an expired leaf is rejected" {
    const gpa = testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    const der = try selfSigned(gpa, &buf, [_]u8{0x42} ** 32, "example.com", 1704067200); // expires 2024-01-01
    var anchors = AnchorSet.empty;
    defer anchors.deinit(gpa);
    try anchors.addDer(gpa, der);
    const msg = try certMessage(gpa, &.{der});
    defer gpa.free(msg);
    try testing.expectError(error.CertificateExpired, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &anchors }, .host = "example.com", .now_sec = 1800000000 }));
}

test "a tampered signature is rejected" {
    const gpa = testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    const der = try selfSigned(gpa, &buf, [_]u8{0x42} ** 32, "example.com", NOT_AFTER);
    const bad = try gpa.dupe(u8, der);
    defer gpa.free(bad);
    bad[bad.len - 1] ^= 0xff; // flip a signature byte
    var anchors = AnchorSet.empty;
    defer anchors.deinit(gpa);
    try anchors.addDer(gpa, der); // trust the pristine cert
    const msg = try certMessage(gpa, &.{bad});
    defer gpa.free(msg);
    try testing.expectError(error.ChainUntrusted, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &anchors }, .host = "example.com", .now_sec = NOW }));
}

test "a leaf signed by a trusted CA verifies through the chain" {
    const gpa = testing.allocator;
    const ca_kp = try EcdsaP256.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    const leaf_kp = try EcdsaP256.KeyPair.generateDeterministic([_]u8{0x22} ** 32);
    var ca_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer ca_buf.deinit(gpa);
    const ca_der = try x509.selfSigned(&ca_buf, gpa, ca_kp, .{ .dns_name = "zttp Test CA", .not_before = NOT_BEFORE, .not_after = NOT_AFTER });
    var leaf_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer leaf_buf.deinit(gpa);
    const leaf_der = try x509.signedBy(&leaf_buf, gpa, leaf_kp.public_key, ca_kp, "zttp Test CA", .{ .dns_name = "example.com", .not_before = NOT_BEFORE, .not_after = NOT_AFTER });

    var anchors = AnchorSet.empty;
    defer anchors.deinit(gpa);
    try anchors.addDer(gpa, ca_der); // trust the CA only
    const msg = try certMessage(gpa, &.{ leaf_der, ca_der });
    defer gpa.free(msg);
    try verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &anchors }, .host = "example.com", .now_sec = NOW });

    var empty2 = AnchorSet.empty;
    defer empty2.deinit(gpa);
    try testing.expectError(error.ChainUntrusted, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &empty2 }, .host = "example.com", .now_sec = NOW }));
}

// Real OpenSSL fixtures (valid 2026-07 .. 2036-07): an ECDSA P-256 leaf for
// example.test signed by a 2048-bit RSA root (sha256WithRSAEncryption), and an
// RSA-PSS self-signed cert for pss.test. These exercise the RSA verification the
// public web needs - ECDSA/RSA leaves under RSA certificate authorities.
const RSA_NOW: i64 = 1800000000; // 2027-01-15, inside the fixtures' window
const RSA_ROOT_HEX = "30820311308201f9a003020102021446201ad42ef894e101f97948bbb9080643f3b56d300d06092a864886f70d01010b050030183116301406035504030c0d7a7474702052534120526f6f74301e170d3236303731383131333134305a170d3336303731353131333134305a30183116301406035504030c0d7a7474702052534120526f6f7430820122300d06092a864886f70d01010105000382010f003082010a0282010100b0a78a6bde412ab773f447b7a0fb16d69f53d62e29d3313e9010e6541cdd1f426b17b4c1870c77497cde8f965f9545ca69baaf2c481d13da0380a292f9123c42e3321919243e0749e85f4495b119fc5727808231e41e5f6e56888603cc52d0989c7456e2b57796ceb9f3b3c7ab2627972e4e5811a44b84fe1a2041caa3647756f459aa704b18399afa05ea414ac62a5f1ad299d84d906669b5edae488fc8aeeea3e3f186286dfd7beadd5e89eb4a708e26badced8ae10b0de3f641afab5b3c3b598844776c5ee608231dc51dd888c272c033e3308ad2e2ea366593569321c37623a77e7c34eb74b53e148bfb201273ad946e3074ba9df347151eea5f4077d7db0203010001a3533051301d0603551d0e041604142487baccc2bd48dc5c60ce2538e8915b205c4534301f0603551d230418301680142487baccc2bd48dc5c60ce2538e8915b205c4534300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100875c7d06e4193c10b63b95adf9ebe6ede2d0f20738aed10dea48e05258d07c514c10757ff0fd1d765fa46fe87491e2f2e848d5642995e507993d8618b96005b580bccb7c0cdc43af6155e0192d521984a23b81a597e2f0fe7414cbed3da532d549057c327c7af18c695e22a8c60d92e35e8d577fac73751204d755f31bc90e5dfedc88de1795157d7e728369bea8350a9b7621526dc2994725f67cb1fc1cc02002befba88b9b075e511435d7336dfa86062cb22a35067531dc4d3e328015078004def1944b401e022c3173736c0c622a4f2547626f3ffd0448042137c184bb712b945f6c8171f78af7ff98fd06438c5f172a821d4c7f063daa5b60d3dfcc9fc8";
const RSA_LEAF_HEX = "3082025830820140a003020102021464d6997c5b2357f7c8d31d41e828e59077374475300d06092a864886f70d01010b050030183116301406035504030c0d7a7474702052534120526f6f74301e170d3236303731383131333135345a170d3336303731353131333135345a30173115301306035504030c0c6578616d706c652e746573743059301306072a8648ce3d020106082a8648ce3d03010703420004647bf087fffd6f44fee6402f9da534992376ac150545606a94a5d66bb405b9dc099722fd069974f64b3d937353a1e8bccb97fb98ce212985cf359624b3c11d29a366306430170603551d110410300e820c6578616d706c652e7465737430090603551d1304023000301d0603551d0e0416041447330cef7e7defc29784ddf12dff4acce5eeca77301f0603551d230418301680142487baccc2bd48dc5c60ce2538e8915b205c4534300d06092a864886f70d01010b05000382010100483645b2a2fe6145035f0ad256ed88a9284a9b8c6a227eb59992d6eaad40784c7c4e0c2fc5828b065a19f47bdc6f6aedb550fd70f3fb35e4acb0ea2c644deac119c0cef4037dbed9b14bf5fa37649acf5ba2906c20cd882cd88747e1d84d1e8e9d84dce524cae99b42e42569de5f067d069d841c5750d02d8a1bd7423168c7f0794b2279ca6bc86391b9819a796d7ff49c3ee5a122d01dac1debb4098820f30d1d9a885a69fad9aba1d0436155f18427003baa05cec23254aaf78da8c010e1d7f1c0b7722d11a0079e7c5785f6accbaa6c1a44e905ce936a740e81dbe402a7be231f321d84435e868c8ebef395caab0ba5fbf200facabe740b191439d56334b7";
const RSA_PSS_HEX = "3082038430820238a00302010202144c9aa9be675ea2c70fb3eaf0652efbcaedb7267b304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012030133111300f06035504030c087a74747020505353301e170d3236303731383131333135345a170d3336303731353131333135345a30133111300f06035504030c087a7474702050535330820122300d06092a864886f70d01010105000382010f003082010a028201010091f8e63579a5f62111c6d9efc71086f5c9ce161001e78d35d1ef6bc966b8ae230839023e25966652aeae7634c6ed2690399faa5ab8d5fc504c75fcaee168208d6077f7851222b1ca5b8912f645dcd5ef0cafe8ca7f9cd17e29b69bb81c2ab11529d6940e47c48083b5f2c2d6a6a5b257b9dc0f2235873885923943b9cf6eaec1931847588e4a36dbd1a7f2a83c6bc740c30ccf4ebe892c6b957a498ae41f6ac4c7b0ef41ff8c959516028b69008d8ec329e4ec22f615fe22edbf6c6ce6089903ed131c10c13bfcd89fc6e21c76eb53641cd7cf4316be06279ec6b02f46cbe7a19f4c1520bb6247e50b552f8644ca9ff3d1e1f7b6c97853701c0f43e6767806830203010001a3683066301d0603551d0e0416041479576872874ab226e776044a2259fb74a2b2c659301f0603551d2304183016801479576872874ab226e776044a2259fb74a2b2c659300f0603551d130101ff040530030101ff30130603551d11040c300a82087073732e74657374304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012003820101001e69e1e65928d62f9df8069475a6ff81b6dd08799c31d97633226d8fe173a3ee4c271c813bcd3f677ac70ec16115e9b27ccd240e5d6909ceec245c7e0edd73f5e4bed29793ae13be8c6c0d7462063db9c8d4bc4f9736fe9f3d69ae2a2cebc05cc94eb83052f0e9eaccfe2f5c10b70ad66063b23ff33a1e5e9681a2fb5da43f5c574adaec1c63e949915a99f409e9e66fda001a12ddcc42eae575044f241eb527d0ad3f767e2b3650f920395391420cd4921157218b73f246ed355b30d9947f822698149e0ec7c0ad1259046387acbce0d8d12c1d4be5bf19bf71373aa45b2447c0ded9cbb5fb7b5edbc10d57037e3a99d680b5dc63b966ca32a29d7925415e76";

fn hexDer(gpa: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, hex.len / 2);
    errdefer gpa.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

test "an ECDSA leaf under an RSA certificate authority verifies" {
    const gpa = testing.allocator;
    const root = try hexDer(gpa, RSA_ROOT_HEX);
    defer gpa.free(root);
    const leaf = try hexDer(gpa, RSA_LEAF_HEX);
    defer gpa.free(leaf);
    var anchors = AnchorSet.empty;
    defer anchors.deinit(gpa);
    try anchors.addDer(gpa, root); // trust the RSA root only
    const msg = try certMessage(gpa, &.{ leaf, root });
    defer gpa.free(msg);

    try verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &anchors }, .host = "example.test", .now_sec = RSA_NOW });
    try testing.expectError(error.HostnameMismatch, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &anchors }, .host = "evil.test", .now_sec = RSA_NOW }));

    var empty2 = AnchorSet.empty;
    defer empty2.deinit(gpa);
    try testing.expectError(error.ChainUntrusted, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &empty2 }, .host = "example.test", .now_sec = RSA_NOW }));
}

test "a tampered RSA-signed leaf is rejected" {
    const gpa = testing.allocator;
    const root = try hexDer(gpa, RSA_ROOT_HEX);
    defer gpa.free(root);
    const leaf = try hexDer(gpa, RSA_LEAF_HEX);
    defer gpa.free(leaf);
    leaf[leaf.len - 1] ^= 0xff; // corrupt the RSA signature
    var anchors = AnchorSet.empty;
    defer anchors.deinit(gpa);
    try anchors.addDer(gpa, root);
    const msg = try certMessage(gpa, &.{ leaf, root });
    defer gpa.free(msg);
    // The leaf no longer verifies against the CA (the "each link signed by the next"
    // check), so the chain is rejected.
    try testing.expectError(error.BadCertificate, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &anchors }, .host = "example.test", .now_sec = RSA_NOW }));
}

test "an RSA-PSS self-signed certificate verifies" {
    const gpa = testing.allocator;
    const pss = try hexDer(gpa, RSA_PSS_HEX);
    defer gpa.free(pss);
    var anchors = AnchorSet.empty;
    defer anchors.deinit(gpa);
    try anchors.addDer(gpa, pss);
    const msg = try certMessage(gpa, &.{pss});
    defer gpa.free(msg);
    try verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &anchors }, .host = "pss.test", .now_sec = RSA_NOW });
    try testing.expectError(error.HostnameMismatch, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &anchors }, .host = "no.test", .now_sec = RSA_NOW }));
}

test "insecure trust skips verification but still requires a leaf" {
    const gpa = testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    const der = try selfSigned(gpa, &buf, [_]u8{0x42} ** 32, "whatever", NOT_AFTER);
    const msg = try certMessage(gpa, &.{der});
    defer gpa.free(msg);
    try verifyCertificateMessage(msg, .{ .trust = .insecure, .host = "anything", .now_sec = NOW });
    const empty_msg = try certMessage(gpa, &.{});
    defer gpa.free(empty_msg);
    try testing.expectError(error.EmptyChain, verifyCertificateMessage(empty_msg, .{ .trust = .insecure, .host = null, .now_sec = NOW }));
}

test "malformed certificates are rejected, never panic" {
    const gpa = testing.allocator;
    const cases = [_][]const u8{
        &.{},
        "not a cert",
        &.{ 0x30, 0x82, 0xff, 0xff }, // length lies past the buffer
        &.{ 0x30, 0x03, 0x02, 0x01, 0x01 }, // valid DER, wrong shape (traps std.crypto)
        &.{ 0x30, 0x00 }, // empty SEQUENCE
        &.{ 0x30, 0x80 }, // indefinite length (not DER)
    };
    for (cases) |bad| {
        try testing.expect(parseCert(bad) == null);
        var anchors = AnchorSet.empty;
        defer anchors.deinit(gpa);
        try testing.expectError(error.BadCertificate, anchors.addDer(gpa, bad));
    }
    var anchors2 = AnchorSet.empty;
    defer anchors2.deinit(gpa);
    const msg = try certMessage(gpa, &.{&.{ 0x30, 0x03, 0x02, 0x01, 0x01 }});
    defer gpa.free(msg);
    try testing.expectError(error.BadCertificate, verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &anchors2 }, .host = "x", .now_sec = NOW }));
}

test "fuzz: parseCert and verify never panic on adversarial certificates" {
    const gpa = testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    const valid = try selfSigned(gpa, &buf, [_]u8{0x42} ** 32, "example.com", NOT_AFTER);

    var empty = AnchorSet.empty; // forces the chain walk to parse every cert
    defer empty.deinit(gpa);

    // Deterministic PRNG (Math.random is unavailable and non-reproducible anyway):
    // random noise, truncated valid certs, and valid certs with a few bytes flipped
    // - the "almost valid" shapes a bounded reader most needs to survive.
    var prng = std.Random.DefaultPrng.init(0x7838353039);
    const rand = prng.random();
    var work: [1024]u8 = undefined;
    for (0..3000) |_| {
        const bytes = switch (rand.intRangeAtMost(u8, 0, 2)) {
            0 => noise: {
                const len = rand.intRangeAtMost(usize, 0, work.len);
                for (work[0..len]) |*b| b.* = rand.int(u8);
                break :noise work[0..len];
            },
            1 => truncated: {
                const len = rand.intRangeAtMost(usize, 0, valid.len);
                @memcpy(work[0..len], valid[0..len]);
                break :truncated work[0..len];
            },
            else => flipped: {
                @memcpy(work[0..valid.len], valid);
                const flips = rand.intRangeAtMost(usize, 1, 8);
                for (0..flips) |_| work[rand.intRangeAtMost(usize, 0, valid.len - 1)] ^= rand.int(u8);
                break :flipped work[0..valid.len];
            },
        };
        _ = parseCert(bytes); // must never panic
        const msg = try certMessage(gpa, &.{bytes});
        defer gpa.free(msg);
        verifyCertificateMessage(msg, .{ .trust = .{ .anchors = &empty }, .host = "x", .now_sec = NOW }) catch {};
    }
}
