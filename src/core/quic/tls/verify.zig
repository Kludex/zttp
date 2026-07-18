//! Server-certificate verification for the QUIC TLS 1.3 client (RFC 8446 4.4.2),
//! parsed the way the rest of zttp parses hostile bytes: a bounded, no-panic DER
//! reader. std.crypto.Certificate.parse indexes without bounds checks and traps on
//! malformed input - unacceptable for a certificate that arrives over the wire from
//! an untrusted peer - so we do the ASN.1 walk here and lean on std.crypto only for
//! the vetted ECDSA math. The reader returns null on any truncation, length lie, or
//! over-deep nesting, so a crafted certificate is a clean verification failure, not
//! a crash.
//!
//! Sans-IO: the trust anchors and the current time are injected. zttp never reads a
//! trust store or a clock; the caller provides both.
//!
//! Scope: the leaf and every chain link must be ECDSA P-256/P-384 (the schemes zttp
//! itself speaks). RSA links are unsupported and fail verification, not the parser.

const std = @import("std");
const wire = @import("wire.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

pub const Trust = union(enum) {
    insecure,
    anchors: *const AnchorSet,
    /// Trust is decided by an injected callback (e.g. the OS-native verifier, via
    /// the integrator's I/O layer). The core still does no I/O - it hands the raw
    /// chain to `call` and honors the verdict, like rustls's ServerCertVerifier.
    verifier: Verifier,
};

pub const Verifier = struct {
    ctx: *anyopaque,
    call: *const fn (ctx: *anyopaque, chain: []const []const u8, host: ?[]const u8, now_sec: i64) bool,
};

/// Certificate chains longer than this are refused before the callback runs; real
/// chains are a handful of certificates and this bounds the on-stack chain array.
pub const MAX_CHAIN = 12;

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
const SigAlgo = enum { ecdsa_sha256, ecdsa_sha384 };

// ecdsa-with-SHA256 / -SHA384 (RFC 5758), id-ecPublicKey, and the two named curves.
const OID_ECDSA_SHA256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const OID_ECDSA_SHA384 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
const OID_EC_PUBLIC_KEY = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const OID_PRIME256V1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const OID_SECP384R1 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
const OID_SUBJECT_ALT_NAME = [_]u8{ 0x55, 0x1d, 0x11 };

const Cert = struct {
    tbs: []const u8, // raw TBSCertificate: the bytes the signature covers
    issuer: []const u8, // raw issuer Name, matched against an anchor's subject
    subject: []const u8, // raw subject Name
    not_before: i64,
    not_after: i64,
    curve: Curve,
    point: []const u8, // SEC1 public point (0x04 || X || Y)
    san: []const u8, // raw SubjectAltName GeneralNames (empty if absent)
    sig_algo: SigAlgo,
    sig: []const u8, // DER ECDSA-Sig-Value

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
        .curve = spki.curve,
        .point = spki.point,
        .san = san,
        .sig_algo = sig_algo,
        .sig = sig_bits.content[1..],
    };
}

const Spki = struct { curve: Curve, point: []const u8 };

fn parseSpki(spki_elem: Element) ?Spki {
    var spki = Reader{ .buf = spki_elem.content };
    var algo = Reader{ .buf = (spki.expect(TAG_SEQUENCE) orelse return null).content };
    const algo_oid = algo.expect(TAG_OID) orelse return null;
    if (!std.mem.eql(u8, algo_oid.content, &OID_EC_PUBLIC_KEY)) return null;
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
    return .{ .curve = curve, .point = key_bits.content[1..] };
}

fn parseSigAlgo(algo_elem: Element) ?SigAlgo {
    var algo = Reader{ .buf = algo_elem.content };
    const oid = algo.expect(TAG_OID) orelse return null;
    if (std.mem.eql(u8, oid.content, &OID_ECDSA_SHA256)) return .ecdsa_sha256;
    if (std.mem.eql(u8, oid.content, &OID_ECDSA_SHA384)) return .ecdsa_sha384;
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
fn verifySignature(tbs: []const u8, algo: SigAlgo, sig: []const u8, issuer_curve: Curve, issuer_point: []const u8) bool {
    switch (algo) {
        .ecdsa_sha256 => {
            if (issuer_curve != .p256) return false;
            const pk = EcdsaP256.PublicKey.fromSec1(issuer_point) catch return false;
            const s = EcdsaP256.Signature.fromDer(sig) catch return false;
            s.verify(tbs, pk) catch return false;
            return true;
        },
        .ecdsa_sha384 => {
            if (issuer_curve != .p384) return false;
            const pk = EcdsaP384.PublicKey.fromSec1(issuer_point) catch return false;
            const s = EcdsaP384.Signature.fromDer(sig) catch return false;
            s.verify(tbs, pk) catch return false;
            return true;
        },
    }
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
            if (verifySignature(subject.tbs, subject.sig_algo, subject.sig, anchor.curve, anchor.point)) return true;
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
        .verifier => |v| {
            // Hand the raw chain to the caller's verifier and honor its verdict.
            var chain: [MAX_CHAIN][]const u8 = undefined;
            var n: usize = 0;
            while (list.remaining() != 0) {
                if (n >= MAX_CHAIN) return error.BadCertificate;
                chain[n] = (list.vector(3) catch return error.BadCertificate).buf;
                _ = list.vector(2) catch return error.BadCertificate; // entry extensions
                n += 1;
            }
            if (v.call(v.ctx, chain[0..n], opts.host, opts.now_sec)) return;
            return error.ChainUntrusted;
        },
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
                } else if (!verifySignature(prev.tbs, prev.sig_algo, prev.sig, cert.curve, cert.point)) {
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
    try testing.expectEqual(Curve.p256, cert.curve);
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

test "a verifier callback decides trust and receives the chain" {
    const gpa = testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    const der = try selfSigned(gpa, &buf, [_]u8{0x42} ** 32, "example.com", NOT_AFTER);
    const msg = try certMessage(gpa, &.{der});
    defer gpa.free(msg);

    const Ctx = struct {
        seen_certs: usize = 0,
        seen_host_len: usize = 0,
        accept: bool,
        fn call(ctx: *anyopaque, chain: []const []const u8, host: ?[]const u8, now_sec: i64) bool {
            _ = now_sec;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.seen_certs = chain.len;
            self.seen_host_len = if (host) |h| h.len else 0;
            return self.accept;
        }
    };
    var ctx = Ctx{ .accept = true };
    const trust: Trust = .{ .verifier = .{ .ctx = &ctx, .call = Ctx.call } };
    try verifyCertificateMessage(msg, .{ .trust = trust, .host = "example.com", .now_sec = NOW });
    try testing.expectEqual(@as(usize, 1), ctx.seen_certs); // the callback saw the leaf
    try testing.expectEqual(@as(usize, 11), ctx.seen_host_len); // and the host "example.com"

    ctx.accept = false;
    try testing.expectError(error.ChainUntrusted, verifyCertificateMessage(msg, .{ .trust = trust, .host = "example.com", .now_sec = NOW }));
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
