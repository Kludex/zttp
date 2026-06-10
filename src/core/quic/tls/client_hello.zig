//! The ClientHello parser (RFC 8446 4.1.2): the one big handshake-message decoder
//! a TLS 1.3 server runs. It carves the fixed prefix, loops the extension block
//! through extension.decode, and routes everything through `Fields`, which rejects
//! duplicates and enforces the single-suite policy in one auditable `finish`.
//!
//! All slices borrow from the fed buffer (zero-copy); crypto inputs are fixed
//! arrays so they drop straight into the crypto core. The transcript consumes
//! `raw`, the exact wire bytes of the message.

const std = @import("std");
const wire = @import("wire.zig");
const extension = @import("extension.zig");
const sign = @import("sign.zig");

const SUITE_AES128_GCM_SHA256: u16 = 0x1301;

pub const ClientHello = struct {
    raw: []const u8, // type || u24 len || body, for transcript.update
    random: [32]u8,
    legacy_session_id: []const u8, // 0 or 32 bytes; echoed verbatim in ServerHello
    cipher_suites: []const u8, // raw u16 list
    client_key_share: [32]u8, // x25519 public key -> keyshare.shared
    key_share_group: u16, // X25519
    signature_schemes: []const u8, // raw u16 list
    server_name: ?[]const u8,
    alpn: ?[]const u8, // raw ProtocolNameList body, or null
    quic_transport_parameters: []const u8,
};

pub const Decoded = struct { value: ClientHello, len: usize };

/// Parse the ClientHello at the start of `buf`. `buf` MUST be the contiguous,
/// in-order CRYPTO-stream prefix holding at least the whole message; reassembly of
/// fragmented/reordered CRYPTO frames is the connection layer's job (see
/// handshake.peek for the "is a whole message buffered yet" gate). Returns the
/// consumed length so the caller can advance to the next message.
pub fn parse(buf: []const u8) wire.Error!Decoded {
    var outer = wire.Reader{ .buf = buf };
    if (try outer.byte() != 0x01) return error.EncodingError; // handshake type client_hello
    const body_len = try outer.readU24();
    const body = try outer.take(body_len);
    const raw = buf[0 .. 4 + @as(usize, body_len)];

    var r = wire.Reader{ .buf = body };
    if (try r.readU16() != 0x0303) return error.EncodingError; // legacy_version MUST be 1.2
    const random = (try r.take(32))[0..32].*;
    const session_id = (try r.vector(1)).buf;
    if (session_id.len != 0 and session_id.len != 32) return error.EncodingError;
    const cipher_suites = (try r.vector(2)).buf;
    if (cipher_suites.len == 0 or cipher_suites.len % 2 != 0) return error.EncodingError;
    const compression = (try r.vector(1)).buf;
    if (compression.len != 1 or compression[0] != 0x00) return error.EncodingError;

    var fields = Fields{};
    var exts = try r.vector(2); // extensions<8..2^16-1>
    try r.expectEnd();
    while (exts.remaining() != 0) {
        try fields.apply(try extension.decode(&exts));
    }
    return .{
        .value = try fields.finish(raw, random, session_id, cipher_suites),
        .len = 4 + @as(usize, body_len),
    };
}

/// Accumulates the extensions, rejecting duplicates, and gates the whole message
/// on the single-suite policy in `finish` - the one place every must-have check lives.
const Fields = struct {
    seen: std.EnumSet(extension.ExtType) = .{},
    key_share: ?extension.KeyShareEntry = null,
    supported_groups: ?[]const u8 = null,
    sig_algs: ?[]const u8 = null,
    tls13: bool = false,
    sni: ?[]const u8 = null,
    alpn: ?[]const u8 = null,
    qtp: ?[]const u8 = null,

    fn apply(self: *Fields, ext: extension.Extension) wire.Error!void {
        const ty: extension.ExtType = switch (ext) {
            .server_name => .server_name,
            .supported_groups => .supported_groups,
            .signature_algorithms => .signature_algorithms,
            .alpn => .alpn,
            .supported_versions => .supported_versions,
            .key_share => .key_share,
            .quic_transport_parameters => .quic_transport_parameters,
            .unknown => return, // ignore unrecognized; do not track for dup-detection
        };
        if (self.seen.contains(ty)) return error.EncodingError; // RFC 8446 4.2: no dup extensions
        self.seen.insert(ty);
        switch (ext) {
            .key_share => |k| self.key_share = k,
            .supported_groups => |g| self.supported_groups = g,
            .signature_algorithms => |s| self.sig_algs = s,
            .supported_versions => |v| self.tls13 = v,
            .server_name => |n| self.sni = if (n.len == 0) null else n,
            .alpn => |a| self.alpn = a,
            .quic_transport_parameters => |q| self.qtp = q,
            .unknown => unreachable,
        }
    }

    fn finish(self: Fields, raw: []const u8, random: [32]u8, sid: []const u8, suites: []const u8) wire.Error!ClientHello {
        if (!self.tls13) return error.EncodingError; // anti-downgrade: TLS 1.3 is mandatory
        const ks = self.key_share orelse return error.EncodingError;
        const sa = self.sig_algs orelse return error.EncodingError;
        const groups = self.supported_groups orelse return error.EncodingError;
        const qtp = self.qtp orelse return error.EncodingError; // RFC 9001 8.2: mandatory in QUIC
        if (!listContainsU16(suites, SUITE_AES128_GCM_SHA256)) return error.EncodingError;
        if (!listContainsU16(sa, sign.SCHEME)) return error.EncodingError;
        if (ks.group != extension.X25519 or ks.key.len != 32) return error.EncodingError;
        // RFC 8446 4.2.8: a key_share group MUST appear in supported_groups.
        if (!listContainsU16(groups, ks.group)) return error.EncodingError;
        return .{
            .raw = raw,
            .random = random,
            .legacy_session_id = sid,
            .cipher_suites = suites,
            .client_key_share = ks.key[0..32].*,
            .key_share_group = ks.group,
            .signature_schemes = sa,
            .server_name = self.sni,
            .alpn = self.alpn,
            .quic_transport_parameters = qtp,
        };
    }
};

fn listContainsU16(list: []const u8, want: u16) bool {
    var i: usize = 0;
    while (i + 2 <= list.len) : (i += 2) {
        if (std.mem.readInt(u16, list[i..][0..2], .big) == want) return true;
    }
    return false;
}
