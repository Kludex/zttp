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
const schedule = @import("schedule.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

const SUITE_AES128_GCM_SHA256: u16 = 0x1301;

pub const ClientHello = struct {
    raw: []const u8, // type || u24 len || body, for transcript.update
    random: [32]u8,
    legacy_session_id: []const u8, // always empty in QUIC; echoed verbatim in ServerHello
    cipher_suites: []const u8, // raw u16 list
    client_key_share: [32]u8, // x25519 public key -> keyshare.shared
    key_share_group: u16, // X25519
    signature_schemes: []const u8, // raw u16 list
    server_name: ?[]const u8,
    alpn: ?[]const u8, // raw ProtocolNameList body, or null
    quic_transport_parameters: []const u8,
    psk_key_exchange_modes: ?[]const u8,
    early_data_offered: bool,
    offered_psks: ?OfferedPsks,
};

pub const Decoded = struct { value: ClientHello, len: usize };

pub const OfferedPsks = struct {
    raw: []const u8,
    truncated_len: usize,

    pub const Identity = struct {
        index: usize,
        identity: []const u8,
        obfuscated_ticket_age: u32,
        binder: []const u8,
    };

    pub fn findIdentity(self: OfferedPsks, want: []const u8) wire.Error!?Identity {
        const split = try splitOfferedPsks(self.raw);
        var identities = split.identities;
        var binders = split.binders;
        var index: usize = 0;
        while (identities.remaining() != 0) : (index += 1) {
            const identity = (try identities.vector(2)).buf;
            const age = try readU32(&identities);
            const binder = (try binders.vector(1)).buf;
            if (std.mem.eql(u8, identity, want)) {
                return .{
                    .index = index,
                    .identity = identity,
                    .obfuscated_ticket_age = age,
                    .binder = binder,
                };
            }
        }
        try binders.expectEnd();
        return null;
    }

    pub fn verifyBinder(self: OfferedPsks, identity: []const u8, psk: [schedule.SECRET_LEN]u8, client_hello: []const u8) wire.Error!bool {
        const found = (try self.findIdentity(identity)) orelse return false;
        if (found.binder.len != schedule.SECRET_LEN) return error.EncodingError;
        if (self.truncated_len > client_hello.len) return error.EncodingError;
        var th: [schedule.SECRET_LEN]u8 = undefined;
        Sha256.hash(client_hello[0..self.truncated_len], &th, .{});
        const expected = schedule.resumptionBinder(psk, th);
        return std.crypto.timing_safe.eql([schedule.SECRET_LEN]u8, expected, found.binder[0..schedule.SECRET_LEN].*);
    }
};

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
    if (session_id.len != 0) return error.EncodingError; // RFC 9001 8.4: empty in QUIC
    const cipher_suites = (try r.vector(2)).buf;
    if (cipher_suites.len == 0 or cipher_suites.len % 2 != 0) return error.EncodingError;
    const compression = (try r.vector(1)).buf;
    if (compression.len != 1 or compression[0] != 0x00) return error.EncodingError;

    var fields = Fields{};
    var seen = std.StaticBitSet(0x1_0000).initEmpty(); // every ext_type seen, RFC 8446 4.2
    var exts = try r.vector(2); // extensions<8..2^16-1>
    try r.expectEnd();
    while (exts.remaining() != 0) {
        const d = try extension.decode(&exts);
        if (seen.isSet(d.ext_type)) return error.EncodingError; // no duplicate of ANY type
        seen.set(d.ext_type);
        fields.apply(d.ext, raw.len - exts.remaining());
    }
    return .{
        .value = try fields.finish(raw, random, session_id, cipher_suites),
        .len = 4 + @as(usize, body_len),
    };
}

/// Accumulates the extensions and gates the whole message on the single-suite
/// policy in `finish` - the one place every must-have check lives. Duplicate
/// rejection happens in `parse` over the raw ext_type, so `apply` just stores.
const Fields = struct {
    key_share: ?extension.KeyShareEntry = null,
    supported_groups: ?[]const u8 = null,
    sig_algs: ?[]const u8 = null,
    tls13: bool = false,
    sni: ?[]const u8 = null,
    alpn: ?[]const u8 = null,
    qtp: ?[]const u8 = null,
    psk_modes: ?[]const u8 = null,
    early_data: bool = false,
    psk_raw: ?[]const u8 = null,
    psk_truncated_len: ?usize = null,

    fn apply(self: *Fields, ext: extension.Extension, raw_end: usize) void {
        switch (ext) {
            .key_share => |k| self.key_share = k,
            .supported_groups => |g| self.supported_groups = g,
            .signature_algorithms => |s| self.sig_algs = s,
            .supported_versions => |v| self.tls13 = v,
            .server_name => |n| self.sni = if (n.len == 0) null else n,
            .alpn => |a| self.alpn = a,
            .pre_shared_key => |p| {
                self.psk_raw = p;
                self.psk_truncated_len = raw_end - (2 + 1 + schedule.SECRET_LEN);
            },
            .early_data => self.early_data = true,
            .psk_key_exchange_modes => |m| self.psk_modes = m,
            .quic_transport_parameters => |q| self.qtp = q,
            .unknown => {}, // ignored; dedup already happened in parse
        }
    }

    fn finish(self: Fields, raw: []const u8, random: [32]u8, sid: []const u8, suites: []const u8) wire.Error!ClientHello {
        if (!self.tls13) return error.EncodingError; // anti-downgrade: TLS 1.3 is mandatory
        const ks = self.key_share orelse return error.EncodingError;
        const sa = self.sig_algs orelse return error.EncodingError;
        const groups = self.supported_groups orelse return error.EncodingError;
        const qtp = self.qtp orelse return error.EncodingError; // RFC 9001 8.2: mandatory in QUIC
        const offered_psks = if (self.psk_raw) |raw_psk| OfferedPsks{ .raw = raw_psk, .truncated_len = self.psk_truncated_len orelse return error.EncodingError } else null;
        if (offered_psks) |psks| try validateOfferedPsks(psks.raw);
        if (offered_psks) |psks| {
            if (psks.truncated_len + 2 + 1 + schedule.SECRET_LEN != raw.len) return error.EncodingError; // pre_shared_key MUST be last
        }
        if (self.early_data and offered_psks == null) return error.EncodingError;
        if (offered_psks != null and self.psk_modes == null) return error.EncodingError;
        if (self.psk_modes) |modes| {
            if (!std.mem.containsAtLeast(u8, modes, 1, &.{0x01})) return error.EncodingError;
        }
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
            .psk_key_exchange_modes = self.psk_modes,
            .early_data_offered = self.early_data,
            .offered_psks = offered_psks,
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

const OfferedPskSplit = struct {
    identities: wire.Reader,
    binders: wire.Reader,
};

fn splitOfferedPsks(raw: []const u8) wire.Error!OfferedPskSplit {
    var r = wire.Reader{ .buf = raw };
    const identities = try r.vector(2);
    const binders = try r.vector(2);
    try r.expectEnd();
    return .{ .identities = identities, .binders = binders };
}

fn validateOfferedPsks(raw: []const u8) wire.Error!void {
    var split = try splitOfferedPsks(raw);
    var identity_count: usize = 0;
    while (split.identities.remaining() != 0) : (identity_count += 1) {
        const identity = (try split.identities.vector(2)).buf;
        if (identity.len == 0) return error.EncodingError;
        _ = try readU32(&split.identities);
    }
    var binder_count: usize = 0;
    while (split.binders.remaining() != 0) : (binder_count += 1) {
        const binder = (try split.binders.vector(1)).buf;
        if (binder.len != schedule.SECRET_LEN) return error.EncodingError;
    }
    if (identity_count == 0 or identity_count != binder_count) return error.EncodingError;
}

fn readU32(r: *wire.Reader) wire.Error!u32 {
    const s = try r.take(4);
    return std.mem.readInt(u32, s[0..4], .big);
}
