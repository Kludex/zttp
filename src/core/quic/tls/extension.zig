//! The ClientHello extension registry and dispatch (RFC 8446 4.2). One enum for
//! the types a QUIC server handles, one tagged union of parsed bodies, and one
//! `decode` that maps a 2-byte type to its body decoder. Each body is parsed on a
//! sub-Reader scoped to exactly its extension_data, and every known branch ends in
//! `expectEnd`, so trailing bytes inside an extension are rejected, not smuggled.

const std = @import("std");
const wire = @import("wire.zig");

pub const X25519: u16 = 0x001d;
pub const TLS13: u16 = 0x0304;

pub const ExtType = enum(u16) {
    server_name = 0x0000,
    supported_groups = 0x000a,
    signature_algorithms = 0x000d,
    alpn = 0x0010,
    pre_shared_key = 0x0029,
    early_data = 0x002a,
    psk_key_exchange_modes = 0x002d,
    supported_versions = 0x002b,
    key_share = 0x0033,
    quic_transport_parameters = 0x0039,
    _,
};

pub const KeyShareEntry = struct { group: u16, key: []const u8 };

/// A parsed extension. The raw-list variants (supported_groups, signature_algorithms,
/// alpn) carry their bytes for the client_hello layer to interpret; the rest are
/// decoded here because the decode is non-trivial. All slices borrow from the input.
pub const Extension = union(enum) {
    server_name: []const u8, // host_name, SNI-unwrapped (empty slice if no host_name)
    supported_groups: []const u8, // raw u16 NamedGroup list
    signature_algorithms: []const u8, // raw u16 SignatureScheme list
    alpn: []const u8, // raw ProtocolNameList body
    pre_shared_key: []const u8, // raw OfferedPsks body
    early_data, // empty ClientHello early_data extension
    psk_key_exchange_modes: []const u8, // raw PskKeyExchangeMode list
    supported_versions: bool, // true iff TLS 1.3 (0x0304) is offered
    key_share: KeyShareEntry, // first x25519 entry, if any
    quic_transport_parameters: []const u8, // opaque, handed to the transport
    unknown: ExtType,
};

/// One decoded extension plus its raw type, so the caller can dedup over the wire
/// type (RFC 8446 4.2 forbids duplicates for ALL types, known or not).
pub const Decoded = struct { ext_type: u16, ext: Extension };

/// Decode one extension from a Reader scoped to the extensions block. The body is
/// carved to exactly extension_data first, so no decoder can read a sibling.
pub fn decode(r: *wire.Reader) wire.Error!Decoded {
    const raw = try r.readU16();
    const ty: ExtType = @enumFromInt(raw);
    var body = try r.vector(2); // extension_data<0..2^16-1>
    const ext: Extension = switch (ty) {
        .server_name => .{ .server_name = try decodeSni(&body) },
        .supported_groups => .{ .supported_groups = try u16List(&body) },
        .signature_algorithms => .{ .signature_algorithms = try u16List(&body) },
        .alpn => .{ .alpn = try decodeAlpn(&body) },
        .pre_shared_key => .{ .pre_shared_key = try body.take(body.remaining()) },
        .early_data => .early_data,
        .psk_key_exchange_modes => .{ .psk_key_exchange_modes = try u8List(&body) },
        .supported_versions => .{ .supported_versions = try decodeSupportedVersions(&body) },
        .key_share => .{ .key_share = try decodeKeyShare(&body) },
        .quic_transport_parameters => .{ .quic_transport_parameters = try body.take(body.remaining()) },
        _ => return .{ .ext_type = raw, .ext = .{ .unknown = ty } }, // body consumed; nothing to validate
    };
    try body.expectEnd(); // trailing bytes inside a known extension are illegal
    return .{ .ext_type = raw, .ext = ext };
}

fn u8List(body: *wire.Reader) wire.Error![]const u8 {
    const list = try body.vector(1);
    if (list.buf.len == 0) return error.EncodingError;
    return list.buf;
}

/// A u16-length-prefixed list of u16 values (NamedGroup / SignatureScheme). Returns
/// the raw element bytes; rejects empty or odd-length, both of which are malformed.
fn u16List(body: *wire.Reader) wire.Error![]const u8 {
    const list = try body.vector(2);
    if (list.buf.len == 0 or list.buf.len % 2 != 0) return error.EncodingError;
    return list.buf;
}

fn decodeKeyShare(body: *wire.Reader) wire.Error!KeyShareEntry {
    var list = try body.vector(2); // client_shares<0..2^16-1>
    var found: ?KeyShareEntry = null;
    while (list.remaining() != 0) {
        const group = try list.readU16();
        const key = (try list.vector(2)).buf; // key_exchange<1..2^16-1>
        if (group == X25519) {
            if (key.len != 32) return error.EncodingError;
            if (found != null) return error.EncodingError; // RFC 8446 4.2.8: one entry per group
            found = .{ .group = group, .key = key };
        }
    }
    return found orelse error.EncodingError; // no x25519 share is a hard reject (no HRR)
}

fn decodeSupportedVersions(body: *wire.Reader) wire.Error!bool {
    var list = try body.vector(1); // versions<2..254>, u8-prefixed
    if (list.buf.len == 0 or list.buf.len % 2 != 0) return error.EncodingError;
    var has_tls13 = false;
    while (list.remaining() != 0) {
        if (try list.readU16() == TLS13) has_tls13 = true;
    }
    return has_tls13;
}

fn decodeAlpn(body: *wire.Reader) wire.Error![]const u8 {
    const list = try body.vector(2); // ProtocolNameList<2..2^16-1>
    if (list.buf.len == 0) return error.EncodingError;
    var scan = wire.Reader{ .buf = list.buf };
    while (scan.remaining() != 0) {
        const name = (try scan.vector(1)).buf; // ProtocolName<1..2^8-1>
        if (name.len == 0) return error.EncodingError; // a zero-length protocol is illegal
    }
    return list.buf;
}

fn decodeSni(body: *wire.Reader) wire.Error![]const u8 {
    var list = try body.vector(2); // ServerNameList<1..2^16-1>
    if (list.remaining() == 0) return error.EncodingError; // an empty list is malformed
    var found: ?[]const u8 = null;
    while (list.remaining() != 0) {
        const name_type = try list.byte();
        const host = (try list.vector(2)).buf; // HostName<1..2^16-1>
        if (name_type == 0x00) {
            if (host.len == 0 or found != null) return error.EncodingError; // RFC 6066: one per type
            found = host;
        }
    }
    return found orelse &.{}; // consume the whole list (trailing garbage rejected) before returning
}

const testing = std.testing;

test "an unknown extension is consumed and reported, not parsed" {
    var r = wire.Reader{ .buf = &.{ 0xFF, 0xFF, 0x00, 0x02, 0xAA, 0xBB } }; // type 0xFFFF, 2-byte body
    const d = try decode(&r);
    try testing.expectEqual(@as(u16, 0xFFFF), d.ext_type);
    try testing.expect(d.ext == .unknown);
    try testing.expectEqual(@as(usize, 0), r.remaining()); // body fully consumed
}

test "key_share returns the first x25519 32-byte point" {
    var b = [_]u8{ 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 } ++ ([_]u8{0x42} ** 32);
    var r = wire.Reader{ .buf = &b };
    const ext = (try decode(&r)).ext;
    try testing.expectEqual(X25519, ext.key_share.group);
    try testing.expectEqualSlices(u8, &([_]u8{0x42} ** 32), ext.key_share.key);
}

test "a 31-byte x25519 key is rejected" {
    var b = [_]u8{ 0x00, 0x33, 0x00, 0x25, 0x00, 0x23, 0x00, 0x1d, 0x00, 0x1f } ++ ([_]u8{0x42} ** 31);
    var r = wire.Reader{ .buf = &b };
    try testing.expectError(error.EncodingError, decode(&r));
}

test "a zero-length ALPN protocol name is rejected" {
    var r = wire.Reader{ .buf = &.{ 0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0x00 } }; // list len 1, one name of len 0
    try testing.expectError(error.EncodingError, decode(&r));
}

test "supported_versions reports TLS 1.3 presence" {
    var yes = wire.Reader{ .buf = &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 } };
    try testing.expect((try decode(&yes)).ext.supported_versions);
    var no = wire.Reader{ .buf = &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x03 } };
    try testing.expect(!(try decode(&no)).ext.supported_versions);
}
