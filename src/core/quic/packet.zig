//! The QUIC packet header codec (RFC 9000 section 17): parses the cleartext
//! structure of long- and short-header packets - form, version, connection ids,
//! token, and the length field - and reports where the header-protected region
//! (the packet-number offset) begins. It does NOT decrypt: header protection and
//! payload AEAD are the crypto layer's job (this just hands it the offsets). Pure
//! and zero-copy: connection ids and the payload are slices INTO the fed datagram.

const std = @import("std");
const varint = @import("varint.zig");
const constants = @import("constants.zig");
const crypto = @import("crypto.zig");

const LongType = constants.LongType;

pub const Error = error{
    /// The datagram is shorter than the header it announces.
    Truncated,
    /// The fixed bit is clear, the version is one we do not speak, or a connection
    /// id length exceeds 20 (RFC 9000 17.2).
    Malformed,
    /// A long-header version we cannot parse (handled by Version Negotiation, not
    /// here); surfaced so the connection layer can respond.
    UnknownVersion,
};

/// A parsed long header up to (but not including) the protected packet number.
/// `pn_offset` is where the packet number starts; `length` is the varint-declared
/// length of (packet number + protected payload), so the protected region is
/// `bytes[pn_offset .. pn_offset + length]`.
pub const LongHeader = struct {
    ltype: LongType,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8, // Initial only; empty otherwise
    retry_tag: []const u8 = &.{},
    length: u64,
    pn_offset: usize,
};

/// The version-independent prefix shared by every long-header packet (RFC 9000
/// 17.2), including unsupported versions and Version Negotiation packets.
pub const LongPrefix = struct {
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    header_len: usize,
};

/// A parsed short (1-RTT) header. The dcid length is not on the wire - the
/// receiver knows its own connection ids - so the caller passes `dcid_len`.
pub const ShortHeader = struct {
    dcid: []const u8,
    pn_offset: usize, // where the protected packet number begins
};

pub const SHORT_KEY_PHASE: u8 = 0x04;

/// Is this a long-header packet? (RFC 9000 17.1, the form bit.)
pub fn isLong(first: u8) bool {
    return (first & constants.HEADER_FORM_LONG) != 0;
}

/// A routing view of a received datagram's first packet, for demultiplexing a
/// shared socket onto per-connection state. A long header carries both connection
/// ids and their lengths on the wire; a short (1-RTT) header does not encode the
/// dcid length, so `dcid`/`scid` are empty for one and the receiver must match it
/// against connection ids it already knows.
pub const DatagramHeader = struct {
    long: bool,
    initial: bool,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
};

/// Parse just the routable prefix of a received datagram (RFC 9000 17), without
/// decrypting. Zero-copy: the connection-id slices point into `buf`. A short-header
/// packet returns `long = false` with empty ids; the caller demuxes it by its own
/// connection ids. This does no version dispatch, so it also routes unsupported
/// versions and Version Negotiation packets (neither is ever `initial`).
pub fn parseDatagramHeader(buf: []const u8) Error!DatagramHeader {
    if (buf.len < 1) return error.Truncated;
    if (!isLong(buf[0])) {
        // A short header still carries the QUIC fixed bit; a clear one is malformed.
        if ((buf[0] & constants.FIXED_BIT) == 0) return error.Malformed;
        return .{ .long = false, .initial = false, .version = 0, .dcid = &.{}, .scid = &.{}, .token = &.{} };
    }
    const prefix = try parseLongPrefix(buf);
    // The long-header type bits are version-specific, so only trust them for QUIC v1;
    // an unsupported version (or a Version Negotiation packet, version 0) is never an
    // Initial we would open a connection for.
    const initial = prefix.version == constants.VERSION_1 and
        @as(LongType, @enumFromInt(@as(u2, @truncate(buf[0] >> 4)))) == .initial;
    const token = if (initial) token: {
        const token_length = varint.decode(buf[prefix.header_len..]) catch return error.Truncated;
        const length = std.math.cast(usize, token_length.value) orelse return error.Malformed;
        const start = prefix.header_len + token_length.len;
        if (length > buf.len - start) return error.Truncated;
        break :token buf[start .. start + length];
    } else &.{};
    return .{ .long = true, .initial = initial, .version = prefix.version, .dcid = prefix.dcid, .scid = prefix.scid, .token = token };
}

/// Parse only the invariant long-header prefix: form/fixed bits, version, and
/// connection IDs. This works before version dispatch, so the connection layer can
/// generate Version Negotiation for unsupported versions.
pub fn parseLongPrefix(buf: []const u8) Error!LongPrefix {
    if (buf.len < 7) return error.Truncated;
    if (!isLong(buf[0]) or (buf[0] & constants.FIXED_BIT) == 0) return error.Malformed;
    const version = std.mem.readInt(u32, buf[1..5], .big);

    var pos: usize = 5;
    const dcid_len = buf[pos];
    pos += 1;
    if (dcid_len > constants.MAX_CID_LEN) return error.Malformed;
    if (pos + dcid_len >= buf.len) return error.Truncated;
    const dcid = buf[pos .. pos + dcid_len];
    pos += dcid_len;

    const scid_len = buf[pos];
    pos += 1;
    if (scid_len > constants.MAX_CID_LEN) return error.Malformed;
    if (pos + scid_len > buf.len) return error.Truncated;
    const scid = buf[pos .. pos + scid_len];
    pos += scid_len;

    return .{ .version = version, .dcid = dcid, .scid = scid, .header_len = pos };
}

/// Parse a long header. Validates the fixed bit and the connection-id lengths,
/// and locates the packet-number offset. Retry and Version-Negotiation packets
/// have no length/packet-number; callers branch on `ltype`/version before using
/// `length`/`pn_offset` (a Retry sets them to 0).
pub fn parseLong(buf: []const u8) Error!LongHeader {
    const prefix = try parseLongPrefix(buf);
    const first = buf[0];
    const version = prefix.version;
    if (version == 0) return error.UnknownVersion; // Version Negotiation
    if (version != constants.VERSION_1) return error.UnknownVersion;

    var pos: usize = prefix.header_len;
    const dcid = prefix.dcid;
    const scid = prefix.scid;

    const ltype: LongType = @enumFromInt(@as(u2, @truncate(first >> 4)));

    if (ltype == .retry) {
        if (buf.len < pos + crypto.TAG_LEN) return error.Truncated;
        return .{
            .ltype = ltype,
            .version = version,
            .dcid = dcid,
            .scid = scid,
            .token = buf[pos .. buf.len - crypto.TAG_LEN],
            .retry_tag = buf[buf.len - crypto.TAG_LEN ..],
            .length = 0,
            .pn_offset = 0,
        };
    }

    var token: []const u8 = &.{};
    if (ltype == .initial) {
        const tlen_d = varint.decode(buf[pos..]) catch return error.Truncated;
        pos += tlen_d.len;
        const tlen = std.math.cast(usize, tlen_d.value) orelse return error.Truncated;
        if (tlen > buf.len - pos) return error.Truncated;
        token = buf[pos .. pos + tlen];
        pos += tlen;
    }

    const len_d = varint.decode(buf[pos..]) catch return error.Truncated;
    pos += len_d.len;
    if (pos + len_d.value > buf.len) return error.Truncated;

    return .{
        .ltype = ltype,
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .token = token,
        .length = len_d.value,
        .pn_offset = pos,
    };
}

pub fn validateRetryIntegrity(gpa: std.mem.Allocator, retry_packet: []const u8, original_dcid: []const u8) !bool {
    if (retry_packet.len < crypto.TAG_LEN) return false;
    var pseudo: std.ArrayListUnmanaged(u8) = .empty;
    defer pseudo.deinit(gpa);
    try pseudo.append(gpa, @intCast(original_dcid.len));
    try pseudo.appendSlice(gpa, original_dcid);
    try pseudo.appendSlice(gpa, retry_packet[0 .. retry_packet.len - crypto.TAG_LEN]);
    const got = retry_packet[retry_packet.len - crypto.TAG_LEN ..][0..crypto.TAG_LEN].*;
    const want = crypto.retryIntegrityTag(pseudo.items);
    return std.crypto.timing_safe.eql([crypto.TAG_LEN]u8, got, want);
}

/// Parse a short header given the local connection-id length (which is not on the
/// wire). The packet number begins right after the dcid; its true length is in
/// the header-protected bits, recovered by the crypto layer.
pub fn parseShort(buf: []const u8, dcid_len: usize) Error!ShortHeader {
    if (buf.len < 1 + dcid_len) return error.Truncated;
    if ((buf[0] & constants.FIXED_BIT) == 0) return error.Malformed;
    return .{ .dcid = buf[1 .. 1 + dcid_len], .pn_offset = 1 + dcid_len };
}

/// Decode a packet number from its truncated on-wire form against the largest
/// number already acknowledged in this space (RFC 9000 appendix A.3). Header
/// protection has already revealed `pn_len` (1-4) and the raw bytes.
pub fn decodePacketNumber(largest_acked: u64, truncated: u64, pn_len: usize) u64 {
    const pn_bits = pn_len * 8;
    const pn_win: u64 = @as(u64, 1) << @intCast(pn_bits);
    const pn_hwin = pn_win / 2;
    const pn_mask = pn_win - 1;
    const expected = largest_acked + 1;
    const candidate = (expected & ~pn_mask) | truncated;
    if (candidate + pn_hwin <= expected and candidate + pn_win <= (1 << 62) - 1) {
        return candidate + pn_win;
    }
    if (candidate > expected + pn_hwin and candidate >= pn_win) {
        return candidate - pn_win;
    }
    return candidate;
}

/// The minimal byte length needed to encode `pn` unambiguously given the largest
/// acknowledged number (RFC 9000 17.1): enough bytes that the receiver's window
/// resolves it. Used by the writer.
pub fn packetNumberLen(pn: u64, largest_acked: ?u64) usize {
    const range = if (largest_acked) |la| pn - la else pn + 1;
    if (range < (1 << 7)) return 1;
    if (range < (1 << 15)) return 2;
    if (range < (1 << 23)) return 3;
    return 4;
}

// -- write (the header writers, the inverse of parseLong/parseShort) ----------
//
// These append a cleartext header through the Length field; the caller then
// writes the `pn_len`-byte packet number and the payload, seals (AEAD), and
// applies header protection. `pn_len` (1-4) is encoded into the first byte's low
// two bits as pn_len-1. The returned pn_offset is where the packet number goes -
// the start of the header-protected region.

/// Write a long header (Initial/Handshake/0-RTT) through the Length field.
/// `length` must cover the packet number plus the protected payload (RFC 9000
/// 17.2). `token` is written only for an Initial (pass empty otherwise). Returns
/// the packet-number offset.
pub fn writeLongHeader(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    ltype: LongType,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    length: u64,
    pn_len: usize,
) !usize {
    std.debug.assert(pn_len >= 1 and pn_len <= 4);
    const first: u8 = constants.HEADER_FORM_LONG | constants.FIXED_BIT |
        (@as(u8, @intFromEnum(ltype)) << 4) | @as(u8, @intCast(pn_len - 1));
    try out.append(gpa, first);
    var ver: [4]u8 = undefined;
    std.mem.writeInt(u32, &ver, version, .big);
    try out.appendSlice(gpa, &ver);
    try out.append(gpa, @intCast(dcid.len));
    try out.appendSlice(gpa, dcid);
    try out.append(gpa, @intCast(scid.len));
    try out.appendSlice(gpa, scid);
    if (ltype == .initial) {
        try varint.append(out, gpa, token.len);
        try out.appendSlice(gpa, token);
    }
    try varint.append(out, gpa, length);
    return out.items.len;
}

pub fn writeRetry(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    original_dcid: []const u8,
) !void {
    const first: u8 = constants.HEADER_FORM_LONG | constants.FIXED_BIT |
        (@as(u8, @intFromEnum(LongType.retry)) << 4);
    try out.append(gpa, first);
    var ver: [4]u8 = undefined;
    std.mem.writeInt(u32, &ver, constants.VERSION_1, .big);
    try out.appendSlice(gpa, &ver);
    try out.append(gpa, @intCast(dcid.len));
    try out.appendSlice(gpa, dcid);
    try out.append(gpa, @intCast(scid.len));
    try out.appendSlice(gpa, scid);
    try out.appendSlice(gpa, token);

    var pseudo: std.ArrayListUnmanaged(u8) = .empty;
    defer pseudo.deinit(gpa);
    try pseudo.append(gpa, @intCast(original_dcid.len));
    try pseudo.appendSlice(gpa, original_dcid);
    try pseudo.appendSlice(gpa, out.items);
    const tag = crypto.retryIntegrityTag(pseudo.items);
    try out.appendSlice(gpa, &tag);
}

/// Write a Version Negotiation packet (RFC 9000 17.2.1). The server swaps the
/// peer's connection IDs: Destination CID is the client's Source CID, Source CID
/// is the client's Destination CID from the unsupported-version packet.
pub fn writeVersionNegotiation(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    dcid: []const u8,
    scid: []const u8,
) !void {
    const first: u8 = constants.HEADER_FORM_LONG | constants.FIXED_BIT;
    try out.append(gpa, first);
    try out.appendSlice(gpa, &[_]u8{ 0, 0, 0, 0 });
    try out.append(gpa, @intCast(dcid.len));
    try out.appendSlice(gpa, dcid);
    try out.append(gpa, @intCast(scid.len));
    try out.appendSlice(gpa, scid);
    var ver: [4]u8 = undefined;
    std.mem.writeInt(u32, &ver, constants.VERSION_1, .big);
    try out.appendSlice(gpa, &ver);
}

/// Write a short (1-RTT) header through the dcid. Returns the packet-number
/// offset (right after the dcid); the caller writes the pn and payload next.
pub fn writeShortHeader(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    dcid: []const u8,
    pn_len: usize,
) !usize {
    return writeShortHeaderWithKeyPhase(out, gpa, dcid, pn_len, false);
}

pub fn writeShortHeaderWithKeyPhase(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    dcid: []const u8,
    pn_len: usize,
    key_phase: bool,
) !usize {
    std.debug.assert(pn_len >= 1 and pn_len <= 4);
    // Short header: the form bit is clear (1-RTT); fixed bit set, pn_len-1 in the
    // low two bits. The spin bit is 0; key phase tracks 1-RTT key updates.
    const first: u8 = constants.FIXED_BIT |
        (if (key_phase) SHORT_KEY_PHASE else 0) |
        @as(u8, @intCast(pn_len - 1));
    try out.append(gpa, first);
    try out.appendSlice(gpa, dcid);
    return out.items.len;
}

/// Write a packet number in its minimal `pn_len`-byte big-endian truncated form
/// (RFC 9000 17.1). The matching length comes from `packetNumberLen`.
pub fn writePacketNumber(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, pn: u64, pn_len: usize) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, @intCast(pn & 0xFFFF_FFFF), .big);
    try out.appendSlice(gpa, buf[4 - pn_len ..]);
}

test "isLong reads the form bit" {
    try std.testing.expect(isLong(0xC0));
    try std.testing.expect(!isLong(0x40));
}

test "parseLong reads an Initial header" {
    // first=0xC0 (long, fixed, type=initial), version=1, dcid_len=4 "abcd",
    // scid_len=0, token_len=0, length=2 (varint 0x02), then 2 protected octets.
    var pkt = [_]u8{ 0xC0, 0, 0, 0, 1, 4, 'a', 'b', 'c', 'd', 0, 0, 0x02, 0xAA, 0xBB };
    const h = try parseLong(&pkt);
    try std.testing.expectEqual(LongType.initial, h.ltype);
    try std.testing.expectEqual(@as(u32, 1), h.version);
    try std.testing.expectEqualStrings("abcd", h.dcid);
    try std.testing.expectEqual(@as(usize, 0), h.scid.len);
    try std.testing.expectEqual(@as(u64, 2), h.length);
    try std.testing.expectEqual(@as(usize, 13), h.pn_offset);
}

test "parseLong rejects a four-gibibyte token length" {
    const huge = [_]u8{ 0xC0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    const packet = [_]u8{ 0xC0, 0, 0, 0, 1, 0, 0 } ++ huge;
    try std.testing.expectError(error.Truncated, parseLong(&packet));
}

test "parseLong rejects a clear fixed bit" {
    var pkt = [_]u8{ 0x80, 0, 0, 0, 1, 0, 0, 0x40, 0x00 };
    try std.testing.expectError(error.Malformed, parseLong(&pkt));
}

test "parseLong reports an unknown version" {
    var pkt = [_]u8{ 0xC0, 0xDE, 0xAD, 0xBE, 0xEF, 0, 0 };
    try std.testing.expectError(error.UnknownVersion, parseLong(&pkt));
}

test "parseLongPrefix reads connection ids before version dispatch" {
    var pkt = [_]u8{ 0xC0, 0xDE, 0xAD, 0xBE, 0xEF, 0x03, 'd', 's', 't', 0x03, 's', 'r', 'c' };
    const p = try parseLongPrefix(&pkt);
    try std.testing.expectEqual(@as(u32, 0xDEAD_BEEF), p.version);
    try std.testing.expectEqualStrings("dst", p.dcid);
    try std.testing.expectEqualStrings("src", p.scid);
    try std.testing.expectEqual(@as(usize, pkt.len), p.header_len);
}

test "parseDatagramHeader routes a long-header Initial" {
    // 0xC0: long form + fixed bit + type bits 00 (Initial); version 1; dcid "dst", scid "src".
    var pkt = [_]u8{ 0xC0, 0x00, 0x00, 0x00, 0x01, 0x03, 'd', 's', 't', 0x03, 's', 'r', 'c', 0x00 };
    const h = try parseDatagramHeader(&pkt);
    try std.testing.expect(h.long);
    try std.testing.expect(h.initial);
    try std.testing.expectEqual(@as(u32, 1), h.version);
    try std.testing.expectEqualStrings("dst", h.dcid);
    try std.testing.expectEqualStrings("src", h.scid);
    try std.testing.expectEqual(@as(usize, 0), h.token.len);
}

test "parseDatagramHeader reports a short header without connection ids" {
    var pkt = [_]u8{ 0x40, 0xAA, 0xBB, 0xCC }; // form bit clear, fixed bit set = short header
    const h = try parseDatagramHeader(&pkt);
    try std.testing.expect(!h.long);
    try std.testing.expect(!h.initial);
    try std.testing.expectEqual(@as(usize, 0), h.dcid.len);
}

test "parseDatagramHeader rejects a short header with the fixed bit clear" {
    var pkt = [_]u8{ 0x00, 0xAA, 0xBB }; // form bit clear AND fixed bit clear = malformed
    try std.testing.expectError(error.Malformed, parseDatagramHeader(&pkt));
}

test "parseDatagramHeader does not flag Version Negotiation as Initial" {
    // Version 0 is a Version Negotiation packet; its type bits are meaningless.
    var pkt = [_]u8{ 0xC0, 0x00, 0x00, 0x00, 0x00, 0x03, 'd', 's', 't', 0x00 };
    const h = try parseDatagramHeader(&pkt);
    try std.testing.expect(h.long);
    try std.testing.expect(!h.initial);
    try std.testing.expectEqual(@as(u32, 0), h.version);
}

test "parseDatagramHeader does not flag an unsupported version as Initial" {
    // Type bits 00 look like Initial, but they are only v1 semantics; a nonzero
    // unsupported version must not be reported as an Initial.
    var pkt = [_]u8{ 0xC0, 0x0A, 0x0A, 0x0A, 0x0A, 0x03, 'd', 's', 't', 0x00 };
    const h = try parseDatagramHeader(&pkt);
    try std.testing.expect(h.long);
    try std.testing.expect(!h.initial);
    try std.testing.expectEqual(@as(u32, 0x0A0A_0A0A), h.version);
}

test "parseDatagramHeader rejects an empty datagram" {
    try std.testing.expectError(error.Truncated, parseDatagramHeader(&[_]u8{}));
}

test "parseLong reads a Retry packet and validates its integrity tag" {
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry = [_]u8{ 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e } ++
        [_]u8{ 0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba };
    const h = try parseLong(&retry);
    try std.testing.expectEqual(LongType.retry, h.ltype);
    try std.testing.expectEqualStrings("token", h.token);
    try std.testing.expectEqualSlices(u8, retry[retry.len - crypto.TAG_LEN ..], h.retry_tag);
    try std.testing.expect(try validateRetryIntegrity(std.testing.allocator, &retry, &odcid));
}

test "parseShort locates the packet number after the dcid" {
    var pkt = [_]u8{ 0x40, 'c', 'i', 'd', 0xAA };
    const h = try parseShort(&pkt, 3);
    try std.testing.expectEqualStrings("cid", h.dcid);
    try std.testing.expectEqual(@as(usize, 4), h.pn_offset);
}

test "decodePacketNumber recovers the full number (RFC 9000 A.3)" {
    // largest_acked = 0xa82f30ea, truncated 2-byte 0x9b32 -> 0xa82f9b32
    try std.testing.expectEqual(@as(u64, 0xa82f_9b32), decodePacketNumber(0xa82f_30ea, 0x9b32, 2));
}

test "decodePacketNumber handles the first packet" {
    try std.testing.expectEqual(@as(u64, 0), decodePacketNumber(0, 0, 1));
    try std.testing.expectEqual(@as(u64, 1), decodePacketNumber(0, 1, 1));
}

test "packetNumberLen grows with the gap" {
    try std.testing.expectEqual(@as(usize, 1), packetNumberLen(5, 0));
    try std.testing.expectEqual(@as(usize, 2), packetNumberLen(1000, 0));
    try std.testing.expectEqual(@as(usize, 1), packetNumberLen(1000, 999));
}

test "writeLongHeader round-trips through parseLong" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    // An Initial header: dcid "abcd", empty scid, empty token, length 5, 1-byte pn.
    const pn_off = try writeLongHeader(&out, gpa, .initial, constants.VERSION_1, "abcd", "", "", 5, 1);
    // Append the 1-byte pn + 4 payload octets so parseLong's length check passes.
    try out.appendSlice(gpa, &.{ 0x00, 0xAA, 0xBB, 0xCC, 0xDD });
    const h = try parseLong(out.items);
    try std.testing.expectEqual(LongType.initial, h.ltype);
    try std.testing.expectEqual(constants.VERSION_1, h.version);
    try std.testing.expectEqualStrings("abcd", h.dcid);
    try std.testing.expectEqual(@as(usize, 0), h.scid.len);
    try std.testing.expectEqual(@as(u64, 5), h.length);
    try std.testing.expectEqual(pn_off, h.pn_offset);
}

test "writeRetry emits a parseable packet with a valid tag" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try writeRetry(&out, gpa, "client", "server", "retry-token", "original");
    const h = try parseLong(out.items);
    try std.testing.expectEqual(LongType.retry, h.ltype);
    try std.testing.expectEqualStrings("client", h.dcid);
    try std.testing.expectEqualStrings("server", h.scid);
    try std.testing.expectEqualStrings("retry-token", h.token);
    try std.testing.expect(try validateRetryIntegrity(gpa, out.items, "original"));
}

test "writeVersionNegotiation emits version zero and supported v1" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try writeVersionNegotiation(&out, gpa, "client", "server");
    const p = try parseLongPrefix(out.items);
    try std.testing.expectEqual(@as(u32, 0), p.version);
    try std.testing.expectEqualStrings("client", p.dcid);
    try std.testing.expectEqualStrings("server", p.scid);
    try std.testing.expectEqual(@as(usize, 4), out.items[p.header_len..].len);
    try std.testing.expectEqual(constants.VERSION_1, std.mem.readInt(u32, out.items[p.header_len..][0..4], .big));
}

test "writeLongHeader encodes pn_len into the first byte" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    _ = try writeLongHeader(&out, gpa, .handshake, constants.VERSION_1, "", "", "", 1, 3);
    // first byte: long(0x80) | fixed(0x40) | type handshake(2<<4=0x20) | pn_len-1(2).
    try std.testing.expectEqual(@as(u8, 0x80 | 0x40 | 0x20 | 0x02), out.items[0]);
}

test "writeShortHeader round-trips through parseShort" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    const pn_off = try writeShortHeader(&out, gpa, "cid", 2);
    try out.appendSlice(gpa, &.{ 0x00, 0x01 }); // 2-byte pn
    const h = try parseShort(out.items, 3);
    try std.testing.expectEqualStrings("cid", h.dcid);
    try std.testing.expectEqual(pn_off, h.pn_offset);
    // form bit clear, fixed bit set, pn_len-1 = 1.
    try std.testing.expect(!isLong(out.items[0]));
    try std.testing.expectEqual(@as(u8, 0x40 | 0x01), out.items[0]);
}

test "writePacketNumber writes the minimal big-endian form" {
    const gpa = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    try writePacketNumber(&out, gpa, 0x1234, 2);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34 }, out.items);
    out.clearRetainingCapacity();
    try writePacketNumber(&out, gpa, 0x05, 1);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x05}, out.items);
}
