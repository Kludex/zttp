//! The QUIC packet header codec (RFC 9000 section 17): parses the cleartext
//! structure of long- and short-header packets - form, version, connection ids,
//! token, and the length field - and reports where the header-protected region
//! (the packet-number offset) begins. It does NOT decrypt: header protection and
//! payload AEAD are the crypto layer's job (this just hands it the offsets). Pure
//! and zero-copy: connection ids and the payload are slices INTO the fed datagram.

const std = @import("std");
const varint = @import("varint.zig");
const constants = @import("constants.zig");

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
    length: u64,
    pn_offset: usize,
};

/// A parsed short (1-RTT) header. The dcid length is not on the wire - the
/// receiver knows its own connection ids - so the caller passes `dcid_len`.
pub const ShortHeader = struct {
    dcid: []const u8,
    pn_offset: usize, // where the protected packet number begins
};

/// Is this a long-header packet? (RFC 9000 17.1, the form bit.)
pub fn isLong(first: u8) bool {
    return (first & constants.HEADER_FORM_LONG) != 0;
}

/// Parse a long header. Validates the fixed bit and the connection-id lengths,
/// and locates the packet-number offset. Retry and Version-Negotiation packets
/// have no length/packet-number; callers branch on `ltype`/version before using
/// `length`/`pn_offset` (a Retry sets them to 0).
pub fn parseLong(buf: []const u8) Error!LongHeader {
    if (buf.len < 7) return error.Truncated;
    const first = buf[0];
    if ((first & constants.FIXED_BIT) == 0) return error.Malformed;
    const version = std.mem.readInt(u32, buf[1..5], .big);
    if (version == 0) return error.UnknownVersion; // Version Negotiation
    if (version != constants.VERSION_1) return error.UnknownVersion;

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

    const ltype: LongType = @enumFromInt(@as(u2, @truncate(first >> 4)));

    if (ltype == .retry) {
        return .{ .ltype = ltype, .version = version, .dcid = dcid, .scid = scid, .token = &.{}, .length = 0, .pn_offset = 0 };
    }

    var token: []const u8 = &.{};
    if (ltype == .initial) {
        const tlen_d = varint.decode(buf[pos..]) catch return error.Truncated;
        pos += tlen_d.len;
        const tlen: usize = @intCast(tlen_d.value);
        if (pos + tlen > buf.len) return error.Truncated;
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

test "parseLong rejects a clear fixed bit" {
    var pkt = [_]u8{ 0x80, 0, 0, 0, 1, 0, 0, 0x40, 0x00 };
    try std.testing.expectError(error.Malformed, parseLong(&pkt));
}

test "parseLong reports an unknown version" {
    var pkt = [_]u8{ 0xC0, 0xDE, 0xAD, 0xBE, 0xEF, 0, 0 };
    try std.testing.expectError(error.UnknownVersion, parseLong(&pkt));
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
