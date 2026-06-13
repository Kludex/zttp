//! The outer TLS handshake-message framing (RFC 8446 4): msg_type(1) || u24 len ||
//! body, identical for every message in both directions and exactly the bytes the
//! transcript consumes. `peek` is the contiguity gate: a handshake message can span
//! multiple QUIC CRYPTO frames and arrive out of order (RFC 9001 4), so the
//! connection layer reassembles the in-order CRYPTO byte stream and feeds it here.
//! Until a WHOLE message is buffered, `peek` returns null ("need more") - that is
//! NOT a malformed message and MUST NOT close the connection. Only once the body is
//! fully present does parsing run, where a length violation is a real error.

const std = @import("std");
const wire = @import("wire.zig");
const finished = @import("finished.zig");

pub const MsgType = enum(u8) {
    client_hello = 0x01,
    server_hello = 0x02,
    new_session_ticket = 0x04,
    encrypted_extensions = 0x08,
    certificate = 0x0b,
    certificate_verify = 0x0f,
    finished = 0x14,
    _,
};

pub const Message = struct {
    msg_type: MsgType,
    body: []const u8, // the body only, borrowing from buf
    len: usize, // 4 + body.len; advance the stream by this to reach the next message
};

/// The framed message at the start of `buf`, or null if the header or the full body
/// is not yet buffered. Never errors: a short buffer means "wait for more CRYPTO
/// bytes", and the body is handed to a per-type decoder, not validated here.
pub fn peek(buf: []const u8) ?Message {
    if (buf.len < 4) return null; // type + u24 length not yet present
    const body_len = (@as(usize, buf[1]) << 16) | (@as(usize, buf[2]) << 8) | buf[3];
    const total = 4 + body_len;
    if (buf.len < total) return null; // whole message not yet buffered
    return .{
        .msg_type = @enumFromInt(buf[0]),
        .body = buf[4..total],
        .len = total,
    };
}

/// The client Finished verify_data (RFC 8446 4.4.4): exactly 32 bytes of body for
/// SHA-256. Anything else is malformed.
pub fn finishedBody(body: []const u8) wire.Error![finished.LEN]u8 {
    if (body.len != finished.LEN) return error.EncodingError;
    return body[0..finished.LEN].*;
}

/// The first certificate's DER from a client Certificate message (RFC 8446 4.4.2):
/// certificate_request_context<0..2^8-1> then CertificateEntry list, each entry a
/// cert_data<1..2^24-1> followed by its own extensions<0..2^16-1>. Returns the
/// first cert_data (empty slice if the chain is empty, which a server may allow).
pub fn firstCertificate(body: []const u8) wire.Error![]const u8 {
    var r = wire.Reader{ .buf = body };
    _ = try r.vector(1); // certificate_request_context, echoed empty for server-auth
    var list = try r.vector(3); // CertificateEntry certificate_list<0..2^24-1>
    try r.expectEnd();
    if (list.remaining() == 0) return &.{};
    const cert = (try list.vector(3)).buf; // cert_data<1..2^24-1>
    _ = try list.vector(2); // extensions<0..2^16-1> for this entry
    return cert;
}

const testing = std.testing;

test "peek returns null until the whole message is buffered" {
    const msg = [_]u8{ 0x14, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD };
    try testing.expect(peek(msg[0..3]) == null); // header incomplete
    try testing.expect(peek(msg[0..7]) == null); // body one byte short
    const m = peek(&msg).?;
    try testing.expectEqual(MsgType.finished, m.msg_type);
    try testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB, 0xCC, 0xDD }, m.body);
    try testing.expectEqual(@as(usize, 8), m.len);
}

test "peek walks back-to-back messages" {
    const two = [_]u8{ 0x14, 0x00, 0x00, 0x01, 0x01, 0x14, 0x00, 0x00, 0x01, 0x02 };
    const first = peek(&two).?;
    try testing.expectEqual(@as(usize, 5), first.len);
    const second = peek(two[first.len..]).?;
    try testing.expectEqualSlices(u8, &.{0x02}, second.body);
}

test "finishedBody requires exactly 32 bytes" {
    try testing.expectError(error.EncodingError, finishedBody(&.{ 0x00, 0x01 }));
    const ok = [_]u8{0x5A} ** 32;
    try testing.expectEqualSlices(u8, &ok, &(try finishedBody(&ok)));
}
