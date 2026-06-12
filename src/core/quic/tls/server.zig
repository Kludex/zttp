//! The server TLS 1.3 handshake driver, Connection-free: it owns the running
//! transcript and the integrator config, and turns a parsed ClientHello into the
//! server flight plus the per-space secrets. It knows nothing about QUIC packets or
//! spaces - the connection seam applies the keys and frames the flight into CRYPTO -
//! so the whole drive is a pure function of (config, transcript, ClientHello) and
//! testable against the RFC vectors with plain byte slices.

const std = @import("std");
const transcript = @import("transcript.zig");
const flight = @import("flight.zig");
const finished = @import("finished.zig");
const handshake = @import("handshake.zig");
const client_hello = @import("client_hello.zig");

pub const State = enum { wait_client_hello, flight_sent, complete };

/// The TLS 1.3 alert descriptions (RFC 8446 6) this server raises. QUIC carries a
/// fatal alert as a CONNECTION_CLOSE with code CRYPTO_ERROR (0x0100 | alert), so a
/// peer learns which TLS rule was broken (RFC 9001 4.8).
pub const Alert = enum(u8) {
    unexpected_message = 10,
    decode_error = 50,
    decrypt_error = 51,
    internal_error = 80,
    no_application_protocol = 120,
};

/// The alert a handshake error maps to. A malformed handshake message decodes to
/// `decode_error`; the rest follow RFC 8446's named conditions.
pub fn alertFor(e: Error) Alert {
    return switch (e) {
        error.UnexpectedMessage => .unexpected_message,
        error.BadFinished => .decrypt_error,
        error.NoAlpnOverlap => .no_application_protocol,
        error.Internal, error.OutOfMemory => .internal_error,
    };
}

pub const Error = error{
    /// A handshake message arrived in a state that forbids it (e.g. a second
    /// ClientHello). The connection maps this to PROTOCOL_VIOLATION.
    UnexpectedMessage,
    /// The client's Finished MAC did not verify (RFC 8446 4.4.4): the client did not
    /// derive the same handshake secret. The connection maps this to a TLS decrypt
    /// alert / CONNECTION_CLOSE.
    BadFinished,
    /// The client did not offer the server's configured protocol - either its ALPN
    /// list lacks it or it sent no ALPN at all, which QUIC forbids (RFC 7301 /
    /// RFC 9001 8.1: no_application_protocol).
    NoAlpnOverlap,
    /// The flight builder could not produce a flight (keyshare/sign failure) or the
    /// built buffer did not start with a ServerHello - a should-never-happen.
    Internal,
    OutOfMemory,
};

/// The result of accepting a ClientHello: the per-space secrets the connection
/// installs, and where in `out` the Initial-space ServerHello ends and the
/// Handshake-space encrypted flight begins.
pub const Outcome = struct {
    built: flight.Built,
    server_hello_len: usize,
};

pub const Server = struct {
    transcript: transcript.Transcript = .{},
    config: flight.Config,
    state: State = .wait_client_hello,
    /// The client handshake traffic secret, kept from the flight build so the
    /// client's Finished MAC can be verified once it arrives.
    client_hs_secret: [32]u8 = undefined,

    pub fn init(config: flight.Config) Server {
        return .{ .config = config };
    }

    /// Feed the parsed ClientHello: hash its raw bytes into the transcript (which
    /// flight.build requires to have happened FIRST, per its contract), run the
    /// flight builder into `out`, and report the ServerHello/flight split. The
    /// caller installs `built`'s keys and frames `out` into CRYPTO per space.
    pub fn onClientHello(
        self: *Server,
        out: *std.ArrayListUnmanaged(u8),
        gpa: std.mem.Allocator,
        ch: client_hello.ClientHello,
    ) Error!Outcome {
        if (self.state != .wait_client_hello) return error.UnexpectedMessage;
        // ALPN (RFC 9001 8.1): application-protocol negotiation is mandatory in
        // QUIC, so with a configured protocol a ClientHello that omits ALPN
        // entirely fails exactly like one whose list lacks the protocol -
        // no_application_protocol either way. A null config.alpn skips negotiation,
        // a test affordance for exercising the transport without an application.
        if (self.config.alpn) |proto| {
            const offered = ch.alpn orelse return error.NoAlpnOverlap;
            if (!alpnOffers(offered, proto)) return error.NoAlpnOverlap;
        }
        self.transcript.update(ch.raw); // CRITICAL: before flight.build (flight.zig contract)
        const view = flight.ClientHelloView{
            .legacy_session_id = ch.legacy_session_id,
            .client_key_share = ch.client_key_share,
        };
        const built = flight.build(out, gpa, &self.transcript, view, self.config) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Internal,
        };
        const sh = handshake.peek(out.items) orelse return error.Internal;
        if (sh.msg_type != .server_hello) return error.Internal;
        self.client_hs_secret = built.client_hs_secret;
        self.state = .flight_sent;
        return .{ .built = built, .server_hello_len = sh.len };
    }

    /// Verify the client's Finished MAC (RFC 8446 4.4.4): the verify_data is HMAC
    /// over the transcript THROUGH the server's Finished, keyed by the client
    /// handshake traffic secret. The transcript is currently at that point (the
    /// flight builder fed every server message), so it is read before the client
    /// Finished is folded in. On success the handshake is complete.
    pub fn onClientFinished(self: *Server, finished_body: [finished.LEN]u8) Error!void {
        if (self.state != .flight_sent) return error.UnexpectedMessage;
        const th = self.transcript.hash(); // through the server Finished
        finished.verify(self.client_hs_secret, th, finished_body) catch return error.BadFinished;
        // Fold the client Finished into the transcript (a later resumption-ticket
        // MAC would read it) and mark the handshake confirmed.
        var framed: [4 + finished.LEN]u8 = undefined;
        framed[0] = 0x14; // handshake type: finished
        framed[1] = 0;
        framed[2] = 0;
        framed[3] = finished.LEN;
        @memcpy(framed[4..], &finished_body);
        self.transcript.update(&framed);
        self.state = .complete;
    }
};

/// Whether the client's raw ProtocolNameList (each entry u8-length-prefixed,
/// RFC 7301 3.1) contains `want`.
fn alpnOffers(list: []const u8, want: []const u8) bool {
    var i: usize = 0;
    while (i < list.len) {
        const n = list[i];
        i += 1;
        if (i + n > list.len) return false; // malformed; the parser already vetted it, but be safe
        if (std.mem.eql(u8, list[i .. i + n], want)) return true;
        i += n;
    }
    return false;
}

const testing = std.testing;
const wire = @import("wire.zig");
const sign = @import("sign.zig");

test "onClientHello builds a flight that starts with the ServerHello and yields secrets" {
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c");

    var ch_buf = std.ArrayListUnmanaged(u8).empty;
    defer ch_buf.deinit(testing.allocator);
    try buildMinimalClientHello(&ch_buf, testing.allocator, pubkey);
    const decoded = try client_hello.parse(ch_buf.items);

    var server = Server.init(.{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &[_]u8{ 0x00, 0x01 },
    });

    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(testing.allocator);
    const outcome = try server.onClientHello(&out, testing.allocator, decoded.value);

    // The flight starts with a ServerHello of the reported length, then the rest.
    const sh = handshake.peek(out.items).?;
    try testing.expectEqual(handshake.MsgType.server_hello, sh.msg_type);
    try testing.expectEqual(sh.len, outcome.server_hello_len);
    try testing.expect(out.items.len > outcome.server_hello_len); // an encrypted flight follows

    // The server's installed key direction: it RECVs with the client traffic secret
    // and SENDs with the server one - distinct, non-empty.
    const hs = outcome.built.handshake_secrets;
    try testing.expect(!std.mem.eql(u8, &hs.client, &hs.server));

    // A second ClientHello in flight_sent state is rejected.
    try testing.expectError(error.UnexpectedMessage, server.onClientHello(&out, testing.allocator, decoded.value));
}

test "onClientFinished verifies the client MAC and completes the handshake" {
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c");
    var ch_buf = std.ArrayListUnmanaged(u8).empty;
    defer ch_buf.deinit(testing.allocator);
    try buildMinimalClientHello(&ch_buf, testing.allocator, pubkey);
    const decoded = try client_hello.parse(ch_buf.items);

    var server = Server.init(.{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &[_]u8{ 0x00, 0x01 },
    });
    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(testing.allocator);
    const outcome = try server.onClientHello(&out, testing.allocator, decoded.value);

    // The correct client Finished: HMAC over the transcript through the server
    // Finished, keyed by the client handshake traffic secret - exactly what the
    // server retained. (The server's transcript is at that point right now.)
    const th = server.transcript.hash();
    const good = finished.build(outcome.built.client_hs_secret, th);

    // A tampered MAC is rejected and does not complete the handshake.
    var bad = good;
    bad[0] ^= 0xFF;
    try testing.expectError(error.BadFinished, server.onClientFinished(bad));
    try testing.expect(server.state == .flight_sent);

    // The correct MAC verifies and completes.
    try server.onClientFinished(good);
    try testing.expect(server.state == .complete);
    // A Finished in the complete state is unexpected.
    try testing.expectError(error.UnexpectedMessage, server.onClientFinished(good));
}

test "a ClientHello without ALPN is rejected when a protocol is configured" {
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c");
    var ch_buf = std.ArrayListUnmanaged(u8).empty;
    defer ch_buf.deinit(testing.allocator);
    try buildMinimalClientHello(&ch_buf, testing.allocator, pubkey); // no ALPN extension at all
    const decoded = try client_hello.parse(ch_buf.items);

    // ALPN is mandatory in QUIC (RFC 9001 8.1): omitting it fails like no overlap.
    var server = Server.init(.{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .alpn = "h3",
        .transport_params = &[_]u8{ 0x00, 0x01 },
    });
    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(testing.allocator);
    try testing.expectError(error.NoAlpnOverlap, server.onClientHello(&out, testing.allocator, decoded.value));
}

test "a configured ALPN absent from the client offer is rejected" {
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c");
    var ch_buf = std.ArrayListUnmanaged(u8).empty;
    defer ch_buf.deinit(testing.allocator);
    try buildClientHelloWithAlpn(&ch_buf, testing.allocator, pubkey, "h3"); // client offers only "h3"
    const decoded = try client_hello.parse(ch_buf.items);

    var server = Server.init(.{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .alpn = "hq-interop", // server supports a protocol the client did not offer
        .transport_params = &[_]u8{ 0x00, 0x01 },
    });
    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(testing.allocator);
    try testing.expectError(error.NoAlpnOverlap, server.onClientHello(&out, testing.allocator, decoded.value));
}

fn buildMinimalClientHello(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, pubkey: [32]u8) !void {
    return buildClientHelloImpl(out, gpa, pubkey, null);
}

fn buildClientHelloWithAlpn(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, pubkey: [32]u8, proto: []const u8) !void {
    return buildClientHelloImpl(out, gpa, pubkey, proto);
}

fn buildClientHelloImpl(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, pubkey: [32]u8, alpn: ?[]const u8) !void {
    const w = wire.Writer{ .out = out, .gpa = gpa };
    try w.u8v(0x01);
    const msg = try w.open(3);
    try w.u16v(0x0303);
    try w.bytes(&[_]u8{0x11} ** 32);
    try w.u8v(0x00); // empty session id
    const suites = try w.open(2);
    try w.u16v(0x1301);
    try w.close(suites);
    const comp = try w.open(1);
    try w.u8v(0x00);
    try w.close(comp);
    const exts = try w.open(2);
    try w.u16v(0x000a); // supported_groups
    const sg = try w.open(2);
    const sgl = try w.open(2);
    try w.u16v(0x001d);
    try w.close(sgl);
    try w.close(sg);
    try w.u16v(0x000d); // signature_algorithms
    const sa = try w.open(2);
    const sal = try w.open(2);
    try w.u16v(0x0403);
    try w.close(sal);
    try w.close(sa);
    try w.u16v(0x002b); // supported_versions
    const sv = try w.open(2);
    const svl = try w.open(1);
    try w.u16v(0x0304);
    try w.close(svl);
    try w.close(sv);
    try w.u16v(0x0033); // key_share
    const ks = try w.open(2);
    const ksl = try w.open(2);
    try w.u16v(0x001d);
    const pt = try w.open(2);
    try w.bytes(&pubkey);
    try w.close(pt);
    try w.close(ksl);
    try w.close(ks);
    if (alpn) |proto| {
        try w.u16v(0x0010); // application_layer_protocol_negotiation
        const ext = try w.open(2);
        const list = try w.open(2);
        const name = try w.open(1);
        try w.bytes(proto);
        try w.close(name);
        try w.close(list);
        try w.close(ext);
    }
    try w.u16v(0x0039); // quic_transport_parameters
    const qtp = try w.open(2);
    try w.bytes(&[_]u8{ 0x01, 0x02, 0x40, 0x01 });
    try w.close(qtp);
    try w.close(exts);
    try w.close(msg);
}
