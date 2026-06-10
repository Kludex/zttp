//! The server TLS 1.3 handshake driver, Connection-free: it owns the running
//! transcript and the integrator config, and turns a parsed ClientHello into the
//! server flight plus the per-space secrets. It knows nothing about QUIC packets or
//! spaces - the connection seam applies the keys and frames the flight into CRYPTO -
//! so the whole drive is a pure function of (config, transcript, ClientHello) and
//! testable against the RFC vectors with plain byte slices.

const std = @import("std");
const transcript = @import("transcript.zig");
const flight = @import("flight.zig");
const handshake = @import("handshake.zig");
const client_hello = @import("client_hello.zig");

pub const State = enum { wait_client_hello, flight_sent, complete };

pub const Error = error{
    /// A handshake message arrived in a state that forbids it (e.g. a second
    /// ClientHello). The connection maps this to PROTOCOL_VIOLATION.
    UnexpectedMessage,
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
        self.state = .flight_sent;
        return .{ .built = built, .server_hello_len = sh.len };
    }
};

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

fn buildMinimalClientHello(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, pubkey: [32]u8) !void {
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
    try w.u16v(0x0039); // quic_transport_parameters
    const qtp = try w.open(2);
    try w.bytes(&[_]u8{ 0x01, 0x02, 0x40, 0x01 });
    try w.close(qtp);
    try w.close(exts);
    try w.close(msg);
}
