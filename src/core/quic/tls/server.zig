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
const extension = @import("extension.zig");
const schedule = @import("schedule.zig");

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
    BadSessionTicket,
    BadPskBinder,
    OutOfMemory,
};

pub const SessionTicketConfig = struct {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    nonce: []const u8 = &.{},
    ticket: []const u8,
    extensions: []const u8 = &.{},
    max_early_data_size: ?u32 = null,
};

const MAX_SESSION_TICKET_NONCE: usize = 255;
const MAX_SESSION_TICKET: usize = 4096;
const MAX_SESSION_TICKET_EXTENSIONS: usize = 4096;
const TICKET_AGE_SKEW_MS: u32 = 10_000;

/// The result of accepting a ClientHello: the per-space secrets the connection
/// installs, and where in `out` the Initial-space ServerHello ends and the
/// Handshake-space encrypted flight begins.
pub const Outcome = struct {
    built: flight.Built,
    server_hello_len: usize,
    early_traffic_secret: ?[schedule.SECRET_LEN]u8 = null,
};

pub const Server = struct {
    transcript: transcript.Transcript = .{},
    config: flight.Config,
    state: State = .wait_client_hello,
    /// The client handshake traffic secret, kept from the flight build so the
    /// client's Finished MAC can be verified once it arrives.
    client_hs_secret: [32]u8 = undefined,
    key_schedule: schedule.Schedule = undefined,
    resumption_master_secret: ?[schedule.SECRET_LEN]u8 = null,

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
        const selected_psk = try self.selectPsk(ch);
        const early_traffic_secret = if (selected_psk) |selected|
            if (ch.early_data_offered and selected.index == 0 and selected.accept_early_data) schedule.clientEarlyTrafficSecret(selected.psk, self.transcript.hash()) else null
        else
            null;
        const view = flight.ClientHelloView{
            .legacy_session_id = ch.legacy_session_id,
            .client_key_share = ch.client_key_share,
            .selected_psk = selected_psk,
            .accept_early_data = early_traffic_secret != null,
        };
        const built = flight.build(out, gpa, &self.transcript, view, self.config) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Internal,
        };
        const sh = handshake.peek(out.items) orelse return error.Internal;
        if (sh.msg_type != .server_hello) return error.Internal;
        self.client_hs_secret = built.client_hs_secret;
        self.key_schedule = built.key_schedule;
        self.state = .flight_sent;
        return .{ .built = built, .server_hello_len = sh.len, .early_traffic_secret = early_traffic_secret };
    }

    fn selectPsk(self: *Server, ch: client_hello.ClientHello) Error!?flight.SelectedPsk {
        const offered = ch.offered_psks orelse return null;
        if (self.config.resumption) |credential| {
            if (try selectCredential(offered, ch.raw, credential, self.config.now_ms, ch.early_data_offered, false)) |selected| return selected;
        }
        for (self.config.resumption_store) |*credential| {
            if (try selectCredential(offered, ch.raw, credential.*, self.config.now_ms, ch.early_data_offered, true)) |selected| {
                if (selected.accept_early_data) credential.early_data_used = true;
                return selected;
            }
        }
        return null;
    }

    fn selectCredential(offered: client_hello.OfferedPsks, raw_client_hello: []const u8, credential: flight.ResumptionCredential, now_ms: u64, early_data_offered: bool, from_store: bool) Error!?flight.SelectedPsk {
        const found = (offered.findIdentity(credential.identity) catch return error.BadPskBinder) orelse return null;
        if (!ticketAgeValid(found.obfuscated_ticket_age, credential, now_ms)) return null;
        const valid = offered.verifyBinder(credential.identity, credential.psk, raw_client_hello) catch return error.BadPskBinder;
        if (!valid) return error.BadPskBinder;
        if (found.index > std.math.maxInt(u16)) return error.BadPskBinder;
        return .{
            .index = @intCast(found.index),
            .psk = credential.psk,
            .accept_early_data = earlyDataAllowed(found.index, early_data_offered, credential, from_store),
        };
    }

    fn earlyDataAllowed(index: usize, early_data_offered: bool, credential: flight.ResumptionCredential, from_store: bool) bool {
        if (!early_data_offered or index != 0) return false;
        if (!from_store) return false;
        const max = credential.max_early_data_size orelse return false;
        return max > 0 and !credential.early_data_used;
    }

    fn ticketAgeValid(obfuscated_ticket_age: u32, credential: flight.ResumptionCredential, now_ms: u64) bool {
        const lifetime = credential.ticket_lifetime orelse return true;
        const issued = credential.issued_at_ms orelse return true;
        if (lifetime == 0 or now_ms < issued) return false;
        const actual_age_ms = now_ms - issued;
        if (actual_age_ms > @as(u64, lifetime) * std.time.ms_per_s) return false;
        const reported_age_ms = obfuscated_ticket_age -% credential.ticket_age_add;
        const actual_mod: u32 = @truncate(actual_age_ms);
        const forward = reported_age_ms -% actual_mod;
        const backward = actual_mod -% reported_age_ms;
        return @min(forward, backward) <= TICKET_AGE_SKEW_MS;
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
        self.resumption_master_secret = self.key_schedule.deriveResumptionMaster(self.transcript.hash());
        self.state = .complete;
    }
};

pub fn buildNewSessionTicket(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, cfg: SessionTicketConfig) Error!void {
    if (cfg.nonce.len > MAX_SESSION_TICKET_NONCE or
        cfg.ticket.len == 0 or cfg.ticket.len > MAX_SESSION_TICKET or
        cfg.extensions.len + (if (cfg.max_early_data_size != null) @as(usize, 8) else 0) > MAX_SESSION_TICKET_EXTENSIONS)
    {
        return error.BadSessionTicket;
    }
    validateTicketExtensions(cfg.extensions, cfg.max_early_data_size != null) catch return error.BadSessionTicket;

    const w = wire.Writer{ .out = out, .gpa = gpa };
    w.u8v(@intFromEnum(handshake.MsgType.new_session_ticket)) catch return error.OutOfMemory;
    const msg = w.open(3) catch return error.OutOfMemory;
    writeU32(w, cfg.ticket_lifetime) catch return error.OutOfMemory;
    writeU32(w, cfg.ticket_age_add) catch return error.OutOfMemory;
    const nonce = w.open(1) catch return error.OutOfMemory;
    w.bytes(cfg.nonce) catch return error.OutOfMemory;
    w.close(nonce) catch return error.BadSessionTicket;
    const ticket = w.open(2) catch return error.OutOfMemory;
    w.bytes(cfg.ticket) catch return error.OutOfMemory;
    w.close(ticket) catch return error.BadSessionTicket;
    const extensions = w.open(2) catch return error.OutOfMemory;
    w.bytes(cfg.extensions) catch return error.OutOfMemory;
    if (cfg.max_early_data_size) |max_early_data_size| {
        w.u16v(@intFromEnum(extension.ExtType.early_data)) catch return error.OutOfMemory;
        const ext = w.open(2) catch return error.OutOfMemory;
        writeU32(w, max_early_data_size) catch return error.OutOfMemory;
        w.close(ext) catch return error.BadSessionTicket;
    }
    w.close(extensions) catch return error.BadSessionTicket;
    w.close(msg) catch return error.BadSessionTicket;
}

fn writeU32(w: wire.Writer, value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .big);
    try w.bytes(&buf);
}

fn validateTicketExtensions(raw: []const u8, disallow_early_data: bool) wire.Error!void {
    var r = wire.Reader{ .buf = raw };
    var seen = std.StaticBitSet(0x1_0000).initEmpty();
    while (r.remaining() != 0) {
        const ext_raw = try r.readU16();
        if (seen.isSet(ext_raw)) return error.EncodingError;
        seen.set(ext_raw);
        if (disallow_early_data and ext_raw == @intFromEnum(extension.ExtType.early_data)) return error.EncodingError;
        var body = try r.vector(2);
        _ = try body.take(body.remaining());
    }
}

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

fn expectServerHelloSelectedPsk(body: []const u8, want_index: u16) !void {
    var r = wire.Reader{ .buf = body };
    _ = try r.readU16(); // legacy_version
    _ = try r.take(32); // random
    _ = try r.vector(1); // legacy_session_id_echo
    _ = try r.readU16(); // cipher_suite
    _ = try r.byte(); // compression
    var exts = try r.vector(2);
    try r.expectEnd();
    var selected: ?u16 = null;
    while (exts.remaining() != 0) {
        const raw = try exts.readU16();
        var ext = try exts.vector(2);
        if (raw == @intFromEnum(extension.ExtType.pre_shared_key)) {
            selected = try ext.readU16();
            try ext.expectEnd();
        } else {
            _ = try ext.take(ext.remaining());
        }
    }
    try testing.expectEqual(want_index, selected orelse return error.EncodingError);
}

fn expectEncryptedExtensionsEarlyData(body: []const u8) !void {
    var r = wire.Reader{ .buf = body };
    var exts = try r.vector(2);
    try r.expectEnd();
    var saw_early_data = false;
    while (exts.remaining() != 0) {
        const raw = try exts.readU16();
        var ext = try exts.vector(2);
        if (raw == @intFromEnum(extension.ExtType.early_data)) {
            try ext.expectEnd();
            saw_early_data = true;
        } else {
            _ = try ext.take(ext.remaining());
        }
    }
    try testing.expect(saw_early_data);
}

const testing = std.testing;
const wire = @import("wire.zig");
const sign = @import("sign.zig");
const tls_client = @import("client.zig");

test "buildNewSessionTicket emits a parseable TLS ticket" {
    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(testing.allocator);
    try buildNewSessionTicket(&out, testing.allocator, .{
        .ticket_lifetime = 7200,
        .ticket_age_add = 0x01020304,
        .nonce = &.{ 0xaa, 0xbb },
        .ticket = "ticket-bytes",
        .extensions = &.{ 0xfa, 0xce, 0x00, 0x00 },
        .max_early_data_size = 4096,
    });

    const msg = handshake.peek(out.items).?;
    try testing.expectEqual(handshake.MsgType.new_session_ticket, msg.msg_type);
    try testing.expectEqual(out.items.len, msg.len);
    var ticket = try tls_client.parseNewSessionTicket(testing.allocator, msg.body);
    defer ticket.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 7200), ticket.ticket_lifetime);
    try testing.expectEqual(@as(u32, 0x01020304), ticket.ticket_age_add);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, ticket.nonce);
    try testing.expectEqualSlices(u8, "ticket-bytes", ticket.ticket);
    try testing.expectEqualSlices(u8, &.{ 0xfa, 0xce, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x10, 0x00 }, ticket.extensions);
    try testing.expectEqual(@as(u32, 4096), ticket.max_early_data_size.?);
}

test "buildNewSessionTicket rejects empty ticket data" {
    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(testing.allocator);
    try testing.expectError(error.BadSessionTicket, buildNewSessionTicket(&out, testing.allocator, .{
        .ticket_lifetime = 0,
        .ticket_age_add = 0,
        .ticket = &.{},
    }));
}

test "buildNewSessionTicket rejects duplicate early_data extension" {
    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(testing.allocator);
    try testing.expectError(error.BadSessionTicket, buildNewSessionTicket(&out, testing.allocator, .{
        .ticket_lifetime = 0,
        .ticket_age_add = 0,
        .ticket = "ticket",
        .extensions = &.{ 0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x10, 0x00 },
        .max_early_data_size = 4096,
    }));
}

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

test "onClientHello selects a valid resumption PSK" {
    const psk = [_]u8{0x7b} ** 32;
    var ch_buf = std.ArrayListUnmanaged(u8).empty;
    defer ch_buf.deinit(testing.allocator);
    _ = try tls_client.buildClientHello(&ch_buf, testing.allocator, .{
        .random = [_]u8{0x11} ** 32,
        .ephemeral_seed = [_]u8{0x22} ** 32,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = "h3",
        .resumption = .{
            .identity = "ticket-identity",
            .obfuscated_ticket_age = 0x01020304,
            .psk = psk,
        },
    });
    const decoded = try client_hello.parse(ch_buf.items);

    var server = Server.init(.{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &[_]u8{ 0x00, 0x01 },
        .resumption = .{ .identity = "ticket-identity", .psk = psk },
    });

    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(testing.allocator);
    const outcome = try server.onClientHello(&out, testing.allocator, decoded.value);
    const sh = handshake.peek(out.items).?;
    try testing.expectEqual(handshake.MsgType.server_hello, sh.msg_type);
    try testing.expectEqual(sh.len, outcome.server_hello_len);
    try expectServerHelloSelectedPsk(sh.body, 0);
}

test "onClientHello selects a PSK from the resumption store" {
    const psk = [_]u8{0x5a} ** 32;
    var ch_buf = std.ArrayListUnmanaged(u8).empty;
    defer ch_buf.deinit(testing.allocator);
    _ = try tls_client.buildClientHello(&ch_buf, testing.allocator, .{
        .random = [_]u8{0x11} ** 32,
        .ephemeral_seed = [_]u8{0x22} ** 32,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = "h3",
        .resumption = .{
            .identity = "stored-ticket",
            .obfuscated_ticket_age = 0x01020304,
            .psk = psk,
        },
    });
    const decoded = try client_hello.parse(ch_buf.items);
    var store = [_]flight.ResumptionCredential{.{ .identity = "stored-ticket", .psk = psk }};

    var server = Server.init(.{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &[_]u8{ 0x00, 0x01 },
        .resumption_store = &store,
    });

    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(testing.allocator);
    const outcome = try server.onClientHello(&out, testing.allocator, decoded.value);
    const sh = handshake.peek(out.items).?;
    try testing.expectEqual(sh.len, outcome.server_hello_len);
    try expectServerHelloSelectedPsk(sh.body, 0);
}

test "onClientHello rejects early data for a static resumption PSK" {
    const psk = [_]u8{0x7b} ** 32;
    var ch_buf = std.ArrayListUnmanaged(u8).empty;
    defer ch_buf.deinit(testing.allocator);
    _ = try tls_client.buildClientHello(&ch_buf, testing.allocator, .{
        .random = [_]u8{0x11} ** 32,
        .ephemeral_seed = [_]u8{0x22} ** 32,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = "h3",
        .resumption = .{
            .identity = "ticket-identity",
            .obfuscated_ticket_age = 0x01020304,
            .psk = psk,
            .early_data = true,
        },
    });
    const decoded = try client_hello.parse(ch_buf.items);

    var server = Server.init(.{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &[_]u8{ 0x00, 0x01 },
        .resumption = .{ .identity = "ticket-identity", .psk = psk },
    });

    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(testing.allocator);
    const outcome = try server.onClientHello(&out, testing.allocator, decoded.value);
    try testing.expect(outcome.early_traffic_secret == null);
    const ee = handshake.peek(out.items[outcome.server_hello_len..]).?;
    try testing.expectEqual(handshake.MsgType.encrypted_extensions, ee.msg_type);
    try testing.expectError(error.TestUnexpectedResult, expectEncryptedExtensionsEarlyData(ee.body));
}

test "onClientHello rejects a matching PSK identity with a bad binder" {
    const psk = [_]u8{0x7b} ** 32;
    var ch_buf = std.ArrayListUnmanaged(u8).empty;
    defer ch_buf.deinit(testing.allocator);
    _ = try tls_client.buildClientHello(&ch_buf, testing.allocator, .{
        .random = [_]u8{0x11} ** 32,
        .ephemeral_seed = [_]u8{0x22} ** 32,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .resumption = .{
            .identity = "ticket-identity",
            .obfuscated_ticket_age = 0x01020304,
            .psk = psk,
        },
    });
    ch_buf.items[ch_buf.items.len - 1] ^= 0xff;
    const decoded = try client_hello.parse(ch_buf.items);

    var server = Server.init(.{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &[_]u8{ 0x00, 0x01 },
        .resumption = .{ .identity = "ticket-identity", .psk = psk },
    });
    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(testing.allocator);
    try testing.expectError(error.BadPskBinder, server.onClientHello(&out, testing.allocator, decoded.value));
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
    const expected_rms = outcome.built.key_schedule.deriveResumptionMaster(server.transcript.hash());
    try testing.expectEqualSlices(u8, &expected_rms, &server.resumption_master_secret.?);
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
