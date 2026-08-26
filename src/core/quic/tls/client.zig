//! TLS 1.3 client-handshake start for QUIC: build the ClientHello bytes and keep
//! the X25519 key share needed to process the server flight later. The follow-up
//! client driver will parse ServerHello/EncryptedExtensions/Finished; this module is
//! the byte-exact first flight shared by the QUIC transport and tests.

const std = @import("std");
const wire = @import("wire.zig");
const keyshare = @import("keyshare.zig");
const sign = @import("sign.zig");
const extension = @import("extension.zig");
const client_hello = @import("client_hello.zig");
const handshake = @import("handshake.zig");
const transcript = @import("transcript.zig");
const schedule = @import("schedule.zig");
const finished = @import("finished.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const State = enum { idle, wait_server_hello, wait_server_flight, complete };

pub const Error = error{
    UnexpectedMessage,
    BadServerHello,
    BadNewSessionTicket,
    Internal,
    OutOfMemory,
};

pub const Config = struct {
    random: [32]u8,
    ephemeral_seed: [32]u8,
    transport_params: []const u8,
    alpn: ?[]const u8 = null,
    server_name: ?[]const u8 = null,
    server_certificate: []const u8 = &.{},
    resumption: ?ResumptionPsk = null,
    validation_token: ?[]const u8 = null,
};

pub const ResumptionPsk = struct {
    identity: []const u8,
    obfuscated_ticket_age: u32,
    psk: [schedule.SECRET_LEN]u8,
    early_data: bool = false,
};

pub const Built = struct {
    key_share: keyshare.KeyShare,
};

pub const ServerHelloOutcome = struct {
    handshake_secrets: schedule.Secrets,
};

pub const ServerFlightOutcome = struct {
    application_secrets: schedule.Secrets,
    peer_transport_params: []const u8,
    early_data_accepted: bool = false,
    consumed: usize,
};

pub const SessionTicket = struct {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    nonce: []u8,
    ticket: []u8,
    extensions: []u8,
    max_early_data_size: ?u32 = null,
    psk: ?[schedule.SECRET_LEN]u8 = null,

    pub fn deinit(self: *SessionTicket, gpa: std.mem.Allocator) void {
        gpa.free(self.nonce);
        gpa.free(self.ticket);
        gpa.free(self.extensions);
        self.* = undefined;
    }
};

const MAX_SESSION_TICKET_NONCE: usize = 255;
const MAX_SESSION_TICKET: usize = 4096;
const MAX_SESSION_TICKET_EXTENSIONS: usize = 4096;

pub const Client = struct {
    transcript: transcript.Transcript = .{},
    state: State = .idle,
    key_share: keyshare.KeyShare = undefined,
    schedule: schedule.Schedule = undefined,
    handshake_secrets: schedule.Secrets = undefined,
    resumption_psk: ?[schedule.SECRET_LEN]u8 = null,
    early_traffic_secret: ?[schedule.SECRET_LEN]u8 = null,
    resumption_master_secret: ?[schedule.SECRET_LEN]u8 = null,
    expected_alpn: [255]u8 = [_]u8{0} ** 255,
    expected_alpn_len: u8 = 0,
    expected_certificate_hash: [Sha256.digest_length]u8 = [_]u8{0} ** Sha256.digest_length,
    certificate_configured: bool = false,

    pub fn init() Client {
        return .{};
    }

    pub fn start(self: *Client, out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, cfg: Config) Error!void {
        if (self.state != .idle) return error.UnexpectedMessage;
        const before = out.items.len;
        const built = buildClientHello(out, gpa, cfg) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Internal,
        };
        self.key_share = built.key_share;
        self.resumption_psk = if (cfg.resumption) |psk| psk.psk else null;
        if (cfg.alpn) |proto| {
            if (proto.len > self.expected_alpn.len) return error.Internal;
            @memcpy(self.expected_alpn[0..proto.len], proto);
            self.expected_alpn_len = @intCast(proto.len);
        } else {
            self.expected_alpn_len = 0;
        }
        self.certificate_configured = cfg.server_certificate.len > 0;
        Sha256.hash(cfg.server_certificate, &self.expected_certificate_hash, .{});
        self.transcript.update(out.items[before..]);
        self.early_traffic_secret = if (cfg.resumption) |psk|
            if (psk.early_data) schedule.clientEarlyTrafficSecret(psk.psk, self.transcript.hash()) else null
        else
            null;
        self.state = .wait_server_hello;
    }

    pub fn onServerHello(self: *Client, raw: []const u8) Error!ServerHelloOutcome {
        if (self.state != .wait_server_hello) return error.UnexpectedMessage;
        const msg = handshake.peek(raw) orelse return error.BadServerHello;
        if (msg.len != raw.len or msg.msg_type != .server_hello) return error.BadServerHello;
        const parsed = parseServerHello(msg.body) catch return error.BadServerHello;
        self.transcript.update(raw);
        const th_sh = self.transcript.hash();
        const ecdhe = self.key_share.shared(parsed.server_pub) catch return error.BadServerHello;
        const d = if (parsed.selected_psk) |selected| blk: {
            if (selected != 0) return error.BadServerHello;
            const psk = self.resumption_psk orelse return error.BadServerHello;
            break :blk schedule.Schedule.deriveHandshakePsk(ecdhe, th_sh, psk);
        } else schedule.Schedule.deriveHandshake(ecdhe, th_sh);
        self.schedule = d.schedule;
        self.handshake_secrets = d.secrets;
        self.state = .wait_server_flight;
        return .{ .handshake_secrets = d.secrets };
    }

    pub fn onServerFlight(self: *Client, out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, raw: []const u8) Error!?ServerFlightOutcome {
        if (self.state != .wait_server_flight) return error.UnexpectedMessage;
        const scanned = try scanServerFlight(raw) orelse return null;
        const ee = parseEncryptedExtensions(scanned.ee.body) catch return error.BadServerHello;
        if (self.expected_alpn_len > 0) {
            const selected = ee.alpn orelse return error.BadServerHello;
            if (!std.mem.eql(u8, selected, self.expected_alpn[0..self.expected_alpn_len])) return error.BadServerHello;
        }
        const cert = handshake.firstCertificate(scanned.cert.body) catch return error.BadServerHello;
        if (!self.certificate_configured) return error.BadServerHello;
        var certificate_hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(cert, &certificate_hash, .{});
        if (!std.crypto.timing_safe.eql([Sha256.digest_length]u8, certificate_hash, self.expected_certificate_hash)) {
            return error.BadServerHello;
        }

        self.transcript.update(scanned.ee.raw);
        self.transcript.update(scanned.cert.raw);

        const th_for_cv = self.transcript.hash();
        const cv = parseCertificateVerify(scanned.cv.body) catch return error.BadServerHello;
        const public_sec1 = sign.certificatePublicKeySec1(cert) catch return error.BadServerHello;
        sign.verify(public_sec1, th_for_cv, cv) catch return error.BadServerHello;
        self.transcript.update(scanned.cv.raw);

        const th_for_finished = self.transcript.hash();
        const server_finished = handshake.finishedBody(scanned.fin.body) catch return error.BadServerHello;
        finished.verify(self.handshake_secrets.server, th_for_finished, server_finished) catch return error.BadServerHello;
        self.transcript.update(scanned.fin.raw);

        const app = self.schedule.deriveApplication(self.transcript.hash());
        const client_verify = finished.build(self.handshake_secrets.client, self.transcript.hash());
        const finished_start = out.items.len;
        try appendFinished(out, gpa, client_verify);
        self.transcript.update(out.items[finished_start..]);
        self.resumption_master_secret = self.schedule.deriveResumptionMaster(self.transcript.hash());
        self.state = .complete;
        return .{ .application_secrets = app, .peer_transport_params = ee.quic_transport_parameters, .early_data_accepted = ee.early_data_accepted, .consumed = scanned.consumed };
    }
};

pub fn deriveTicketPsk(ticket: *SessionTicket, resumption_master_secret: [schedule.SECRET_LEN]u8) void {
    ticket.psk = schedule.resumptionPsk(resumption_master_secret, ticket.nonce);
}

pub fn parseNewSessionTicket(gpa: std.mem.Allocator, body: []const u8) Error!SessionTicket {
    var r = wire.Reader{ .buf = body };
    const ticket_lifetime = readU32(&r) catch return error.BadNewSessionTicket;
    const ticket_age_add = readU32(&r) catch return error.BadNewSessionTicket;
    const nonce_src = (r.vector(1) catch return error.BadNewSessionTicket).buf;
    const ticket_src = (r.vector(2) catch return error.BadNewSessionTicket).buf;
    const ext_src = (r.vector(2) catch return error.BadNewSessionTicket).buf;
    r.expectEnd() catch return error.BadNewSessionTicket;
    const max_early_data_size = parseTicketExtensions(ext_src) catch return error.BadNewSessionTicket;
    if (nonce_src.len > MAX_SESSION_TICKET_NONCE or
        ticket_src.len == 0 or ticket_src.len > MAX_SESSION_TICKET or
        ext_src.len > MAX_SESSION_TICKET_EXTENSIONS)
    {
        return error.BadNewSessionTicket;
    }

    const nonce = try gpa.dupe(u8, nonce_src);
    errdefer gpa.free(nonce);
    const ticket = try gpa.dupe(u8, ticket_src);
    errdefer gpa.free(ticket);
    const extensions = try gpa.dupe(u8, ext_src);
    errdefer gpa.free(extensions);
    return .{
        .ticket_lifetime = ticket_lifetime,
        .ticket_age_add = ticket_age_add,
        .nonce = nonce,
        .ticket = ticket,
        .extensions = extensions,
        .max_early_data_size = max_early_data_size,
    };
}

fn readU32(r: *wire.Reader) wire.Error!u32 {
    const s = try r.take(4);
    return std.mem.readInt(u32, s[0..4], .big);
}

fn parseTicketExtensions(raw: []const u8) wire.Error!?u32 {
    var r = wire.Reader{ .buf = raw };
    var seen = std.StaticBitSet(0x1_0000).initEmpty();
    var max_early_data_size: ?u32 = null;
    while (r.remaining() != 0) {
        const ext_raw = try r.readU16();
        if (seen.isSet(ext_raw)) return error.EncodingError;
        seen.set(ext_raw);
        var body = try r.vector(2);
        const ty: extension.ExtType = @enumFromInt(ext_raw);
        switch (ty) {
            .early_data => {
                max_early_data_size = try readU32(&body);
                try body.expectEnd();
            },
            else => _ = try body.take(body.remaining()),
        }
    }
    return max_early_data_size;
}

pub fn buildClientHello(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, cfg: Config) !Built {
    const ks = try keyshare.KeyShare.ephemeral(cfg.ephemeral_seed);
    const w = wire.Writer{ .out = out, .gpa = gpa };
    const hello_start = out.items.len;
    try w.u8v(0x01); // client_hello
    const msg = try w.open(3);
    try w.u16v(0x0303); // legacy_version
    try w.bytes(&cfg.random);
    try w.u8v(0x00); // legacy_session_id: empty for QUIC
    const suites = try w.open(2);
    try w.u16v(0x1301); // TLS_AES_128_GCM_SHA256
    try w.close(suites);
    const comp = try w.open(1);
    try w.u8v(0x00);
    try w.close(comp);

    const exts = try w.open(2);
    if (cfg.server_name) |name| {
        try w.u16v(@intFromEnum(extension.ExtType.server_name));
        const ext = try w.open(2);
        const list = try w.open(2);
        try w.u8v(0x00); // host_name
        const host = try w.open(2);
        try w.bytes(name);
        try w.close(host);
        try w.close(list);
        try w.close(ext);
    }
    try w.u16v(@intFromEnum(extension.ExtType.supported_groups));
    const sg = try w.open(2);
    const sgl = try w.open(2);
    try w.u16v(extension.X25519);
    try w.close(sgl);
    try w.close(sg);

    try w.u16v(@intFromEnum(extension.ExtType.signature_algorithms));
    const sa = try w.open(2);
    const sal = try w.open(2);
    try w.u16v(sign.SCHEME);
    try w.close(sal);
    try w.close(sa);

    if (cfg.alpn) |proto| {
        try w.u16v(@intFromEnum(extension.ExtType.alpn));
        const ext = try w.open(2);
        const list = try w.open(2);
        const name = try w.open(1);
        try w.bytes(proto);
        try w.close(name);
        try w.close(list);
        try w.close(ext);
    }

    try w.u16v(@intFromEnum(extension.ExtType.supported_versions));
    const sv = try w.open(2);
    const svl = try w.open(1);
    try w.u16v(extension.TLS13);
    try w.close(svl);
    try w.close(sv);

    try w.u16v(@intFromEnum(extension.ExtType.key_share));
    const ks_ext = try w.open(2);
    const shares = try w.open(2);
    try w.u16v(extension.X25519);
    const public_key = try w.open(2);
    try w.bytes(&ks.public_key);
    try w.close(public_key);
    try w.close(shares);
    try w.close(ks_ext);

    try w.u16v(@intFromEnum(extension.ExtType.quic_transport_parameters));
    const qtp = try w.open(2);
    try w.bytes(cfg.transport_params);
    try w.close(qtp);

    try w.u16v(@intFromEnum(extension.ExtType.psk_key_exchange_modes));
    const modes_ext = try w.open(2);
    const modes = try w.open(1);
    try w.u8v(0x01); // psk_dhe_ke
    try w.close(modes);
    try w.close(modes_ext);

    const psk_binder = if (cfg.resumption) |psk| blk: {
        if (psk.identity.len == 0 or psk.identity.len > 0xffff) return error.EncodingError;

        if (psk.early_data) {
            try w.u16v(@intFromEnum(extension.ExtType.early_data));
            const early = try w.open(2);
            try w.close(early);
        }

        try w.u16v(@intFromEnum(extension.ExtType.pre_shared_key));
        const psk_ext = try w.open(2);
        const identities = try w.open(2);
        const identity = try w.open(2);
        try w.bytes(psk.identity);
        try w.close(identity);
        try writeU32(w, psk.obfuscated_ticket_age);
        try w.close(identities);

        const truncate_at = out.items.len;
        const binders = try w.open(2);
        try w.u8v(schedule.SECRET_LEN);
        const binder_at = out.items.len;
        try out.appendNTimes(gpa, 0, schedule.SECRET_LEN);
        try w.close(binders);
        try w.close(psk_ext);
        break :blk PskBinderPatch{ .hello_start = hello_start, .truncate_at = truncate_at, .binder_at = binder_at, .psk = psk.psk };
    } else null;

    try w.close(exts);
    try w.close(msg);
    if (psk_binder) |patch| {
        var th: [schedule.SECRET_LEN]u8 = undefined;
        Sha256.hash(out.items[patch.hello_start..patch.truncate_at], &th, .{});
        const binder = schedule.resumptionBinder(patch.psk, th);
        @memcpy(out.items[patch.binder_at .. patch.binder_at + binder.len], &binder);
    }
    return .{ .key_share = ks };
}

const PskBinderPatch = struct {
    hello_start: usize,
    truncate_at: usize,
    binder_at: usize,
    psk: [schedule.SECRET_LEN]u8,
};

fn writeU32(w: wire.Writer, value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .big);
    try w.bytes(&buf);
}

const ParsedServerHello = struct {
    server_pub: [32]u8,
    selected_psk: ?u16 = null,
};

fn parseServerHello(body: []const u8) wire.Error!ParsedServerHello {
    var r = wire.Reader{ .buf = body };
    if (try r.readU16() != 0x0303) return error.EncodingError;
    _ = try r.take(32); // random
    _ = try r.vector(1); // legacy_session_id_echo
    if (try r.readU16() != 0x1301) return error.EncodingError;
    if (try r.byte() != 0x00) return error.EncodingError;
    var exts = try r.vector(2);
    try r.expectEnd();

    var tls13 = false;
    var server_pub: ?[32]u8 = null;
    var selected_psk: ?u16 = null;
    var seen = std.StaticBitSet(0x1_0000).initEmpty();
    while (exts.remaining() != 0) {
        const raw = try exts.readU16();
        if (seen.isSet(raw)) return error.EncodingError;
        seen.set(raw);
        var ext = try exts.vector(2);
        const ty: extension.ExtType = @enumFromInt(raw);
        switch (ty) {
            .supported_versions => {
                if (try ext.readU16() != extension.TLS13) return error.EncodingError;
                tls13 = true;
                try ext.expectEnd();
            },
            .key_share => {
                if (try ext.readU16() != extension.X25519) return error.EncodingError;
                const key = (try ext.vector(2)).buf;
                if (key.len != 32) return error.EncodingError;
                server_pub = key[0..32].*;
                try ext.expectEnd();
            },
            .pre_shared_key => {
                selected_psk = try ext.readU16();
                try ext.expectEnd();
            },
            .server_name, .supported_groups, .signature_algorithms, .alpn, .early_data, .psk_key_exchange_modes, .quic_transport_parameters, _ => {
                _ = try ext.take(ext.remaining());
            },
        }
    }
    if (!tls13) return error.EncodingError;
    return .{
        .server_pub = server_pub orelse return error.EncodingError,
        .selected_psk = selected_psk,
    };
}

const FlightMsg = struct { raw: []const u8, body: []const u8 };
const ScannedFlight = struct {
    ee: FlightMsg,
    cert: FlightMsg,
    cv: FlightMsg,
    fin: FlightMsg,
    consumed: usize,
};

fn scanOne(buf: []const u8, off: *usize, want: handshake.MsgType) Error!?FlightMsg {
    const msg = handshake.peek(buf[off.*..]) orelse return null;
    if (msg.msg_type != want) return error.BadServerHello;
    const raw = buf[off.* .. off.* + msg.len];
    off.* += msg.len;
    return .{ .raw = raw, .body = msg.body };
}

fn scanServerFlight(raw: []const u8) Error!?ScannedFlight {
    var off: usize = 0;
    const ee = (try scanOne(raw, &off, .encrypted_extensions)) orelse return null;
    const cert = (try scanOne(raw, &off, .certificate)) orelse return null;
    const cv = (try scanOne(raw, &off, .certificate_verify)) orelse return null;
    const fin = (try scanOne(raw, &off, .finished)) orelse return null;
    if (off != raw.len) return error.BadServerHello;
    return .{ .ee = ee, .cert = cert, .cv = cv, .fin = fin, .consumed = off };
}

const ParsedEncryptedExtensions = struct {
    quic_transport_parameters: []const u8,
    early_data_accepted: bool = false,
    alpn: ?[]const u8 = null,
};

fn parseEncryptedExtensions(body: []const u8) wire.Error!ParsedEncryptedExtensions {
    var r = wire.Reader{ .buf = body };
    var exts = try r.vector(2);
    try r.expectEnd();
    var qtp: ?[]const u8 = null;
    var early_data_accepted = false;
    var alpn: ?[]const u8 = null;
    var seen = std.StaticBitSet(0x1_0000).initEmpty();
    while (exts.remaining() != 0) {
        const raw = try exts.readU16();
        if (seen.isSet(raw)) return error.EncodingError;
        seen.set(raw);
        var ext = try exts.vector(2);
        const ty: extension.ExtType = @enumFromInt(raw);
        switch (ty) {
            .quic_transport_parameters => qtp = try ext.take(ext.remaining()),
            .early_data => {
                try ext.expectEnd();
                early_data_accepted = true;
            },
            .alpn => alpn = try parseSelectedAlpn(ext.buf),
            .server_name, .supported_groups, .signature_algorithms, .pre_shared_key, .psk_key_exchange_modes, .supported_versions, .key_share, _ => _ = try ext.take(ext.remaining()),
        }
    }
    return .{
        .quic_transport_parameters = qtp orelse return error.EncodingError,
        .early_data_accepted = early_data_accepted,
        .alpn = alpn,
    };
}

fn parseSelectedAlpn(body: []const u8) wire.Error![]const u8 {
    var r = wire.Reader{ .buf = body };
    var protocols = try r.vector(2);
    try r.expectEnd();
    var name = try protocols.vector(1);
    try protocols.expectEnd();
    if (name.remaining() == 0) return error.EncodingError;
    return try name.take(name.remaining());
}

fn parseCertificateVerify(body: []const u8) wire.Error![]const u8 {
    var r = wire.Reader{ .buf = body };
    if (try r.readU16() != sign.SCHEME) return error.EncodingError;
    const sig = (try r.vector(2)).buf;
    try r.expectEnd();
    return sig;
}

fn appendFinished(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, verify_data: [finished.LEN]u8) !void {
    try out.append(gpa, 0x14);
    try out.appendSlice(gpa, &.{ 0x00, 0x00, @as(u8, @intCast(finished.LEN)) });
    try out.appendSlice(gpa, &verify_data);
}

const testing = std.testing;

test "buildClientHello emits a parseable QUIC ClientHello" {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(testing.allocator);
    const cfg = Config{
        .random = [_]u8{0x11} ** 32,
        .ephemeral_seed = [_]u8{0x22} ** 32,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = "h3",
        .server_name = "example.com",
    };
    const built = try buildClientHello(&out, testing.allocator, cfg);
    const d = try client_hello.parse(out.items);
    try testing.expectEqual(out.items.len, d.len);
    try testing.expectEqualSlices(u8, &cfg.random, &d.value.random);
    try testing.expectEqualStrings("example.com", d.value.server_name.?);
    try testing.expectEqualSlices(u8, &.{ 0x02, 'h', '3' }, d.value.alpn.?);
    try testing.expectEqualSlices(u8, cfg.transport_params, d.value.quic_transport_parameters);
    try testing.expectEqualSlices(u8, &.{0x01}, d.value.psk_key_exchange_modes.?);
    try testing.expectEqualSlices(u8, &built.key_share.public_key, &d.value.client_key_share);
}

test "buildClientHello can offer a resumption PSK with a valid binder" {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(testing.allocator);
    const psk = [_]u8{0x7b} ** schedule.SECRET_LEN;
    const cfg = Config{
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
    };
    _ = try buildClientHello(&out, testing.allocator, cfg);
    const decoded = try client_hello.parse(out.items);
    try testing.expectEqual(out.items.len, decoded.len);

    const msg = handshake.peek(out.items).?;
    var r = wire.Reader{ .buf = msg.body };
    _ = try r.readU16(); // legacy_version
    _ = try r.take(32); // random
    _ = try r.vector(1); // legacy_session_id
    _ = try r.vector(2); // cipher_suites
    _ = try r.vector(1); // compression_methods
    var exts = try r.vector(2);
    try r.expectEnd();

    var saw_modes = false;
    var saw_early = false;
    var last_ext: u16 = 0;
    var psk_body: []const u8 = &.{};
    while (exts.remaining() != 0) {
        const raw = try exts.readU16();
        last_ext = raw;
        var body = try exts.vector(2);
        switch (@as(extension.ExtType, @enumFromInt(raw))) {
            .psk_key_exchange_modes => {
                const modes = (try body.vector(1)).buf;
                try testing.expectEqualSlices(u8, &.{0x01}, modes);
                try body.expectEnd();
                saw_modes = true;
            },
            .early_data => {
                try body.expectEnd();
                saw_early = true;
            },
            .pre_shared_key => psk_body = body.buf,
            else => _ = try body.take(body.remaining()),
        }
    }
    try testing.expect(saw_modes);
    try testing.expect(saw_early);
    try testing.expectEqual(@intFromEnum(extension.ExtType.pre_shared_key), last_ext);

    var psk_r = wire.Reader{ .buf = psk_body };
    var identities = try psk_r.vector(2);
    const identity = (try identities.vector(2)).buf;
    try testing.expectEqualSlices(u8, "ticket-identity", identity);
    try testing.expectEqual(@as(u32, 0x01020304), try readU32(&identities));
    try identities.expectEnd();
    var binders = try psk_r.vector(2);
    const binder_len = try binders.byte();
    try testing.expectEqual(@as(u8, schedule.SECRET_LEN), binder_len);
    const binder = try binders.take(schedule.SECRET_LEN);
    try binders.expectEnd();
    try psk_r.expectEnd();

    const truncated_len = out.items.len - (2 + 1 + schedule.SECRET_LEN);
    var th: [schedule.SECRET_LEN]u8 = undefined;
    Sha256.hash(out.items[0..truncated_len], &th, .{});
    const expected = schedule.resumptionBinder(psk, th);
    try testing.expectEqualSlices(u8, &expected, binder);
    const offered = decoded.value.offered_psks.?;
    try testing.expect(try offered.verifyBinder("ticket-identity", psk, decoded.value.raw));
    try testing.expect(!try offered.verifyBinder("missing-ticket", psk, decoded.value.raw));

    var bad = try out.clone(testing.allocator);
    defer bad.deinit(testing.allocator);
    bad.items[truncated_len + 2] = schedule.SECRET_LEN - 1; // binder vector element length
    try testing.expectError(error.EncodingError, client_hello.parse(bad.items));
}

test "client stores the early traffic secret when it offers early data" {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(testing.allocator);
    const psk = [_]u8{0x7b} ** schedule.SECRET_LEN;
    var client = Client.init();
    try client.start(&out, testing.allocator, .{
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
    var th: [schedule.SECRET_LEN]u8 = undefined;
    Sha256.hash(out.items, &th, .{});
    const expected = schedule.clientEarlyTrafficSecret(psk, th);
    try testing.expectEqualSlices(u8, &expected, &client.early_traffic_secret.?);
}

test "parseNewSessionTicket keeps the ticket fields" {
    const body = [_]u8{
        0x00, 0x00, 0x0e, 0x10, // ticket_lifetime
        0xaa, 0xbb, 0xcc, 0xdd, // ticket_age_add
        0x02, 0x01, 0x02, // ticket_nonce
        0x00, 0x03, 0x41, 0x42, 0x43, // ticket
        0x00, 0x08, 0x00, 0x2a, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, // early_data max=65536
    };
    var ticket = try parseNewSessionTicket(testing.allocator, &body);
    defer ticket.deinit(testing.allocator);

    try testing.expectEqual(@as(u32, 3600), ticket.ticket_lifetime);
    try testing.expectEqual(@as(u32, 0xaabbccdd), ticket.ticket_age_add);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, ticket.nonce);
    try testing.expectEqualSlices(u8, "ABC", ticket.ticket);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x2a, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00 }, ticket.extensions);
    try testing.expectEqual(@as(u32, 65536), ticket.max_early_data_size.?);
}

test "parseNewSessionTicket rejects an empty ticket vector" {
    const body = [_]u8{
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, // ticket_nonce
        0x00, 0x00, // empty ticket
        0x00, 0x00, // extensions
    };
    try testing.expectError(error.BadNewSessionTicket, parseNewSessionTicket(testing.allocator, &body));
}

test "parseNewSessionTicket rejects duplicate ticket extensions" {
    const body = [_]u8{
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, // ticket_nonce
        0x00, 0x01, 0x42, // ticket
        0x00, 0x08, 0xfa, 0xce, 0x00, 0x00, 0xfa, 0xce, 0x00, 0x00, // duplicate unknown extension
    };
    try testing.expectError(error.BadNewSessionTicket, parseNewSessionTicket(testing.allocator, &body));
}

test "client derives handshake secrets from a server hello" {
    const server_flight = @import("flight.zig");
    var ch: std.ArrayListUnmanaged(u8) = .empty;
    defer ch.deinit(testing.allocator);
    var client = Client.init();
    try client.start(&ch, testing.allocator, .{
        .random = [_]u8{0x11} ** 32,
        .ephemeral_seed = [_]u8{0x22} ** 32,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = "h3",
    });
    const decoded = try client_hello.parse(ch.items);

    var server_transcript = transcript.Transcript{};
    server_transcript.update(decoded.value.raw);
    var flight_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer flight_bytes.deinit(testing.allocator);
    const server_built = try server_flight.build(&flight_bytes, testing.allocator, &server_transcript, .{
        .legacy_session_id = decoded.value.legacy_session_id,
        .client_key_share = decoded.value.client_key_share,
    }, .{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = "h3",
    });
    const sh = handshake.peek(flight_bytes.items).?;
    const outcome = try client.onServerHello(flight_bytes.items[0..sh.len]);
    try testing.expectEqualSlices(u8, &server_built.handshake_secrets.client, &outcome.handshake_secrets.client);
    try testing.expectEqualSlices(u8, &server_built.handshake_secrets.server, &outcome.handshake_secrets.server);
}

test "client derives resumed handshake secrets when the server selects its PSK" {
    const server_flight = @import("flight.zig");
    const psk = [_]u8{0x7b} ** schedule.SECRET_LEN;
    var ch: std.ArrayListUnmanaged(u8) = .empty;
    defer ch.deinit(testing.allocator);
    var client = Client.init();
    try client.start(&ch, testing.allocator, .{
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
    const decoded = try client_hello.parse(ch.items);

    var server_transcript = transcript.Transcript{};
    server_transcript.update(decoded.value.raw);
    var flight_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer flight_bytes.deinit(testing.allocator);
    const server_built = try server_flight.build(&flight_bytes, testing.allocator, &server_transcript, .{
        .legacy_session_id = decoded.value.legacy_session_id,
        .client_key_share = decoded.value.client_key_share,
        .selected_psk = .{ .index = 0, .psk = psk },
    }, .{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = "h3",
    });
    const sh = handshake.peek(flight_bytes.items).?;
    const outcome = try client.onServerHello(flight_bytes.items[0..sh.len]);
    try testing.expectEqualSlices(u8, &server_built.handshake_secrets.client, &outcome.handshake_secrets.client);
    try testing.expectEqualSlices(u8, &server_built.handshake_secrets.server, &outcome.handshake_secrets.server);
}

test "client rejects a server flight without the offered ALPN" {
    const server_flight = @import("flight.zig");
    var ch: std.ArrayListUnmanaged(u8) = .empty;
    defer ch.deinit(testing.allocator);
    var client = Client.init();
    try client.start(&ch, testing.allocator, .{
        .random = [_]u8{0x11} ** 32,
        .ephemeral_seed = [_]u8{0x22} ** 32,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = "h3",
    });
    const decoded = try client_hello.parse(ch.items);

    var server_transcript = transcript.Transcript{};
    server_transcript.update(decoded.value.raw);
    var flight_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer flight_bytes.deinit(testing.allocator);
    _ = try server_flight.build(&flight_bytes, testing.allocator, &server_transcript, .{
        .legacy_session_id = decoded.value.legacy_session_id,
        .client_key_share = decoded.value.client_key_share,
    }, .{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = null,
    });
    const sh = handshake.peek(flight_bytes.items).?;
    _ = try client.onServerHello(flight_bytes.items[0..sh.len]);
    try testing.expectError(error.BadServerHello, client.onServerFlight(&ch, testing.allocator, flight_bytes.items[sh.len..]));
}

test "client rejects a server flight with a mismatched ALPN" {
    const server_flight = @import("flight.zig");
    var ch: std.ArrayListUnmanaged(u8) = .empty;
    defer ch.deinit(testing.allocator);
    var client = Client.init();
    try client.start(&ch, testing.allocator, .{
        .random = [_]u8{0x11} ** 32,
        .ephemeral_seed = [_]u8{0x22} ** 32,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = "h3",
    });
    const decoded = try client_hello.parse(ch.items);

    var server_transcript = transcript.Transcript{};
    server_transcript.update(decoded.value.raw);
    var flight_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer flight_bytes.deinit(testing.allocator);
    _ = try server_flight.build(&flight_bytes, testing.allocator, &server_transcript, .{
        .legacy_session_id = decoded.value.legacy_session_id,
        .client_key_share = decoded.value.client_key_share,
    }, .{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = "h2",
    });
    const sh = handshake.peek(flight_bytes.items).?;
    _ = try client.onServerHello(flight_bytes.items[0..sh.len]);
    try testing.expectError(error.BadServerHello, client.onServerFlight(&ch, testing.allocator, flight_bytes.items[sh.len..]));
}

test "client rejects a selected PSK it did not offer" {
    const server_flight = @import("flight.zig");
    const psk = [_]u8{0x7b} ** schedule.SECRET_LEN;
    var ch: std.ArrayListUnmanaged(u8) = .empty;
    defer ch.deinit(testing.allocator);
    var client = Client.init();
    try client.start(&ch, testing.allocator, .{
        .random = [_]u8{0x11} ** 32,
        .ephemeral_seed = [_]u8{0x22} ** 32,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = "h3",
    });
    const decoded = try client_hello.parse(ch.items);

    var server_transcript = transcript.Transcript{};
    server_transcript.update(decoded.value.raw);
    var flight_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer flight_bytes.deinit(testing.allocator);
    _ = try server_flight.build(&flight_bytes, testing.allocator, &server_transcript, .{
        .legacy_session_id = decoded.value.legacy_session_id,
        .client_key_share = decoded.value.client_key_share,
        .selected_psk = .{ .index = 0, .psk = psk },
    }, .{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = "h3",
    });
    const sh = handshake.peek(flight_bytes.items).?;
    try testing.expectError(error.BadServerHello, client.onServerHello(flight_bytes.items[0..sh.len]));
}

test "client rejects a selected PSK index it did not offer" {
    const server_flight = @import("flight.zig");
    const psk = [_]u8{0x7b} ** schedule.SECRET_LEN;
    var ch: std.ArrayListUnmanaged(u8) = .empty;
    defer ch.deinit(testing.allocator);
    var client = Client.init();
    try client.start(&ch, testing.allocator, .{
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
    const decoded = try client_hello.parse(ch.items);

    var server_transcript = transcript.Transcript{};
    server_transcript.update(decoded.value.raw);
    var flight_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer flight_bytes.deinit(testing.allocator);
    _ = try server_flight.build(&flight_bytes, testing.allocator, &server_transcript, .{
        .legacy_session_id = decoded.value.legacy_session_id,
        .client_key_share = decoded.value.client_key_share,
        .selected_psk = .{ .index = 1, .psk = psk },
    }, .{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &.{ 0x04, 0x01, 0x40 },
        .alpn = "h3",
    });
    const sh = handshake.peek(flight_bytes.items).?;
    try testing.expectError(error.BadServerHello, client.onServerHello(flight_bytes.items[0..sh.len]));
}
