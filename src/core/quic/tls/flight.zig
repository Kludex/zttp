//! The server handshake flight builder (RFC 8446 4): ServerHello, then the
//! encrypted EncryptedExtensions / Certificate / CertificateVerify / Finished, all
//! as back-to-back handshake messages appended to one buffer the connection layer
//! later chops into CRYPTO frames. Each message is built, fed to the transcript as
//! its exact wire bytes, and at the RFC-defined points the transcript hash is read
//! to drive the key schedule. The build/hash/derive order IS the protocol; it is
//! pinned by the RFC 8448 vectors, not just by inspection.

const std = @import("std");
const wire = @import("wire.zig");
const tr = @import("transcript.zig");
const schedule = @import("schedule.zig");
const keyshare = @import("keyshare.zig");
const sign = @import("sign.zig");
const finished = @import("finished.zig");

/// The ClientHello subset the builder needs. A slim view keeps build decoupled
/// from the full parsed struct.
pub const ClientHelloView = struct {
    legacy_session_id: []const u8,
    client_key_share: [32]u8,
    selected_psk: ?SelectedPsk = null,
    accept_early_data: bool = false,
};

pub const SelectedPsk = struct {
    index: u16,
    psk: [schedule.SECRET_LEN]u8,
    accept_early_data: bool = true,
};

pub const ResumptionCredential = struct {
    identity: []const u8,
    psk: [schedule.SECRET_LEN]u8,
    ticket_lifetime: ?u32 = null,
    ticket_age_add: u32 = 0,
    issued_at_ms: ?u64 = null,
    max_early_data_size: ?u32 = null,
    early_data_used: bool = false,
};

/// Integrator config the crypto core does not supply: the ServerHello randomness,
/// the ephemeral seed, the signing key, the cert chain, and the echoed protocols.
pub const Config = struct {
    random: [32]u8, // ServerHello.random; injected entropy (sans-IO)
    ephemeral_seed: [32]u8, // feeds keyshare.ephemeral
    signer: sign.Signer,
    cert_chain: []const u8, // leaf DER cert_data; retained for single-certificate callers
    certificates: []const []const u8 = &.{}, // ordered leaf and intermediate DER entries
    /// The server's application protocol. When set, the ClientHello must offer it
    /// (RFC 9001 8.1 makes ALPN mandatory) and it is echoed into
    /// EncryptedExtensions; null skips negotiation - a transport-test affordance.
    alpn: ?[]const u8 = null,
    transport_params: []const u8, // server quic_transport_parameters body
    resumption: ?ResumptionCredential = null,
    resumption_store: []ResumptionCredential = &.{},
    now_ms: u64 = 0,
};

/// What the driver installs after the flight is built.
pub const Built = struct {
    handshake_secrets: schedule.Secrets, // Handshake space
    application_secrets: schedule.Secrets, // Application (1-RTT) space
    client_hs_secret: [32]u8, // verifies the client's later Finished
    key_schedule: schedule.Schedule, // derives the resumption master after client Finished
};

/// Build the full server flight into `out`, threading `transcript` (which the
/// caller has already fed the parsed ClientHello). Returns the per-space secrets.
pub fn build(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    transcript: *tr.Transcript,
    ch: ClientHelloView,
    cfg: Config,
) !Built {
    const w = wire.Writer{ .out = out, .gpa = gpa };
    const ks = try keyshare.KeyShare.ephemeral(cfg.ephemeral_seed);

    try emitFramed(out, w, transcript, 0x02, ServerHello{ .cfg = cfg, .ch = ch, .server_pub = ks.public_key });
    const th_sh = transcript.hash();
    const ecdhe = try ks.shared(ch.client_key_share);
    const hs = if (ch.selected_psk) |selected|
        schedule.Schedule.deriveHandshakePsk(ecdhe, th_sh, selected.psk)
    else
        schedule.Schedule.deriveHandshake(ecdhe, th_sh);

    try emitFramed(out, w, transcript, 0x08, EncryptedExtensions{ .cfg = cfg, .accept_early_data = ch.accept_early_data });
    try emitFramed(out, w, transcript, 0x0b, Certificate{ .cfg = cfg });

    const th_cert = transcript.hash();
    try emitFramed(out, w, transcript, 0x0f, CertificateVerify{ .cfg = cfg, .th = th_cert });

    const th_cv = transcript.hash();
    try emitFramed(out, w, transcript, 0x14, Finished{ .secret = hs.secrets.server, .th = th_cv });

    const th_fin = transcript.hash();
    return .{
        .handshake_secrets = hs.secrets,
        .application_secrets = hs.schedule.deriveApplication(th_fin),
        .client_hs_secret = hs.secrets.client,
        .key_schedule = hs.schedule,
    };
}

/// Append `msg_type || u24 len || body`, where the body is emitted by `payload`,
/// then feed the exact framed bytes to the transcript. One owner for the framing
/// keeps the "transcript sees the wire bytes" rule in a single place.
fn emitFramed(out: *std.ArrayListUnmanaged(u8), w: wire.Writer, transcript: *tr.Transcript, msg_type: u8, payload: anytype) !void {
    const start = out.items.len;
    try w.u8v(msg_type);
    const len = try w.open(3);
    try payload.emit(w);
    try w.close(len);
    transcript.update(out.items[start..]);
}

const ServerHello = struct {
    cfg: Config,
    ch: ClientHelloView,
    server_pub: [32]u8,

    fn emit(self: ServerHello, w: wire.Writer) !void {
        try w.u16v(0x0303); // legacy_version
        try w.bytes(&self.cfg.random);
        const sid = try w.open(1); // legacy_session_id echo
        try w.bytes(self.ch.legacy_session_id);
        try w.close(sid);
        try w.u16v(0x1301); // cipher_suite TLS_AES_128_GCM_SHA256
        try w.u8v(0x00); // legacy_compression_method
        const exts = try w.open(2);
        try w.u16v(0x002b); // supported_versions
        const sv = try w.open(2);
        try w.u16v(0x0304); // selected_version TLS 1.3
        try w.close(sv);
        try w.u16v(0x0033); // key_share
        const ks = try w.open(2);
        try w.u16v(0x001d); // x25519
        const pt = try w.open(2);
        try w.bytes(&self.server_pub);
        try w.close(pt);
        try w.close(ks);
        if (self.ch.selected_psk) |selected| {
            try w.u16v(0x0029); // pre_shared_key
            const psk = try w.open(2);
            try w.u16v(selected.index);
            try w.close(psk);
        }
        try w.close(exts);
    }
};

const EncryptedExtensions = struct {
    cfg: Config,
    accept_early_data: bool = false,

    fn emit(self: EncryptedExtensions, w: wire.Writer) !void {
        const exts = try w.open(2);
        try w.u16v(0x0039); // quic_transport_parameters
        const qtp = try w.open(2);
        try w.bytes(self.cfg.transport_params);
        try w.close(qtp);
        if (self.cfg.alpn) |proto| {
            try w.u16v(0x0010); // application_layer_protocol_negotiation
            const ext = try w.open(2);
            const list = try w.open(2);
            const name = try w.open(1);
            try w.bytes(proto);
            try w.close(name);
            try w.close(list);
            try w.close(ext);
        }
        if (self.accept_early_data) {
            try w.u16v(0x002a); // early_data
            const ext = try w.open(2);
            try w.close(ext);
        }
        try w.close(exts);
    }
};

const Certificate = struct {
    cfg: Config,

    fn emit(self: Certificate, w: wire.Writer) !void {
        try w.u8v(0x00); // certificate_request_context: empty for server auth
        const list = try w.open(3); // certificate_list<0..2^24-1>
        if (self.cfg.certificates.len > 0) {
            for (self.cfg.certificates) |certificate| try emitCertificateEntry(w, certificate);
        } else {
            try emitCertificateEntry(w, self.cfg.cert_chain);
        }
        try w.close(list);
    }
};

fn emitCertificateEntry(w: wire.Writer, certificate: []const u8) !void {
    const cert = try w.open(3); // cert_data<1..2^24-1>
    try w.bytes(certificate);
    try w.close(cert);
    const ext = try w.open(2); // per-entry extensions: none
    try w.close(ext);
}

const CertificateVerify = struct {
    cfg: Config,
    th: [32]u8,

    fn emit(self: CertificateVerify, w: wire.Writer) !void {
        var der_buf: [sign.SIG_DER_MAX]u8 = undefined;
        const der = try self.cfg.signer.sign(self.th, &der_buf);
        try w.u16v(sign.SCHEME); // 0x0403
        const sig = try w.open(2);
        try w.bytes(der);
        try w.close(sig);
    }
};

const Finished = struct {
    secret: [32]u8,
    th: [32]u8,

    fn emit(self: Finished, w: wire.Writer) !void {
        try w.bytes(&finished.build(self.secret, self.th));
    }
};

const testing = std.testing;

test "server flight serializes every certificate as an ordered CertificateEntry" {
    const gpa = testing.allocator;
    const client_keys = try keyshare.KeyShare.ephemeral([_]u8{0x11} ** 32);
    const leaf = [_]u8{ 0x30, 0x01, 0xaa };
    const intermediate = [_]u8{ 0x30, 0x01, 0xbb };
    const certificates = [_][]const u8{ &leaf, &intermediate };
    var transcript = tr.Transcript{};
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);

    _ = try build(&out, gpa, &transcript, .{
        .legacy_session_id = &.{},
        .client_key_share = client_keys.public_key,
    }, .{
        .random = [_]u8{0x22} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = try sign.Signer.fromSeed([_]u8{0x42} ** 32),
        .cert_chain = &leaf,
        .certificates = &certificates,
        .transport_params = &.{},
    });

    var messages = wire.Reader{ .buf = out.items };
    try testing.expectEqual(@as(u8, 0x02), try messages.byte());
    _ = try messages.vector(3);
    try testing.expectEqual(@as(u8, 0x08), try messages.byte());
    _ = try messages.vector(3);
    try testing.expectEqual(@as(u8, 0x0b), try messages.byte());
    var certificate_message = try messages.vector(3);
    try testing.expectEqual(@as(usize, 0), (try certificate_message.vector(1)).buf.len);
    var list = try certificate_message.vector(3);
    const first = try list.vector(3);
    try testing.expectEqualSlices(u8, &leaf, first.buf);
    try testing.expectEqual(@as(usize, 0), (try list.vector(2)).buf.len);
    const second = try list.vector(3);
    try testing.expectEqualSlices(u8, &intermediate, second.buf);
    try testing.expectEqual(@as(usize, 0), (try list.vector(2)).buf.len);
    try list.expectEnd();
    try certificate_message.expectEnd();
}
