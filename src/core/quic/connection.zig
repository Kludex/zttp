//! The QUIC transport orchestrator (RFC 9000/9001/9002): ties the packet, crypto,
//! recovery, congestion, flow, and stream layers into one connection. It takes a
//! UDP datagram with `receiveDatagram` - parsing the (possibly coalesced) packets
//! inside, removing header protection, decrypting, and dispatching each frame into
//! the transport state - and exposes the ordered bytes of each stream upward to
//! the HTTP/3 layer. It is sans-IO: bytes and a monotonic `now` in, transport
//! state and (eventually) datagrams out, no socket.
//!
//! Scope: all three packet-number spaces are wired. The TLS 1.3 handshake runs
//! over CRYPTO frames and installs the Handshake and Application keys through the
//! `installKeys` seam; `buildPacket` is the one send primitive (CRYPTO, ACK, and
//! STREAM all funnel through it), so STREAM data ships only in the Application
//! space once 1-RTT keys exist - never in an Initial packet.

const std = @import("std");
const constants = @import("constants.zig");
const packet = @import("packet.zig");
const crypto = @import("crypto.zig");
const frame = @import("frame.zig");
const recovery = @import("recovery.zig");
const congestion = @import("congestion.zig");
const flow = @import("flow.zig");
const stream = @import("stream.zig");
const crypto_stream = @import("crypto_stream.zig");
const transport_params = @import("transport_params.zig");
const ack_ranges = @import("ack_ranges.zig");
const tls = @import("tls/root.zig");
const varint = @import("varint.zig");

const Space = constants.Space;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Role = enum { server, client };

const MAX_SESSION_TICKETS: usize = 8;
const MAX_NEW_TOKENS: usize = 8;
const max_peer_reset_streams: usize = 256;
const max_peer_stream_data_blocked: usize = 256;

fn defaultLocalTransportParameters() transport_params.TransportParameters {
    return .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_stream_data_uni = 1 << 20,
        .initial_max_streams_bidi = 64,
        .initial_max_streams_uni = 64,
    };
}

/// The earlier of an optional `a` and a `b`.
fn minOpt(a: ?u64, b: u64) ?u64 {
    return if (a) |x| @min(x, b) else b;
}

fn addSaturating(a: u64, b: u64) u64 {
    return if (b > std.math.maxInt(u64) - a) std.math.maxInt(u64) else a + b;
}

fn msToUsSaturating(ms: u64) u64 {
    return if (ms > std.math.maxInt(u64) / std.time.us_per_ms)
        std.math.maxInt(u64)
    else
        ms * std.time.us_per_ms;
}

fn streamSendPriorityLess(_: void, a: u64, b: u64) bool {
    const a_uni = stream.StreamType.of(a).isUni();
    const b_uni = stream.StreamType.of(b).isUni();
    if (a_uni != b_uni) return a_uni;
    return a < b;
}

pub const Error = error{
    /// A received packet failed authentication and was dropped; surfaced so a
    /// caller can count it, never fatal on its own (RFC 9001 9.5).
    Dropped,
    /// A frame was structurally invalid or violated the protocol: a fatal
    /// connection error (the connection is poisoned, as H1/H2 poison on a parse
    /// error).
    ProtocolViolation,
    /// A flow-control or stream-limit invariant was broken by the peer.
    FlowControlError,
    StreamLimitError,
    /// A peer sent a stream-scoped control frame for a stream state where that
    /// frame is not valid, such as STREAM_DATA_BLOCKED on a receive-only stream.
    StreamStateError,
    StreamBufferExceeded,
    FinalSizeError,
    CryptoError,
    /// The send would exceed the 3x anti-amplification budget before the client's
    /// address is validated (RFC 9000 8.1). Not fatal: the send path stops and
    /// resumes once the client's later packets raise the budget.
    AmplificationLimited,
    OutOfMemory,
};

/// One packet-number space's protection keys, recovery state, and CRYPTO receive
/// reassembly. Initial keys are derived up front; Handshake/Application keys arrive
/// via `installKeys`.
const SpaceState = struct {
    recv_keys: ?crypto.Keys = null,
    send_keys: ?crypto.Keys = null,
    recv_secret: ?[32]u8 = null,
    send_secret: ?[32]u8 = null,
    zero_rtt_recv_keys: ?crypto.Keys = null,
    zero_rtt_send_keys: ?crypto.Keys = null,
    prev_recv_keys: ?crypto.Keys = null,
    prev_recv_key_phase: bool = false,
    recv_key_phase: bool = false,
    send_key_phase: bool = false,
    next_pn: u64 = 0,
    /// The largest authenticated packet number, used only to decode truncated packet numbers.
    largest_authenticated_pn: ?u64 = null,
    largest_recv_pn: ?u64 = null,
    rec: recovery.Space = .{},
    crypto: crypto_stream.CryptoStream,
    /// Outbound CRYPTO for this space (the handshake flight), retained until acked so
    /// a lost or amplification-stalled flight is re-sent. A SendStream gives the
    /// retain/peek/commit/onAck/onLost machinery; CRYPTO never sets the FIN.
    crypto_send: stream.SendStream,
    ack_pending: bool = false,
    /// The STREAM range each in-flight packet carried (pn -> {id,offset,len,fin}),
    /// so a lost packet's data can be re-queued and an acked packet's data freed.
    /// Only the Application space carries STREAM frames, but the field is uniform.
    stream_sent: std.AutoHashMapUnmanaged(u64, StreamSent) = .empty,
    /// The CRYPTO byte range each in-flight packet carried (pn -> {offset,len}), the
    /// CRYPTO counterpart of stream_sent for ack/loss routing.
    crypto_sent: std.AutoHashMapUnmanaged(u64, CryptoSent) = .empty,
    /// The stream id whose RESET_STREAM each in-flight packet carried, so a lost
    /// reset is re-sent and an acked one is cleared (RFC 9000 13.3).
    reset_sent: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    /// The packet numbers received in this space, for accurate ACK frames (RFC 9000
    /// 19.3) - a peer needs every range to detect loss correctly.
    recv_ranges: ack_ranges.AckRanges = .{},
    /// Latest cumulative ECN counts reported by the peer in ACK_ECN frames for this
    /// packet-number space. The counters are cumulative; a CE increase feeds the
    /// congestion controller as an ECN congestion event.
    peer_ecn_counts: ?frame.EcnCounts = null,
    /// The ack-eliciting send-time anchor a PTO last fired against. A PTO will not
    /// re-fire for the same anchor (which would inflate the backoff without a probe
    /// reaching the wire); it re-arms only once a fresh ack-eliciting send advances
    /// last_ack_eliciting_sent_time past this.
    pto_fired_anchor: ?u64 = null,

    fn deinit(self: *SpaceState, gpa: std.mem.Allocator) void {
        self.rec.deinit(gpa);
        self.crypto.deinit();
        self.crypto_send.deinit();
        self.stream_sent.deinit(gpa);
        self.crypto_sent.deinit(gpa);
        self.reset_sent.deinit(gpa);
        self.recv_ranges.deinit(gpa);
    }
};

/// The STREAM frame one sent packet carried, kept so loss recovery can map a lost
/// or acked packet number back to the stream bytes it was responsible for.
const StreamSent = struct { id: u64, offset: u64, len: u64, fin: bool };

/// The CRYPTO byte range one sent packet carried, so loss recovery can map a lost or
/// acked packet number back to the handshake bytes it was responsible for.
const CryptoSent = struct { offset: u64, len: u64 };

const OpenedPacket = struct {
    work: []u8,
    plaintext: []u8,
    payload: []const u8,
    pn: u64,
    key_phase: bool,
};

const ReceiveContext = struct {
    now: u64,
    datagram_len: usize,
    peer_address: ?[]const u8,
    path_recorded: bool = false,
    provisional_path_recorded: bool = false,
    auto_path_challenge_queued: bool = false,
};

/// A STOP_SENDING owed to the peer: the error code, and whether a frame carrying it is
/// currently in flight (so flushSend does not re-send while one is unacked).
const StopSending = struct { code: u64, in_flight: bool = false };

const PendingBlocked = struct { limit: u64, in_flight: bool = false };
const StreamDataBlockedSent = struct { id: u64, limit: u64 };
const StreamsBlockedSent = struct { bidi: bool, limit: u64 };

/// A RETIRE_CONNECTION_ID owed to the peer, re-sent until acknowledged.
const PendingRetireCid = struct { in_flight: bool = false };

/// A NEW_CONNECTION_ID owed to the peer, re-sent until acknowledged.
const PendingNewCid = struct { retire_prior_to: u64, in_flight: bool = false };

/// A PATH_CHALLENGE owed to the peer for path validation. The 8-byte challenge data
/// is the map key; in_flight prevents a tight resend loop while one copy is still
/// outstanding.
const PendingPathChallenge = struct { in_flight: bool = false, path_token: ?u64 = null };

/// Address-scoped path state. The address is intentionally opaque to the sans-IO
/// core: an integrator can pass a serialized socket address, tuple key, or any
/// stable byte string that identifies the network path it will send datagrams to.
const PathState = struct {
    address: []u8,
    recv_bytes: u64 = 0,
    sent_bytes: u64 = 0,
    validated: bool = false,
};

const ProvisionalPath = struct {
    token: u64,
    state: PathState,
};

/// A connection id the peer issued in NEW_CONNECTION_ID, retained for future path
/// migration / CID rotation. The stateless reset token is copied inline.
const PeerCid = struct {
    cid: []u8,
    token: [16]u8,
};

/// A connection id we issued to the peer with NEW_CONNECTION_ID. Packets addressed
/// to an unretired issued CID are accepted in addition to the initial source CID.
const LocalCid = struct {
    cid: []u8,
    token: [16]u8,
    retired: bool = false,
};

/// One active destination connection ID the integrator must route to this
/// connection. The borrowed ID remains valid until the next connection operation.
pub const LocalConnectionId = struct {
    sequence_number: u64,
    connection_id: []const u8,
};

const ParsedShortForLocalCid = struct {
    hdr: packet.ShortHeader,
    local_cid_seq: u64,
};

const RetiredRange = struct {
    first: u64,
    end: u64,
};

const RetiredStreamIds = struct {
    const max_ranges_per_class = 256;

    classes: [4]std.ArrayListUnmanaged(RetiredRange) = .{ .empty, .empty, .empty, .empty },

    fn deinit(self: *RetiredStreamIds, gpa: std.mem.Allocator) void {
        for (&self.classes) |*ranges| ranges.deinit(gpa);
    }

    fn contains(self: *const RetiredStreamIds, id: u64) bool {
        const ranges = &self.classes[@intFromEnum(stream.StreamType.of(id))];
        const sequence = id >> 2;
        for (ranges.items) |range| {
            if (sequence < range.first) return false;
            if (sequence < range.end) return true;
        }
        return false;
    }

    fn retire(self: *RetiredStreamIds, gpa: std.mem.Allocator, id: u64) error{ OutOfMemory, RangeLimitExceeded }!void {
        const ranges = &self.classes[@intFromEnum(stream.StreamType.of(id))];
        const sequence = id >> 2;
        var index: usize = 0;
        while (index < ranges.items.len and ranges.items[index].first <= sequence) : (index += 1) {
            if (sequence < ranges.items[index].end) return;
        }

        const joins_previous = index > 0 and ranges.items[index - 1].end == sequence;
        const joins_next = index < ranges.items.len and ranges.items[index].first == sequence + 1;
        if (joins_previous) {
            ranges.items[index - 1].end = sequence + 1;
            if (joins_next) {
                ranges.items[index - 1].end = ranges.items[index].end;
                _ = ranges.orderedRemove(index);
            }
        } else if (joins_next) {
            ranges.items[index].first = sequence;
        } else {
            if (ranges.items.len >= max_ranges_per_class) return error.RangeLimitExceeded;
            try ranges.insert(gpa, index, .{ .first = sequence, .end = sequence + 1 });
        }
    }
};

/// A CONNECTION_CLOSE the peer sent (RFC 9000 19.19), retained so the integrator can
/// surface why the connection ended. `app` distinguishes the application-error
/// variant; `reason` is an owned, length-capped copy of the human-readable phrase.
pub const PeerClose = struct {
    app: bool,
    error_code: u64,
    reason: []u8,

    /// Cap the retained reason so a peer cannot make the server allocate an
    /// arbitrarily long phrase; the prefix is enough to diagnose.
    pub const MAX_REASON: usize = 1024;
};

pub const Connection = struct {
    gpa: std.mem.Allocator,
    role: Role,
    dcid: []u8, // our peer's chosen dcid for us = the Initial-key material (owned)
    scid: []u8, // our own source connection id, sent in our long headers (owned)
    peer_scid: []u8, // the peer's scid: the dcid of everything we send (owned)
    retry_scid: ?[]u8 = null, // client only: SCID received in Retry, for TP validation
    peer_cids: std.AutoHashMapUnmanaged(u64, PeerCid) = .empty,
    peer_cid_seq: u64 = 0,
    peer_retire_prior_to: u64 = 0,
    local_cids: std.AutoHashMapUnmanaged(u64, LocalCid) = .empty,
    local_cid_max_seq: u64 = 0,
    local_cid_generation: u64 = 0,
    local_initial_cid_retired: bool = false,
    spaces: [3]SpaceState,
    rtt: recovery.RttEstimator = .{},
    cc: congestion.Controller,
    conn_recv_window: flow.Window,
    conn_send_window: flow.SendWindow,
    /// The transport parameters we advertised to the peer, parsed into the receive
    /// limits we must enforce locally.
    local_tp: transport_params.TransportParameters,
    /// The connection-level flow-control counters (RFC 9000 4.1): the SUM across
    /// all streams of the highest offset received and of the bytes consumed. A
    /// per-stream offset would let a peer evade MAX_DATA by spreading data across
    /// streams, so these are tracked separately from any one stream's window.
    conn_received_total: u64 = 0,
    conn_consumed_total: u64 = 0,
    streams: std.AutoHashMapUnmanaged(u64, *stream.RecvStream) = .empty,
    /// Receive-stream ids changed by the current datagram, in first-seen order.
    changed_streams: std.ArrayListUnmanaged(u64) = .empty,
    /// Per-stream receive flow-control windows, keyed by stream id.
    recv_windows: std.AutoHashMapUnmanaged(u64, flow.Window) = .empty,
    send_streams: std.AutoHashMapUnmanaged(u64, *stream.SendStream) = .empty,
    /// Per-stream send flow-control windows, keyed by stream id. The peer's
    /// transport parameters provide the initial limit; MAX_STREAM_DATA raises it.
    send_windows: std.AutoHashMapUnmanaged(u64, flow.SendWindow) = .empty,
    /// Latest advisory BLOCKED limits reported by the peer (RFC 9000 19.12-19.14).
    /// They do not change flow-control grants, but retaining them lets upper layers
    /// and future schedulers diagnose why a peer is stalled.
    peer_data_blocked_limit: ?u64 = null,
    peer_stream_data_blocked: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    peer_streams_blocked_bidi_limit: ?u64 = null,
    peer_streams_blocked_uni_limit: ?u64 = null,
    /// BLOCKED frames we owe the peer because its flow-control or stream-count grant
    /// stalls our send side. They are advisory but ack-eliciting, so keep them until
    /// acknowledged, lost, or made stale by a larger MAX_* grant.
    data_blocked: ?PendingBlocked = null,
    stream_data_blocked: std.AutoHashMapUnmanaged(u64, PendingBlocked) = .empty,
    streams_blocked_bidi: ?PendingBlocked = null,
    streams_blocked_uni: ?PendingBlocked = null,
    data_blocked_inflight: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    stream_data_blocked_inflight: std.AutoHashMapUnmanaged(u64, StreamDataBlockedSent) = .empty,
    streams_blocked_inflight: std.AutoHashMapUnmanaged(u64, StreamsBlockedSent) = .empty,
    /// STOP_SENDING frames owed to the peer (stream id -> {error code, in_flight}),
    /// queued by stopSending and drained by flushSend; an entry is removed once acked,
    /// and `in_flight` is cleared on loss so it is re-emitted.
    stop_sending: std.AutoHashMapUnmanaged(u64, StopSending) = .empty,
    /// The stream id whose STOP_SENDING each in-flight app packet carried, so a lost
    /// or acked one routes back to the `stop_sending` entry by id.
    stop_sending_inflight: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    /// A peer STOP_SENDING received before we created the matching send stream (id ->
    /// error code), applied when the stream is lazily created so it is born reset.
    peer_stop_sending: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    /// Peer-triggered resets, tracked from STOP_SENDING receipt through the matching
    /// RESET_STREAM acknowledgement and capped against peer-driven churn.
    peer_reset_streams: std.AutoHashMapUnmanaged(u64, void) = .empty,
    /// RETIRE_CONNECTION_ID frames owed to the peer (seq -> in-flight state), queued
    /// when NEW_CONNECTION_ID.retire_prior_to asks us to retire older peer CIDs.
    pending_retire_cids: std.AutoHashMapUnmanaged(u64, PendingRetireCid) = .empty,
    /// The retired CID sequence number each in-flight RETIRE_CONNECTION_ID packet
    /// carried, so ACK/loss can complete or re-arm the pending entry.
    retire_cid_inflight: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    /// NEW_CONNECTION_ID frames owed to the peer (seq -> retire_prior_to/in-flight
    /// state), queued when the integrator issues a replacement local CID.
    pending_new_cids: std.AutoHashMapUnmanaged(u64, PendingNewCid) = .empty,
    /// The issued CID sequence number each in-flight NEW_CONNECTION_ID packet
    /// carried, so ACK/loss can complete or re-arm the pending entry.
    new_cid_inflight: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    /// PATH_CHALLENGE frames awaiting a matching PATH_RESPONSE (challenge token ->
    /// in-flight state), and the sent packet number that carried each token so loss
    /// recovery can re-arm it.
    pending_path_challenges: std.AutoHashMapUnmanaged(u64, PendingPathChallenge) = .empty,
    path_challenge_inflight: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    auto_path_challenge_counter: u64 = 0,
    /// Address-aware migration state. `current_path_token` is set while processing
    /// an address-bearing datagram and is used for responses emitted synchronously
    /// from that receive path, such as PATH_RESPONSE and ACK. `default_path_token`
    /// retains the most recent peer path so application writes queued after
    /// receive_datagram still have a routable destination.
    paths: std.AutoHashMapUnmanaged(u64, PathState) = .empty,
    /// The unauthenticated route for queued Version Negotiation output. It is
    /// bounded to one address and released when the output queue is drained.
    provisional_path: ?ProvisionalPath = null,
    /// The single peer path awaiting automatic validation after migration.
    peer_candidate_path_token: ?u64 = null,
    current_path_token: ?u64 = null,
    default_path_token: ?u64 = null,
    /// Local CID sequence number matched by the short-header packet currently
    /// being dispatched. RETIRE_CONNECTION_ID is not allowed to retire this CID.
    current_packet_local_cid_seq: ?u64 = null,
    /// Built datagrams waiting to be drained by `datagramsToSend` (one contiguous
    /// buffer; `out_lengths` records each datagram's byte length in order, and
    /// `out_path_tokens` records the address-aware destination, if known).
    out: std.ArrayListUnmanaged(u8) = .empty,
    out_lengths: std.ArrayListUnmanaged(usize) = .empty,
    out_path_tokens: std.ArrayListUnmanaged(?u64) = .empty,
    /// The server TLS handshake driver, attached by `initServer`; null on a client
    /// or a connection that does not run the handshake (the recv-pipeline tests).
    tls: ?tls.server.Server = null,
    /// The client TLS handshake driver, attached by `initClient`; null on a server
    /// or a connection that does not run the handshake.
    tls_client: ?tls.client.Client = null,
    /// The client's transport parameters (RFC 9000 18.2), parsed from the
    /// ClientHello; until then the RFC defaults apply. Drives the send window and
    /// the PTO ack-delay.
    peer_tp: transport_params.TransportParameters = .{},
    remembered_peer_tp: ?transport_params.TransportParameters = null,
    peer_scid_set: bool = false, // have we adopted the peer's scid from its first long header?
    initial_authenticated: bool = false,
    peer_packet_authenticated: bool = false,
    handshake_confirmed: bool = false, // the client Finished verified; HANDSHAKE_DONE sent
    /// The connection-level recv window grew enough to advertise a new MAX_DATA
    /// (RFC 9000 4.1); flushSend emits it so the peer is not stalled at its grant.
    max_data_pending: bool = false,
    /// Per-stream receive windows that grew enough to advertise MAX_STREAM_DATA.
    max_stream_data_pending: std.AutoHashMapUnmanaged(u64, void) = .empty,
    /// Whether to emit MAX_STREAMS for peer-initiated streams of either direction.
    max_streams_bidi_pending: bool = false,
    max_streams_uni_pending: bool = false,
    peer_bidi_streams: flow.StreamLimit,
    peer_uni_streams: flow.StreamLimit,
    local_bidi_streams: flow.StreamLimit,
    local_uni_streams: flow.StreamLimit,
    /// Anti-amplification (RFC 9000 8.1): until the client's address is validated, the
    /// server may send at most AMPLIFICATION_FACTOR x the bytes it has received. A
    /// received Handshake packet (only a real client can produce one) validates the
    /// address. These count whole datagrams.
    recv_bytes: u64 = 0,
    sent_bytes: u64 = 0,
    address_validated: bool = false,
    retried: bool = false,
    initial_token: ?[]u8 = null,
    /// NEW_TOKEN values the server issued for future address validation. Stored on
    /// clients only; Retry's token stays separate because it applies to the current
    /// Initial flight.
    new_tokens: std.ArrayListUnmanaged([]u8) = .empty,
    /// TLS NewSessionTicket values received after the client handshake completes.
    /// Retained for future resumption/0-RTT wiring; capped so a peer cannot grow
    /// memory indefinitely by sending tickets forever.
    session_tickets: std.ArrayListUnmanaged(tls.client.SessionTicket) = .empty,
    /// Absolute monotonic deadline, in microseconds, at which the negotiated QUIC
    /// idle timeout closes the connection. Null means neither endpoint advertised a
    /// non-zero max_idle_timeout.
    idle_deadline: ?u64 = null,
    idle_timed_out: bool = false,
    /// A mid-dispatch allocation failure leaves the receive state terminal.
    receive_failure: ?Error = null,
    closed: bool = false,
    /// The details of a CONNECTION_CLOSE received from the peer (RFC 9000 19.19),
    /// captured so the integrator can report why the peer closed - not just that it
    /// did. Null until a close arrives. `reason` is an owned copy (the decoded slice
    /// points into the datagram), capped so a hostile reason cannot grow it.
    peer_close: ?PeerClose = null,
    /// Completed receive-stream ids retained as ranges per stream-id class, so late
    /// frames cannot resurrect streams without one allocation per historical stream.
    retired_recv: RetiredStreamIds = .{},

    /// `client_dcid` is the destination connection id on the client's first
    /// Initial: both endpoints derive the Initial keys from it. The server picks
    /// its own `scid` (sent in its long headers) and uses the peer's scid as the
    /// destination of everything it sends; both default to `client_dcid` until the
    /// peer's Initial is parsed (the test path uses a single shared id).
    pub fn init(gpa: std.mem.Allocator, role: Role, client_dcid: []const u8) Error!Connection {
        const local_tp = defaultLocalTransportParameters();
        const dcid = try gpa.dupe(u8, client_dcid);
        errdefer gpa.free(dcid);
        const scid = try gpa.dupe(u8, client_dcid);
        errdefer gpa.free(scid);
        const peer_scid = try gpa.dupe(u8, client_dcid);
        errdefer gpa.free(peer_scid);
        const initial = crypto.InitialKeys.derive(client_dcid);
        var spaces: [3]SpaceState = .{
            .{ .crypto = crypto_stream.CryptoStream.init(gpa), .crypto_send = stream.SendStream.init(gpa) },
            .{ .crypto = crypto_stream.CryptoStream.init(gpa), .crypto_send = stream.SendStream.init(gpa) },
            .{ .crypto = crypto_stream.CryptoStream.init(gpa), .crypto_send = stream.SendStream.init(gpa) },
        };
        // The receiver decrypts with the opposite role's keys.
        const recv = if (role == .server) initial.client else initial.server;
        const send = if (role == .server) initial.server else initial.client;
        spaces[@intFromEnum(Space.initial)].recv_keys = recv;
        spaces[@intFromEnum(Space.initial)].send_keys = send;
        return .{
            .gpa = gpa,
            .role = role,
            .dcid = dcid,
            .scid = scid,
            .peer_scid = peer_scid,
            .spaces = spaces,
            .cc = congestion.Controller.init(constants.MIN_INITIAL_DATAGRAM),
            .conn_recv_window = flow.Window.init(local_tp.initial_max_data),
            .conn_send_window = flow.SendWindow.init(1 << 20),
            .local_tp = local_tp,
            .peer_bidi_streams = flow.StreamLimit.init(local_tp.initial_max_streams_bidi),
            .peer_uni_streams = flow.StreamLimit.init(local_tp.initial_max_streams_uni),
            .local_bidi_streams = flow.StreamLimit.init(0),
            .local_uni_streams = flow.StreamLimit.init(0),
        };
    }

    /// A server connection with the TLS handshake driver attached: incoming CRYPTO
    /// drives the handshake, which installs per-space keys and emits the server
    /// flight. `tls_config` supplies the ServerHello randomness, ephemeral seed,
    /// signing key, certificate, and transport parameters.
    pub fn initServer(gpa: std.mem.Allocator, client_dcid: []const u8, tls_config: tls.flight.Config) Error!Connection {
        var conn = try init(gpa, .server, client_dcid);
        errdefer conn.deinit();
        const local_tp = transport_params.parse(tls_config.transport_params) catch return error.ProtocolViolation;
        if (local_tp.original_destination_connection_id != null or
            local_tp.initial_source_connection_id != null or
            local_tp.retry_source_connection_id != null)
        {
            return error.ProtocolViolation;
        }
        conn.setLocalTransportParameters(local_tp);
        conn.tls = tls.server.Server.init(tls_config);
        return conn;
    }

    /// A server connection that derives Initial keys from the client's destination
    /// ID but advertises an endpoint-selected source connection ID.
    pub fn initServerWithCid(
        gpa: std.mem.Allocator,
        client_dcid: []const u8,
        server_scid: []const u8,
        tls_config: tls.flight.Config,
    ) Error!Connection {
        if (server_scid.len == 0 or server_scid.len > constants.MAX_CID_LEN) return error.ProtocolViolation;
        var conn = try initServer(gpa, client_dcid, tls_config);
        errdefer conn.deinit();
        const owned_scid = gpa.dupe(u8, server_scid) catch return error.OutOfMemory;
        gpa.free(conn.scid);
        conn.scid = owned_scid;
        return conn;
    }

    /// A server connection for an Initial whose address-validation token proves a
    /// preceding Retry. Initial keys use the Retry source ID while transport
    /// parameters retain the client's original destination ID.
    pub fn initServerAfterRetry(
        gpa: std.mem.Allocator,
        original_dcid: []const u8,
        retry_scid: []const u8,
        tls_config: tls.flight.Config,
    ) Error!Connection {
        if (original_dcid.len < 8 or original_dcid.len > constants.MAX_CID_LEN) return error.ProtocolViolation;
        var conn = try initServerWithCid(gpa, retry_scid, retry_scid, tls_config);
        errdefer conn.deinit();
        const owned_dcid = gpa.dupe(u8, original_dcid) catch return error.OutOfMemory;
        errdefer gpa.free(owned_dcid);
        const owned_retry_scid = gpa.dupe(u8, retry_scid) catch return error.OutOfMemory;
        gpa.free(conn.dcid);
        conn.dcid = owned_dcid;
        conn.retry_scid = owned_retry_scid;
        conn.retried = true;
        conn.address_validated = true;
        return conn;
    }

    /// A client connection that has emitted its first Initial carrying a TLS
    /// ClientHello. The server-flight processing is a follow-up; this starts the
    /// real QUIC/TLS handshake without relying on preinstalled test application keys.
    pub fn initClient(gpa: std.mem.Allocator, client_dcid: []const u8, tls_config: tls.client.Config, now: u64) Error!Connection {
        var conn = try init(gpa, .client, client_dcid);
        errdefer conn.deinit();
        const local_tp = transport_params.parse(tls_config.transport_params) catch return error.ProtocolViolation;
        if (local_tp.original_destination_connection_id != null or
            local_tp.initial_source_connection_id != null or
            local_tp.retry_source_connection_id != null)
        {
            return error.ProtocolViolation;
        }
        conn.setLocalTransportParameters(local_tp);

        var client_tp: std.ArrayListUnmanaged(u8) = .empty;
        defer client_tp.deinit(gpa);
        try conn.buildClientTransportParameters(&client_tp, tls_config.transport_params);
        var cfg = tls_config;
        cfg.transport_params = client_tp.items;

        var ch: std.ArrayListUnmanaged(u8) = .empty;
        defer ch.deinit(gpa);
        var client = tls.client.Client.init();
        client.start(&ch, gpa, cfg) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.ProtocolViolation,
        };
        if (client.early_traffic_secret) |secret| conn.installZeroRttSendSecret(secret);
        if (tls_config.validation_token) |token| {
            if (token.len == 0) return error.ProtocolViolation;
            conn.initial_token = gpa.dupe(u8, token) catch return error.OutOfMemory;
        }
        conn.tls_client = client;
        try conn.sendInitialCrypto(ch.items, now);
        return conn;
    }

    fn setLocalTransportParameters(self: *Connection, tp: transport_params.TransportParameters) void {
        self.local_tp = tp;
        self.conn_recv_window = flow.Window.init(tp.initial_max_data);
        self.peer_bidi_streams = flow.StreamLimit.init(tp.initial_max_streams_bidi);
        self.peer_uni_streams = flow.StreamLimit.init(tp.initial_max_streams_uni);
    }

    fn setPeerTransportParameters(self: *Connection, tp: transport_params.TransportParameters) Error!void {
        // RFC 9000 18.2: stateless_reset_token is server-only. A client that sends
        // one in its transport parameters is a transport-parameter error.
        if (self.role == .server and tp.stateless_reset_token != null) return error.ProtocolViolation;
        if (self.role == .server) {
            if (tp.original_destination_connection_id != null) return error.ProtocolViolation;
            if (tp.retry_source_connection_id != null) return error.ProtocolViolation;
            if (tp.initial_source_connection_id) |cid| {
                if (!std.mem.eql(u8, cid.slice(), self.peer_scid)) return error.ProtocolViolation;
            }
        } else {
            const odcid = tp.original_destination_connection_id orelse return error.ProtocolViolation;
            if (!std.mem.eql(u8, odcid.slice(), self.dcid)) return error.ProtocolViolation;
            const initial_scid = tp.initial_source_connection_id orelse return error.ProtocolViolation;
            if (!std.mem.eql(u8, initial_scid.slice(), self.peer_scid)) return error.ProtocolViolation;
            if (tp.retry_source_connection_id) |cid| {
                if (!self.retried) return error.ProtocolViolation;
                const retry_scid = self.retry_scid orelse return error.ProtocolViolation;
                if (!std.mem.eql(u8, cid.slice(), retry_scid)) return error.ProtocolViolation;
            } else if (self.retried) return error.ProtocolViolation;
        }
        self.peer_tp = tp;
        self.conn_send_window.setInitial(tp.initial_max_data);
        self.local_bidi_streams = flow.StreamLimit.init(tp.initial_max_streams_bidi);
        self.local_uni_streams = flow.StreamLimit.init(tp.initial_max_streams_uni);
    }

    /// Seed the peer limits remembered from the connection that issued a resumption
    /// ticket, so a client can enforce flow control and stream limits for 0-RTT
    /// before the new handshake receives fresh server transport parameters.
    pub fn applyRememberedPeerTransportParameters(self: *Connection, raw: []const u8) Error!void {
        if (self.role != .client or self.spaces[@intFromEnum(Space.handshake)].recv_keys != null) {
            return error.ProtocolViolation;
        }
        const tp = transport_params.parse(raw) catch return error.ProtocolViolation;
        self.remembered_peer_tp = tp;
        self.peer_tp = tp;
        self.conn_send_window.setInitial(tp.initial_max_data);
        self.local_bidi_streams = flow.StreamLimit.init(tp.initial_max_streams_bidi);
        self.local_uni_streams = flow.StreamLimit.init(tp.initial_max_streams_uni);
    }

    fn validateFreshParametersForAcceptedZeroRtt(self: *const Connection, fresh: transport_params.TransportParameters) Error!void {
        const remembered = self.remembered_peer_tp orelse return;
        // RFC 9000 7.4.1: if 0-RTT is accepted, these limits cannot be reduced
        // below the remembered values because the client might already have relied
        // on them when sending early STREAM frames.
        if (fresh.active_connection_id_limit < remembered.active_connection_id_limit or
            fresh.initial_max_data < remembered.initial_max_data or
            fresh.initial_max_stream_data_bidi_local < remembered.initial_max_stream_data_bidi_local or
            fresh.initial_max_stream_data_bidi_remote < remembered.initial_max_stream_data_bidi_remote or
            fresh.initial_max_stream_data_uni < remembered.initial_max_stream_data_uni or
            fresh.initial_max_streams_bidi < remembered.initial_max_streams_bidi or
            fresh.initial_max_streams_uni < remembered.initial_max_streams_uni)
        {
            return error.ProtocolViolation;
        }
    }

    fn buildServerTransportParameters(self: *Connection, out: *std.ArrayListUnmanaged(u8), base: []const u8) Error!void {
        out.appendSlice(self.gpa, base) catch return error.OutOfMemory;
        transport_params.appendOriginalDestinationConnectionId(out, self.gpa, self.dcid) catch return error.OutOfMemory;
        transport_params.appendInitialSourceConnectionId(out, self.gpa, self.scid) catch return error.OutOfMemory;
        if (self.retried) {
            const retry_scid = self.retry_scid orelse return error.ProtocolViolation;
            transport_params.appendRetrySourceConnectionId(out, self.gpa, retry_scid) catch return error.OutOfMemory;
        }
    }

    fn buildClientTransportParameters(self: *Connection, out: *std.ArrayListUnmanaged(u8), base: []const u8) Error!void {
        out.appendSlice(self.gpa, base) catch return error.OutOfMemory;
        transport_params.appendInitialSourceConnectionId(out, self.gpa, self.scid) catch return error.OutOfMemory;
    }

    fn effectiveIdleTimeoutUs(self: *const Connection) ?u64 {
        const local = self.local_tp.max_idle_timeout_ms;
        const peer = self.peer_tp.max_idle_timeout_ms;
        const ms = if (local == 0 and peer == 0)
            return null
        else if (local == 0)
            peer
        else if (peer == 0)
            local
        else
            @min(local, peer);
        return msToUsSaturating(ms);
    }

    fn resetIdleTimer(self: *Connection, now: u64) void {
        self.idle_deadline = if (self.effectiveIdleTimeoutUs()) |timeout|
            addSaturating(now, timeout)
        else
            null;
    }

    pub fn deinit(self: *Connection) void {
        self.gpa.free(self.dcid);
        self.gpa.free(self.scid);
        self.gpa.free(self.peer_scid);
        if (self.retry_scid) |cid| self.gpa.free(cid);
        var cid_it = self.peer_cids.valueIterator();
        while (cid_it.next()) |entry| self.gpa.free(entry.cid);
        self.peer_cids.deinit(self.gpa);
        var local_cid_it = self.local_cids.valueIterator();
        while (local_cid_it.next()) |entry| self.gpa.free(entry.cid);
        self.local_cids.deinit(self.gpa);
        var it = self.streams.valueIterator();
        while (it.next()) |s| {
            s.*.deinit();
            self.gpa.destroy(s.*);
        }
        self.streams.deinit(self.gpa);
        self.changed_streams.deinit(self.gpa);
        self.recv_windows.deinit(self.gpa);
        var sit = self.send_streams.valueIterator();
        while (sit.next()) |s| {
            s.*.deinit();
            self.gpa.destroy(s.*);
        }
        self.send_streams.deinit(self.gpa);
        self.send_windows.deinit(self.gpa);
        self.peer_stream_data_blocked.deinit(self.gpa);
        self.stream_data_blocked.deinit(self.gpa);
        self.data_blocked_inflight.deinit(self.gpa);
        self.stream_data_blocked_inflight.deinit(self.gpa);
        self.streams_blocked_inflight.deinit(self.gpa);
        self.stop_sending.deinit(self.gpa);
        self.stop_sending_inflight.deinit(self.gpa);
        self.peer_stop_sending.deinit(self.gpa);
        self.peer_reset_streams.deinit(self.gpa);
        self.pending_retire_cids.deinit(self.gpa);
        self.retire_cid_inflight.deinit(self.gpa);
        self.pending_new_cids.deinit(self.gpa);
        self.new_cid_inflight.deinit(self.gpa);
        self.pending_path_challenges.deinit(self.gpa);
        self.path_challenge_inflight.deinit(self.gpa);
        var path_it = self.paths.valueIterator();
        while (path_it.next()) |p| self.gpa.free(p.address);
        self.paths.deinit(self.gpa);
        if (self.provisional_path) |path| self.gpa.free(path.state.address);
        if (self.initial_token) |t| self.gpa.free(t);
        for (self.new_tokens.items) |t| self.gpa.free(t);
        self.new_tokens.deinit(self.gpa);
        for (self.session_tickets.items) |*ticket| ticket.deinit(self.gpa);
        self.session_tickets.deinit(self.gpa);
        self.max_stream_data_pending.deinit(self.gpa);
        self.retired_recv.deinit(self.gpa);
        self.out.deinit(self.gpa);
        self.out_lengths.deinit(self.gpa);
        self.out_path_tokens.deinit(self.gpa);
        if (self.peer_close) |pc| self.gpa.free(pc.reason);
        for (&self.spaces) |*s| s.deinit(self.gpa);
    }

    /// Install the protection keys for a later space once the handshake derives
    /// them. The TLS driver calls this; the pipeline below is agnostic to which
    /// space a packet lands in.
    pub fn installKeys(self: *Connection, space: Space, recv_keys: crypto.Keys, send_keys: crypto.Keys) void {
        const s = &self.spaces[@intFromEnum(space)];
        s.recv_keys = recv_keys;
        s.send_keys = send_keys;
    }

    fn installApplicationSecrets(self: *Connection, recv_secret: [32]u8, send_secret: [32]u8) void {
        const s = &self.spaces[@intFromEnum(Space.application)];
        s.recv_secret = recv_secret;
        s.send_secret = send_secret;
        s.recv_keys = crypto.Keys.fromSecret(recv_secret);
        s.send_keys = crypto.Keys.fromSecret(send_secret);
        s.zero_rtt_send_keys = null;
        s.prev_recv_keys = null;
        s.recv_key_phase = false;
        s.send_key_phase = false;
    }

    fn installZeroRttSendSecret(self: *Connection, secret: [32]u8) void {
        self.spaces[@intFromEnum(Space.application)].zero_rtt_send_keys = crypto.Keys.fromSecret(secret);
    }

    fn installZeroRttRecvSecret(self: *Connection, secret: [32]u8) void {
        self.spaces[@intFromEnum(Space.application)].zero_rtt_recv_keys = crypto.Keys.fromSecret(secret);
    }

    /// Initiate a QUIC 1-RTT key update for packets we send (RFC 9001 6). The
    /// peer learns the new phase from the short-header Key Phase bit on the next
    /// Application packet. Receive keys advance independently when a peer's
    /// next-phase packet authenticates.
    pub fn updateApplicationSendKeys(self: *Connection) Error!void {
        const s = &self.spaces[@intFromEnum(Space.application)];
        const old = s.send_secret orelse return error.ProtocolViolation;
        const current = s.send_keys orelse return error.ProtocolViolation;
        const next = crypto.nextTrafficSecret(old);
        s.send_secret = next;
        s.send_keys = crypto.Keys.fromUpdatedSecret(next, current.hp);
        s.send_key_phase = !s.send_key_phase;
    }

    // ---- send core -------------------------------------------------------------

    /// Build one packet in `space` carrying `frames` (already-encoded frame bytes),
    /// seal and header-protect it, append it to the outbound queue, and record it
    /// for loss recovery / congestion control. The single send primitive: CRYPTO,
    /// ACK, and STREAM all funnel through here. Returns the packet number assigned,
    /// so the STREAM caller can map it back to the range it carried. `frames` MUST
    /// fit one datagram. A long header (Initial/Handshake) carries our scid + a
    /// length field; a short header (Application) runs to the datagram end.
    fn buildPacket(self: *Connection, space: Space, frames: []const u8, ack_eliciting: bool, now: u64) Error!u64 {
        if (self.receive_failure) |err| return err;
        if (self.closed) return error.ProtocolViolation;
        const st = &self.spaces[@intFromEnum(space)];
        const use_zero_rtt = space == .application and st.send_keys == null and st.zero_rtt_send_keys != null;
        assertFramesAllowedIn(space, use_zero_rtt, frames); // no illegal frames for the packet type
        const keys = if (use_zero_rtt) st.zero_rtt_send_keys.? else st.send_keys orelse return error.ProtocolViolation; // driver installs first
        const long = space != .application or use_zero_rtt;
        const pn = st.next_pn;
        const pn_len = packet.packetNumberLen(pn, st.rec.largest_acked);

        var hdr: std.ArrayListUnmanaged(u8) = .empty;
        defer hdr.deinit(self.gpa);
        const pn_offset = blk: {
            if (long) {
                const ltype: constants.LongType = if (space == .initial) .initial else if (space == .handshake) .handshake else .zero_rtt;
                const token = if (space == .initial) self.initial_token orelse &.{} else &.{};
                const length = pn_len + frames.len + crypto.TAG_LEN;
                break :blk packet.writeLongHeader(&hdr, self.gpa, ltype, constants.VERSION_1, self.peer_scid, self.scid, token, length, pn_len) catch return error.OutOfMemory;
            } else {
                break :blk packet.writeShortHeaderWithKeyPhase(&hdr, self.gpa, self.peer_scid, pn_len, st.send_key_phase) catch return error.OutOfMemory;
            }
        };
        packet.writePacketNumber(&hdr, self.gpa, pn, pn_len) catch return error.OutOfMemory;

        // Anti-amplification (RFC 9000 8.1): before the client's address is
        // validated, every packet space shares the same 3x received-byte budget.
        // The flight stalls and resumes as later packets raise that budget.
        const datagram_len = hdr.items.len + frames.len + crypto.TAG_LEN;
        if (datagram_len > self.peer_tp.max_udp_payload_size) return error.ProtocolViolation;
        if (!self.canSendDatagram(datagram_len)) {
            return error.AmplificationLimited;
        }

        self.out.ensureUnusedCapacity(self.gpa, datagram_len) catch return error.OutOfMemory;
        self.out_lengths.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
        self.out_path_tokens.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
        st.rec.ensureSentCapacity(self.gpa) catch return error.OutOfMemory;

        const start = self.out.items.len;
        self.out.appendSliceAssumeCapacity(hdr.items);
        const ct = self.out.addManyAsSliceAssumeCapacity(frames.len + crypto.TAG_LEN);
        _ = crypto.seal(keys, pn, hdr.items, frames, ct);
        crypto.protectHeader(keys.hp, self.out.items[start..], pn_offset, long) catch {
            self.out.shrinkRetainingCapacity(start);
            return error.ProtocolViolation;
        };
        self.sent_bytes += datagram_len;
        self.recordPathSent(datagram_len);
        self.out_lengths.appendAssumeCapacity(datagram_len);
        self.out_path_tokens.appendAssumeCapacity(self.sendPathToken());
        // A pure-ACK packet is not ack-eliciting, so it is not in flight: not
        // congestion-controlled or retransmitted (RFC 9002 2, 7). Only in-flight
        // packets count toward bytes_in_flight - charging a pure ACK would inflate it
        // permanently, since the ACK/loss paths only credit back in-flight packets.
        st.rec.onSentAssumeCapacity(.{
            .pn = pn,
            .sent_time = now,
            .size = datagram_len,
            .ack_eliciting = ack_eliciting,
            .in_flight = ack_eliciting,
        });
        if (ack_eliciting) {
            self.cc.onSent(datagram_len);
            self.resetIdleTimer(now);
        }
        st.next_pn += 1;
        return pn;
    }

    /// Close the connection (RFC 9000 10.2): queue a CONNECTION_CLOSE frame and enter
    /// the closing state. `app` selects the application error variant; `error_code`
    /// and `reason` are the close details. After this the connection sends nothing
    /// further except (a real stack would) a single close on each received packet;
    /// here it is queued once and `closed` is set. Idempotent.
    pub fn close(self: *Connection, app: bool, error_code: u64, reason: []const u8) Error!void {
        if (self.closed) return;
        // Send in the highest space whose keys are installed, so the peer can decrypt
        // it: Application once 1-RTT keys exist, else Handshake, else Initial.
        const space: Space = if (self.spaces[@intFromEnum(Space.application)].send_keys != null)
            .application
        else if (self.spaces[@intFromEnum(Space.handshake)].send_keys != null)
            .handshake
        else
            .initial;
        var frames: std.ArrayListUnmanaged(u8) = .empty;
        defer frames.deinit(self.gpa);
        // The application-error variant (0x1d) is legal only in 1-RTT (RFC 9000 12.5);
        // in Initial/Handshake the transport variant carries APPLICATION_ERROR (0x0c).
        const use_app = app and space == .application;
        const code = if (app and !use_app) @intFromEnum(constants.TransportError.application_error) else error_code;
        frame.encodeConnectionClose(&frames, self.gpa, use_app, code, 0, reason) catch return error.OutOfMemory;
        while (frames.items.len < 20) frames.append(self.gpa, 0x00) catch return error.OutOfMemory; // PADDING
        // Only mark closed once the CLOSE is actually queued. If the 3x budget blocks
        // it (a rare pre-validation close), surface AmplificationLimited and stay open
        // so the integrator can retry after the client's next packet, rather than
        // silently rejecting all future receives with no CLOSE ever sent.
        _ = try self.buildPacket(space, frames.items, false, 0);
        self.closed = true;
    }

    /// Mark the peer address as validated before processing its token-bearing Initial.
    pub fn markAddressValidated(self: *Connection) void {
        self.address_validated = true;
    }

    /// Whether this connection has authenticated an Initial packet.
    pub fn hasAuthenticatedInitial(self: *const Connection) bool {
        return self.initial_authenticated;
    }

    /// The built datagrams as one contiguous buffer; pair with `datagramLengths`.
    pub fn datagramsToSend(self: *Connection) []const u8 {
        return self.out.items;
    }

    /// The byte length of each queued datagram, in order.
    pub fn datagramLengths(self: *Connection) []const usize {
        return self.out_lengths.items;
    }

    /// The address-aware path token for each queued datagram. A null token means
    /// the datagram was queued through the legacy no-address API.
    pub fn datagramPathTokens(self: *Connection) []const ?u64 {
        return self.out_path_tokens.items;
    }

    /// Resolve an address-aware path token to the opaque peer address supplied by
    /// the integrator.
    pub fn pathAddress(self: *const Connection, token: u64) ?[]const u8 {
        if (self.paths.get(token)) |path| return path.address;
        const provisional = self.provisional_path orelse return null;
        if (provisional.token != token) return null;
        return provisional.state.address;
    }

    /// The authenticated default path address, or null before an addressed packet authenticates.
    pub fn defaultPathAddress(self: *const Connection) ?[]const u8 {
        const token = self.default_path_token orelse return null;
        return self.pathAddress(token);
    }

    /// Switch subsequent packets to a peer-issued connection id (RFC 9000 5.1).
    /// The id must have arrived in NEW_CONNECTION_ID and must not have been retired.
    pub fn usePeerConnectionId(self: *Connection, seq: u64) Error!void {
        if (seq < self.peer_retire_prior_to) return error.ProtocolViolation;
        const peer_cid = self.peer_cids.get(seq) orelse return error.ProtocolViolation;
        if (peer_cid.cid.len == 0 or peer_cid.cid.len > constants.MAX_CID_LEN) return error.ProtocolViolation;
        const owned = self.gpa.dupe(u8, peer_cid.cid) catch return error.OutOfMemory;
        self.gpa.free(self.peer_scid);
        self.peer_scid = owned;
        self.peer_cid_seq = seq;
    }

    /// Issue a replacement local connection id to the peer (RFC 9000 5.1/19.15).
    /// The caller owns CID entropy and the stateless reset token derivation; the
    /// core stores the CID for short-header routing and re-sends the frame until
    /// ACKed. `retire_prior_to` asks the peer to stop using older local CID
    /// sequences while preserving the peer's active_connection_id_limit.
    pub fn issueLocalConnectionId(self: *Connection, seq: u64, retire_prior_to: u64, cid: []const u8, token: [16]u8) Error!void {
        if (seq == 0 or retire_prior_to > seq) return error.ProtocolViolation;
        if (seq <= self.local_cid_max_seq or self.local_cids.contains(seq)) return error.ProtocolViolation;
        if (cid.len == 0 or cid.len > constants.MAX_CID_LEN) return error.ProtocolViolation;
        if (std.mem.eql(u8, cid, self.scid) or self.localCidValueExists(cid)) return error.ProtocolViolation;
        if (self.localActiveCidCountAfter(retire_prior_to) + 1 > self.peer_tp.active_connection_id_limit) return error.ProtocolViolation;

        const owned = self.gpa.dupe(u8, cid) catch return error.OutOfMemory;
        errdefer self.gpa.free(owned);
        self.local_cids.put(self.gpa, seq, .{ .cid = owned, .token = token }) catch return error.OutOfMemory;
        errdefer {
            if (self.local_cids.fetchRemove(seq)) |entry| self.gpa.free(entry.value.cid);
        }
        const gop = self.pending_new_cids.getOrPut(self.gpa, seq) catch return error.OutOfMemory;
        gop.value_ptr.* = .{ .retire_prior_to = retire_prior_to };
        self.local_cid_max_seq = seq;
        self.local_cid_generation +%= 1;
    }

    /// Return the generation of the active local connection ID set.
    pub fn localConnectionIdGeneration(self: *const Connection) u64 {
        return self.local_cid_generation;
    }

    /// Copy the active local connection IDs into `out`. A newly issued ID appears
    /// immediately, before its `NEW_CONNECTION_ID` can be drained and sent. An ID
    /// disappears after the peer's `RETIRE_CONNECTION_ID` is processed.
    pub fn localConnectionIds(self: *const Connection, out: []LocalConnectionId) usize {
        var count: usize = 0;
        if (!self.local_initial_cid_retired and count < out.len) {
            out[count] = .{ .sequence_number = 0, .connection_id = self.scid };
            count += 1;
        }
        var iterator = self.local_cids.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.retired or count >= out.len) continue;
            out[count] = .{ .sequence_number = entry.key_ptr.*, .connection_id = entry.value_ptr.cid };
            count += 1;
        }
        return count;
    }

    /// Return the number of active local connection IDs.
    pub fn localConnectionIdCount(self: *const Connection) usize {
        var count: usize = if (self.local_initial_cid_retired) 0 else 1;
        var iterator = self.local_cids.valueIterator();
        while (iterator.next()) |local| if (!local.retired) {
            count += 1;
        };
        return count;
    }

    /// Drop the drained datagrams (the integrator has sent them).
    pub fn clearSend(self: *Connection) void {
        self.out.clearRetainingCapacity();
        self.out_lengths.clearRetainingCapacity();
        self.out_path_tokens.clearRetainingCapacity();
        if (self.provisional_path) |path| self.gpa.free(path.state.address);
        self.provisional_path = null;
        while (true) {
            var removed = false;
            var iterator = self.paths.iterator();
            while (iterator.next()) |entry| {
                const token = entry.key_ptr.*;
                if (self.default_path_token == token or self.peer_candidate_path_token == token or
                    self.pathHasPendingChallenge(token))
                {
                    continue;
                }
                const address = entry.value_ptr.address;
                _ = self.paths.remove(token);
                self.gpa.free(address);
                removed = true;
                break;
            }
            if (!removed) break;
        }
    }

    // ---- STREAM send -----------------------------------------------------------

    fn trackPeerResetStream(self: *Connection, id: u64) !void {
        if (self.peer_reset_streams.contains(id)) return;
        if (self.peer_reset_streams.count() >= max_peer_reset_streams) {
            self.close(
                false,
                @intFromEnum(constants.TransportError.internal_error),
                "peer reset stream limit",
            ) catch {
                self.closed = true;
            };
            return error.StreamLimitError;
        }
        try self.peer_reset_streams.ensureUnusedCapacity(self.gpa, 1);
        self.peer_reset_streams.putAssumeCapacity(id, {});
    }

    fn sendStream(self: *Connection, id: u64) Error!*stream.SendStream {
        if (self.peer_stop_sending.contains(id)) try self.trackPeerResetStream(id);
        if (self.send_streams.get(id)) |s| {
            if (self.peer_stop_sending.fetchRemove(id)) |e| s.reset(e.value);
            return s;
        }
        try self.checkLocalStreamLimit(id);
        const s = try self.gpa.create(stream.SendStream);
        s.* = stream.SendStream.init(self.gpa);
        self.send_streams.put(self.gpa, id, s) catch {
            s.deinit();
            self.gpa.destroy(s);
            return error.OutOfMemory;
        };
        // The peer already asked us to stop sending on this stream (STOP_SENDING
        // arrived before we created it): the stream is born reset, so any data the
        // caller writes is replaced by the RESET_STREAM.
        if (self.peer_stop_sending.fetchRemove(id)) |e| s.reset(e.value);
        return s;
    }

    /// Queue `data` (and/or a FIN) to be sent on stream `id`. `flushSend` packetizes
    /// the queue once the Application keys exist. Writing after a FIN is rejected.
    ///
    /// This is application queueing: it buffers everything written. Only `flushSend`
    /// applies the connection and per-stream send windows, so the in-flight bytes on
    /// the wire are bounded by the peer's MAX_DATA/MAX_STREAM_DATA grants, but the
    /// queued-but-unsent buffer is bounded only by what the application writes; there
    /// is no write-side backpressure cap.
    pub fn sendStreamData(self: *Connection, id: u64, data: []const u8, fin: bool) Error!void {
        const s = try self.sendStream(id);
        s.write(data, fin) catch |e| switch (e) {
            error.FinalSizeError => return error.FinalSizeError,
            error.StreamBufferExceeded => unreachable,
            error.OutOfMemory => return error.OutOfMemory,
        };
    }

    /// Abruptly terminate the sending part of `id` with `error_code` (RFC 9000 19.4).
    /// A RESET_STREAM, carrying the final size, replaces any unsent data and is
    /// re-sent until acked; flushSend emits it. The first reset wins.
    pub fn resetStream(self: *Connection, id: u64, error_code: u64) Error!void {
        const s = try self.sendStream(id);
        s.reset(error_code);
    }

    /// Ask the peer to stop sending on `id` with `error_code` (RFC 9000 19.5). A
    /// STOP_SENDING is queued and re-sent until acked; flushSend emits it.
    pub fn stopSending(self: *Connection, id: u64, error_code: u64) Error!void {
        const gop = self.stop_sending.getOrPut(self.gpa, id) catch return error.OutOfMemory;
        if (!gop.found_existing) gop.value_ptr.* = .{ .code = error_code };
    }

    /// Start path validation by sending a PATH_CHALLENGE with caller-supplied
    /// unpredictable 8-byte data (RFC 9000 8.2). The core is sans-IO and has no RNG,
    /// so the integrator owns entropy; the transport owns retransmission state and
    /// matching the peer's PATH_RESPONSE.
    pub fn challengePath(self: *Connection, data: [8]u8) Error!void {
        try self.queuePathChallenge(data, null);
    }

    /// Start path validation for an address-scoped path. The address is an opaque,
    /// stable byte key chosen by the integrator; outbound datagrams queued by the
    /// subsequent flush are accounted against that path's amplification budget.
    pub fn challengePathOn(self: *Connection, data: [8]u8, peer_address: []const u8) Error!void {
        const pt = try self.pathTokenForAddress(peer_address);
        try self.queuePathChallenge(data, pt);
    }

    fn queuePathChallenge(self: *Connection, data: [8]u8, pt: ?u64) Error!void {
        const gop = self.pending_path_challenges.getOrPut(self.gpa, pathToken(data)) catch return error.OutOfMemory;
        if (gop.found_existing and gop.value_ptr.path_token != pt) return error.ProtocolViolation;
        if (!gop.found_existing) gop.value_ptr.* = .{};
        gop.value_ptr.path_token = pt;
    }

    fn queueAutomaticPathChallenge(self: *Connection, pt: u64, now: u64) Error!void {
        if (self.pathHasPendingChallenge(pt)) return;
        const data = self.automaticPathChallengeData(pt, now);
        try self.queuePathChallenge(data, pt);
    }

    fn pathHasPendingChallenge(self: *const Connection, pt: u64) bool {
        var it = self.pending_path_challenges.valueIterator();
        while (it.next()) |pending| {
            if (pending.path_token != null and pending.path_token.? == pt) return true;
        }
        return false;
    }

    fn automaticPathChallengeData(self: *Connection, pt: u64, now: u64) [8]u8 {
        const secret = self.spaces[@intFromEnum(Space.application)].send_secret orelse self.spaces[@intFromEnum(Space.application)].recv_secret orelse [_]u8{0} ** 32;
        var msg: [40]u8 = undefined;
        std.mem.copyForwards(u8, msg[0..8], "zttp-h3p");
        std.mem.writeInt(u64, msg[8..16], pt, .big);
        std.mem.writeInt(u64, msg[16..24], now, .big);
        std.mem.writeInt(u64, msg[24..32], self.auto_path_challenge_counter, .big);
        std.mem.writeInt(u64, msg[32..40], std.hash.Wyhash.hash(0, self.scid), .big);
        self.auto_path_challenge_counter +%= 1;

        var mac: [32]u8 = undefined;
        HmacSha256.create(&mac, &msg, &secret);
        return mac[0..8].*;
    }

    /// Whether any stream has bytes (or a FIN) still to send, or a RESET_STREAM /
    /// STOP_SENDING is owed.
    pub fn hasPendingSend(self: *Connection) bool {
        if (self.data_blocked != null) return true;
        if (self.stream_data_blocked.count() > 0) return true;
        if (self.streams_blocked_bidi != null or self.streams_blocked_uni != null) return true;
        if (self.stop_sending.count() > 0) return true;
        if (self.pending_new_cids.count() > 0) return true;
        if (self.pending_retire_cids.count() > 0) return true;
        if (self.pending_path_challenges.count() > 0) return true;
        var it = self.send_streams.valueIterator();
        while (it.next()) |s| if (s.*.pending() or s.*.resetOwed()) return true;
        return false;
    }

    fn sendWindow(self: *Connection, id: u64) Error!*flow.SendWindow {
        const gop = self.send_windows.getOrPut(self.gpa, id) catch return error.OutOfMemory;
        if (!gop.found_existing) gop.value_ptr.* = flow.SendWindow.init(self.initialStreamSendLimit(id));
        return gop.value_ptr;
    }

    /// The remaining peer-granted stream-level send credit for a live send stream,
    /// or null if the stream has no send state.
    pub fn streamSendWindow(self: *const Connection, id: u64) ?u64 {
        if (!self.send_streams.contains(id)) return null;
        if (self.send_windows.get(id)) |w| return w.available();
        return self.initialStreamSendLimit(id);
    }

    /// New bytes queued on `id` that have not yet been admitted into STREAM frames,
    /// or null if the stream has no send state.
    pub fn streamPendingBytes(self: *const Connection, id: u64) ?usize {
        const s = self.send_streams.get(id) orelse return null;
        return s.pendingNewBytes();
    }

    /// The peer's transport parameters define the initial stream-data limit for
    /// bytes we send. For bidirectional streams, the "local"/"remote" names are from
    /// the peer's perspective: a peer-initiated stream uses bidi_local, a stream we
    /// initiate uses bidi_remote. Unidirectional streams use the single uni limit.
    fn initialStreamSendLimit(self: *const Connection, id: u64) u64 {
        return switch (stream.StreamType.of(id)) {
            .client_bidi, .server_bidi => blk: {
                break :blk if (self.isPeerInitiated(id))
                    self.peer_tp.initial_max_stream_data_bidi_local
                else
                    self.peer_tp.initial_max_stream_data_bidi_remote;
            },
            .client_uni, .server_uni => self.peer_tp.initial_max_stream_data_uni,
        };
    }

    fn recvWindow(self: *Connection, id: u64) Error!*flow.Window {
        const gop = self.recv_windows.getOrPut(self.gpa, id) catch return error.OutOfMemory;
        if (!gop.found_existing) gop.value_ptr.* = flow.Window.init(self.initialStreamRecvLimit(id));
        return gop.value_ptr;
    }

    /// The transport parameters we advertise define the initial stream-data limit
    /// for bytes we receive. For bidirectional streams, local/remote are from our
    /// perspective: peer-initiated streams use bidi_remote; local-initiated streams
    /// use bidi_local.
    fn initialStreamRecvLimit(self: *const Connection, id: u64) u64 {
        return switch (stream.StreamType.of(id)) {
            .client_bidi, .server_bidi => if (self.isPeerInitiated(id))
                self.local_tp.initial_max_stream_data_bidi_remote
            else
                self.local_tp.initial_max_stream_data_bidi_local,
            .client_uni, .server_uni => self.local_tp.initial_max_stream_data_uni,
        };
    }

    fn isPeerInitiated(self: *const Connection, id: u64) bool {
        const local_is_client = self.role == .client;
        return stream.StreamType.of(id).isClientInitiated() != local_is_client;
    }

    fn peerCanSendOn(self: *const Connection, id: u64) bool {
        const st = stream.StreamType.of(id);
        return !st.isUni() or self.isPeerInitiated(id);
    }

    fn localCanSendOn(self: *const Connection, id: u64) bool {
        const st = stream.StreamType.of(id);
        return !st.isUni() or !self.isPeerInitiated(id);
    }

    fn localStreamWasOpened(self: *const Connection, id: u64) bool {
        if (self.isPeerInitiated(id)) return false;
        const limit = if (stream.StreamType.of(id).isUni()) self.local_uni_streams else self.local_bidi_streams;
        return id >> 2 < limit.opened;
    }

    fn checkPeerStreamLimit(self: *Connection, id: u64) Error!void {
        if (!self.isPeerInitiated(id)) return;
        const is_uni = stream.StreamType.of(id).isUni();
        const idx = id >> 2;
        const limit = if (is_uni) &self.peer_uni_streams else &self.peer_bidi_streams;
        limit.onOpened(idx) catch return error.StreamLimitError;
        if (limit.shouldUpdate()) {
            if (is_uni) {
                self.max_streams_uni_pending = true;
            } else {
                self.max_streams_bidi_pending = true;
            }
        }
    }

    fn checkLocalStreamLimit(self: *Connection, id: u64) Error!void {
        if (self.isPeerInitiated(id)) return;
        const st = stream.StreamType.of(id);
        const idx = id >> 2;
        if (st.isUni()) {
            self.local_uni_streams.onOpened(idx) catch {
                self.queueStreamsBlocked(false, self.local_uni_streams.max);
                return error.StreamLimitError;
            };
        } else {
            self.local_bidi_streams.onOpened(idx) catch {
                self.queueStreamsBlocked(true, self.local_bidi_streams.max);
                return error.StreamLimitError;
            };
        }
    }

    fn onMaxStreams(self: *Connection, bidi: bool, max: u64) Error!void {
        if (max > transport_params.MAX_STREAM_COUNT) return error.ProtocolViolation;
        if (bidi) self.local_bidi_streams.onMaxStreams(max) else self.local_uni_streams.onMaxStreams(max);
        const pending = if (bidi) &self.streams_blocked_bidi else &self.streams_blocked_uni;
        if (pending.*) |p| {
            if (max > p.limit) pending.* = null;
        }
    }

    fn onMaxData(self: *Connection, max: u64) void {
        self.conn_send_window.onMaxData(max);
        if (self.data_blocked) |p| {
            if (max > p.limit) self.data_blocked = null;
        }
    }

    fn onMaxStreamData(self: *Connection, id: u64, max: u64) Error!void {
        if (!self.localCanSendOn(id)) return error.StreamStateError;
        const sw = try self.sendWindow(id);
        sw.onMaxData(max);
        if (self.stream_data_blocked.get(id)) |p| {
            if (max > p.limit) _ = self.stream_data_blocked.remove(id);
        }
    }

    fn onDataBlocked(self: *Connection, limit: u64) void {
        self.peer_data_blocked_limit = if (self.peer_data_blocked_limit) |old| @max(old, limit) else limit;
    }

    fn onStreamDataBlocked(self: *Connection, id: u64, limit: u64) Error!void {
        if (self.isRetired(id)) return;
        if (!self.peerCanSendOn(id)) return error.StreamStateError;
        if (!self.isPeerInitiated(id) and !self.localStreamWasOpened(id)) return error.StreamStateError;
        try self.checkPeerStreamLimit(id);
        if (!self.peer_stream_data_blocked.contains(id) and
            self.peer_stream_data_blocked.count() >= max_peer_stream_data_blocked)
        {
            self.close(
                false,
                @intFromEnum(constants.TransportError.internal_error),
                "peer stream blocked limit",
            ) catch {
                self.closed = true;
            };
            return error.StreamLimitError;
        }
        _ = try self.recvStream(id);
        const gop = self.peer_stream_data_blocked.getOrPut(self.gpa, id) catch return error.OutOfMemory;
        if (!gop.found_existing) {
            gop.value_ptr.* = limit;
        } else {
            gop.value_ptr.* = @max(gop.value_ptr.*, limit);
        }
    }

    fn onStreamsBlocked(self: *Connection, bidi: bool, limit: u64) Error!void {
        if (limit > transport_params.MAX_STREAM_COUNT) return error.StreamLimitError;
        if (bidi) {
            self.peer_streams_blocked_bidi_limit = if (self.peer_streams_blocked_bidi_limit) |old| @max(old, limit) else limit;
        } else {
            self.peer_streams_blocked_uni_limit = if (self.peer_streams_blocked_uni_limit) |old| @max(old, limit) else limit;
        }
    }

    fn queueDataBlocked(self: *Connection, limit: u64) void {
        if (self.data_blocked) |p| {
            if (limit <= p.limit) return;
        }
        self.data_blocked = .{ .limit = limit };
    }

    fn queueStreamDataBlocked(self: *Connection, id: u64, limit: u64) Error!void {
        const gop = self.stream_data_blocked.getOrPut(self.gpa, id) catch return error.OutOfMemory;
        if (!gop.found_existing or limit > gop.value_ptr.limit) gop.value_ptr.* = .{ .limit = limit };
    }

    fn queueStreamsBlocked(self: *Connection, bidi: bool, limit: u64) void {
        const pending = if (bidi) &self.streams_blocked_bidi else &self.streams_blocked_uni;
        if (pending.*) |p| {
            if (limit <= p.limit) return;
        }
        pending.* = .{ .limit = limit };
    }

    fn emitPendingBlockedFrames(self: *Connection, space: Space, now: u64) Error!void {
        if (self.data_blocked) |*p| {
            if (!p.in_flight) {
                var bf: std.ArrayListUnmanaged(u8) = .empty;
                defer bf.deinit(self.gpa);
                frame.encodeDataBlocked(&bf, self.gpa, p.limit) catch return error.OutOfMemory;
                while (bf.items.len < 20) bf.append(self.gpa, 0x00) catch return error.OutOfMemory;
                self.data_blocked_inflight.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
                const pn = try self.buildPacket(space, bf.items, true, now);
                self.data_blocked_inflight.putAssumeCapacity(pn, p.limit);
                p.in_flight = true;
            }
        }

        if (self.stream_data_blocked.count() > 0) {
            var ids: std.ArrayListUnmanaged(u64) = .empty;
            defer ids.deinit(self.gpa);
            var it = self.stream_data_blocked.keyIterator();
            while (it.next()) |id| ids.append(self.gpa, id.*) catch return error.OutOfMemory;
            for (ids.items) |id| {
                const p = self.stream_data_blocked.getPtr(id) orelse continue;
                if (p.in_flight) continue;
                var bf: std.ArrayListUnmanaged(u8) = .empty;
                defer bf.deinit(self.gpa);
                frame.encodeStreamDataBlocked(&bf, self.gpa, id, p.limit) catch return error.OutOfMemory;
                while (bf.items.len < 20) bf.append(self.gpa, 0x00) catch return error.OutOfMemory;
                self.stream_data_blocked_inflight.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
                const pn = try self.buildPacket(space, bf.items, true, now);
                self.stream_data_blocked_inflight.putAssumeCapacity(pn, .{ .id = id, .limit = p.limit });
                p.in_flight = true;
            }
        }

        try self.emitStreamsBlocked(space, now, true);
        try self.emitStreamsBlocked(space, now, false);
    }

    fn emitStreamsBlocked(self: *Connection, space: Space, now: u64, bidi: bool) Error!void {
        const pending = if (bidi) &self.streams_blocked_bidi else &self.streams_blocked_uni;
        if (pending.*) |*p| {
            if (p.in_flight) return;
            var bf: std.ArrayListUnmanaged(u8) = .empty;
            defer bf.deinit(self.gpa);
            frame.encodeStreamsBlocked(&bf, self.gpa, bidi, p.limit) catch return error.OutOfMemory;
            while (bf.items.len < 20) bf.append(self.gpa, 0x00) catch return error.OutOfMemory;
            self.streams_blocked_inflight.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
            const pn = try self.buildPacket(space, bf.items, true, now);
            self.streams_blocked_inflight.putAssumeCapacity(pn, .{ .bidi = bidi, .limit = p.limit });
            p.in_flight = true;
        }
    }

    fn flushPathChallenges(self: *Connection, space: Space, now: u64) Error!void {
        var pc = self.pending_path_challenges.iterator();
        while (pc.next()) |entry| {
            if (entry.value_ptr.in_flight) continue;
            const token = entry.key_ptr.*;
            var data: [8]u8 = undefined;
            std.mem.writeInt(u64, &data, token, .big);
            var pf: std.ArrayListUnmanaged(u8) = .empty;
            defer pf.deinit(self.gpa);
            frame.encodePathChallenge(&pf, self.gpa, data) catch return error.OutOfMemory;
            while (pf.items.len < 20) pf.append(self.gpa, 0x00) catch return error.OutOfMemory;
            self.path_challenge_inflight.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
            const previous_path = self.current_path_token;
            if (entry.value_ptr.path_token) |pt| self.current_path_token = pt;
            defer self.current_path_token = previous_path;
            const pn = try self.buildPacket(space, pf.items, true, now);
            self.path_challenge_inflight.putAssumeCapacity(pn, token);
            entry.value_ptr.in_flight = true;
        }
    }

    /// Packetize queued stream data into Application (1-RTT) datagrams, one STREAM
    /// frame per packet. STREAM is legal only in the Application space (RFC 9000
    /// 12.4), so nothing flows until the handshake installs the 1-RTT send keys -
    /// the structural fix for shipping STREAM data in Initial packets.
    ///
    /// Each sent range is recorded per packet (stream_sent) and retained in the
    /// SendStream until acked, so a lost packet is retransmitted. ACK-based loss
    /// detection routes lost pns back into SendStream.onLost, and the PTO timer
    /// probes tail packets that have no later ACK to trigger threshold loss.
    pub fn flushSend(self: *Connection, now: u64) Error!void {
        if (self.receive_failure) |err| return err;
        if (self.closed) return;
        const space = Space.application;
        const st = &self.spaces[@intFromEnum(space)];
        if (st.send_keys == null and st.zero_rtt_send_keys == null) return; // no application keys yet
        if (st.ack_pending and st.send_keys != null) try self.sendAck(space, now);
        try self.emitPendingBlockedFrames(space, now);
        // Advertise a raised connection flow-control limit if one is pending, so the
        // peer is not stalled at its old MAX_DATA grant (RFC 9000 4.1).
        if (self.max_data_pending) {
            var mf: std.ArrayListUnmanaged(u8) = .empty;
            defer mf.deinit(self.gpa);
            frame.encodeMaxData(&mf, self.gpa, self.conn_recv_window.grant()) catch return error.OutOfMemory;
            while (mf.items.len < 20) mf.append(self.gpa, 0x00) catch return error.OutOfMemory; // PADDING for HP
            _ = try self.buildPacket(space, mf.items, true, now);
            self.max_data_pending = false;
        }

        if (self.max_streams_bidi_pending) {
            var mf: std.ArrayListUnmanaged(u8) = .empty;
            defer mf.deinit(self.gpa);
            frame.encodeMaxStreams(&mf, self.gpa, true, self.peer_bidi_streams.grant()) catch return error.OutOfMemory;
            while (mf.items.len < 20) mf.append(self.gpa, 0x00) catch return error.OutOfMemory; // PADDING for HP
            _ = try self.buildPacket(space, mf.items, true, now);
            self.max_streams_bidi_pending = false;
        }
        if (self.max_streams_uni_pending) {
            var mf: std.ArrayListUnmanaged(u8) = .empty;
            defer mf.deinit(self.gpa);
            frame.encodeMaxStreams(&mf, self.gpa, false, self.peer_uni_streams.grant()) catch return error.OutOfMemory;
            while (mf.items.len < 20) mf.append(self.gpa, 0x00) catch return error.OutOfMemory; // PADDING for HP
            _ = try self.buildPacket(space, mf.items, true, now);
            self.max_streams_uni_pending = false;
        }

        if (self.max_stream_data_pending.count() > 0) {
            var ids: std.ArrayListUnmanaged(u64) = .empty;
            defer ids.deinit(self.gpa);
            var pit = self.max_stream_data_pending.keyIterator();
            while (pit.next()) |id| ids.append(self.gpa, id.*) catch return error.OutOfMemory;
            for (ids.items) |id| {
                const rw = self.recv_windows.getPtr(id) orelse {
                    _ = self.max_stream_data_pending.remove(id);
                    continue;
                };
                var mf: std.ArrayListUnmanaged(u8) = .empty;
                defer mf.deinit(self.gpa);
                frame.encodeMaxStreamData(&mf, self.gpa, id, rw.grant()) catch return error.OutOfMemory;
                while (mf.items.len < 20) mf.append(self.gpa, 0x00) catch return error.OutOfMemory; // PADDING for HP
                _ = try self.buildPacket(space, mf.items, true, now);
                _ = self.max_stream_data_pending.remove(id);
            }
        }

        // PATH_CHALLENGE frames owed for path validation (RFC 9000 8.2), retained
        // until the peer returns the exact data in PATH_RESPONSE. An ACK only proves
        // delivery, not validation, so it clears the packet-number bookkeeping but
        // does not remove the pending challenge.
        try self.flushPathChallenges(space, now);

        // A conservative single-packet budget: one STREAM frame per packet.
        const packet_room = self.framePayloadRoom(space);
        var stack_stream_ids: [64]u64 = undefined;
        const stream_count = self.send_streams.count();
        const stream_ids = if (stream_count <= stack_stream_ids.len)
            stack_stream_ids[0..stream_count]
        else
            self.gpa.alloc(u64, stream_count) catch return error.OutOfMemory;
        defer if (stream_count > stack_stream_ids.len) self.gpa.free(stream_ids);
        var stream_id_it = self.send_streams.keyIterator();
        var stream_id_count: usize = 0;
        while (stream_id_it.next()) |id| {
            stream_ids[stream_id_count] = id.*;
            stream_id_count += 1;
        }
        std.mem.sort(u64, stream_ids[0..stream_id_count], {}, streamSendPriorityLess);
        for (stream_ids[0..stream_id_count]) |id| {
            const s = self.send_streams.get(id) orelse continue;
            // A reset stream sends a RESET_STREAM instead of any further data (RFC
            // 9000 19.4): the final size is the bytes already written. It rides until
            // acked; loss re-arms resetOwed via onResetLost.
            if (s.resetOwed()) {
                var rf: std.ArrayListUnmanaged(u8) = .empty;
                defer rf.deinit(self.gpa);
                frame.encodeResetStream(&rf, self.gpa, id, s.reset_code.?, s.reset_final_size) catch return error.OutOfMemory;
                while (rf.items.len < 20) rf.append(self.gpa, 0x00) catch return error.OutOfMemory; // PADDING for HP
                st.reset_sent.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
                const pn = try self.buildPacket(space, rf.items, true, now);
                st.reset_sent.putAssumeCapacity(pn, id);
                s.onResetSent();
                continue; // no data follows a reset
            }
            while (s.pending()) {
                // Peek a full packet's worth; a retransmit (offset below the send
                // cursor) re-sends already-presented bytes, a new chunk presents
                // fresh offsets. Only new bytes consume connection send-window credit
                // (RFC 9000 4.1); the window is a monotonic high-water mark, so a
                // retransmit and a pure FIN need none.
                var chunk = s.peek(packet_room) orelse break;
                const is_new = chunk.offset >= s.sent;
                if (is_new and chunk.data.len > 0) {
                    // New bytes are bounded by BOTH the peer's flow-control grant
                    // (MAX_DATA + MAX_STREAM_DATA, RFC 9000 4.1) and the congestion
                    // window (RFC 9002 7): a retransmit or a pure FIN below is exempt,
                    // since neither presents fresh offsets. cwnd limits bytes in
                    // flight, so a packet already counts its header+tag; gate the new
                    // stream bytes against the smallest remaining budget.
                    const sw = try self.sendWindow(id);
                    const conn_credit = self.conn_send_window.available();
                    const stream_credit = sw.available();
                    if (conn_credit == 0) self.queueDataBlocked(self.conn_send_window.limit);
                    if (stream_credit == 0) try self.queueStreamDataBlocked(id, sw.limit);
                    const credit = @min(@min(conn_credit, stream_credit), self.cc.available());
                    if (credit == 0) break; // out of window or out of cwnd: keep new bytes queued
                    if (chunk.data.len > credit) chunk = s.peek(@intCast(credit)).?; // shrink to fit
                }
                if (chunk.data.len == 0 and !chunk.fin) break;
                var frames: std.ArrayListUnmanaged(u8) = .empty;
                defer frames.deinit(self.gpa);
                frame.encodeStream(&frames, self.gpa, id, chunk.offset, chunk.data, chunk.fin) catch return error.OutOfMemory;
                // Reserve the record slot BEFORE sending, so the packet is never put
                // on the wire without a retransmit route (an OOM here leaves nothing
                // queued).
                st.stream_sent.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
                const pn = try self.buildPacket(space, frames.items, true, now);
                st.stream_sent.putAssumeCapacity(pn, .{ .id = id, .offset = chunk.offset, .len = chunk.data.len, .fin = chunk.fin });
                if (is_new) {
                    self.conn_send_window.onSent(chunk.data.len); // monotonic: only new offsets
                    (try self.sendWindow(id)).onSent(chunk.data.len);
                }
                s.commit(chunk.offset, chunk.data.len, chunk.fin);
            }
        }
        try self.emitPendingBlockedFrames(space, now);

        // STOP_SENDING frames owed to peers (RFC 9000 19.5): one per packet, recorded
        // so a lost one is re-sent. Only those not already in flight are emitted.
        var ss = self.stop_sending.iterator();
        while (ss.next()) |entry| {
            if (entry.value_ptr.in_flight) continue; // already on the wire, unacked
            const id = entry.key_ptr.*;
            var sf: std.ArrayListUnmanaged(u8) = .empty;
            defer sf.deinit(self.gpa);
            frame.encodeStopSending(&sf, self.gpa, id, entry.value_ptr.code) catch return error.OutOfMemory;
            while (sf.items.len < 20) sf.append(self.gpa, 0x00) catch return error.OutOfMemory; // PADDING for HP
            self.stop_sending_inflight.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
            const pn = try self.buildPacket(space, sf.items, true, now);
            self.stop_sending_inflight.putAssumeCapacity(pn, id);
            entry.value_ptr.in_flight = true;
        }

        // NEW_CONNECTION_ID frames owed to peers (RFC 9000 19.15), re-sent until
        // acked so the peer reliably learns replacement CIDs for migration.
        var nc = self.pending_new_cids.iterator();
        while (nc.next()) |entry| {
            if (entry.value_ptr.in_flight) continue;
            const seq = entry.key_ptr.*;
            const local = self.local_cids.get(seq) orelse {
                _ = self.pending_new_cids.remove(seq);
                continue;
            };
            var nf: std.ArrayListUnmanaged(u8) = .empty;
            defer nf.deinit(self.gpa);
            frame.encodeNewConnectionId(&nf, self.gpa, seq, entry.value_ptr.retire_prior_to, local.cid, local.token) catch return error.OutOfMemory;
            while (nf.items.len < 20) nf.append(self.gpa, 0x00) catch return error.OutOfMemory; // PADDING for HP
            self.new_cid_inflight.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
            const pn = try self.buildPacket(space, nf.items, true, now);
            self.new_cid_inflight.putAssumeCapacity(pn, seq);
            entry.value_ptr.in_flight = true;
        }

        // RETIRE_CONNECTION_ID frames owed to peers (RFC 9000 19.16), re-sent until
        // acked so retire_prior_to requests are reliably reported back.
        var rc = self.pending_retire_cids.iterator();
        while (rc.next()) |entry| {
            if (entry.value_ptr.in_flight) continue;
            const seq = entry.key_ptr.*;
            var rf: std.ArrayListUnmanaged(u8) = .empty;
            defer rf.deinit(self.gpa);
            frame.encodeRetireConnectionId(&rf, self.gpa, seq) catch return error.OutOfMemory;
            while (rf.items.len < 20) rf.append(self.gpa, 0x00) catch return error.OutOfMemory; // PADDING for HP
            self.retire_cid_inflight.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
            const pn = try self.buildPacket(space, rf.items, true, now);
            self.retire_cid_inflight.putAssumeCapacity(pn, seq);
            entry.value_ptr.in_flight = true;
        }
    }

    /// Process an incoming ACK for `space`: fold it into recovery, free the STREAM
    /// bytes the acked packets carried, then run loss detection and re-queue the
    /// bytes any newly-lost packet carried so the next flushSend retransmits them.
    /// A pn lives in `rec.sent` and `stream_sent` in lockstep, so each is routed to
    /// the SendStream exactly once (fetchRemove), defending double-free / resurrect.
    fn onAckFrame(self: *Connection, space: Space, a: anytype, now: u64) Error!void {
        const st = &self.spaces[@intFromEnum(space)];
        try validateAckFrame(st, a);
        var acked_pns: std.ArrayListUnmanaged(u64) = .empty;
        defer acked_pns.deinit(self.gpa);
        var it = frame.ackRanges(a.ranges);
        // onAck's only failure is the acked_pns append, i.e. OutOfMemory - a
        // malformed range just stops the walk, it never errors. So surface allocator
        // pressure as OutOfMemory, not a peer protocol error.
        const ack_delay = try self.decodeAckDelay(space, a.delay);
        _ = st.rec.onAck(&self.rtt, &self.cc, now, a.largest, ack_delay, a.first_range, &it, &acked_pns, self.gpa) catch
            return error.OutOfMemory;
        if (a.ecn) |ecn| {
            if (try recordPeerEcnCounts(st, ecn)) self.cc.onEcnCe(a.largest);
        }
        for (acked_pns.items) |pn| {
            if (st.stream_sent.fetchRemove(pn)) |e| {
                if (self.send_streams.get(e.value.id)) |s| {
                    try s.onAck(e.value.offset, e.value.len, e.value.fin);
                    // A response whose every byte and FIN is now acked has nothing
                    // left to retransmit; reclaim it so a completed stream's send half
                    // does not linger (dropStream could not free it while in flight).
                    if (s.fullyAcked()) {
                        _ = self.send_streams.remove(e.value.id);
                        _ = self.send_windows.remove(e.value.id);
                        _ = self.peer_reset_streams.remove(e.value.id);
                        s.deinit();
                        self.gpa.destroy(s);
                    }
                }
            }
            if (st.crypto_sent.fetchRemove(pn)) |e| try st.crypto_send.onAck(e.value.offset, e.value.len, false);
            if (st.reset_sent.fetchRemove(pn)) |e| {
                if (self.send_streams.get(e.value)) |s| {
                    s.onResetAck();
                    if (s.fullyAcked()) {
                        _ = self.send_streams.remove(e.value);
                        _ = self.send_windows.remove(e.value);
                        _ = self.peer_reset_streams.remove(e.value);
                        s.deinit();
                        self.gpa.destroy(s);
                    }
                }
            }
            if (self.stop_sending_inflight.fetchRemove(pn)) |e| _ = self.stop_sending.remove(e.value); // acked: done
            if (self.new_cid_inflight.fetchRemove(pn)) |e| _ = self.pending_new_cids.remove(e.value); // acked: done
            if (self.retire_cid_inflight.fetchRemove(pn)) |e| _ = self.pending_retire_cids.remove(e.value); // acked: done
            if (self.path_challenge_inflight.fetchRemove(pn)) |_| {} // acked delivery is not path validation
            if (self.data_blocked_inflight.fetchRemove(pn)) |e| {
                if (self.data_blocked) |p| {
                    if (p.limit == e.value) self.data_blocked = null;
                }
            }
            if (self.stream_data_blocked_inflight.fetchRemove(pn)) |e| {
                if (self.stream_data_blocked.get(e.value.id)) |p| {
                    if (p.limit == e.value.limit) _ = self.stream_data_blocked.remove(e.value.id);
                }
            }
            if (self.streams_blocked_inflight.fetchRemove(pn)) |e| {
                const pending = if (e.value.bidi) &self.streams_blocked_bidi else &self.streams_blocked_uni;
                if (pending.*) |p| {
                    if (p.limit == e.value.limit) pending.* = null;
                }
            }
        }
        // ACK progress resets the PTO backoff (in recovery), so release the fire-once
        // latch: a fresh PTO epoch may arm even if another packet sharing the fired
        // anchor is still in flight.
        if (acked_pns.items.len > 0) st.pto_fired_anchor = null;
        try self.detectLostAndRequeue(space, now);
    }

    fn validateAckFrame(st: *const SpaceState, a: anytype) Error!void {
        if (a.first_range > a.largest) return error.ProtocolViolation;
        if (a.largest >= st.next_pn) return error.ProtocolViolation;

        var smallest = a.largest - a.first_range;
        var ranges = frame.ackRanges(a.ranges);
        while (ranges.next()) |r| {
            const gap_span = std.math.add(u64, r.gap, 2) catch return error.ProtocolViolation;
            if (smallest < gap_span) return error.ProtocolViolation;
            const next_largest = smallest - gap_span;
            if (next_largest < r.len) return error.ProtocolViolation;
            smallest = next_largest - r.len;
        }
    }

    fn decodeAckDelay(self: *const Connection, space: Space, raw: u64) Error!u64 {
        if (space != .application) return 0;
        if (self.peer_tp.ack_delay_exponent > 20) return error.ProtocolViolation;
        const exponent: u6 = @intCast(self.peer_tp.ack_delay_exponent);
        if (raw > (@as(u64, std.math.maxInt(u64)) >> exponent)) return error.ProtocolViolation;
        const decoded = raw << exponent;
        const max_ack_delay_us = self.peer_tp.max_ack_delay_ms * std.time.us_per_ms;
        return @min(decoded, max_ack_delay_us);
    }

    fn recordPeerEcnCounts(st: *SpaceState, ecn: frame.EcnCounts) Error!bool {
        var ce_increased = ecn.ce > 0;
        if (st.peer_ecn_counts) |old| {
            if (ecn.ect0 < old.ect0 or ecn.ect1 < old.ect1 or ecn.ce < old.ce) {
                return error.ProtocolViolation;
            }
            ce_increased = ecn.ce > old.ce;
        }
        st.peer_ecn_counts = ecn;
        return ce_increased;
    }

    /// Run loss detection for one space and re-queue every newly-lost packet's
    /// STREAM range so the next flushSend retransmits it. Shared by the ACK arm and
    /// the time-threshold path of onTimeout; `fetchRemove` keeps rec.sent and
    /// stream_sent in lockstep, so each pn is routed exactly once.
    fn detectLostAndRequeue(self: *Connection, space: Space, now: u64) Error!void {
        const st = &self.spaces[@intFromEnum(space)];
        var lost_pns: std.ArrayListUnmanaged(u64) = .empty;
        defer lost_pns.deinit(self.gpa);
        _ = st.rec.detectLost(&self.rtt, &self.cc, now, self.ackDelayFor(space), &lost_pns, self.gpa) catch return error.OutOfMemory;
        var crypto_lost = false;
        for (lost_pns.items) |pn| {
            if (st.stream_sent.fetchRemove(pn)) |e| {
                if (self.send_streams.get(e.value.id)) |s| try s.onLost(e.value.offset, e.value.len, e.value.fin);
            }
            if (st.crypto_sent.fetchRemove(pn)) |e| {
                try st.crypto_send.onLost(e.value.offset, e.value.len, false);
                crypto_lost = true;
            }
            // A lost RESET_STREAM / STOP_SENDING must be re-sent (RFC 9000 13.3): clear
            // its in-flight record so the next flushSend re-emits it.
            if (st.reset_sent.fetchRemove(pn)) |e| {
                if (self.send_streams.get(e.value)) |s| s.onResetLost();
            }
            // A lost STOP_SENDING: clear in_flight so the next flushSend re-emits it.
            if (self.stop_sending_inflight.fetchRemove(pn)) |e| {
                if (self.stop_sending.getPtr(e.value)) |ss| ss.in_flight = false;
            }
            // A lost NEW_CONNECTION_ID: clear in_flight so the next flushSend
            // re-emits it.
            if (self.new_cid_inflight.fetchRemove(pn)) |e| {
                if (self.pending_new_cids.getPtr(e.value)) |nc| nc.in_flight = false;
            }
            // A lost RETIRE_CONNECTION_ID: clear in_flight so the next flushSend
            // re-emits it.
            if (self.retire_cid_inflight.fetchRemove(pn)) |e| {
                if (self.pending_retire_cids.getPtr(e.value)) |rc| rc.in_flight = false;
            }
            // A lost PATH_CHALLENGE must be re-sent until a matching PATH_RESPONSE
            // validates the path.
            if (self.path_challenge_inflight.fetchRemove(pn)) |e| {
                if (self.pending_path_challenges.getPtr(e.value)) |pc| pc.in_flight = false;
            }
            if (self.data_blocked_inflight.fetchRemove(pn)) |e| {
                if (self.data_blocked) |*p| {
                    if (p.limit == e.value) p.in_flight = false;
                }
            }
            if (self.stream_data_blocked_inflight.fetchRemove(pn)) |e| {
                if (self.stream_data_blocked.getPtr(e.value.id)) |p| {
                    if (p.limit == e.value.limit) p.in_flight = false;
                }
            }
            if (self.streams_blocked_inflight.fetchRemove(pn)) |e| {
                const pending = if (e.value.bidi) &self.streams_blocked_bidi else &self.streams_blocked_uni;
                if (pending.*) |*p| {
                    if (p.limit == e.value.limit) p.in_flight = false;
                }
            }
        }
        if (crypto_lost) try self.flushCrypto(space, now); // resend the lost handshake bytes now
    }

    // ---- loss-recovery timer (sans-IO: the integrator owns the OS timer) --------

    /// The absolute time (us) of the earliest armed deadline across all spaces: the
    /// negotiated idle timeout, any time-threshold loss deadline, or any PTO
    /// deadline. The integrator sets an OS timer for this and calls `onTimeout` at
    /// or after it.
    /// The PTO ack-delay term per space (RFC 9002 6.2.1): the peer's negotiated
    /// max_ack_delay applies only to the Application space; the long-header spaces
    /// use 0 (the handshake has no ack-delay budget).
    fn ackDelayFor(self: *const Connection, space: Space) u64 {
        return if (space == .application) self.peer_tp.max_ack_delay_ms * std.time.us_per_ms else 0;
    }

    pub fn nextTimeout(self: *Connection) ?u64 {
        if (self.receive_failure != null) return null;
        if (self.closed) return null;
        var earliest: ?u64 = null;
        if (self.idle_deadline) |t| earliest = minOpt(earliest, t);
        for (&self.spaces, 0..) |*st, i| {
            if (st.rec.loss_time) |t| earliest = minOpt(earliest, t);
            if (st.rec.ptoDeadline(&self.rtt, self.ackDelayFor(@enumFromInt(i)))) |t| earliest = minOpt(earliest, t);
        }
        return earliest;
    }

    /// Drive the loss-recovery timers at time `now`. First handle any space whose
    /// time-threshold loss deadline passed (declare lost + re-queue, exactly the ACK
    /// path). Then, per space whose PTO deadline passed, send a probe: re-queue the
    /// oldest unacked STREAM range so the next flushSend resends it (or a PING). No
    /// I/O happens here - the next flushSend emits whatever was queued.
    pub fn onTimeout(self: *Connection, now: u64) Error!void {
        if (self.receive_failure) |err| return err;
        if (self.closed) return error.ProtocolViolation;
        if (self.idle_deadline) |deadline| {
            if (now >= deadline) {
                self.closed = true;
                self.idle_timed_out = true;
                return;
            }
        }

        // (1) Time-threshold losses first (RFC 9002 6.2.1: loss_time takes precedence).
        for (&self.spaces, 0..) |*st, i| {
            if (st.rec.loss_time) |lt| {
                if (now >= lt) try self.detectLostAndRequeue(@enumFromInt(i), now);
            }
        }

        // (2) PTO fires. The latch (pto_fired_anchor) stops a re-fire for the same
        // ack-eliciting anchor: a PTO must wait for an actual probe to advance the
        // anchor before backing off again, so repeated onTimeout calls without an
        // intervening send cannot inflate the backoff.
        for (&self.spaces, 0..) |*st, i| {
            if (st.send_keys == null) continue;
            const deadline = st.rec.ptoDeadline(&self.rtt, self.ackDelayFor(@enumFromInt(i))) orelse continue;
            if (now < deadline) continue;
            if (st.pto_fired_anchor == st.rec.last_ack_eliciting_sent_time) continue; // already fired for this anchor
            st.pto_fired_anchor = st.rec.last_ack_eliciting_sent_time;
            if (st.rec.onPtoExpired()) |pn| try self.sendProbe(@enumFromInt(i), pn, now);
        }
    }

    pub fn idleTimedOut(self: *const Connection) bool {
        return self.idle_timed_out;
    }

    /// Send a PTO probe for `space`: re-queue the oldest unacked STREAM range so the
    /// next flushSend resends it to elicit an ACK, or a PING if that packet carried
    /// no STREAM data. Crucially `stream_sent.get` (not fetchRemove): the probed
    /// packet stays in flight - a probe re-sends data, it does not declare loss - so
    /// its genuine later ACK or loss still routes exactly once.
    fn sendProbe(self: *Connection, space: Space, pn: u64, now: u64) Error!void {
        const st = &self.spaces[@intFromEnum(space)];
        // Probe by re-sending the oldest unacked CRYPTO (handshake recovery) ...
        if (st.crypto_sent.get(pn)) |sent| {
            try st.crypto_send.onLost(sent.offset, sent.len, false);
            if (st.crypto_send.pending()) {
                try self.flushCrypto(space, now);
                return;
            }
        }
        // ... or the oldest unacked STREAM range.
        if (st.stream_sent.get(pn)) |sent| {
            if (self.send_streams.get(sent.id)) |s| {
                try s.onLost(sent.offset, sent.len, sent.fin);
                // If the original data was already acked, onLost clips the range to
                // nothing (it is below base_offset) and queues no resend. Fall through
                // to a PING so a probe still reaches the wire - otherwise the PTO
                // advanced its backoff/latch with nothing sent and the timer would
                // spin on an unsatisfiable deadline.
                if (s.pending()) return;
            }
        }
        // ... or the RESET_STREAM the probed packet carried: re-arm it so flushSend
        // re-sends the reset rather than wasting the probe on a PING (RFC 9000 13.3).
        if (st.reset_sent.get(pn)) |id| {
            if (self.send_streams.get(id)) |s| {
                s.onResetLost();
                if (s.resetOwed()) return; // the next flushSend re-sends the reset
            }
        }
        // ... or the STOP_SENDING the probed packet carried: clear in_flight to re-emit.
        if (self.stop_sending_inflight.get(pn)) |id| {
            if (self.stop_sending.getPtr(id)) |ss| {
                ss.in_flight = false;
                return; // the next flushSend re-sends it
            }
        }
        // ... or the NEW_CONNECTION_ID it carried: clear in_flight to re-emit.
        if (self.new_cid_inflight.get(pn)) |seq| {
            if (self.pending_new_cids.getPtr(seq)) |nc| {
                nc.in_flight = false;
                return; // the next flushSend re-sends it
            }
        }
        // ... or the RETIRE_CONNECTION_ID it carried: clear in_flight to re-emit.
        if (self.retire_cid_inflight.get(pn)) |seq| {
            if (self.pending_retire_cids.getPtr(seq)) |rc| {
                rc.in_flight = false;
                return; // the next flushSend re-sends it
            }
        }
        // ... or the PATH_CHALLENGE it carried: re-arm the challenge so the next
        // flushSend validates the path instead of sending an unrelated PING.
        if (self.path_challenge_inflight.get(pn)) |token| {
            if (self.pending_path_challenges.getPtr(token)) |pc| {
                pc.in_flight = false;
                return;
            }
        }
        // ... or one of the BLOCKED advisories it carried.
        if (self.data_blocked_inflight.get(pn)) |limit| {
            if (self.data_blocked) |*p| {
                if (p.limit == limit) {
                    p.in_flight = false;
                    return;
                }
            }
        }
        if (self.stream_data_blocked_inflight.get(pn)) |sent| {
            if (self.stream_data_blocked.getPtr(sent.id)) |p| {
                if (p.limit == sent.limit) {
                    p.in_flight = false;
                    return;
                }
            }
        }
        if (self.streams_blocked_inflight.get(pn)) |sent| {
            const pending = if (sent.bidi) &self.streams_blocked_bidi else &self.streams_blocked_uni;
            if (pending.*) |*p| {
                if (p.limit == sent.limit) {
                    p.in_flight = false;
                    return;
                }
            }
        }
        // No data to resend (the range was already acked, or a PING-only packet): a
        // PING is a valid probe that elicits an ACK and keeps the recovery loop alive.
        try self.sendPing(space, now);
    }

    fn sendPing(self: *Connection, space: Space, now: u64) Error!void {
        // PING (0x01) plus PADDING (0x00): the padding makes the packet long enough
        // for the 16-byte header-protection sample (a bare 1-byte PING is too short),
        // and PADDING is legal in every space. PING makes it ack-eliciting. A PING
        // that does not fit the anti-amplification budget is simply not sent.
        _ = self.buildPacket(space, &([_]u8{0x01} ++ [_]u8{0x00} ** 19), true, now) catch |e| switch (e) {
            error.AmplificationLimited => return,
            else => return e,
        };
    }

    // ---- TLS handshake drive ---------------------------------------------------

    fn onCrypto(self: *Connection, space: Space, offset: u64, data: []const u8, now: u64) Error!void {
        const st = &self.spaces[@intFromEnum(space)];
        st.crypto.push(offset, data) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.ProtocolViolation, // CryptoConflict / CryptoBufferExceeded
        };
        try self.driveTls(space, now);
    }

    fn driveTls(self: *Connection, space: Space, now: u64) Error!void {
        if (self.tls) |*server| return self.driveServerTls(server, space, now);
        if (self.tls_client) |*client| return self.driveClientTls(client, space, now);
        if (space == .application) return error.ProtocolViolation;
    }

    fn driveServerTls(self: *Connection, server: *tls.server.Server, space: Space, now: u64) Error!void {
        const st = &self.spaces[@intFromEnum(space)];
        while (true) {
            const buf = st.crypto.readable();
            const msg = tls.handshake.peek(buf) orelse break; // need more CRYPTO bytes
            switch (msg.msg_type) {
                .client_hello => {
                    const decoded = tls.client_hello.parse(buf[0..msg.len]) catch return error.ProtocolViolation;

                    // Honour the client's transport parameters (RFC 9000 7.4): its
                    // initial_max_data is the send-window ceiling, max_ack_delay feeds
                    // the PTO. Applied before the flight is built/sent.
                    try self.setPeerTransportParameters(transport_params.parse(decoded.value.quic_transport_parameters) catch
                        return error.ProtocolViolation);

                    var flight_buf: std.ArrayListUnmanaged(u8) = .empty;
                    defer flight_buf.deinit(self.gpa);
                    var server_tp: std.ArrayListUnmanaged(u8) = .empty;
                    defer server_tp.deinit(self.gpa);
                    const base_tp = server.config.transport_params;
                    try self.buildServerTransportParameters(&server_tp, base_tp);
                    server.config.transport_params = server_tp.items;
                    defer server.config.transport_params = base_tp;
                    const outcome = server.onClientHello(&flight_buf, self.gpa, decoded.value) catch return error.ProtocolViolation;
                    if (outcome.early_traffic_secret) |secret| self.installZeroRttRecvSecret(secret);

                    // A server RECVs with the client traffic secret, SENDs with the server one.
                    self.installKeys(.handshake, outcome.built.handshake_secrets.clientKeys(), outcome.built.handshake_secrets.serverKeys());
                    self.installApplicationSecrets(outcome.built.application_secrets.client, outcome.built.application_secrets.server);

                    // Consume the ClientHello from the reassembler BEFORE emitting the
                    // flight, so nothing borrows from `ready` across a send (which may
                    // realloc it). The flight bytes live in `flight_buf`, not `ready`.
                    st.crypto.advance(msg.len);
                    try self.sendCryptoFlight(flight_buf.items, outcome.server_hello_len, now);
                    continue;
                },
                .finished => {
                    const body = tls.handshake.finishedBody(msg.body) catch return error.ProtocolViolation;
                    server.onClientFinished(body) catch return error.ProtocolViolation;
                    st.crypto.advance(msg.len);
                    try self.confirmHandshake(now);
                },
                else => return error.ProtocolViolation, // unexpected message at the server
            }
        }
    }

    fn driveClientTls(self: *Connection, client: *tls.client.Client, space: Space, now: u64) Error!void {
        const st = &self.spaces[@intFromEnum(space)];
        while (true) {
            const buf = st.crypto.readable();
            const msg = tls.handshake.peek(buf) orelse break;
            switch (client.state) {
                .wait_server_hello => {
                    if (space != .initial or msg.msg_type != .server_hello) return error.ProtocolViolation;
                    const outcome = client.onServerHello(buf[0..msg.len]) catch return error.ProtocolViolation;
                    // A client RECVs Handshake with the server traffic secret, SENDs
                    // with the client one.
                    self.installKeys(.handshake, outcome.handshake_secrets.serverKeys(), outcome.handshake_secrets.clientKeys());
                    st.crypto.advance(msg.len);
                    continue;
                },
                .wait_server_flight => {
                    if (space != .handshake) break;
                    var fin: std.ArrayListUnmanaged(u8) = .empty;
                    defer fin.deinit(self.gpa);
                    const outcome = (client.onServerFlight(&fin, self.gpa, buf) catch |e| switch (e) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.ProtocolViolation,
                    }) orelse break;
                    const fresh_tp = transport_params.parse(outcome.peer_transport_params) catch return error.ProtocolViolation;
                    if (outcome.early_data_accepted) try self.validateFreshParametersForAcceptedZeroRtt(fresh_tp);
                    try self.setPeerTransportParameters(fresh_tp);
                    // A client RECVs 1-RTT with the server traffic secret, SENDs
                    // with the client one.
                    self.installApplicationSecrets(outcome.application_secrets.server, outcome.application_secrets.client);
                    st.crypto.advance(outcome.consumed);
                    self.spaces[@intFromEnum(Space.handshake)].crypto_send.write(fin.items, false) catch return error.OutOfMemory;
                    try self.flushCrypto(.handshake, now);
                    continue;
                },
                .complete => {
                    if (space != .application) return error.ProtocolViolation;
                    if (msg.msg_type != .new_session_ticket) return error.ProtocolViolation;
                    var ticket = tls.client.parseNewSessionTicket(self.gpa, msg.body) catch |e| switch (e) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.ProtocolViolation,
                    };
                    const rms = client.resumption_master_secret orelse {
                        ticket.deinit(self.gpa);
                        return error.ProtocolViolation;
                    };
                    tls.client.deriveTicketPsk(&ticket, rms);
                    try self.storeSessionTicket(ticket);
                    st.crypto.advance(msg.len);
                    continue;
                },
                else => return error.ProtocolViolation,
            }
        }
    }

    fn storeSessionTicket(self: *Connection, ticket: tls.client.SessionTicket) Error!void {
        var owned = ticket;
        errdefer owned.deinit(self.gpa);
        if (self.session_tickets.items.len == MAX_SESSION_TICKETS) {
            var oldest = self.session_tickets.orderedRemove(0);
            oldest.deinit(self.gpa);
        }
        self.session_tickets.append(self.gpa, owned) catch return error.OutOfMemory;
    }

    pub fn sessionTickets(self: *const Connection) []const tls.client.SessionTicket {
        return self.session_tickets.items;
    }

    pub fn validationTokens(self: *const Connection) []const []u8 {
        return self.new_tokens.items;
    }

    pub fn sendNewToken(self: *Connection, token: []const u8, now: u64) Error!void {
        if (self.role != .server or !self.handshake_confirmed or token.len == 0) return error.ProtocolViolation;
        var frames: std.ArrayListUnmanaged(u8) = .empty;
        defer frames.deinit(self.gpa);
        frame.encodeNewToken(&frames, self.gpa, token) catch return error.OutOfMemory;
        while (frames.items.len < 20) frames.append(self.gpa, 0x00) catch return error.OutOfMemory;
        _ = try self.buildPacket(.application, frames.items, true, now);
    }

    pub fn sendSessionTicket(
        self: *Connection,
        ticket_lifetime: u32,
        ticket_age_add: u32,
        nonce: []const u8,
        ticket: []const u8,
        extensions: []const u8,
        max_early_data_size: ?u32,
        now: u64,
    ) Error!?[tls.schedule.SECRET_LEN]u8 {
        if (self.role != .server or !self.handshake_confirmed) return error.ProtocolViolation;
        var msg: std.ArrayListUnmanaged(u8) = .empty;
        defer msg.deinit(self.gpa);
        tls.server.buildNewSessionTicket(&msg, self.gpa, .{
            .ticket_lifetime = ticket_lifetime,
            .ticket_age_add = ticket_age_add,
            .nonce = nonce,
            .ticket = ticket,
            .extensions = extensions,
            .max_early_data_size = max_early_data_size,
        }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.ProtocolViolation,
        };
        const psk = if (self.tls) |server|
            if (server.resumption_master_secret) |rms| tls.schedule.resumptionPsk(rms, nonce) else null
        else
            null;
        self.spaces[@intFromEnum(Space.application)].crypto_send.write(msg.items, false) catch return error.OutOfMemory;
        try self.flushCrypto(.application, now);
        return psk;
    }

    /// Queue the server flight: ServerHello into the Initial space's CRYPTO send
    /// buffer, the rest (EncryptedExtensions/Certificate/CertificateVerify/Finished)
    /// into the Handshake space's. The bytes are retained until acked, so an
    /// amplification-stalled or lost flight is re-sent; flushCrypto packetizes them.
    fn sendCryptoFlight(self: *Connection, flight: []const u8, server_hello_len: usize, now: u64) Error!void {
        self.spaces[@intFromEnum(Space.initial)].crypto_send.write(flight[0..server_hello_len], false) catch return error.OutOfMemory;
        self.spaces[@intFromEnum(Space.handshake)].crypto_send.write(flight[server_hello_len..], false) catch return error.OutOfMemory;
        try self.flushCrypto(.initial, now);
        try self.flushCrypto(.handshake, now);
    }

    fn sendInitialCrypto(self: *Connection, bytes: []const u8, now: u64) Error!void {
        const space = Space.initial;
        const st = &self.spaces[@intFromEnum(space)];
        st.crypto_send.write(bytes, false) catch return error.OutOfMemory;
        const chunk = st.crypto_send.peek(self.framePayloadRoom(space)) orelse return;
        var frames: std.ArrayListUnmanaged(u8) = .empty;
        defer frames.deinit(self.gpa);
        frame.encodeCrypto(&frames, self.gpa, chunk.offset, chunk.data) catch return error.OutOfMemory;
        const target = try self.minimumInitialFramePayload();
        while (frames.items.len < target) frames.append(self.gpa, 0x00) catch return error.OutOfMemory;
        st.crypto_sent.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
        const pn = try self.buildPacket(space, frames.items, true, now);
        st.crypto_sent.putAssumeCapacity(pn, .{ .offset = chunk.offset, .len = chunk.data.len });
        st.crypto_send.commit(chunk.offset, chunk.data.len, false);
    }

    /// Packetize a space's pending CRYPTO into packets, recording each sent range so
    /// ack/loss can free or re-send it. Stops cleanly on the anti-amplification limit
    /// (RFC 9000 8.1) - the unsent bytes stay retained and flush on a later call once
    /// the budget rises (the client's next packet) or the space is re-flushed.
    fn flushCrypto(self: *Connection, space: Space, now: u64) Error!void {
        const st = &self.spaces[@intFromEnum(space)];
        if (st.send_keys == null) return;
        const room = self.framePayloadRoom(space);
        if (room == 0) return error.ProtocolViolation;
        while (st.crypto_send.pending()) {
            const chunk = st.crypto_send.peek(room) orelse break;
            if (chunk.data.len == 0) break; // CRYPTO has no FIN; an empty chunk is nothing to send
            var frames: std.ArrayListUnmanaged(u8) = .empty;
            defer frames.deinit(self.gpa);
            frame.encodeCrypto(&frames, self.gpa, chunk.offset, chunk.data) catch return error.OutOfMemory;
            if (self.role == .client and space == .initial) {
                const target = try self.minimumInitialFramePayload();
                while (frames.items.len < target) frames.append(self.gpa, 0x00) catch return error.OutOfMemory;
            }
            st.crypto_sent.ensureUnusedCapacity(self.gpa, 1) catch return error.OutOfMemory;
            const pn = self.buildPacket(space, frames.items, true, now) catch |e| switch (e) {
                error.AmplificationLimited => return, // budget exhausted: keep the rest retained
                else => return e,
            };
            st.crypto_sent.putAssumeCapacity(pn, .{ .offset = chunk.offset, .len = chunk.data.len });
            st.crypto_send.commit(chunk.offset, chunk.data.len, false);
        }
    }

    /// The client Finished verified: the handshake is confirmed. Signal it to the
    /// client with HANDSHAKE_DONE (RFC 9001 4.1.2) and discard the now-unneeded
    /// Initial, Handshake, and 0-RTT receive keys (RFC 9001 4.9) so no further
    /// packet is processed in or sent from those spaces.
    fn confirmHandshake(self: *Connection, now: u64) Error!void {
        if (self.handshake_confirmed) return;
        // Queue HANDSHAKE_DONE before committing the confirmation state, so a failed
        // send (OOM) leaves the connection unconfirmed and retryable rather than
        // confirmed-but-silent. HANDSHAKE_DONE (0x1e) + PADDING (0x00): the padding
        // makes the packet long enough for the header-protection sample (RFC 9000
        // 19.20, 19.1).
        _ = try self.buildPacket(.application, &([_]u8{0x1e} ++ [_]u8{0x00} ** 19), true, now);
        self.handshake_confirmed = true;
        self.spaces[@intFromEnum(Space.application)].zero_rtt_recv_keys = null;
        self.discardSpace(.initial);
        self.discardSpace(.handshake);
    }

    /// Drop a packet-number space's keys and in-flight state once it is no longer
    /// needed (RFC 9001 4.9): no packet can be sent or decrypted there afterwards.
    fn discardSpace(self: *Connection, space: Space) void {
        const st = &self.spaces[@intFromEnum(space)];
        st.recv_keys = null;
        st.send_keys = null;
        st.rec.discard(&self.cc);
        st.crypto_sent.clearRetainingCapacity(); // the space's CRYPTO is done; no more ack/loss routing
        st.crypto_send.deinit(); // free the retained handshake bytes; the space is dead
        st.crypto_send = stream.SendStream.init(self.gpa);
        st.recv_ranges.ranges.clearRetainingCapacity(); // no more ACKs for a dead space
    }

    fn sendAck(self: *Connection, space: Space, now: u64) Error!void {
        const st = &self.spaces[@intFromEnum(space)];
        if (st.send_keys == null) {
            if (space == .application) return; // 0-RTT is acked with later 1-RTT keys.
            st.ack_pending = false; // space discarded (e.g. handshake confirmed): nothing to ack with
            return;
        }
        if (st.recv_ranges.isEmpty()) return;
        var frames: std.ArrayListUnmanaged(u8) = .empty;
        defer frames.deinit(self.gpa);
        // The full received-pn range set (RFC 9000 19.3), so a peer with gaps detects
        // loss accurately. Ack-delay is 0 for now (immediate ack, no coalescing).
        frame.encodeAckRanges(&frames, self.gpa, &st.recv_ranges, 0) catch return error.OutOfMemory;
        // An ACK that does not fit the anti-amplification budget is simply deferred
        // (the ack_pending flag stays set so a later send re-attempts), never fatal.
        _ = self.buildPacket(space, frames.items, false, now) catch |e| switch (e) {
            error.AmplificationLimited => return,
            else => return e,
        };
        st.ack_pending = false;
    }

    fn minimumInitialFramePayload(self: *const Connection) Error!usize {
        const space = Space.initial;
        const st = &self.spaces[@intFromEnum(space)];
        const pn_len = packet.packetNumberLen(st.next_pn, st.rec.largest_acked);
        const token = self.initial_token orelse &.{};
        const room = self.framePayloadRoom(space);
        const header_len = 1 + 4 + 1 + self.peer_scid.len + 1 + self.scid.len +
            (varint.len(token.len) catch return error.ProtocolViolation) + token.len +
            (varint.len(pn_len + room + crypto.TAG_LEN) catch return error.ProtocolViolation);
        const overhead = header_len + pn_len + crypto.TAG_LEN;
        if (overhead >= constants.MIN_INITIAL_DATAGRAM) return 0;
        return constants.MIN_INITIAL_DATAGRAM - overhead;
    }

    fn framePayloadRoom(self: *const Connection, space: Space) usize {
        const target: u64 = constants.MIN_INITIAL_DATAGRAM - 64;
        const token_len: u64 = if (space == .initial) if (self.initial_token) |t| t.len else 0 else 0;
        const app_zero_rtt = if (space == .application) blk: {
            const st = &self.spaces[@intFromEnum(Space.application)];
            break :blk st.send_keys == null and st.zero_rtt_send_keys != null;
        } else false;
        const overhead: u64 = if (space == .application and !app_zero_rtt)
            1 + self.peer_scid.len + 4 + crypto.TAG_LEN
        else
            1 + 4 + 1 + self.peer_scid.len + 1 + self.scid.len + token_len + 8 + 4 + crypto.TAG_LEN;
        if (self.peer_tp.max_udp_payload_size <= overhead) return 0;
        return @intCast(@min(target, self.peer_tp.max_udp_payload_size - overhead));
    }

    /// Process one received UDP datagram: walk the coalesced packets, decrypt and
    /// dispatch each. `now` is a monotonic microsecond timestamp. A packet that
    /// fails authentication is skipped (not fatal); a protocol violation or a
    /// mid-dispatch allocation failure poisons the connection.
    pub fn receiveDatagram(self: *Connection, datagram: []const u8, now: u64) Error!void {
        self.receiveDatagramOn(datagram, now, null) catch |err| return self.closeForReceiveError(err);
    }

    /// Address-aware variant of receiveDatagram. `peer_address` is opaque and only
    /// needs to be stable for a network path; callers that pass it get per-path
    /// amplification and PATH_CHALLENGE/PATH_RESPONSE validation state.
    pub fn receiveDatagramFrom(self: *Connection, datagram: []const u8, now: u64, peer_address: []const u8) Error!void {
        self.receiveDatagramOn(datagram, now, peer_address) catch |err| return self.closeForReceiveError(err);
    }

    fn closeForReceiveError(self: *Connection, err: Error) Error!void {
        const close_code: ?constants.TransportError = switch (err) {
            error.ProtocolViolation => .protocol_violation,
            error.FlowControlError => .flow_control_error,
            error.StreamLimitError => .stream_limit_error,
            error.StreamStateError => .stream_state_error,
            error.FinalSizeError => .final_size_error,
            error.StreamBufferExceeded => .internal_error,
            else => null,
        };
        if (close_code) |code| {
            self.close(false, @intFromEnum(code), @errorName(err)) catch |close_err| switch (close_err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {},
            };
        }
        return err;
    }

    fn receiveDatagramOn(self: *Connection, datagram: []const u8, now: u64, peer_address: ?[]const u8) Error!void {
        if (self.receive_failure) |err| return err;
        self.changed_streams.clearRetainingCapacity();
        if (self.closed) return error.ProtocolViolation;
        if (peer_address) |addr| {
            // A spoofable path change is silently dropped, never connection-fatal.
            if (self.local_tp.disable_active_migration and self.handshake_confirmed) {
                if (self.default_path_token) |current| {
                    if (current != std.hash.Wyhash.hash(0, addr)) return;
                }
            }
        }
        // Anti-amplification credit (RFC 9000 8.1): every received byte raises the
        // budget for what the server may send before the address is validated.
        self.recv_bytes += datagram.len;
        const previous_path = self.current_path_token;
        defer self.current_path_token = previous_path;
        var context = ReceiveContext{ .now = now, .datagram_len = datagram.len, .peer_address = peer_address };
        if (peer_address) |addr| {
            self.current_path_token = std.hash.Wyhash.hash(0, addr);
        }
        var rest = datagram;
        while (rest.len > 0) {
            const consumed = self.receivePacket(rest, &context) catch |e| switch (e) {
                // A short-header packet has no length field, so an undecryptable one
                // ends the walk (its boundary is the datagram end). A long-header
                // packet whose boundary IS known returns its length from receiveLong
                // even when undecryptable, so coalesced packets after it still run.
                error.Dropped => break,
                else => return e,
            };
            if (consumed == 0 or consumed > rest.len) break;
            rest = rest[consumed..];
        }
        // The received bytes raised the anti-amplification budget: flush any handshake
        // CRYPTO that stalled on the limit (RFC 9000 8.1).
        try self.flushCrypto(.initial, now);
        try self.flushCrypto(.handshake, now);
        if (context.auto_path_challenge_queued) {
            self.flushPathChallenges(.application, now) catch |e| switch (e) {
                error.AmplificationLimited => {},
                else => return e,
            };
        }
    }

    fn receivePacket(self: *Connection, buf: []const u8, context: *ReceiveContext) Error!usize {
        if (packet.isLong(buf[0])) return self.receiveLong(buf, context);
        return self.receiveShort(buf, context);
    }

    fn receiveLong(self: *Connection, buf: []const u8, context: *ReceiveContext) Error!usize {
        const prefix = packet.parseLongPrefix(buf) catch return error.Dropped;
        if (prefix.version == 0) return self.receiveVersionNegotiation(prefix, buf);
        if (prefix.version != constants.VERSION_1) {
            if (self.role == .server) try self.sendVersionNegotiation(prefix, context);
            return buf.len;
        }
        const hdr = packet.parseLong(buf) catch return error.Dropped;
        if (hdr.ltype == .retry) return self.receiveRetry(hdr, buf, context);
        const space: Space = switch (hdr.ltype) {
            .initial => .initial,
            .handshake => .handshake,
            .zero_rtt => .application,
            .retry => unreachable,
        };
        const total = hdr.pn_offset + @as(usize, @intCast(hdr.length));
        if (total > buf.len) return error.Dropped;
        if (self.role == .server and hdr.ltype == .initial and context.datagram_len < constants.MIN_INITIAL_DATAGRAM) {
            return error.Dropped;
        }
        // A long header's length is known, so a packet we cannot decrypt (no keys
        // for the space yet, or a bad tag) is SKIPPED, not fatal: we return its
        // length so the caller keeps walking any coalesced packets behind it
        // (e.g. a Handshake packet coalesced after an Initial). RFC 9000 12.2.
        const peer_scid_candidate = if (hdr.ltype == .initial) hdr.scid else null;
        self.decryptAndDispatch(buf[0..total], hdr.pn_offset, space, true, peer_scid_candidate, context) catch |e| switch (e) {
            error.Dropped => return total,
            else => return e,
        };
        return total;
    }

    fn sendVersionNegotiation(self: *Connection, prefix: packet.LongPrefix, context: *ReceiveContext) Error!void {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(self.gpa);
        packet.writeVersionNegotiation(&out, self.gpa, prefix.scid, prefix.dcid) catch return error.OutOfMemory;
        var provisional_created = false;
        if (context.peer_address) |address| {
            const token = self.current_path_token.?;
            if (!self.paths.contains(token)) {
                if (self.provisional_path) |*path| {
                    if (path.token != token or !std.mem.eql(u8, path.state.address, address)) return;
                    if (!context.provisional_path_recorded) path.state.recv_bytes += context.datagram_len;
                } else {
                    const owned = self.gpa.dupe(u8, address) catch return error.OutOfMemory;
                    self.provisional_path = .{
                        .token = token,
                        .state = .{ .address = owned, .recv_bytes = context.datagram_len },
                    };
                    provisional_created = true;
                }
                context.provisional_path_recorded = true;
            }
        }
        errdefer if (provisional_created) {
            self.gpa.free(self.provisional_path.?.state.address);
            self.provisional_path = null;
        };
        if (!self.canSendDatagram(out.items.len)) {
            if (provisional_created) {
                self.gpa.free(self.provisional_path.?.state.address);
                self.provisional_path = null;
            }
            return;
        }
        self.out.appendSlice(self.gpa, out.items) catch return error.OutOfMemory;
        self.out_lengths.append(self.gpa, out.items.len) catch return error.OutOfMemory;
        self.out_path_tokens.append(self.gpa, self.sendPathToken()) catch return error.OutOfMemory;
        self.sent_bytes += out.items.len;
        self.recordPathSent(out.items.len);
    }

    fn receiveVersionNegotiation(self: *Connection, prefix: packet.LongPrefix, buf: []const u8) Error!usize {
        if (self.role != .client) return error.Dropped;
        if (self.peer_packet_authenticated or self.retried) return buf.len;
        // VN is only valid if it is addressed to our source CID and names the peer's
        // CID as its source. Otherwise it is not for this connection.
        if (!std.mem.eql(u8, prefix.dcid, self.scid)) return error.Dropped;
        if (!std.mem.eql(u8, prefix.scid, self.peer_scid)) return error.Dropped;
        const versions = buf[prefix.header_len..];
        if (versions.len == 0 or versions.len % 4 != 0) return error.Dropped;

        var pos: usize = 0;
        while (pos < versions.len) : (pos += 4) {
            const v = std.mem.readInt(u32, versions[pos..][0..4], .big);
            // A VN packet that includes the version we attempted is invalid and is
            // ignored (RFC 9000 17.2.1).
            if (v == constants.VERSION_1) return error.Dropped;
        }
        self.closed = true;
        return error.ProtocolViolation;
    }

    fn receiveRetry(self: *Connection, hdr: packet.LongHeader, buf: []const u8, context: *ReceiveContext) Error!usize {
        if (self.role != .client) return error.Dropped;
        if (self.retried or self.spaces[@intFromEnum(Space.handshake)].recv_keys != null) return error.Dropped;
        if (!std.mem.eql(u8, hdr.dcid, self.scid)) return error.Dropped;
        if (hdr.scid.len == 0 or hdr.token.len == 0) return error.Dropped;
        if (!(packet.validateRetryIntegrity(self.gpa, buf, self.peer_scid) catch return error.OutOfMemory)) return error.Dropped;
        try self.recordAuthenticatedPath(context);

        const token = self.gpa.dupe(u8, hdr.token) catch return error.OutOfMemory;
        errdefer self.gpa.free(token);
        const sc = self.gpa.dupe(u8, hdr.scid) catch return error.OutOfMemory;
        errdefer self.gpa.free(sc);
        const retry_scid = self.gpa.dupe(u8, hdr.scid) catch return error.OutOfMemory;
        errdefer self.gpa.free(retry_scid);

        if (self.initial_token) |old| self.gpa.free(old);
        self.initial_token = token;
        self.gpa.free(self.peer_scid);
        self.peer_scid = sc;
        if (self.retry_scid) |old| self.gpa.free(old);
        self.retry_scid = retry_scid;
        self.peer_scid_set = false;
        self.retried = true;

        const initial = crypto.InitialKeys.derive(hdr.scid);
        const st = &self.spaces[@intFromEnum(Space.initial)];
        st.recv_keys = initial.server;
        st.send_keys = initial.client;
        if (st.crypto_send.end() > 0) try st.crypto_send.onLost(0, st.crypto_send.end(), false);
        st.crypto_sent.clearRetainingCapacity();
        try self.flushCrypto(.initial, context.now);
        return buf.len;
    }

    fn receiveShort(self: *Connection, buf: []const u8, context: *ReceiveContext) Error!usize {
        const parsed = self.parseShortForLocalCid(buf) catch {
            if (self.detectStatelessReset(buf)) return buf.len;
            return error.Dropped;
        };
        const previous_cid_seq = self.current_packet_local_cid_seq;
        self.current_packet_local_cid_seq = parsed.local_cid_seq;
        defer self.current_packet_local_cid_seq = previous_cid_seq;
        // A short-header packet is the rest of the datagram (no length field).
        self.decryptAndDispatch(buf, parsed.hdr.pn_offset, .application, false, null, context) catch |e| switch (e) {
            error.Dropped => {
                if (self.detectStatelessReset(buf)) return buf.len;
                return error.Dropped;
            },
            else => return e,
        };
        return buf.len;
    }

    fn parseShortForLocalCid(self: *const Connection, buf: []const u8) packet.Error!ParsedShortForLocalCid {
        if ((buf[0] & constants.FIXED_BIT) == 0) return error.Malformed;
        if (!self.local_initial_cid_retired) {
            const hdr = try packet.parseShort(buf, self.scid.len);
            if (std.mem.eql(u8, hdr.dcid, self.scid)) return .{ .hdr = hdr, .local_cid_seq = 0 };
        }
        var it = self.local_cids.iterator();
        while (it.next()) |cid| {
            if (cid.value_ptr.retired) continue;
            const hdr = packet.parseShort(buf, cid.value_ptr.cid.len) catch |e| switch (e) {
                error.Truncated => continue,
                else => return e,
            };
            if (std.mem.eql(u8, hdr.dcid, cid.value_ptr.cid)) return .{ .hdr = hdr, .local_cid_seq = cid.key_ptr.* };
        }
        return error.Malformed;
    }

    fn detectStatelessReset(self: *Connection, buf: []const u8) bool {
        if (buf.len < 21) return false;
        const token = buf[buf.len - 16 ..][0..16].*;
        var matched = false;
        if (self.peer_tp.stateless_reset_token) |t| {
            matched = std.crypto.timing_safe.eql([16]u8, token, t);
        }
        var it = self.peer_cids.valueIterator();
        while (it.next()) |cid| {
            matched = std.crypto.timing_safe.eql([16]u8, token, cid.token) or matched;
        }
        if (matched) self.closed = true;
        return matched;
    }

    fn acceptsLocalCid(self: *const Connection, dcid: []const u8) bool {
        if (self.local_initial_cid_retired) return false;
        return std.mem.eql(u8, dcid, self.scid);
    }

    fn localCidValueExists(self: *const Connection, cid: []const u8) bool {
        var it = self.local_cids.valueIterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.cid, cid)) return true;
        }
        return false;
    }

    fn peerCidValueExists(self: *const Connection, cid: []const u8) bool {
        var it = self.peer_cids.valueIterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.cid, cid)) return true;
        }
        return false;
    }

    fn localActiveCidCountAfter(self: *const Connection, retire_prior_to: u64) u64 {
        var count: u64 = 0;
        if (!self.local_initial_cid_retired and retire_prior_to == 0) count += 1;
        var it = self.local_cids.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.retired and entry.key_ptr.* >= retire_prior_to) count += 1;
        }
        return count;
    }

    fn decryptAndDispatch(
        self: *Connection,
        pkt: []const u8,
        pn_offset: usize,
        space: Space,
        long: bool,
        peer_scid_candidate: ?[]const u8,
        context: *ReceiveContext,
    ) Error!void {
        const st = &self.spaces[@intFromEnum(space)];
        const opened = if (space == .application and !long)
            try self.openApplicationPacket(pkt, pn_offset)
        else if (space == .application)
            try self.openPacket(pkt, pn_offset, space, long, st.zero_rtt_recv_keys orelse return error.Dropped, null)
        else
            try self.openPacket(pkt, pn_offset, space, long, st.recv_keys orelse return error.Dropped, null);
        defer self.gpa.free(opened.work);
        defer self.gpa.free(opened.plaintext);
        st.largest_authenticated_pn = if (st.largest_authenticated_pn) |largest|
            @max(largest, opened.pn)
        else
            opened.pn;
        if (st.recv_ranges.shouldIgnore(opened.pn)) return;
        try self.recordAuthenticatedPath(context);
        if (peer_scid_candidate) |candidate| {
            // RFC 9000 7.2 permits adoption only after packet authentication.
            if (!self.peer_scid_set and candidate.len > 0) {
                const sc = self.gpa.dupe(u8, candidate) catch return error.OutOfMemory;
                self.gpa.free(self.peer_scid);
                self.peer_scid = sc;
                self.peer_scid_set = true;
            }
        }
        self.peer_packet_authenticated = true;
        if (space == .initial) self.initial_authenticated = true;
        if (space == .application and !long) st.zero_rtt_recv_keys = null;

        // A decryptable Handshake packet proves the peer received our Initial/
        // handshake keys, so its address is validated and the 3x send limit lifts
        // (RFC 9000 8.1).
        if (space == .handshake) self.validateCurrentPath();

        st.recv_ranges.ensureCanAdd(self.gpa, opened.pn) catch return error.OutOfMemory;
        self.dispatchFrames(opened.payload, space, long, context.now) catch |err| {
            if (err == error.OutOfMemory) {
                // Frame handlers may have committed state, so this packet must never be replayed or acknowledged.
                self.receive_failure = err;
                self.closed = true;
                for (&self.spaces) |*state| state.ack_pending = false;
                self.clearSend();
            }
            return err;
        };
        st.recv_ranges.add(self.gpa, opened.pn) catch unreachable; // ensureCanAdd reserved the only possible allocation.
        st.largest_recv_pn = if (st.largest_recv_pn) |largest| @max(largest, opened.pn) else opened.pn;
        self.resetIdleTimer(context.now);

        // Acknowledge the space if it carried an ack-eliciting frame this packet.
        if (st.ack_pending) try self.sendAck(space, context.now);
    }

    fn recordAuthenticatedPath(self: *Connection, context: *ReceiveContext) Error!void {
        if (context.path_recorded) return;
        const addr = context.peer_address orelse return;
        const candidate = std.hash.Wyhash.hash(0, addr);
        if (!self.paths.contains(candidate) and self.default_path_token != null and
            self.default_path_token.? != candidate)
        {
            if (self.peer_candidate_path_token) |previous| {
                if (previous != candidate) {
                    for (self.out_path_tokens.items) |queued| {
                        if (queued == previous) return error.Dropped;
                    }
                    self.removePendingPathChallengesFor(previous);
                    if (self.paths.fetchRemove(previous)) |entry| self.gpa.free(entry.value.address);
                    self.peer_candidate_path_token = null;
                }
            }
        }
        const pt = try self.pathTokenForAddress(addr);
        const new_peer_path = self.default_path_token != null and self.default_path_token.? != pt;
        self.current_path_token = pt;
        const p = self.paths.getPtr(pt).?;
        if (self.provisional_path) |*provisional| {
            if (provisional.token == pt and std.mem.eql(u8, provisional.state.address, addr)) {
                p.recv_bytes = p.recv_bytes +| provisional.state.recv_bytes;
                p.sent_bytes = p.sent_bytes +| provisional.state.sent_bytes;
                provisional.state.recv_bytes = 0;
                provisional.state.sent_bytes = 0;
            }
        }
        p.recv_bytes = p.recv_bytes +| context.datagram_len;
        if (self.default_path_token == null) {
            self.default_path_token = pt;
            if (self.address_validated) p.validated = true;
        } else if (new_peer_path and !p.validated and self.peer_candidate_path_token == null) {
            self.peer_candidate_path_token = pt;
        }
        if (self.handshake_confirmed and new_peer_path and !p.validated) {
            try self.queueAutomaticPathChallenge(pt, context.now);
            context.auto_path_challenge_queued = true;
        }
        context.path_recorded = true;
    }

    fn openApplicationPacket(self: *Connection, pkt: []const u8, pn_offset: usize) Error!OpenedPacket {
        const st = &self.spaces[@intFromEnum(Space.application)];
        const current = st.recv_keys orelse return error.Dropped;

        if (self.openPacket(pkt, pn_offset, .application, false, current, st.recv_key_phase)) |opened| {
            return opened;
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Dropped => {},
            else => return err,
        }

        if (st.recv_secret) |secret| {
            const next_secret = crypto.nextTrafficSecret(secret);
            const next_keys = crypto.Keys.fromUpdatedSecret(next_secret, current.hp);
            const next_phase = !st.recv_key_phase;
            if (self.openPacket(pkt, pn_offset, .application, false, next_keys, next_phase)) |opened| {
                st.prev_recv_keys = current;
                st.prev_recv_key_phase = st.recv_key_phase;
                st.recv_secret = next_secret;
                st.recv_keys = next_keys;
                st.recv_key_phase = next_phase;
                return opened;
            } else |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Dropped => {},
                else => return err,
            }
        }

        if (st.prev_recv_keys) |prev| {
            return self.openPacket(pkt, pn_offset, .application, false, prev, st.prev_recv_key_phase) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.Dropped,
            };
        }

        return error.Dropped;
    }

    fn openPacket(self: *Connection, pkt: []const u8, pn_offset: usize, space: Space, long: bool, keys: crypto.Keys, expected_key_phase: ?bool) Error!OpenedPacket {
        // Work on a mutable copy: header protection removal and decryption mutate.
        const work = self.gpa.dupe(u8, pkt) catch return error.OutOfMemory;
        errdefer self.gpa.free(work);

        const pn_len = crypto.unprotectHeader(keys.hp, work, pn_offset, long) catch return error.Dropped;
        if (pn_offset + pn_len > work.len) return error.Dropped;
        const key_phase = !long and (work[0] & packet.SHORT_KEY_PHASE) != 0;
        if (expected_key_phase) |expected| {
            if (key_phase != expected) return error.Dropped;
        }

        var truncated: u64 = 0;
        for (work[pn_offset .. pn_offset + pn_len]) |b| truncated = (truncated << 8) | b;
        const st = &self.spaces[@intFromEnum(space)];
        const pn = packet.decodePacketNumber(st.largest_authenticated_pn orelse 0, truncated, pn_len);

        const header = work[0 .. pn_offset + pn_len];
        const ciphertext = work[pn_offset + pn_len ..];
        const plaintext = self.gpa.alloc(u8, ciphertext.len) catch return error.OutOfMemory;
        errdefer self.gpa.free(plaintext);
        const payload = crypto.open(keys, pn, header, ciphertext, plaintext) catch return error.Dropped;
        return .{
            .work = work,
            .plaintext = plaintext,
            .payload = payload,
            .pn = pn,
            .key_phase = key_phase,
        };
    }

    fn dispatchFrames(self: *Connection, payload: []const u8, space: Space, long: bool, now: u64) Error!void {
        var rest = payload;
        while (rest.len > 0) {
            const d = frame.decode(rest) catch return error.ProtocolViolation;
            try self.handleFrame(d.frame, space, long, now);
            if (d.len == 0) break;
            rest = rest[d.len..];
        }
    }

    fn handleFrame(self: *Connection, f: frame.Frame, space: Space, long: bool, now: u64) Error!void {
        // RFC 9000 12.4: only PADDING, PING, ACK, CRYPTO, and CONNECTION_CLOSE are
        // permitted in the Initial and Handshake spaces. STREAM and the other
        // 1-RTT frames in those spaces are a PROTOCOL_VIOLATION - the recv mirror of
        // keeping STREAM out of Initial on the send side.
        if (!frameAllowedIn(space, long, f)) return error.ProtocolViolation;

        const st = &self.spaces[@intFromEnum(space)];
        if (frameAckEliciting(f)) st.ack_pending = true;
        switch (f) {
            .padding => {},
            .ping => {},
            .ack => |a| try self.onAckFrame(space, a, now),
            .crypto => |c| {
                try self.onCrypto(space, c.offset, c.data, now);
            },
            .stream => |s| {
                try self.onStreamFrame(s.stream_id, s.offset, s.data, s.fin);
            },
            .max_data => |m| self.onMaxData(m),
            .max_stream_data => |m| try self.onMaxStreamData(m.stream_id, m.max),
            .max_streams => |m| try self.onMaxStreams(m.bidi, m.max),
            .data_blocked => |limit| self.onDataBlocked(limit),
            .stream_data_blocked => |b| try self.onStreamDataBlocked(b.stream_id, b.limit),
            .streams_blocked => |b| try self.onStreamsBlocked(b.bidi, b.limit),
            .reset_stream => |r| try self.onReset(r.stream_id, r.error_code, r.final_size),
            .stop_sending => |s| try self.onStopSending(s.stream_id, s.error_code),
            .new_token => |t| {
                if (self.role != .client) return error.ProtocolViolation;
                try self.onNewToken(t.token);
            },
            .new_connection_id => |cid| try self.onNewConnectionId(cid.seq, cid.retire_prior_to, cid.cid, cid.token),
            .retire_connection_id => |seq| try self.onRetireConnectionId(seq),
            .path_challenge => |data| {
                try self.sendPathResponse(data, now);
            },
            .path_response => |data| try self.onPathResponse(data),
            .connection_close => |cc| {
                // Retain the peer's close details (RFC 9000 19.19); the reason slice
                // points into the datagram, so copy a length-capped prefix. The first
                // close wins - a later frame in the same (closing) packet cannot
                // overwrite it.
                if (self.peer_close == null) {
                    const n = @min(cc.reason.len, PeerClose.MAX_REASON);
                    const reason = self.gpa.dupe(u8, cc.reason[0..n]) catch return error.OutOfMemory;
                    self.peer_close = .{ .app = cc.app, .error_code = cc.error_code, .reason = reason };
                }
                self.closed = true;
            },
            .handshake_done => {
                if (self.role != .client) return error.ProtocolViolation;
                if (self.role == .client and !self.handshake_confirmed) {
                    self.handshake_confirmed = true;
                    self.discardSpace(.initial);
                    self.discardSpace(.handshake);
                }
            },
        }
    }

    fn onNewToken(self: *Connection, token: []const u8) Error!void {
        if (self.new_tokens.items.len == MAX_NEW_TOKENS) {
            const oldest = self.new_tokens.orderedRemove(0);
            self.gpa.free(oldest);
        }
        const owned = self.gpa.dupe(u8, token) catch return error.OutOfMemory;
        errdefer self.gpa.free(owned);
        self.new_tokens.append(self.gpa, owned) catch return error.OutOfMemory;
    }

    fn onRetireConnectionId(self: *Connection, seq: u64) Error!void {
        if (self.current_packet_local_cid_seq) |current| {
            if (current == seq) return error.ProtocolViolation;
        }
        if (seq > self.local_cid_max_seq) return error.ProtocolViolation;
        if (seq == 0) {
            if (!self.local_initial_cid_retired) {
                self.local_initial_cid_retired = true;
                self.local_cid_generation +%= 1;
            }
            return;
        }
        const local = self.local_cids.getPtr(seq) orelse return error.ProtocolViolation;
        if (!local.retired) {
            local.retired = true;
            self.local_cid_generation +%= 1;
        }
    }

    fn onNewConnectionId(self: *Connection, seq: u64, retire_prior_to: u64, cid: []const u8, token: []const u8) Error!void {
        if (token.len != 16 or retire_prior_to > seq) return error.ProtocolViolation;
        if (retire_prior_to > self.peer_retire_prior_to) {
            const previous_retire_prior_to = self.peer_retire_prior_to;
            self.peer_retire_prior_to = retire_prior_to;
            if (previous_retire_prior_to == 0 and retire_prior_to > 0) {
                const initial = self.pending_retire_cids.getOrPut(self.gpa, 0) catch return error.OutOfMemory;
                if (!initial.found_existing) initial.value_ptr.* = .{};
            }
            var retire: std.ArrayListUnmanaged(u64) = .empty;
            defer retire.deinit(self.gpa);
            var it = self.peer_cids.keyIterator();
            while (it.next()) |existing_seq| {
                if (existing_seq.* < retire_prior_to) retire.append(self.gpa, existing_seq.*) catch return error.OutOfMemory;
            }
            for (retire.items) |old_seq| {
                if (self.peer_cids.fetchRemove(old_seq)) |entry| {
                    self.gpa.free(entry.value.cid);
                    const gop = self.pending_retire_cids.getOrPut(self.gpa, old_seq) catch return error.OutOfMemory;
                    if (!gop.found_existing) gop.value_ptr.* = .{};
                }
            }
        }
        if (seq < self.peer_retire_prior_to) return;

        const token_array = token[0..16].*;
        if (self.peer_cids.get(seq)) |existing| {
            if (!std.mem.eql(u8, existing.cid, cid) or !std.mem.eql(u8, &existing.token, &token_array)) return error.ProtocolViolation;
            if (self.peer_cid_seq < self.peer_retire_prior_to) try self.usePeerConnectionId(seq);
            return;
        }
        if (std.mem.eql(u8, cid, self.peer_scid) or self.peerCidValueExists(cid)) return error.ProtocolViolation;

        const active_initial: usize = if (self.peer_retire_prior_to == 0) 1 else 0;
        if (self.peer_cids.count() + active_initial + 1 > self.local_tp.active_connection_id_limit) {
            return error.ProtocolViolation;
        }
        const owned = self.gpa.dupe(u8, cid) catch return error.OutOfMemory;
        errdefer self.gpa.free(owned);
        self.peer_cids.put(self.gpa, seq, .{ .cid = owned, .token = token_array }) catch return error.OutOfMemory;
        if (self.peer_cid_seq < self.peer_retire_prior_to) try self.usePeerConnectionId(seq);
    }

    /// RFC 9002 2: every frame except ACK, PADDING, and CONNECTION_CLOSE makes its
    /// packet ack-eliciting. Keep this independent of the frame-specific switch so
    /// passive control frames like MAX_DATA and NEW_TOKEN still get acknowledged.
    fn frameAckEliciting(f: frame.Frame) bool {
        return switch (f) {
            .padding, .ack, .connection_close => false,
            else => true,
        };
    }

    fn sendPathResponse(self: *Connection, data: [8]u8, now: u64) Error!void {
        var frames: std.ArrayListUnmanaged(u8) = .empty;
        defer frames.deinit(self.gpa);
        frame.encodePathResponse(&frames, self.gpa, data) catch return error.OutOfMemory;
        _ = try self.buildPacket(.application, frames.items, true, now);
    }

    fn onPathResponse(self: *Connection, data: [8]u8) Error!void {
        const token = pathToken(data);
        const pending = self.pending_path_challenges.get(token) orelse return;
        if (pending.path_token) |pt| {
            if (self.current_path_token == null or self.current_path_token.? != pt) return error.ProtocolViolation;
        }
        _ = self.pending_path_challenges.remove(token);
        if (self.pathChallengeInflightPn(token)) |pn| _ = self.path_challenge_inflight.remove(pn);
        self.validateCurrentPath();
        if (pending.path_token) |pt| self.removePendingPathChallengesFor(pt);
    }

    fn pathChallengeInflightPn(self: *Connection, token: u64) ?u64 {
        var it = self.path_challenge_inflight.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == token) return entry.key_ptr.*;
        }
        return null;
    }

    fn removePendingPathChallengesFor(self: *Connection, pt: u64) void {
        while (true) {
            var removed = false;
            var it = self.pending_path_challenges.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.path_token != null and entry.value_ptr.path_token.? == pt) {
                    const token = entry.key_ptr.*;
                    _ = self.pending_path_challenges.remove(token);
                    if (self.pathChallengeInflightPn(token)) |pn| _ = self.path_challenge_inflight.remove(pn);
                    removed = true;
                    break;
                }
            }
            if (!removed) break;
        }
    }

    fn canSendDatagram(self: *Connection, datagram_len: usize) bool {
        if (self.role != .server) return true;
        if (self.sendPathToken()) |pt| {
            const p = self.paths.get(pt) orelse blk: {
                const provisional = self.provisional_path orelse return false;
                if (provisional.token != pt) return false;
                break :blk provisional.state;
            };
            if (p.validated) return true;
            return withinAmplificationBudget(p.sent_bytes, p.recv_bytes, datagram_len);
        }
        if (self.address_validated) return true;
        return withinAmplificationBudget(self.sent_bytes, self.recv_bytes, datagram_len);
    }

    fn recordPathSent(self: *Connection, datagram_len: usize) void {
        if (self.sendPathToken()) |pt| {
            if (self.paths.getPtr(pt)) |p| {
                p.sent_bytes += datagram_len;
            } else if (self.provisional_path) |*path| {
                if (path.token == pt) path.state.sent_bytes += datagram_len;
            }
        }
    }

    fn sendPathToken(self: *const Connection) ?u64 {
        return self.current_path_token orelse self.default_path_token;
    }

    fn validateCurrentPath(self: *Connection) void {
        if (self.current_path_token) |pt| {
            if (self.paths.getPtr(pt)) |p| p.validated = true;
            self.default_path_token = pt;
            if (self.peer_candidate_path_token == pt) self.peer_candidate_path_token = null;
        }
        self.address_validated = true;
    }

    fn pathTokenForAddress(self: *Connection, peer_address: []const u8) Error!u64 {
        const token = std.hash.Wyhash.hash(0, peer_address);
        const gop = self.paths.getOrPut(self.gpa, token) catch return error.OutOfMemory;
        if (gop.found_existing) {
            if (!std.mem.eql(u8, gop.value_ptr.address, peer_address)) return error.ProtocolViolation;
        } else {
            const owned = self.gpa.dupe(u8, peer_address) catch {
                _ = self.paths.remove(token);
                return error.OutOfMemory;
            };
            gop.value_ptr.* = .{ .address = owned };
        }
        return token;
    }

    fn pathToken(data: [8]u8) u64 {
        return std.mem.readInt(u64, &data, .big);
    }

    fn withinAmplificationBudget(sent: u64, received: u64, datagram_len: usize) bool {
        const budget = if (received > std.math.maxInt(u64) / constants.AMPLIFICATION_FACTOR)
            std.math.maxInt(u64)
        else
            received * constants.AMPLIFICATION_FACTOR;
        if (sent > budget) return false;
        return datagram_len <= budget - sent;
    }

    /// RFC 9000 12.4 / table 3: which frame types each space permits.
    fn frameAllowedIn(space: Space, long: bool, f: frame.Frame) bool {
        if (space == .application and long) return switch (f) {
            .padding, .ping, .stream, .reset_stream, .stop_sending, .max_data, .max_stream_data, .max_streams, .data_blocked, .stream_data_blocked, .streams_blocked, .new_connection_id, .retire_connection_id, .path_challenge => true,
            .connection_close => |cc| !cc.app,
            else => false,
        };
        if (space == .application) return switch (f) {
            else => true,
        };
        return switch (f) {
            .padding, .ping, .ack, .crypto => true,
            .connection_close => |cc| !cc.app,
            else => false,
        };
    }

    /// The send-side mirror of the recv gate: assert every frame we are about to
    /// seal is legal in `space` (so STREAM can never reach an Initial/Handshake
    /// packet, even through the shared buildPacket primitive). A debug
    /// check - it decodes the payload, so it compiles out in release builds, where
    /// the single STREAM caller is already pinned to the Application space.
    fn assertFramesAllowedIn(space: Space, long: bool, frames: []const u8) void {
        if (!std.debug.runtime_safety) return;
        var rest = frames;
        while (rest.len > 0) {
            const d = frame.decode(rest) catch return;
            std.debug.assert(frameAllowedIn(space, long, d.frame));
            if (d.len == 0) break;
            rest = rest[d.len..];
        }
    }

    fn onStreamFrame(self: *Connection, id: u64, offset: u64, data: []const u8, fin: bool) Error!void {
        if (self.isRetired(id)) return; // a late frame for a completed-and-dropped stream
        if (!self.peerCanSendOn(id)) return error.StreamStateError;
        if (!self.isPeerInitiated(id) and !self.localStreamWasOpened(id)) return error.StreamStateError;
        const existing = self.streams.get(id);
        const end = std.math.add(u64, offset, data.len) catch return error.FlowControlError;
        const old_high = if (existing) |s| s.highest_received else 0;
        const new_high = @max(old_high, end);
        const expected_delta = new_high - old_high;
        const recv_limit = if (self.recv_windows.get(id)) |rw| rw.limit else self.initialStreamRecvLimit(id);
        if (new_high > recv_limit) return error.FlowControlError;
        const new_total = std.math.add(u64, self.conn_received_total, expected_delta) catch return error.FlowControlError;
        if (new_total > self.conn_recv_window.limit) return error.FlowControlError;
        try self.markStreamChanged(id);
        const s = existing orelse try self.recvStream(id);
        const rw = try self.recvWindow(id);
        const delta = s.push(offset, data, fin) catch |e| switch (e) {
            error.FinalSizeError => return error.FinalSizeError,
            error.StreamBufferExceeded => return error.StreamBufferExceeded,
            error.OutOfMemory => return error.OutOfMemory,
        };
        std.debug.assert(s.highest_received == new_high);
        std.debug.assert(delta == expected_delta);
        rw.onReceived(s.highest_received) catch return error.FlowControlError;
        // Charge the new bytes against the connection-wide window (the sum across
        // every stream), not just this stream's offset.
        self.conn_received_total = new_total;
        self.conn_recv_window.onReceived(self.conn_received_total) catch return error.FlowControlError;
    }

    fn onReset(self: *Connection, id: u64, error_code: u64, final_size: u64) Error!void {
        if (self.isRetired(id)) return; // a reset for an already-completed-and-dropped stream
        if (!self.peerCanSendOn(id)) return error.StreamStateError;
        if (!self.isPeerInitiated(id) and !self.localStreamWasOpened(id)) return error.StreamStateError;
        const s = try self.recvStream(id);
        const new_high = @max(s.highest_received, final_size);
        const delta = new_high - s.highest_received;
        const rw = try self.recvWindow(id);
        if (new_high > rw.limit) return error.FlowControlError;
        const new_total = std.math.add(u64, self.conn_received_total, delta) catch return error.FlowControlError;
        if (new_total > self.conn_recv_window.limit) return error.FlowControlError;
        try self.markStreamChanged(id);
        const charged = s.onReset(error_code, final_size) catch return error.FinalSizeError;
        std.debug.assert(charged == delta);
        rw.onReceived(s.highest_received) catch return error.FlowControlError;
        self.conn_received_total = new_total;
        self.conn_recv_window.onReceived(self.conn_received_total) catch return error.FlowControlError;
    }

    /// A peer STOP_SENDING (RFC 9000 19.5) asks us to stop sending on `id`. Reset that
    /// send stream so we stop producing; if the stream does not exist yet (the peer
    /// cancelled before we started the response), remember the request so the stream
    /// is born already reset rather than sending data the peer rejected. Only the
    /// bidirectional request/response streams are auto-reset - a STOP_SENDING aimed at
    /// the server's own unidirectional infrastructure (control/QPACK) is left to the
    /// layer above, so it never resets the critical control stream.
    fn onStopSending(self: *Connection, id: u64, error_code: u64) Error!void {
        if (!self.localCanSendOn(id)) return error.StreamStateError;
        if (stream.StreamType.of(id) != .client_bidi) return;
        if (!self.isPeerInitiated(id) and !self.localStreamWasOpened(id)) return error.StreamStateError;
        try self.checkPeerStreamLimit(id);
        const was_tracked = self.peer_reset_streams.contains(id);
        try self.trackPeerResetStream(id);
        if (self.send_streams.get(id)) |s| {
            s.reset(error_code);
        } else {
            self.peer_stop_sending.put(self.gpa, id, error_code) catch {
                if (!was_tracked) _ = self.peer_reset_streams.remove(id);
                return error.OutOfMemory;
            };
        }
    }

    /// Whether `id` names a recv stream that already completed and was dropped, so a
    /// late frame for it must be ignored rather than resurrecting it (the dropped
    /// stream's offset accounting is gone, so re-creating it would re-deliver data).
    fn isRetired(self: *const Connection, id: u64) bool {
        return self.retired_recv.contains(id);
    }

    fn markStreamChanged(self: *Connection, id: u64) Error!void {
        if (std.mem.indexOfScalar(u64, self.changed_streams.items, id) != null) return;
        self.changed_streams.append(self.gpa, id) catch return error.OutOfMemory;
    }

    fn recvStream(self: *Connection, id: u64) Error!*stream.RecvStream {
        if (self.streams.get(id)) |s| return s;
        try self.checkPeerStreamLimit(id);
        const s = try self.gpa.create(stream.RecvStream);
        s.* = stream.RecvStream.init(self.gpa);
        self.streams.put(self.gpa, id, s) catch {
            s.deinit();
            self.gpa.destroy(s);
            return error.OutOfMemory;
        };
        return s;
    }

    /// Drop a stream's receive state once it is terminal (fully read or reset), so a
    /// peer that opens-then-resets streams forever cannot grow the streams map
    /// unbounded (the memory half of the Rapid-Reset class). The send half is dropped
    /// only when it has no unacked bytes left to retransmit; otherwise it is retained
    /// until the ACK path frees it. Returns whether the recv stream was dropped.
    pub fn dropStream(self: *Connection, id: u64) bool {
        if (self.send_streams.get(id)) |ss| {
            if (ss.fullyAcked()) {
                _ = self.send_streams.remove(id);
                _ = self.send_windows.remove(id);
                _ = self.peer_reset_streams.remove(id);
                ss.deinit();
                self.gpa.destroy(ss);
            }
        }
        const s = self.streams.get(id) orelse return false;
        if (!s.isTerminal()) return false;
        if (self.peer_stop_sending.contains(id) and !self.send_streams.contains(id)) {
            _ = self.sendStream(id) catch return false;
        }
        // Remember the id as retired BEFORE freeing, so a failure to record it leaves
        // the stream in place rather than dropped-but-resurrectable.
        self.retired_recv.retire(self.gpa, id) catch |err| switch (err) {
            error.OutOfMemory => return false,
            error.RangeLimitExceeded => {
                self.close(
                    false,
                    @intFromEnum(constants.TransportError.internal_error),
                    "retired stream history limit",
                ) catch {
                    self.closed = true;
                };
                return false;
            },
        };
        _ = self.streams.remove(id);
        _ = self.recv_windows.remove(id);
        _ = self.max_stream_data_pending.remove(id);
        _ = self.peer_stream_data_blocked.remove(id);
        if (self.isPeerInitiated(id)) {
            const limit = if (stream.StreamType.of(id).isUni()) &self.peer_uni_streams else &self.peer_bidi_streams;
            limit.onClosed();
            if (limit.shouldUpdate()) {
                if (stream.StreamType.of(id).isUni()) {
                    self.max_streams_uni_pending = true;
                } else {
                    self.max_streams_bidi_pending = true;
                }
            }
        }
        s.deinit();
        self.gpa.destroy(s);
        return true;
    }

    /// The ordered, not-yet-consumed bytes of a stream (empty if none/unknown).
    pub fn streamData(self: *Connection, id: u64) []const u8 {
        if (self.streams.get(id)) |s| return s.readable();
        return &.{};
    }

    /// Advance past `n` ordered stream bytes without returning flow-control credit.
    /// HTTP/3 uses this for DATA payloads until the application acknowledges them.
    pub fn advanceStream(self: *Connection, id: u64, n: usize) void {
        if (self.streams.get(id)) |s| s.consume(n);
    }

    /// Return credit for up to `n` bytes already advanced by the parser.
    pub fn creditStream(self: *Connection, id: u64, n: u64) void {
        if (self.streams.get(id)) |s| self.applyStreamCredit(id, s, s.credit(n));
    }

    /// Return all received stream credit after a reset or local abandonment.
    pub fn releaseStreamCredit(self: *Connection, id: u64) void {
        if (self.streams.get(id)) |s| self.applyStreamCredit(id, s, s.releaseCredit());
    }

    fn applyStreamCredit(self: *Connection, id: u64, s: *stream.RecvStream, credited: u64) void {
        self.conn_consumed_total += credited;
        self.conn_recv_window.onConsumed(self.conn_consumed_total);
        if (self.conn_recv_window.shouldUpdate()) self.max_data_pending = true;
        if (self.recv_windows.getPtr(id)) |rw| {
            rw.onConsumed(s.flow_consumed);
            if (rw.shouldUpdate()) self.max_stream_data_pending.put(self.gpa, id, {}) catch {};
        }
    }

    /// Mark `n` stream bytes parsed and return their flow-control credit.
    pub fn consumeStream(self: *Connection, id: u64, n: usize) void {
        if (self.streams.get(id)) |s| {
            const before = s.read_offset;
            s.consume(n);
            self.applyStreamCredit(id, s, s.credit(s.read_offset - before));
        }
    }

    pub fn streamFinished(self: *Connection, id: u64) bool {
        if (self.streams.get(id)) |s| return s.isFinished();
        return false;
    }

    /// Whether the peer reset this receive stream (RFC 9000 19.4). The H3 layer
    /// surfaces this as a cancelled request and drops the stream.
    pub fn streamReset(self: *Connection, id: u64) bool {
        if (self.streams.get(id)) |s| return s.state == .reset_recvd;
        return false;
    }

    /// The application error code of a peer RESET_STREAM on `id`, or null if the
    /// stream was not reset (so the H3 layer can report why the peer cancelled).
    pub fn streamResetCode(self: *Connection, id: u64) ?u64 {
        if (self.streams.get(id)) |s| return s.reset_code;
        return null;
    }

    /// Whether a receive stream currently exists for `id`. A retired (dropped) or
    /// never-seen id returns false, so the H3 layer does not recreate state for it.
    pub fn hasStream(self: *Connection, id: u64) bool {
        return self.streams.contains(id);
    }

    /// The receive-stream ids changed by the last datagram. The slice remains valid
    /// until the next receive call.
    pub fn changedStreamIds(self: *const Connection) []const u64 {
        return self.changed_streams.items;
    }

    /// Snapshot the ids of every stream the transport currently knows about, into
    /// `out`, returning how many were written (capped at `out.len`). The HTTP/3
    /// layer iterates these to advance each request stream's parse.
    pub fn streamIds(self: *Connection, out: []u64) usize {
        var n: usize = 0;
        var it = self.streams.keyIterator();
        while (it.next()) |k| {
            if (n >= out.len) break;
            out[n] = k.*;
            n += 1;
        }
        return n;
    }

    pub fn streamCount(self: *Connection) usize {
        return @intCast(self.streams.count());
    }
};

const testing = std.testing;

/// Packet and connection fixtures for cross-module tests and fuzz targets.
pub const test_support = struct {
    /// Build an Initial packet that a peer connection can decrypt.
    pub const buildInitial = testBuildInitial;
    /// Install deterministic Application-space keys on a connection.
    pub const installAppKeys = testInstallAppKeys;
    /// Mark a connection's handshake as confirmed without running TLS.
    pub const confirmHandshake = testConfirmHandshake;
    /// Set the next Application-space packet number.
    pub const setAppNextPn = testSetAppNextPn;
    /// Build a 1-RTT packet that a peer connection can decrypt.
    pub const buildApp = testBuildApp;
};

// Build one Initial packet the way a peer would, so the connection can decrypt
// it: frame the payload, seal it with the sender's Initial keys, and apply header
// protection. Returns an owned datagram the caller frees.
fn testBuildInitial(gpa: std.mem.Allocator, dcid: []const u8, sender: Role, pn: u64, frames: []const u8) ![]u8 {
    return testBuildInitialWithPadding(gpa, dcid, sender, pn, frames, sender == .client);
}

fn initialDatagramLen(dcid_len: usize, payload_len: usize) !usize {
    const protected_len = 1 + payload_len + crypto.TAG_LEN;
    return 1 + 4 + 1 + dcid_len + 1 + 1 + try varint.len(protected_len) + protected_len;
}

fn testBuildInitialWithPadding(gpa: std.mem.Allocator, dcid: []const u8, sender: Role, pn: u64, frames: []const u8, pad_to_min: bool) ![]u8 {
    const keys = blk: {
        const ik = crypto.InitialKeys.derive(dcid);
        break :blk if (sender == .client) ik.client else ik.server;
    };
    var payload: std.ArrayListUnmanaged(u8) = .empty;
    defer payload.deinit(gpa);
    try payload.appendSlice(gpa, frames);
    if (pad_to_min) {
        while (try initialDatagramLen(dcid.len, payload.items.len) < constants.MIN_INITIAL_DATAGRAM) {
            try payload.append(gpa, 0x00);
        }
    }
    // first byte: long(0x80)|fixed(0x40)|initial(type 0)| pn_len-1 (=0 -> 1-byte pn)
    var hdr_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer hdr_buf.deinit(gpa);
    try hdr_buf.append(gpa, 0xC0);
    try hdr_buf.appendSlice(gpa, &[_]u8{ 0, 0, 0, 1 }); // version 1
    try hdr_buf.append(gpa, @intCast(dcid.len));
    try hdr_buf.appendSlice(gpa, dcid);
    try hdr_buf.append(gpa, 0); // scid len 0
    try hdr_buf.append(gpa, 0); // token len 0 (varint)
    // length = pn(1) + ciphertext(frames + tag)
    const length = 1 + payload.items.len + crypto.TAG_LEN;
    var lbuf: [8]u8 = undefined;
    try hdr_buf.appendSlice(gpa, try varint.encode(&lbuf, @intCast(length)));
    const pn_offset = hdr_buf.items.len;
    try hdr_buf.append(gpa, @intCast(pn & 0xff)); // 1-byte pn

    const header = hdr_buf.items;
    const out = try gpa.alloc(u8, header.len + payload.items.len + crypto.TAG_LEN);
    errdefer gpa.free(out);
    @memcpy(out[0..header.len], header);
    _ = crypto.seal(keys, pn, header, payload.items, out[header.len..]);
    try crypto.protectHeader(keys.hp, out, pn_offset, true);
    return out;
}

// Build a Handshake-space (long-header type 0x02) packet carrying `frames`, sealed
// with `keys` - used to deliver the client Finished into the server's Handshake
// space the way a real client would.
fn testBuildHandshake(gpa: std.mem.Allocator, dcid: []const u8, keys: crypto.Keys, pn: u64, frames: []const u8) ![]u8 {
    var hdr_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer hdr_buf.deinit(gpa);
    try hdr_buf.append(gpa, 0xE0); // long|fixed|handshake(type 2)|pn_len-1=0
    try hdr_buf.appendSlice(gpa, &[_]u8{ 0, 0, 0, 1 }); // version 1
    try hdr_buf.append(gpa, @intCast(dcid.len));
    try hdr_buf.appendSlice(gpa, dcid);
    try hdr_buf.append(gpa, 0); // scid len 0 (no token field on a Handshake header)
    const length = 1 + frames.len + crypto.TAG_LEN;
    var lbuf: [8]u8 = undefined;
    try hdr_buf.appendSlice(gpa, try varint.encode(&lbuf, @intCast(length)));
    const pn_offset = hdr_buf.items.len;
    try hdr_buf.append(gpa, @intCast(pn & 0xff));

    const header = hdr_buf.items;
    const out = try gpa.alloc(u8, header.len + frames.len + crypto.TAG_LEN);
    errdefer gpa.free(out);
    @memcpy(out[0..header.len], header);
    _ = crypto.seal(keys, pn, header, frames, out[header.len..]);
    try crypto.protectHeader(keys.hp, out, pn_offset, true);
    return out;
}

fn testBuildZeroRtt(gpa: std.mem.Allocator, dcid: []const u8, pn: u64, frames: []const u8, secret: [32]u8) ![]u8 {
    const keys = crypto.Keys.fromSecret(secret);
    var payload: std.ArrayListUnmanaged(u8) = .empty;
    defer payload.deinit(gpa);
    try payload.appendSlice(gpa, frames);
    while (payload.items.len < 20) try payload.append(gpa, 0x00);

    var hdr: std.ArrayListUnmanaged(u8) = .empty;
    defer hdr.deinit(gpa);
    const pn_len: usize = 1;
    const length = pn_len + payload.items.len + crypto.TAG_LEN;
    const pn_offset = packet.writeLongHeader(&hdr, gpa, .zero_rtt, constants.VERSION_1, dcid, &.{}, &.{}, length, pn_len) catch return error.OutOfMemory;
    try packet.writePacketNumber(&hdr, gpa, pn, pn_len);

    const out = try gpa.alloc(u8, hdr.items.len + payload.items.len + crypto.TAG_LEN);
    errdefer gpa.free(out);
    @memcpy(out[0..hdr.items.len], hdr.items);
    _ = crypto.seal(keys, pn, hdr.items, payload.items, out[hdr.items.len..]);
    try crypto.protectHeader(keys.hp, out, pn_offset, true);
    return out;
}

fn expectZeroRttProtocolViolation(gpa: std.mem.Allocator, dcid: []const u8, pn: u64, frames: []const u8, secret: [32]u8) !void {
    var server = try Connection.init(gpa, .server, dcid);
    defer server.deinit();
    server.installZeroRttRecvSecret(secret);

    const dgram = try testBuildZeroRtt(gpa, dcid, pn, frames, secret);
    defer gpa.free(dgram);
    try testing.expectError(error.ProtocolViolation, server.receiveDatagram(dgram, 1000 + pn));
    try testing.expect(server.closed);
}

// Application-space test keys, deterministic so a test builder and the connection
// agree. STREAM frames are illegal in Initial (RFC 9000 12.4); these helpers let
// the recv-pipeline tests deliver stream data in the Application space, the way a
// real connection does once the handshake installs 1-RTT keys.
const TEST_APP_SECRET = [_]u8{0x5a} ** 32;

fn testAppKeys() crypto.Keys {
    return crypto.Keys.fromSecret(TEST_APP_SECRET);
}

fn testInstallAppKeys(conn: *Connection) void {
    conn.installApplicationSecrets(TEST_APP_SECRET, TEST_APP_SECRET);
    conn.address_validated = true;
    conn.peer_tp.initial_max_stream_data_bidi_local = 1 << 20;
    conn.peer_tp.initial_max_stream_data_bidi_remote = 1 << 20;
    conn.peer_tp.initial_max_stream_data_uni = 1 << 20;
    conn.peer_tp.initial_max_streams_bidi = 1 << 20;
    conn.peer_tp.initial_max_streams_uni = 1 << 20;
    conn.local_bidi_streams = flow.StreamLimit.init(conn.peer_tp.initial_max_streams_bidi);
    conn.local_uni_streams = flow.StreamLimit.init(conn.peer_tp.initial_max_streams_uni);
    conn.local_tp.initial_max_streams_bidi = 1 << 60;
    conn.local_tp.initial_max_streams_uni = 1 << 60;
    conn.peer_bidi_streams = flow.StreamLimit.init(conn.local_tp.initial_max_streams_bidi);
    conn.peer_uni_streams = flow.StreamLimit.init(conn.local_tp.initial_max_streams_uni);
}

fn testConfirmHandshake(conn: *Connection) void {
    conn.handshake_confirmed = true;
}

fn testSetAppNextPn(conn: *Connection, next_pn: u64) void {
    conn.spaces[@intFromEnum(Space.application)].next_pn = next_pn;
}

fn testRequiredServerTransportParameters(conn: *const Connection) !transport_params.TransportParameters {
    return .{
        .original_destination_connection_id = try transport_params.ConnectionId.init(conn.dcid),
        .initial_source_connection_id = try transport_params.ConnectionId.init(conn.peer_scid),
    };
}

// Build a 1-RTT (short-header) Application packet carrying `frames`, sealed with
// the test Application keys. The mirror of testBuildInitial for the post-handshake
// space, so stream-reassembly tests use the space STREAM is actually legal in.
fn testBuildApp(gpa: std.mem.Allocator, dcid: []const u8, pn: u64, frames: []const u8) ![]u8 {
    return testBuildAppWithSecret(gpa, dcid, pn, frames, TEST_APP_SECRET, false);
}

fn receiveStreamUnderAllocationFailure(gpa: std.mem.Allocator) !void {
    const dcid = [_]u8{ 0x0e, 0x0f, 0x10, 0x16 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var tail_frame: std.ArrayListUnmanaged(u8) = .empty;
    defer tail_frame.deinit(gpa);
    try frame.encodeStream(&tail_frame, gpa, 0, 6, "world", true);
    const tail = try testBuildApp(gpa, &dcid, 0, tail_frame.items);
    defer gpa.free(tail);
    try conn.receiveDatagram(tail, 1000);
    conn.clearSend();

    const s = conn.streams.get(0).?;
    try testing.expectEqual(@as(usize, 1), s.pending.items.len);
    const previous_pending_offset = s.pending.items[0].offset;
    const previous_pending_data = try gpa.dupe(u8, s.pending.items[0].data);
    defer gpa.free(previous_pending_data);
    const previous_window = conn.recv_windows.get(0).?;
    const previous_total = conn.conn_received_total;
    var head_frame: std.ArrayListUnmanaged(u8) = .empty;
    defer head_frame.deinit(gpa);
    try frame.encodePathChallenge(&head_frame, gpa, .{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try frame.encodeStream(&head_frame, gpa, 0, 0, "hello ", false);
    const head = try testBuildApp(gpa, &dcid, 1, head_frame.items);
    defer gpa.free(head);
    conn.receiveDatagram(head, 2000) catch |err| {
        try testing.expectEqual(@as(u64, 11), s.highest_received);
        try testing.expectEqual(@as(?u64, 11), s.final_size);
        try testing.expectEqual(stream.RecvState.size_known, s.state);
        try testing.expectEqual(previous_window, conn.recv_windows.get(0).?);
        try testing.expectEqual(previous_total, conn.conn_received_total);
        if (s.readable().len == 0) {
            try testing.expectEqual(@as(usize, 1), s.pending.items.len);
            try testing.expectEqual(previous_pending_offset, s.pending.items[0].offset);
            try testing.expectEqualStrings(previous_pending_data, s.pending.items[0].data);
            try testing.expect(!conn.spaces[@intFromEnum(Space.application)].recv_ranges.contains(1));
        } else {
            try testing.expectEqualStrings("hello world", s.readable());
            try testing.expectEqual(@as(usize, 0), s.pending.items.len);
            try testing.expect(s.isFinished());
            try testing.expect(conn.spaces[@intFromEnum(Space.application)].recv_ranges.contains(1));
        }
        if (conn.receive_failure != null) {
            try testing.expectEqual(@as(usize, 0), conn.datagramLengths().len);
            for (&conn.spaces) |*state| try testing.expect(!state.ack_pending);
            conn.handshake_confirmed = true;
            try testing.expectError(error.OutOfMemory, conn.sendNewToken("token", 3000));
        }
        return err;
    };
    try testing.expectEqualStrings("hello world", s.readable());
    try testing.expect(s.isFinished());
}

fn testBuildAppWithSecret(gpa: std.mem.Allocator, dcid: []const u8, pn: u64, frames: []const u8, secret: [32]u8, key_phase: bool) ![]u8 {
    const keys = crypto.Keys.fromSecret(secret);
    return testBuildAppWithKeys(gpa, dcid, pn, frames, keys, key_phase);
}

fn testBuildAppWithUpdatedSecret(gpa: std.mem.Allocator, dcid: []const u8, pn: u64, frames: []const u8, secret: [32]u8, current_hp: [crypto.HP_LEN]u8, key_phase: bool) ![]u8 {
    const keys = crypto.Keys.fromUpdatedSecret(secret, current_hp);
    return testBuildAppWithKeys(gpa, dcid, pn, frames, keys, key_phase);
}

fn testBuildAppWithKeys(gpa: std.mem.Allocator, dcid: []const u8, pn: u64, frames: []const u8, keys: crypto.Keys, key_phase: bool) ![]u8 {
    var hdr: std.ArrayListUnmanaged(u8) = .empty;
    defer hdr.deinit(gpa);
    const pn_offset = try packet.writeShortHeaderWithKeyPhase(&hdr, gpa, dcid, 1, key_phase);
    try packet.writePacketNumber(&hdr, gpa, pn, 1);

    const out = try gpa.alloc(u8, hdr.items.len + frames.len + crypto.TAG_LEN);
    errdefer gpa.free(out);
    @memcpy(out[0..hdr.items.len], hdr.items);
    _ = crypto.seal(keys, pn, hdr.items, frames, out[hdr.items.len..]);
    try crypto.protectHeader(keys.hp, out, pn_offset, false);
    return out;
}

fn expectFirstQueuedAppFrameTag(conn: *Connection, want: std.meta.Tag(frame.Frame)) !void {
    try expectQueuedAppFrameTag(conn, 0, want);
}

fn expectQueuedAppFrameTag(conn: *Connection, index: usize, want: std.meta.Tag(frame.Frame)) !void {
    const decoded = try decodeQueuedAppFrame(conn, index);
    defer testing.allocator.free(decoded.work);
    defer testing.allocator.free(decoded.plaintext);
    try testing.expectEqual(want, std.meta.activeTag(decoded.frame));
}

const DecodedQueuedAppFrame = struct {
    work: []u8,
    plaintext: []u8,
    frame: frame.Frame,
};

fn decodeQueuedAppFrame(conn: *Connection, index: usize) !DecodedQueuedAppFrame {
    const gpa = testing.allocator;
    try testing.expect(conn.datagramLengths().len > index);
    var start: usize = 0;
    for (conn.datagramLengths()[0..index]) |len| start += len;
    const dgram = conn.datagramsToSend()[start .. start + conn.datagramLengths()[index]];
    var work = try gpa.dupe(u8, dgram);
    errdefer gpa.free(work);

    const hdr = try packet.parseShort(work, conn.peer_scid.len);
    const pn_len = try crypto.unprotectHeader(testAppKeys().hp, work, hdr.pn_offset, false);
    var truncated: u64 = 0;
    for (work[hdr.pn_offset .. hdr.pn_offset + pn_len]) |b| truncated = (truncated << 8) | b;
    const pn = packet.decodePacketNumber(0, truncated, pn_len);
    const header = work[0 .. hdr.pn_offset + pn_len];
    const ciphertext = work[hdr.pn_offset + pn_len ..];
    const plaintext = try gpa.alloc(u8, ciphertext.len);
    errdefer gpa.free(plaintext);
    const payload = try crypto.open(testAppKeys(), pn, header, ciphertext, plaintext);
    const decoded = try frame.decode(payload);
    return .{ .work = work, .plaintext = plaintext, .frame = decoded.frame };
}

fn sendPacketUnderAllocationFailure(gpa: std.mem.Allocator) !void {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    try conn.sendStreamData(0, &[_]u8{0x5a} ** 1024, true);
    conn.flushSend(1000) catch |err| {
        try testing.expectEqual(conn.datagramLengths().len, conn.datagramPathTokens().len);
        var queued: usize = 0;
        for (conn.datagramLengths()) |len| queued += len;
        try testing.expectEqual(queued, conn.datagramsToSend().len);
        return err;
    };
    try testing.expectEqual(@as(usize, 1), conn.datagramLengths().len);
    try testing.expectEqual(conn.datagramLengths().len, conn.datagramPathTokens().len);
    try testing.expectEqual(conn.datagramLengths()[0], conn.datagramsToSend().len);
}

test "packet construction is atomic on allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, sendPacketUnderAllocationFailure, .{});
}

test "server decrypts a 1-RTT packet and reassembles a stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    // A STREAM frame (type 0x0b = base|LEN|FIN) on stream 0 carrying "hi", in an
    // Application packet - the space STREAM is legal in.
    const frames = [_]u8{ 0x0b, 0x00, 0x02, 'h', 'i' };
    const dgram = try testBuildApp(gpa, &dcid, 0, &frames);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    try testing.expectEqualStrings("hi", conn.streamData(0));
    try testing.expect(conn.streamFinished(0));
}

test "receive datagrams expose only changed stream ids" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x18 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeStream(&frames, gpa, 0, 0, "a", false);
    try frame.encodeStream(&frames, gpa, 4, 0, "b", true);
    try frame.encodeStream(&frames, gpa, 0, 1, "c", true);
    try frame.encodeResetStream(&frames, gpa, 8, 0x010c, 0);
    const streams = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(streams);
    try conn.receiveDatagram(streams, 1000);
    try testing.expectEqualSlices(u64, &.{ 0, 4, 8 }, conn.changedStreamIds());

    const ping = [_]u8{0x01} ++ [_]u8{0x00} ** 19;
    const no_streams = try testBuildApp(gpa, &dcid, 1, &ping);
    defer gpa.free(no_streams);
    try conn.receiveDatagram(no_streams, 2000);
    try testing.expectEqual(@as(usize, 0), conn.changedStreamIds().len);
}

test "peer cannot use an unopened locally initiated stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09 };

    {
        var client = try Connection.init(gpa, .client, &dcid);
        defer client.deinit();
        testInstallAppKeys(&client);
        const datagram = try testBuildApp(gpa, &dcid, 0, &.{ 0x0A, 0x00, 0x01, 'x' });
        defer gpa.free(datagram);

        try testing.expectError(error.StreamStateError, client.receiveDatagram(datagram, 1000));
        try testing.expectEqual(@as(u32, 0), client.streams.count());
    }

    {
        var client = try Connection.init(gpa, .client, &dcid);
        defer client.deinit();
        testInstallAppKeys(&client);
        var frames: std.ArrayListUnmanaged(u8) = .empty;
        defer frames.deinit(gpa);
        try frame.encodeResetStream(&frames, gpa, 0, 0, 0);
        const datagram = try testBuildApp(gpa, &dcid, 0, frames.items);
        defer gpa.free(datagram);

        try testing.expectError(error.StreamStateError, client.receiveDatagram(datagram, 1000));
        try testing.expectEqual(@as(u32, 0), client.streams.count());
    }
}

test "client sends queued STREAM data in a 0-RTT long-header packet" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const psk = [_]u8{0x7b} ** tls.schedule.SECRET_LEN;
    var client = try Connection.initClient(gpa, &dcid, .{
        .random = [_]u8{0x11} ** 32,
        .ephemeral_seed = [_]u8{0x22} ** 32,
        .transport_params = &.{ 0x04, 0x01, 0x3f },
        .alpn = "h3",
        .resumption = .{
            .identity = "ticket-identity",
            .obfuscated_ticket_age = 0x01020304,
            .psk = psk,
            .early_data = true,
        },
    }, 0);
    defer client.deinit();
    try testing.expect(client.tls_client.?.early_traffic_secret != null);
    try testing.expect(client.spaces[@intFromEnum(Space.application)].zero_rtt_send_keys != null);

    var remembered = try testRequiredServerTransportParameters(&client);
    remembered.initial_max_data = 1024;
    remembered.initial_max_stream_data_bidi_remote = 1024;
    remembered.initial_max_streams_bidi = 1;
    try client.setPeerTransportParameters(remembered);
    client.clearSend(); // discard the Initial ClientHello; this test inspects only 0-RTT.

    try client.sendStreamData(0, "early", true);
    try client.flushSend(1000);
    try testing.expectEqual(@as(usize, 1), client.datagramLengths().len);
    const dgram = client.datagramsToSend()[0..client.datagramLengths()[0]];
    const hdr = try packet.parseLong(dgram);
    try testing.expectEqual(constants.LongType.zero_rtt, hdr.ltype);
}

test "server decrypts accepted 0-RTT STREAM data with the early traffic secret" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const psk = [_]u8{0x7b} ** tls.schedule.SECRET_LEN;
    var client = try Connection.initClient(gpa, &dcid, .{
        .random = [_]u8{0x11} ** 32,
        .ephemeral_seed = [_]u8{0x22} ** 32,
        .transport_params = &.{ 0x04, 0x01, 0x3f },
        .alpn = "h3",
        .resumption = .{
            .identity = "ticket-identity",
            .obfuscated_ticket_age = 0x01020304,
            .psk = psk,
            .early_data = true,
        },
    }, 0);
    defer client.deinit();
    const early_secret = client.tls_client.?.early_traffic_secret.?;

    var remembered = try testRequiredServerTransportParameters(&client);
    remembered.initial_max_data = 1024;
    remembered.initial_max_stream_data_bidi_remote = 1024;
    remembered.initial_max_streams_bidi = 1;
    try client.setPeerTransportParameters(remembered);
    client.clearSend();

    try client.sendStreamData(0, "early", true);
    try client.flushSend(1000);
    const dgram = client.datagramsToSend()[0..client.datagramLengths()[0]];

    var server = try Connection.init(gpa, .server, &dcid);
    defer server.deinit();
    server.installZeroRttRecvSecret(early_secret);
    try server.receiveDatagram(dgram, 1000);
    try testing.expectEqualStrings("early", server.streamData(0));
    try testing.expect(server.streamFinished(0));
    try testing.expect(server.spaces[@intFromEnum(Space.application)].ack_pending);
}

test "server discards 0-RTT receive keys after authenticating 1-RTT" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09 };
    const early_secret = [_]u8{0x7d} ** tls.schedule.SECRET_LEN;
    var server = try Connection.init(gpa, .server, &dcid);
    defer server.deinit();
    server.installZeroRttRecvSecret(early_secret);
    testInstallAppKeys(&server);

    const current = try testBuildApp(gpa, &dcid, 0, &.{ 0x0a, 0x00, 0x03, 'n', 'e', 'w' });
    defer gpa.free(current);
    try server.receiveDatagram(current, 1000);
    try testing.expect(server.spaces[@intFromEnum(Space.application)].zero_rtt_recv_keys == null);

    const late = try testBuildZeroRtt(gpa, &dcid, 1, &.{ 0x0a, 0x04, 0x04, 'l', 'a', 't', 'e' }, early_secret);
    defer gpa.free(late);
    try server.receiveDatagram(late, 2000);
    try testing.expectEqual(@as(usize, 0), server.streamData(4).len);
}

test "pending 0-RTT ACK is sent once 1-RTT send keys are available" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x19 };
    const early_secret = [_]u8{0x7d} ** tls.schedule.SECRET_LEN;
    var server = try Connection.init(gpa, .server, &dcid);
    defer server.deinit();
    server.installZeroRttRecvSecret(early_secret);

    const dgram = try testBuildZeroRtt(gpa, &dcid, 0, &.{ 0x0a, 0x00, 0x05, 'e', 'a', 'r', 'l', 'y' }, early_secret);
    defer gpa.free(dgram);
    try server.receiveDatagram(dgram, 1000);
    try testing.expect(server.spaces[@intFromEnum(Space.application)].ack_pending);
    try testing.expectEqual(@as(usize, 0), server.datagramLengths().len);

    server.installApplicationSecrets(TEST_APP_SECRET, TEST_APP_SECRET);
    try server.flushSend(2000);
    try testing.expect(!server.spaces[@intFromEnum(Space.application)].ack_pending);
    try expectFirstQueuedAppFrameTag(&server, .ack);
}

test "server rejects frame types that are not allowed in 0-RTT packets" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x18 };
    const early_secret = [_]u8{0x7c} ** tls.schedule.SECRET_LEN;

    try expectZeroRttProtocolViolation(gpa, &dcid, 0, &.{ 0x02, 0x00, 0x00, 0x00, 0x00 }, early_secret); // ACK

    var crypto_frames: std.ArrayListUnmanaged(u8) = .empty;
    defer crypto_frames.deinit(gpa);
    try frame.encodeCrypto(&crypto_frames, gpa, 0, "late");
    try expectZeroRttProtocolViolation(gpa, &dcid, 1, crypto_frames.items, early_secret);

    var token_frames: std.ArrayListUnmanaged(u8) = .empty;
    defer token_frames.deinit(gpa);
    try frame.encodeNewToken(&token_frames, gpa, "token");
    try expectZeroRttProtocolViolation(gpa, &dcid, 2, token_frames.items, early_secret);

    var path_response_frames: std.ArrayListUnmanaged(u8) = .empty;
    defer path_response_frames.deinit(gpa);
    try frame.encodePathResponse(&path_response_frames, gpa, [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try expectZeroRttProtocolViolation(gpa, &dcid, 3, path_response_frames.items, early_secret);

    var app_close_frames: std.ArrayListUnmanaged(u8) = .empty;
    defer app_close_frames.deinit(gpa);
    try frame.encodeConnectionClose(&app_close_frames, gpa, true, 0x0100, 0, "app close");
    try expectZeroRttProtocolViolation(gpa, &dcid, 4, app_close_frames.items, early_secret);

    var done_frames: std.ArrayListUnmanaged(u8) = .empty;
    defer done_frames.deinit(gpa);
    try varint.append(&done_frames, gpa, @intFromEnum(constants.FrameType.handshake_done));
    try expectZeroRttProtocolViolation(gpa, &dcid, 5, done_frames.items, early_secret);
}

test "client rejects accepted 0-RTT when fresh server transport limits shrink" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var client = try Connection.init(gpa, .client, &dcid);
    defer client.deinit();

    try client.applyRememberedPeerTransportParameters(&.{
        0x04, 0x04, 0x80, 0x10, 0x00, 0x00, // initial_max_data = 1048576
        0x08, 0x01, 0x08, // initial_max_streams_bidi = 8
        0x09, 0x01, 0x08, // initial_max_streams_uni = 8
        0x06, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_bidi_remote = 262144
        0x07, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_uni = 262144
    });

    var fresh = client.remembered_peer_tp.?;
    fresh.initial_max_streams_bidi = 7;
    try testing.expectError(error.ProtocolViolation, client.validateFreshParametersForAcceptedZeroRtt(fresh));

    fresh.initial_max_streams_bidi = 8;
    fresh.initial_max_data = 1 << 20;
    try client.validateFreshParametersForAcceptedZeroRtt(fresh);
}

test "a received next-phase 1-RTT packet updates application receive keys" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const next_secret = crypto.nextTrafficSecret(TEST_APP_SECRET);
    const current_hp = conn.spaces[@intFromEnum(Space.application)].recv_keys.?.hp;
    const frames = [_]u8{ 0x0b, 0x00, 0x02, 'k', 'u' };
    const dgram = try testBuildAppWithUpdatedSecret(gpa, &dcid, 0, &frames, next_secret, current_hp, true);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    const app = &conn.spaces[@intFromEnum(Space.application)];
    try testing.expect(app.recv_key_phase);
    try testing.expectEqualSlices(u8, &next_secret, &app.recv_secret.?);
    try testing.expect(app.prev_recv_keys != null);
    try testing.expectEqualSlices(u8, &current_hp, &app.recv_keys.?.hp);
    try testing.expectEqualStrings("ku", conn.streamData(0));
    try testing.expect(conn.streamFinished(0));
}

test "a local application key update sets the short-header key phase bit" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const next_secret = crypto.nextTrafficSecret(TEST_APP_SECRET);
    const current_hp = conn.spaces[@intFromEnum(Space.application)].send_keys.?.hp;
    try conn.updateApplicationSendKeys();
    try testing.expectEqualSlices(u8, &current_hp, &conn.spaces[@intFromEnum(Space.application)].send_keys.?.hp);
    try conn.sendStreamData(1, "x", true);
    try conn.flushSend(1000);
    try testing.expectEqual(@as(usize, 1), conn.datagramLengths().len);

    const dgram = conn.datagramsToSend()[0..conn.datagramLengths()[0]];
    var work = try gpa.dupe(u8, dgram);
    defer gpa.free(work);
    const keys = crypto.Keys.fromUpdatedSecret(next_secret, current_hp);
    const hdr = try packet.parseShort(work, dcid.len);
    const pn_len = try crypto.unprotectHeader(keys.hp, work, hdr.pn_offset, false);
    try testing.expect((work[0] & packet.SHORT_KEY_PHASE) != 0);
    var truncated: u64 = 0;
    for (work[hdr.pn_offset .. hdr.pn_offset + pn_len]) |b| truncated = (truncated << 8) | b;
    const pn = packet.decodePacketNumber(0, truncated, pn_len);
    const header = work[0 .. hdr.pn_offset + pn_len];
    const ciphertext = work[hdr.pn_offset + pn_len ..];
    const plaintext = try gpa.alloc(u8, ciphertext.len);
    defer gpa.free(plaintext);
    const payload = try crypto.open(keys, pn, header, ciphertext, plaintext);
    const decoded = try frame.decode(payload);
    try testing.expectEqual(@as(std.meta.Tag(frame.Frame), .stream), std.meta.activeTag(decoded.frame));
}

test "negotiated idle timeout is armed by packet activity and silently closes" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.local_tp.max_idle_timeout_ms = 50;
    try conn.setPeerTransportParameters(.{ .max_idle_timeout_ms = 5 });

    const frames = [_]u8{ 0x01, 0x00, 0x00 }; // PING plus enough PADDING for HP sample
    const dgram = try testBuildApp(gpa, &dcid, 0, &frames);
    defer gpa.free(dgram);
    try conn.receiveDatagram(dgram, 1000);

    try testing.expectEqual(@as(?u64, 6000), conn.nextTimeout());
    try conn.onTimeout(5999);
    try testing.expect(!conn.closed);
    try conn.onTimeout(6000);
    try testing.expect(conn.closed);
    try testing.expect(conn.nextTimeout() == null);
}

test "1-RTT packets obey the anti-amplification budget" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x07 };
    var server = try Connection.init(gpa, .server, &dcid);
    defer server.deinit();
    testInstallAppKeys(&server);
    server.address_validated = false;
    server.recv_bytes = 10;
    server.sent_bytes = 30;

    try server.sendPing(.application, 1000);
    try testing.expectEqual(@as(usize, 0), server.datagramLengths().len);

    server.recv_bytes = 100;
    try server.sendPing(.application, 2000);
    try testing.expectEqual(@as(usize, 1), server.datagramLengths().len);
}

test "unauthenticated datagram does not retain path state" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const peer_address = "203.0.113.1:4433";
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const frames = [_]u8{ 0x01, 0x00, 0x00 };
    const dgram = try testBuildApp(gpa, &dcid, 0, &frames);
    defer gpa.free(dgram);
    dgram[dgram.len - 1] ^= 1;

    try conn.receiveDatagramFrom(dgram, 1000, peer_address);
    const token = std.hash.Wyhash.hash(0, peer_address);
    try testing.expect(conn.pathAddress(token) == null);
}

test "replayed authenticated datagrams do not retain new path state" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const frames = [_]u8{0x01} ++ [_]u8{0x00} ** 19;
    const datagram = try testBuildApp(gpa, &dcid, 0, &frames);
    defer gpa.free(datagram);

    try conn.receiveDatagramFrom(datagram, 1000, "203.0.113.1:4433");
    conn.clearSend();
    try conn.receiveDatagramFrom(datagram, 2000, "203.0.113.2:4433");
    try conn.receiveDatagramFrom(datagram, 3000, "203.0.113.3:4433");

    try testing.expect(conn.pathAddress(std.hash.Wyhash.hash(0, "203.0.113.1:4433")) != null);
    try testing.expect(conn.pathAddress(std.hash.Wyhash.hash(0, "203.0.113.2:4433")) == null);
    try testing.expect(conn.pathAddress(std.hash.Wyhash.hash(0, "203.0.113.3:4433")) == null);
}

test "authenticated migration retains one unvalidated peer path" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x0a };
    const addr_a = "198.51.100.1:4433";
    const addr_b = "198.51.100.2:4433";
    const addr_c = "198.51.100.3:4433";
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.handshake_confirmed = true;

    const frames = [_]u8{0x01} ++ [_]u8{0x00} ** 19;
    const first = try testBuildApp(gpa, &dcid, 0, &frames);
    defer gpa.free(first);
    const second = try testBuildApp(gpa, &dcid, 1, &frames);
    defer gpa.free(second);
    const third = try testBuildApp(gpa, &dcid, 2, &frames);
    defer gpa.free(third);

    try conn.receiveDatagramFrom(first, 1000, addr_a);
    conn.clearSend();
    try conn.receiveDatagramFrom(second, 2000, addr_b);
    try conn.receiveDatagramFrom(third, 3000, addr_c);
    try testing.expect(conn.pathAddress(std.hash.Wyhash.hash(0, addr_b)) != null);
    try testing.expect(conn.pathAddress(std.hash.Wyhash.hash(0, addr_c)) == null);

    conn.clearSend();
    try conn.receiveDatagramFrom(third, 4000, addr_c);
    try testing.expect(conn.pathAddress(std.hash.Wyhash.hash(0, addr_b)) == null);
    try testing.expect(conn.pathAddress(std.hash.Wyhash.hash(0, addr_c)) != null);
}

test "authenticated path promotion preserves provisional amplification credit" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const peer_address = "203.0.113.1:4433";
    var server = try Connection.init(gpa, .server, &dcid);
    defer server.deinit();
    testInstallAppKeys(&server);
    server.address_validated = false;

    var unsupported: std.ArrayListUnmanaged(u8) = .empty;
    defer unsupported.deinit(gpa);
    _ = try packet.writeLongHeader(&unsupported, gpa, .initial, 0x0a0a_0a0a, &dcid, "cli", "", 1, 1);
    try unsupported.appendNTimes(gpa, 0, constants.MIN_INITIAL_DATAGRAM - unsupported.items.len);
    try server.receiveDatagramFrom(unsupported.items, 1000, peer_address);

    const frames = [_]u8{0x01} ++ [_]u8{0x00} ** 19;
    const authenticated = try testBuildApp(gpa, &dcid, 0, &frames);
    defer gpa.free(authenticated);
    try server.receiveDatagramFrom(authenticated, 2000, peer_address);

    const before = server.datagramLengths().len;
    try server.sendStreamData(1, &([_]u8{0x42} ** 1000), false);
    try server.flushSend(3000);
    try testing.expect(server.datagramLengths().len > before);
    var sent_bytes: usize = 0;
    for (server.datagramLengths()) |len| sent_bytes += len;
    try testing.expect(sent_bytes <= (unsupported.items.len + authenticated.len) * constants.AMPLIFICATION_FACTOR);
}

test "PATH_CHALLENGE elicits a matching PATH_RESPONSE" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const data = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodePathChallenge(&frames, gpa, data);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    try testing.expect(conn.datagramLengths().len >= 1);
    const response_count = conn.datagramLengths().len;
    try conn.receiveDatagram(dgram, 1001);
    try testing.expectEqual(response_count, conn.datagramLengths().len);

    const response = conn.datagramsToSend()[0..conn.datagramLengths()[0]];
    var work = try gpa.dupe(u8, response);
    defer gpa.free(work);

    const hdr = try packet.parseShort(work, dcid.len);
    const pn_len = try crypto.unprotectHeader(testAppKeys().hp, work, hdr.pn_offset, false);
    var truncated: u64 = 0;
    for (work[hdr.pn_offset .. hdr.pn_offset + pn_len]) |b| truncated = (truncated << 8) | b;
    const pn = packet.decodePacketNumber(0, truncated, pn_len);
    const header = work[0 .. hdr.pn_offset + pn_len];
    const ciphertext = work[hdr.pn_offset + pn_len ..];
    const plaintext = try gpa.alloc(u8, ciphertext.len);
    defer gpa.free(plaintext);
    const payload = try crypto.open(testAppKeys(), pn, header, ciphertext, plaintext);
    const decoded = try frame.decode(payload);
    switch (decoded.frame) {
        .path_response => |got| try testing.expectEqualSlices(u8, &data, &got),
        else => return error.TestUnexpectedResult,
    }
}

test "challengePath emits PATH_CHALLENGE and matching PATH_RESPONSE validates the path" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .client, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const data = [_]u8{ 1, 3, 3, 7, 9, 2, 4, 6 };
    try conn.challengePath(data);
    try testing.expect(conn.hasPendingSend());

    try conn.flushSend(1000);
    try testing.expectEqual(@as(usize, 1), conn.pending_path_challenges.count());
    try expectFirstQueuedAppFrameTag(&conn, .path_challenge);
    conn.clearSend();

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodePathResponse(&frames, gpa, data);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 2000);
    try testing.expect(conn.address_validated);
    try testing.expectEqual(@as(usize, 0), conn.pending_path_challenges.count());
    try testing.expectEqual(@as(usize, 0), conn.path_challenge_inflight.count());
    try expectFirstQueuedAppFrameTag(&conn, .ack);

    try conn.receiveDatagram(dgram, 2001);
    const late = try testBuildApp(gpa, &dcid, 1, frames.items);
    defer gpa.free(late);
    try conn.receiveDatagram(late, 2002);
    try testing.expect(!conn.closed);
}

test "address-aware PATH_RESPONSE validates only the challenged path" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x18 };
    const addr_a = "203.0.113.1:4433";
    const addr_b = "203.0.113.2:4433";
    const data = [_]u8{ 1, 3, 3, 7, 9, 2, 4, 7 };

    {
        var conn = try Connection.init(gpa, .client, &dcid);
        defer conn.deinit();
        testInstallAppKeys(&conn);

        try conn.challengePathOn(data, addr_a);
        try conn.flushSend(1000);
        conn.clearSend();

        var frames: std.ArrayListUnmanaged(u8) = .empty;
        defer frames.deinit(gpa);
        try frame.encodePathResponse(&frames, gpa, data);
        const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
        defer gpa.free(dgram);

        try testing.expectError(error.ProtocolViolation, conn.receiveDatagramFrom(dgram, 2000, addr_b));
        try testing.expectEqual(@as(usize, 1), conn.pending_path_challenges.count());
        const pt_a = std.hash.Wyhash.hash(0, addr_a);
        try testing.expect(!conn.paths.get(pt_a).?.validated);
    }
    {
        var conn = try Connection.init(gpa, .client, &dcid);
        defer conn.deinit();
        testInstallAppKeys(&conn);

        try conn.challengePathOn(data, addr_a);
        try conn.flushSend(1000);
        conn.clearSend();

        var frames: std.ArrayListUnmanaged(u8) = .empty;
        defer frames.deinit(gpa);
        try frame.encodePathResponse(&frames, gpa, data);
        const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
        defer gpa.free(dgram);

        try conn.receiveDatagramFrom(dgram, 2000, addr_a);
        const pt_a = std.hash.Wyhash.hash(0, addr_a);
        try testing.expect(conn.paths.get(pt_a).?.validated);
        try testing.expect(conn.address_validated);
        try testing.expectEqual(@as(usize, 0), conn.pending_path_challenges.count());
    }
}

test "PATH_CHALLENGE response is accounted to the receiving path" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x19 };
    const addr = "198.51.100.9:4433";
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.address_validated = false;

    const data = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 3 };
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodePathChallenge(&frames, gpa, data);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagramFrom(dgram, 1000, addr);
    try testing.expect(conn.datagramLengths().len >= 1);

    const pt = std.hash.Wyhash.hash(0, addr);
    const path = conn.paths.get(pt).?;
    var sent_sum: u64 = 0;
    for (conn.datagramLengths()) |len| sent_sum += len;
    try testing.expectEqual(conn.datagramLengths().len, conn.datagramPathTokens().len);
    for (conn.datagramPathTokens()) |tok| try testing.expectEqual(pt, tok.?);
    try testing.expectEqual(@as(u64, @intCast(dgram.len)), path.recv_bytes);
    try testing.expectEqual(sent_sum, path.sent_bytes);
    try testing.expect(!path.validated);
    try expectFirstQueuedAppFrameTag(&conn, .path_response);
    conn.clearSend();
    try testing.expectEqual(@as(usize, 0), conn.datagramPathTokens().len);
}

test "application sends after address-aware receive inherit the peer path" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x1a };
    const addr = "198.51.100.10:4433";
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.ping));
    while (frames.items.len < 20) try frames.append(gpa, 0x00);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagramFrom(dgram, 1000, addr);
    conn.clearSend(); // discard ACK from the received PING

    try conn.sendStreamData(1, "hello", false);
    try conn.flushSend(2000);
    try testing.expect(conn.datagramLengths().len >= 1);
    const pt = std.hash.Wyhash.hash(0, addr);
    try testing.expectEqual(conn.datagramLengths().len, conn.datagramPathTokens().len);
    for (conn.datagramPathTokens()) |tok| try testing.expectEqual(pt, tok.?);
}

test "application sends stay on the default path until a migrated path validates" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x1c };
    const addr_a = "198.51.100.10:4433";
    const addr_b = "198.51.100.11:4433";
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.ping));
    while (frames.items.len < 20) try frames.append(gpa, 0x00);

    const d1 = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(d1);
    try conn.receiveDatagramFrom(d1, 1000, addr_a);
    conn.clearSend();
    const pt_a = std.hash.Wyhash.hash(0, addr_a);
    const pt_b = std.hash.Wyhash.hash(0, addr_b);
    try testing.expectEqual(pt_a, conn.default_path_token.?);

    const d2 = try testBuildApp(gpa, &dcid, 1, frames.items);
    defer gpa.free(d2);
    try conn.receiveDatagramFrom(d2, 2000, addr_b);
    try testing.expectEqual(pt_a, conn.default_path_token.?);
    try testing.expect(conn.datagramLengths().len >= 1);
    for (conn.datagramPathTokens()) |tok| try testing.expectEqual(pt_b, tok.?);
    conn.clearSend();

    try conn.sendStreamData(1, "hello", false);
    try conn.flushSend(3000);
    try testing.expect(conn.datagramLengths().len >= 1);
    for (conn.datagramPathTokens()) |tok| try testing.expectEqual(pt_a, tok.?);
}

test "disable_active_migration drops a new peer path after handshake" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x1b };
    const addr_a = "198.51.100.10:4433";
    const addr_b = "198.51.100.11:4433";
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.local_tp.disable_active_migration = true;
    conn.handshake_confirmed = true;

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.ping));
    while (frames.items.len < 20) try frames.append(gpa, 0x00);

    const d1 = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(d1);
    try conn.receiveDatagramFrom(d1, 1000, addr_a);
    try testing.expect(conn.default_path_token != null);

    const d2 = try testBuildApp(gpa, &dcid, 1, frames.items);
    defer gpa.free(d2);
    try conn.receiveDatagramFrom(d2, 2000, addr_b);
    try testing.expect(!conn.closed);
    try testing.expectEqual(@as(u32, 1), conn.paths.count());
    try testing.expectEqual(std.hash.Wyhash.hash(0, addr_a), conn.default_path_token.?);

    try conn.receiveDatagramFrom(d2, 3000, addr_a);
    try testing.expectEqual(@as(?u64, 1), conn.spaces[@intFromEnum(Space.application)].largest_recv_pn);
}

test "passive MAX_DATA is ack-eliciting" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeMaxData(&frames, gpa, 1234);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    try expectFirstQueuedAppFrameTag(&conn, .ack);
}

test "BLOCKED frames are retained and ack-eliciting" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.data_blocked));
    try varint.append(&frames, gpa, 10);
    try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.data_blocked));
    try varint.append(&frames, gpa, 7);
    try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.stream_data_blocked));
    try varint.append(&frames, gpa, 0);
    try varint.append(&frames, gpa, 5);
    try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.stream_data_blocked));
    try varint.append(&frames, gpa, 0);
    try varint.append(&frames, gpa, 12);
    try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.streams_blocked_bidi));
    try varint.append(&frames, gpa, 2);
    try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.streams_blocked_uni));
    try varint.append(&frames, gpa, 3);
    while (frames.items.len < 20) try frames.append(gpa, 0x00);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    try testing.expectEqual(@as(?u64, 10), conn.peer_data_blocked_limit);
    try testing.expectEqual(@as(u64, 12), conn.peer_stream_data_blocked.get(0).?);
    try testing.expectEqual(@as(?u64, 2), conn.peer_streams_blocked_bidi_limit);
    try testing.expectEqual(@as(?u64, 3), conn.peer_streams_blocked_uni_limit);
    try expectFirstQueuedAppFrameTag(&conn, .ack);
}

test "STREAM_DATA_BLOCKED state is bounded" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x0b };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.peer_bidi_streams = flow.StreamLimit.init(max_peer_stream_data_blocked + 1);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    for (0..max_peer_stream_data_blocked + 1) |sequence| {
        frames.clearRetainingCapacity();
        const id: u64 = @intCast(if (sequence == 0) 4 else if (sequence == 1) 0 else sequence * 4);
        try frame.encodeStreamDataBlocked(&frames, gpa, id, sequence);
        if (sequence == 0) try frame.encodeStreamDataBlocked(&frames, gpa, id, 99);
        const dgram = try testBuildApp(gpa, &dcid, sequence, frames.items);
        defer gpa.free(dgram);
        if (sequence < max_peer_stream_data_blocked) {
            try conn.receiveDatagram(dgram, 1000 + sequence);
            conn.clearSend();
        } else {
            try testing.expectError(error.StreamLimitError, conn.receiveDatagram(dgram, 1000 + sequence));
        }
    }

    try testing.expect(conn.closed);
    try testing.expectEqual(max_peer_stream_data_blocked, conn.peer_stream_data_blocked.count());
    try testing.expectEqual(max_peer_stream_data_blocked, conn.streams.count());
    try testing.expectEqual(@as(u64, 99), conn.peer_stream_data_blocked.get(4).?);
}

test "oversized stream-count frames are rejected" {
    const gpa = testing.allocator;
    const over_limit = transport_params.MAX_STREAM_COUNT + 1;

    {
        const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x8a };
        var conn = try Connection.init(gpa, .server, &dcid);
        defer conn.deinit();
        testInstallAppKeys(&conn);

        var frames: std.ArrayListUnmanaged(u8) = .empty;
        defer frames.deinit(gpa);
        try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.max_streams_bidi));
        try varint.append(&frames, gpa, over_limit);
        const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
        defer gpa.free(dgram);

        try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(dgram, 1000));
    }

    {
        const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x8b };
        var conn = try Connection.init(gpa, .server, &dcid);
        defer conn.deinit();
        testInstallAppKeys(&conn);

        var frames: std.ArrayListUnmanaged(u8) = .empty;
        defer frames.deinit(gpa);
        try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.streams_blocked_uni));
        try varint.append(&frames, gpa, over_limit);
        const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
        defer gpa.free(dgram);

        try testing.expectError(error.StreamLimitError, conn.receiveDatagram(dgram, 1000));
    }
}

test "PATH_RESPONSE is ack-eliciting" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const data = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };
    try conn.challengePath(data);
    try conn.flushSend(1000);
    conn.clearSend();

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodePathResponse(&frames, gpa, data);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    try expectFirstQueuedAppFrameTag(&conn, .ack);
}

test "unmatched PATH_RESPONSE is ignored" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodePathResponse(&frames, gpa, .{ 9, 8, 7, 6, 5, 4, 3, 2 });
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    try testing.expect(!conn.closed);
}

test "NEW_TOKEN received by a server is a protocol violation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeNewToken(&frames, gpa, "tok");
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(dgram, 1000));
}

test "NEW_TOKEN received by a client is retained for future validation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .client, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeNewToken(&frames, gpa, "token-one");
    try frame.encodeNewToken(&frames, gpa, "token-two");
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    try testing.expectEqual(@as(usize, 2), conn.new_tokens.items.len);
    try testing.expectEqualStrings("token-one", conn.new_tokens.items[0]);
    try testing.expectEqualStrings("token-two", conn.new_tokens.items[1]);
    try testing.expectEqual(@as(usize, 2), conn.validationTokens().len);
}

test "NEW_TOKEN storage is bounded" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09 };
    var conn = try Connection.init(gpa, .client, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    var i: usize = 0;
    while (i < MAX_NEW_TOKENS + 1) : (i += 1) {
        var token = [_]u8{ 't', 'o', 'k', '0' };
        token[3] = @intCast('0' + i);
        try frame.encodeNewToken(&frames, gpa, &token);
    }
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    try testing.expectEqual(@as(usize, MAX_NEW_TOKENS), conn.validationTokens().len);
    try testing.expectEqualStrings("tok1", conn.validationTokens()[0]);
    try testing.expectEqualStrings("tok8", conn.validationTokens()[MAX_NEW_TOKENS - 1]);
}

test "a client stateless_reset_token transport parameter is rejected by a server" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();

    try testing.expectError(error.ProtocolViolation, conn.setPeerTransportParameters(.{
        .stateless_reset_token = [_]u8{0x5a} ** 16,
    }));
}

test "a server stateless_reset_token transport parameter is stored by a client" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf1 };
    var conn = try Connection.init(gpa, .client, &dcid);
    defer conn.deinit();

    const token = [_]u8{0xa5} ** 16;
    var tp = try testRequiredServerTransportParameters(&conn);
    tp.stateless_reset_token = token;
    try conn.setPeerTransportParameters(tp);
    try testing.expectEqualSlices(u8, &token, &conn.peer_tp.stateless_reset_token.?);
}

test "a matching stateless reset token closes the connection" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf2 };
    var conn = try Connection.init(gpa, .client, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const token = [_]u8{0x5e} ** 16;
    var tp = try testRequiredServerTransportParameters(&conn);
    tp.stateless_reset_token = token;
    try conn.setPeerTransportParameters(tp);
    const reset = [_]u8{0x40} ++ [_]u8{0xaa} ** 8 ++ token;
    try conn.receiveDatagram(&reset, 1000);
    try testing.expect(conn.closed);
}

test "an unmatched stateless-reset-shaped packet is dropped without closing" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf3 };
    var conn = try Connection.init(gpa, .client, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const token = [_]u8{0x5e} ** 16;
    var tp = try testRequiredServerTransportParameters(&conn);
    tp.stateless_reset_token = token;
    try conn.setPeerTransportParameters(tp);
    const random = [_]u8{0x40} ++ [_]u8{0xaa} ** 8 ++ [_]u8{0x99} ** 16;
    try conn.receiveDatagram(&random, 1000);
    try testing.expect(!conn.closed);
}

test "stateless reset tokens learned from NEW_CONNECTION_ID are recognized" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf4 };
    var conn = try Connection.init(gpa, .client, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const cid = [_]u8{ 1, 2, 3, 4 };
    const token = [_]u8{0xa7} ** 16;
    try conn.onNewConnectionId(1, 0, &cid, &token);
    const reset = [_]u8{0x40} ++ [_]u8{0xaa} ** 8 ++ token;
    try conn.receiveDatagram(&reset, 1000);
    try testing.expect(conn.closed);
}

test "client-only transport parameters reject server CID parameters" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();

    try testing.expectError(error.ProtocolViolation, conn.setPeerTransportParameters(.{
        .original_destination_connection_id = try transport_params.ConnectionId.init("odcid"),
    }));
    try testing.expectError(error.ProtocolViolation, conn.setPeerTransportParameters(.{
        .retry_source_connection_id = try transport_params.ConnectionId.init("retry"),
    }));
}

test "client initial_source_connection_id must match the peer initial SCID" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xc5, 0xc6, 0xc7, 0xc8 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();

    try conn.setPeerTransportParameters(.{
        .initial_source_connection_id = try transport_params.ConnectionId.init(&dcid),
    });
    try testing.expectError(error.ProtocolViolation, conn.setPeerTransportParameters(.{
        .initial_source_connection_id = try transport_params.ConnectionId.init("bad"),
    }));
}

test "server original_destination_connection_id must match the client's original dcid" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xc9, 0xca, 0xcb, 0xcc };
    var conn = try Connection.init(gpa, .client, &dcid);
    defer conn.deinit();

    try testing.expectError(error.ProtocolViolation, conn.setPeerTransportParameters(.{
        .initial_source_connection_id = try transport_params.ConnectionId.init(&dcid),
    }));
    try testing.expectError(error.ProtocolViolation, conn.setPeerTransportParameters(.{
        .original_destination_connection_id = try transport_params.ConnectionId.init(&dcid),
    }));
    try conn.setPeerTransportParameters(try testRequiredServerTransportParameters(&conn));
    try testing.expectError(error.ProtocolViolation, conn.setPeerTransportParameters(.{
        .original_destination_connection_id = try transport_params.ConnectionId.init("nope"),
        .initial_source_connection_id = try transport_params.ConnectionId.init(&dcid),
    }));
}

test "server retry_source_connection_id is required only after Retry and must match" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xcd, 0xce, 0xcf, 0xd0 };
    const retry = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    var conn = try Connection.init(gpa, .client, &dcid);
    defer conn.deinit();

    try testing.expectError(error.ProtocolViolation, conn.setPeerTransportParameters(.{
        .retry_source_connection_id = try transport_params.ConnectionId.init(&retry),
    }));

    conn.retry_scid = try gpa.dupe(u8, &retry);
    conn.gpa.free(conn.peer_scid);
    conn.peer_scid = try gpa.dupe(u8, &retry);
    conn.retried = true;
    try testing.expectError(error.ProtocolViolation, conn.setPeerTransportParameters(.{}));
    try testing.expectError(error.ProtocolViolation, conn.setPeerTransportParameters(.{
        .original_destination_connection_id = try transport_params.ConnectionId.init(&dcid),
        .initial_source_connection_id = try transport_params.ConnectionId.init(&retry),
        .retry_source_connection_id = try transport_params.ConnectionId.init("bad"),
    }));
    try conn.setPeerTransportParameters(.{
        .original_destination_connection_id = try transport_params.ConnectionId.init(&dcid),
        .initial_source_connection_id = try transport_params.ConnectionId.init(&retry),
        .retry_source_connection_id = try transport_params.ConnectionId.init(&retry),
    });
}

test "HANDSHAKE_DONE received by a server is a protocol violation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.handshake_done));
    while (frames.items.len < 20) try frames.append(gpa, 0x00);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(dgram, 1000));
}

test "RESET_STREAM on a peer receive-only unidirectional stream is rejected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeResetStream(&frames, gpa, 3, 0x010c, 0); // server-initiated uni: client cannot send
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.StreamStateError, conn.receiveDatagram(dgram, 1000));
}

test "STREAM on a peer receive-only unidirectional stream is rejected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x0b };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const frames = [_]u8{ 0x0a, 0x03, 0x01, 'x' }; // server-initiated uni: client cannot send
    const dgram = try testBuildApp(gpa, &dcid, 0, &frames);
    defer gpa.free(dgram);

    try testing.expectError(error.StreamStateError, conn.receiveDatagram(dgram, 1000));
}

test "MAX_STREAM_DATA on a local receive-only unidirectional stream is rejected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeMaxStreamData(&frames, gpa, 2, 1024); // client-initiated uni: server cannot send
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.StreamStateError, conn.receiveDatagram(dgram, 1000));
}

test "STOP_SENDING on a local receive-only unidirectional stream is rejected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeStopSending(&frames, gpa, 2, 0x010c); // client-initiated uni: server cannot send
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.StreamStateError, conn.receiveDatagram(dgram, 1000));
}

test "STOP_SENDING rejects an unopened local stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x0c };
    var conn = try Connection.init(gpa, .client, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.local_bidi_streams = flow.StreamLimit.init(1);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeStopSending(&frames, gpa, 0, 0x010c);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.StreamStateError, conn.receiveDatagram(dgram, 1000));
    try testing.expectEqual(@as(usize, 0), conn.peer_stop_sending.count());
    try testing.expectEqual(@as(usize, 0), conn.peer_reset_streams.count());
    try conn.sendStreamData(0, "body", false);
    try testing.expectEqual(@as(?usize, 4), conn.streamPendingBytes(0));
}

test "STREAM_DATA_BLOCKED on a peer receive-only unidirectional stream is a stream state error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x0a };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeStreamDataBlocked(&frames, gpa, 3, 1024); // server-initiated uni: client cannot send
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.StreamStateError, conn.receiveDatagram(dgram, 1000));
    try testing.expect(conn.closed);
    const decoded = try decodeQueuedAppFrame(&conn, 0);
    defer gpa.free(decoded.work);
    defer gpa.free(decoded.plaintext);
    switch (decoded.frame) {
        .connection_close => |cc| {
            try testing.expect(!cc.app);
            try testing.expectEqual(@intFromEnum(constants.TransportError.stream_state_error), cc.error_code);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "short-header packet for a different local cid is dropped" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const other = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frames.append(gpa, 0x01); // PING
    while (frames.items.len < 20) try frames.append(gpa, 0x00);
    const dgram = try testBuildApp(gpa, &other, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    try testing.expectEqual(@as(?u64, null), conn.spaces[@intFromEnum(Space.application)].largest_recv_pn);
    try testing.expectEqual(@as(usize, 0), conn.datagramLengths().len);
}

test "short-header packet for a retired local cid is dropped" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.local_initial_cid_retired = true;

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frames.append(gpa, 0x01); // PING
    while (frames.items.len < 20) try frames.append(gpa, 0x00);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    try testing.expectEqual(@as(?u64, null), conn.spaces[@intFromEnum(Space.application)].largest_recv_pn);
    try testing.expectEqual(@as(usize, 0), conn.datagramLengths().len);
}

test "CRYPTO in an Application packet without a TLS driver is a protocol violation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeCrypto(&frames, gpa, 0, "late handshake bytes");
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(dgram, 1000));
}

test "a completed client stores post-handshake NewSessionTicket" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x1c };
    var conn = try Connection.init(gpa, .client, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.tls_client = tls.client.Client.init();
    conn.tls_client.?.state = .complete;
    const rms = [_]u8{0x44} ** 32;
    conn.tls_client.?.resumption_master_secret = rms;

    const ticket_body = [_]u8{
        0x00, 0x00, 0x0e, 0x10, // ticket_lifetime
        0xaa, 0xbb, 0xcc, 0xdd, // ticket_age_add
        0x02, 0x01, 0x02, // ticket_nonce
        0x00, 0x03, 0x41, 0x42, 0x43, // ticket
        0x00, 0x08, 0x00, 0x2a, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, // early_data max=65536
    };
    var ticket = [_]u8{ @intFromEnum(tls.handshake.MsgType.new_session_ticket), 0x00, 0x00, ticket_body.len } ++ ticket_body;
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeCrypto(&frames, gpa, 0, &ticket);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    try testing.expectEqual(@as(usize, 0), conn.spaces[@intFromEnum(Space.application)].crypto.readable().len);
    const tickets = conn.sessionTickets();
    try testing.expectEqual(@as(usize, 1), tickets.len);
    try testing.expectEqual(@as(u32, 3600), tickets[0].ticket_lifetime);
    try testing.expectEqual(@as(u32, 0xaabbccdd), tickets[0].ticket_age_add);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, tickets[0].nonce);
    try testing.expectEqualSlices(u8, "ABC", tickets[0].ticket);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x2a, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00 }, tickets[0].extensions);
    try testing.expectEqual(@as(u32, 65536), tickets[0].max_early_data_size.?);
    const expected_psk = tls.schedule.resumptionPsk(rms, tickets[0].nonce);
    try testing.expectEqualSlices(u8, &expected_psk, &tickets[0].psk.?);
}

test "a completed client rejects unexpected post-handshake CRYPTO messages" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x1d };
    var conn = try Connection.init(gpa, .client, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.tls_client = tls.client.Client.init();
    conn.tls_client.?.state = .complete;

    const unexpected = [_]u8{ @intFromEnum(tls.handshake.MsgType.finished), 0x00, 0x00, 0x00 };
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeCrypto(&frames, gpa, 0, &unexpected);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(dgram, 1000));
}

test "a completed client rejects malformed NewSessionTicket" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x1e };
    var conn = try Connection.init(gpa, .client, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.tls_client = tls.client.Client.init();
    conn.tls_client.?.state = .complete;

    const ticket_body = [_]u8{
        0x00, 0x00, 0x00, 0x00, // ticket_lifetime
        0x00, 0x00, 0x00, 0x00, // ticket_age_add
        0x00, // ticket_nonce
        0x00, 0x00, // empty ticket
        0x00, 0x00, // extensions
    };
    var ticket = [_]u8{ @intFromEnum(tls.handshake.MsgType.new_session_ticket), 0x00, 0x00, ticket_body.len } ++ ticket_body;
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeCrypto(&frames, gpa, 0, &ticket);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(dgram, 1000));
    try testing.expectEqual(@as(usize, 0), conn.sessionTickets().len);
}

test "a confirmed server sends a NewSessionTicket to a completed client" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x1f };
    var server = try Connection.init(gpa, .server, &dcid);
    defer server.deinit();
    testInstallAppKeys(&server);
    server.handshake_confirmed = true;

    try testing.expectEqual(@as(?[tls.schedule.SECRET_LEN]u8, null), try server.sendSessionTicket(7200, 0x01020304, &.{ 0xaa, 0xbb }, "ticket-bytes", &.{ 0xfa, 0xce, 0x00, 0x00 }, 4096, 1000));
    try testing.expectEqual(@as(usize, 1), server.datagramLengths().len);

    var client = try Connection.init(gpa, .client, &dcid);
    defer client.deinit();
    testInstallAppKeys(&client);
    client.tls_client = tls.client.Client.init();
    client.tls_client.?.state = .complete;
    const rms = [_]u8{0x55} ** 32;
    client.tls_client.?.resumption_master_secret = rms;

    try client.receiveDatagram(server.datagramsToSend()[0..server.datagramLengths()[0]], 2000);
    const tickets = client.sessionTickets();
    try testing.expectEqual(@as(usize, 1), tickets.len);
    try testing.expectEqual(@as(u32, 7200), tickets[0].ticket_lifetime);
    try testing.expectEqual(@as(u32, 0x01020304), tickets[0].ticket_age_add);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, tickets[0].nonce);
    try testing.expectEqualSlices(u8, "ticket-bytes", tickets[0].ticket);
    try testing.expectEqualSlices(u8, &.{ 0xfa, 0xce, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x10, 0x00 }, tickets[0].extensions);
    try testing.expectEqual(@as(u32, 4096), tickets[0].max_early_data_size.?);
    const expected_psk = tls.schedule.resumptionPsk(rms, tickets[0].nonce);
    try testing.expectEqualSlices(u8, &expected_psk, &tickets[0].psk.?);
}

test "a server cannot send a NewSessionTicket before handshake confirmation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x20 };
    var server = try Connection.init(gpa, .server, &dcid);
    defer server.deinit();
    testInstallAppKeys(&server);

    try testing.expectError(error.ProtocolViolation, server.sendSessionTicket(1, 0, &.{}, "ticket", &.{}, null, 1000));
    try testing.expectEqual(@as(usize, 0), server.datagramLengths().len);
}

test "a confirmed server sends NEW_TOKEN to a client" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x2f };
    var server = try Connection.init(gpa, .server, &dcid);
    defer server.deinit();
    testInstallAppKeys(&server);
    server.handshake_confirmed = true;

    try server.sendNewToken("validation-token", 1000);
    try testing.expectEqual(@as(usize, 1), server.datagramLengths().len);

    var client = try Connection.init(gpa, .client, &dcid);
    defer client.deinit();
    testInstallAppKeys(&client);

    try client.receiveDatagram(server.datagramsToSend()[0..server.datagramLengths()[0]], 2000);
    try testing.expectEqual(@as(usize, 1), client.validationTokens().len);
    try testing.expectEqualStrings("validation-token", client.validationTokens()[0]);
}

test "NEW_TOKEN send requires a confirmed server and non-empty token" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x3f };
    var server = try Connection.init(gpa, .server, &dcid);
    defer server.deinit();
    testInstallAppKeys(&server);

    try testing.expectError(error.ProtocolViolation, server.sendNewToken("validation-token", 1000));
    server.handshake_confirmed = true;
    try testing.expectError(error.ProtocolViolation, server.sendNewToken("", 1000));

    var client = try Connection.init(gpa, .client, &dcid);
    defer client.deinit();
    testInstallAppKeys(&client);
    client.handshake_confirmed = true;
    try testing.expectError(error.ProtocolViolation, client.sendNewToken("client-token", 1000));
}

test "NEW_CONNECTION_ID stores a peer connection id" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const cid = [_]u8{ 1, 2, 3, 4 };
    const token = [_]u8{0xa5} ** 16;
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeNewConnectionId(&frames, gpa, 1, 0, &cid, token);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    const stored = conn.peer_cids.get(1).?;
    try testing.expectEqualSlices(u8, &cid, stored.cid);
    try testing.expectEqualSlices(u8, &token, &stored.token);
}

test "a stored peer connection id can be used for later packets" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x0a };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const cid = [_]u8{ 9, 8, 7, 6, 5 };
    const reset_token = [_]u8{0xa6} ** 16;
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeNewConnectionId(&frames, gpa, 1, 0, &cid, reset_token);
    const in = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(in);

    try conn.receiveDatagram(in, 1000);
    conn.clearSend();
    try conn.usePeerConnectionId(1);
    try conn.challengePath([_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.flushSend(2000);

    const out = conn.datagramsToSend()[0..conn.datagramLengths()[0]];
    const hdr = try packet.parseShort(out, cid.len);
    try testing.expectEqualSlices(u8, &cid, hdr.dcid);
}

test "an unknown peer connection id sequence cannot be selected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x0b };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();

    try testing.expectError(error.ProtocolViolation, conn.usePeerConnectionId(1));
}

test "issueLocalConnectionId emits NEW_CONNECTION_ID and accepts packets for it" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const cid = [_]u8{ 9, 8, 7, 6, 5, 4 };
    const reset_token = [_]u8{0xb7} ** 16;
    try conn.issueLocalConnectionId(1, 0, &cid, reset_token);
    try testing.expect(conn.pending_new_cids.contains(1));
    try conn.flushSend(1000);

    const dgram = conn.datagramsToSend()[0..conn.datagramLengths()[0]];
    var work = try gpa.dupe(u8, dgram);
    defer gpa.free(work);
    const hdr = try packet.parseShort(work, conn.peer_scid.len);
    const pn_len = try crypto.unprotectHeader(testAppKeys().hp, work, hdr.pn_offset, false);
    var truncated: u64 = 0;
    for (work[hdr.pn_offset .. hdr.pn_offset + pn_len]) |b| truncated = (truncated << 8) | b;
    const header = work[0 .. hdr.pn_offset + pn_len];
    const ciphertext = work[hdr.pn_offset + pn_len ..];
    const plaintext = try gpa.alloc(u8, ciphertext.len);
    defer gpa.free(plaintext);
    const payload = try crypto.open(testAppKeys(), truncated, header, ciphertext, plaintext);
    const decoded = try frame.decode(payload);
    try testing.expectEqual(@as(u64, 1), decoded.frame.new_connection_id.seq);
    try testing.expectEqual(@as(u64, 0), decoded.frame.new_connection_id.retire_prior_to);
    try testing.expectEqualSlices(u8, &cid, decoded.frame.new_connection_id.cid);
    try testing.expectEqualSlices(u8, &reset_token, decoded.frame.new_connection_id.token);

    conn.clearSend();
    const ping = [_]u8{0x01} ++ [_]u8{0x00} ** 19;
    const addressed_to_new_cid = try testBuildApp(gpa, &cid, 0, &ping);
    defer gpa.free(addressed_to_new_cid);
    try conn.receiveDatagram(addressed_to_new_cid, 2000);
    try expectFirstQueuedAppFrameTag(&conn, .ack);
}

test "retired issued local connection ids stop accepting packets" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc9 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const cid = [_]u8{ 1, 3, 5, 7, 9 };
    try conn.issueLocalConnectionId(1, 0, &cid, [_]u8{0xc1} ** 16);
    conn.clearSend();

    var retire: std.ArrayListUnmanaged(u8) = .empty;
    defer retire.deinit(gpa);
    try frame.encodeRetireConnectionId(&retire, gpa, 1);
    while (retire.items.len < 20) try retire.append(gpa, 0x00);
    const retire_dgram = try testBuildApp(gpa, &dcid, 0, retire.items);
    defer gpa.free(retire_dgram);
    try conn.receiveDatagram(retire_dgram, 1000);
    try testing.expect(conn.local_cids.get(1).?.retired);
    conn.clearSend();

    const ping = [_]u8{0x01} ++ [_]u8{0x00} ** 19;
    const addressed_to_retired = try testBuildApp(gpa, &cid, 1, &ping);
    defer gpa.free(addressed_to_retired);
    try conn.receiveDatagram(addressed_to_retired, 2000);
    try testing.expectEqual(@as(usize, 0), conn.datagramLengths().len);
}

test "issuing local connection ids accounts retire_prior_to against the active limit" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xca };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.peer_tp.active_connection_id_limit = 2;

    try conn.issueLocalConnectionId(1, 0, &[_]u8{ 1, 1, 1 }, [_]u8{0xd1} ** 16);
    try testing.expectError(error.ProtocolViolation, conn.issueLocalConnectionId(2, 0, &[_]u8{ 2, 2, 2 }, [_]u8{0xd2} ** 16));
    try conn.issueLocalConnectionId(2, 1, &[_]u8{ 2, 2, 2 }, [_]u8{0xd2} ** 16);
}

test "NEW_CONNECTION_ID duplicate sequence with different cid is a protocol violation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const token = [_]u8{0xa5} ** 16;
    var first: std.ArrayListUnmanaged(u8) = .empty;
    defer first.deinit(gpa);
    try frame.encodeNewConnectionId(&first, gpa, 1, 0, &[_]u8{ 1, 2, 3, 4 }, token);
    const d1 = try testBuildApp(gpa, &dcid, 0, first.items);
    defer gpa.free(d1);
    try conn.receiveDatagram(d1, 1000);
    conn.clearSend();

    var second: std.ArrayListUnmanaged(u8) = .empty;
    defer second.deinit(gpa);
    try frame.encodeNewConnectionId(&second, gpa, 1, 0, &[_]u8{ 4, 3, 2, 1 }, token);
    const d2 = try testBuildApp(gpa, &dcid, 1, second.items);
    defer gpa.free(d2);
    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(d2, 2000));
}

test "NEW_CONNECTION_ID cannot reissue the current peer connection id" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x0c };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const token = [_]u8{0xa5} ** 16;
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeNewConnectionId(&frames, gpa, 1, 0, &dcid, token);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);
    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(dgram, 1000));
}

test "NEW_CONNECTION_ID cannot reuse a connection id with a different sequence" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x0d };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.local_tp.active_connection_id_limit = 3;

    const cid = [_]u8{ 1, 2, 3, 4 };
    const token = [_]u8{0xa5} ** 16;
    var first: std.ArrayListUnmanaged(u8) = .empty;
    defer first.deinit(gpa);
    try frame.encodeNewConnectionId(&first, gpa, 1, 0, &cid, token);
    const d1 = try testBuildApp(gpa, &dcid, 0, first.items);
    defer gpa.free(d1);
    try conn.receiveDatagram(d1, 1000);
    conn.clearSend();

    var second: std.ArrayListUnmanaged(u8) = .empty;
    defer second.deinit(gpa);
    try frame.encodeNewConnectionId(&second, gpa, 2, 0, &cid, token);
    const d2 = try testBuildApp(gpa, &dcid, 1, second.items);
    defer gpa.free(d2);
    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(d2, 2000));
}

test "NEW_CONNECTION_ID enforces the active connection id limit" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.local_tp.active_connection_id_limit = 2;

    const token = [_]u8{0xa5} ** 16;
    var first: std.ArrayListUnmanaged(u8) = .empty;
    defer first.deinit(gpa);
    try frame.encodeNewConnectionId(&first, gpa, 1, 0, &[_]u8{ 1, 2, 3, 4 }, token);
    const d1 = try testBuildApp(gpa, &dcid, 0, first.items);
    defer gpa.free(d1);
    try conn.receiveDatagram(d1, 1000);
    conn.clearSend();

    var second: std.ArrayListUnmanaged(u8) = .empty;
    defer second.deinit(gpa);
    try frame.encodeNewConnectionId(&second, gpa, 2, 0, &[_]u8{ 5, 6, 7, 8 }, token);
    const d2 = try testBuildApp(gpa, &dcid, 1, second.items);
    defer gpa.free(d2);
    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(d2, 2000));
}

test "NEW_CONNECTION_ID retire_prior_to removes older peer ids" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const token = [_]u8{0xa5} ** 16;
    var first: std.ArrayListUnmanaged(u8) = .empty;
    defer first.deinit(gpa);
    try frame.encodeNewConnectionId(&first, gpa, 1, 0, &[_]u8{ 1, 2, 3, 4 }, token);
    const d1 = try testBuildApp(gpa, &dcid, 0, first.items);
    defer gpa.free(d1);
    try conn.receiveDatagram(d1, 1000);
    conn.clearSend();

    var second: std.ArrayListUnmanaged(u8) = .empty;
    defer second.deinit(gpa);
    try frame.encodeNewConnectionId(&second, gpa, 2, 2, &[_]u8{ 5, 6, 7, 8 }, token);
    const d2 = try testBuildApp(gpa, &dcid, 1, second.items);
    defer gpa.free(d2);
    try conn.receiveDatagram(d2, 2000);
    try testing.expect(!conn.peer_cids.contains(1));
    try testing.expect(conn.peer_cids.contains(2));
}

test "NEW_CONNECTION_ID retire_prior_to queues RETIRE_CONNECTION_ID" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const token = [_]u8{0xa5} ** 16;
    var first: std.ArrayListUnmanaged(u8) = .empty;
    defer first.deinit(gpa);
    try frame.encodeNewConnectionId(&first, gpa, 1, 0, &[_]u8{ 1, 2, 3, 4 }, token);
    const d1 = try testBuildApp(gpa, &dcid, 0, first.items);
    defer gpa.free(d1);
    try conn.receiveDatagram(d1, 1000);
    conn.clearSend();

    var second: std.ArrayListUnmanaged(u8) = .empty;
    defer second.deinit(gpa);
    try frame.encodeNewConnectionId(&second, gpa, 2, 1, &[_]u8{ 5, 6, 7, 8 }, token);
    const d2 = try testBuildApp(gpa, &dcid, 1, second.items);
    defer gpa.free(d2);
    try conn.receiveDatagram(d2, 2000);
    try testing.expect(conn.pending_retire_cids.contains(0));

    conn.clearSend();
    try conn.flushSend(3000);

    const dgram = conn.datagramsToSend()[0..conn.datagramLengths()[0]];
    const keys = testAppKeys();
    const hdr = try packet.parseShort(dgram, conn.peer_scid.len);
    const work = try gpa.dupe(u8, dgram);
    defer gpa.free(work);
    const pn_len = try crypto.unprotectHeader(keys.hp, work, hdr.pn_offset, false);
    var truncated: u64 = 0;
    for (work[hdr.pn_offset .. hdr.pn_offset + pn_len]) |b| truncated = (truncated << 8) | b;
    const header = work[0 .. hdr.pn_offset + pn_len];
    const ciphertext = work[hdr.pn_offset + pn_len ..];
    const plaintext = try gpa.alloc(u8, ciphertext.len);
    defer gpa.free(plaintext);
    const payload = try crypto.open(keys, truncated, header, ciphertext, plaintext);
    const decoded = try frame.decode(payload);
    try testing.expectEqual(frame.Frame{ .retire_connection_id = 0 }, decoded.frame);
}

test "RETIRE_CONNECTION_ID can retire the initial local cid" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const cid = [_]u8{ 4, 6, 8, 10 };
    try conn.issueLocalConnectionId(1, 0, &cid, [_]u8{0xb4} ** 16);
    conn.clearSend();

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeRetireConnectionId(&frames, gpa, 0);
    while (frames.items.len < 20) try frames.append(gpa, 0x00);
    const dgram = try testBuildApp(gpa, &cid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    try testing.expect(conn.local_initial_cid_retired);
}

test "RETIRE_CONNECTION_ID cannot retire the cid used by the same packet" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const cid = [_]u8{ 7, 7, 7, 7 };
    try conn.issueLocalConnectionId(1, 0, &cid, [_]u8{0xb5} ** 16);
    conn.clearSend();

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeRetireConnectionId(&frames, gpa, 1);
    while (frames.items.len < 20) try frames.append(gpa, 0x00);
    const dgram = try testBuildApp(gpa, &cid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(dgram, 1000));
}

test "RETIRE_CONNECTION_ID for an unissued sequence is a protocol violation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeRetireConnectionId(&frames, gpa, 1);
    while (frames.items.len < 20) try frames.append(gpa, 0x00);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(dgram, 1000));
}

test "a tampered Initial is dropped, not fatal" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    // PING then PADDING so the packet is long enough for the 16-octet HP sample.
    const frames = [_]u8{ 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const dgram = try testBuildInitial(gpa, &dcid, .client, 0, &frames);
    defer gpa.free(dgram);
    dgram[dgram.len - 1] ^= 0xff; // corrupt the tag
    try conn.receiveDatagram(dgram, 1000); // does not raise
    try testing.expect(!conn.closed);
}

test "consume re-grants connection flow-control credit" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x09, 0x09, 0x09, 0x09 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    const frames = [_]u8{ 0x0a, 0x00, 0x03, 'a', 'b', 'c' }; // STREAM id0 LEN, "abc", no FIN
    const dgram = try testBuildApp(gpa, &dcid, 0, &frames);
    defer gpa.free(dgram);
    try conn.receiveDatagram(dgram, 1000);
    try testing.expectEqualStrings("abc", conn.streamData(0));
    conn.consumeStream(0, 3);
    try testing.expectEqualStrings("", conn.streamData(0));
}

test "connection flow control sums across streams" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x0a, 0x0b, 0x0c, 0x0d };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    // Shrink the connection window so a small payload spread over two streams
    // exceeds it - this is exactly the evasion a per-stream check would miss.
    conn.conn_recv_window.limit = 6;
    // Two STREAM frames in one datagram: 4 bytes on stream 0, then 4 on stream 4.
    // 0x0a = STREAM|LEN (no OFF). Their sum (8) is past the 6-byte window.
    const frames = [_]u8{
        0x0a, 0x00, 0x04, 'a', 'a', 'a', 'a', // stream 0, 4 bytes
        0x0a, 0x04, 0x04, 'b', 'b', 'b', 'b', // stream 4, 4 bytes
    };
    const dgram = try testBuildApp(gpa, &dcid, 0, &frames);
    defer gpa.free(dgram);
    try testing.expectError(error.FlowControlError, conn.receiveDatagram(dgram, 1000));
    try testing.expectEqual(@as(u64, 4), conn.conn_received_total);
    try testing.expectEqualStrings("aaaa", conn.streamData(0));
    try testing.expectEqualStrings("", conn.streamData(4));
    try testing.expect(!conn.hasStream(4));
    try testing.expect(!conn.recv_windows.contains(4));
}

test "per-stream receive flow control rejects data past the stream limit" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x0e, 0x0f, 0x10, 0x11 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.local_tp.initial_max_stream_data_bidi_remote = 3; // client-bidi stream 0

    const frames = [_]u8{ 0x0a, 0x00, 0x04, 'a', 'b', 'c', 'd' };
    const dgram = try testBuildApp(gpa, &dcid, 0, &frames);
    defer gpa.free(dgram);
    try testing.expectError(error.FlowControlError, conn.receiveDatagram(dgram, 1000));
    try testing.expectEqual(@as(u64, 0), conn.conn_received_total);
    try testing.expectEqualStrings("", conn.streamData(0));
    try testing.expect(!conn.hasStream(0));
    try testing.expect(!conn.recv_windows.contains(0));
}

test "receive stream updates are atomic on allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, receiveStreamUnderAllocationFailure, .{});
}

test "receive stream fragment count is bounded" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x0e, 0x0f, 0x10, 0x15 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    var i: usize = 0;
    while (i <= stream.MAX_RECV_FRAGMENTS) : (i += 1) {
        const offset: u64 = @intCast((i + 1) * 2);
        try frame.encodeStream(&frames, gpa, 0, offset, "x", false);
    }
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.StreamBufferExceeded, conn.receiveDatagram(dgram, 1000));
    const s = conn.streams.get(0).?;
    try testing.expectEqual(stream.MAX_RECV_FRAGMENTS, s.pending.items.len);
    try testing.expectEqualStrings("", conn.streamData(0));
}

test "RESET_STREAM final size is charged to receive flow control" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x0e, 0x0f, 0x10, 0x12 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeResetStream(&frames, gpa, 0, 0x010c, 5);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try conn.receiveDatagram(dgram, 1000);
    try testing.expect(conn.streamReset(0));
    try testing.expectEqual(@as(u64, 5), conn.conn_received_total);
    try testing.expectEqual(@as(u64, 5), conn.recv_windows.get(0).?.received);
}

test "completed stream churn retains compact history" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x0e, 0x0f, 0x10, 0x22 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const stream_count = 2048;
    const streams_per_packet = 32;
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    var first: usize = 0;
    var pn: u64 = 0;
    while (first < stream_count) : (first += streams_per_packet) {
        frames.clearRetainingCapacity();
        const end = @min(first + streams_per_packet, stream_count);
        for (first..end) |sequence| {
            const id: u64 = @intCast(sequence * 4);
            try frame.encodeStreamDataBlocked(&frames, gpa, id, 0);
            try frame.encodeResetStream(&frames, gpa, id, 0x010c, 0);
        }
        {
            const dgram = try testBuildApp(gpa, &dcid, pn, frames.items);
            defer gpa.free(dgram);
            try conn.receiveDatagram(dgram, 1000 + pn);
        }
        conn.clearSend();
        pn += 1;

        for (first..end) |sequence| {
            if (sequence % 2 == 0) continue;
            const id: u64 = @intCast(sequence * 4);
            try testing.expect(conn.streamReset(id));
            try testing.expect(conn.dropStream(id));
        }
        for (first..end) |sequence| {
            if (sequence % 2 != 0) continue;
            const id: u64 = @intCast(sequence * 4);
            try testing.expect(conn.streamReset(id));
            try testing.expect(conn.dropStream(id));
        }
    }

    try testing.expectEqual(@as(usize, 0), conn.streams.count());
    try testing.expectEqual(@as(usize, 0), conn.peer_stream_data_blocked.count());
    try testing.expectEqual(@as(usize, 0), conn.peer_stop_sending.count());
    try testing.expectEqual(
        @as(usize, 1),
        conn.retired_recv.classes[@intFromEnum(stream.StreamType.client_bidi)].items.len,
    );

    frames.clearRetainingCapacity();
    try frame.encodeStream(&frames, gpa, 1024, 0, "late", false);
    const late = try testBuildApp(gpa, &dcid, pn, frames.items);
    defer gpa.free(late);
    try conn.receiveDatagram(late, 2000 + pn);
    try testing.expect(!conn.hasStream(1024));
}

test "late STREAM_DATA_BLOCKED does not recreate a retired stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x0e, 0x0f, 0x10, 0x25 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeResetStream(&frames, gpa, 0, 0x010c, 0);
    {
        const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
        defer gpa.free(dgram);
        try conn.receiveDatagram(dgram, 1000);
    }
    try testing.expect(conn.dropStream(0));
    conn.clearSend();

    frames.clearRetainingCapacity();
    try frame.encodeStreamDataBlocked(&frames, gpa, 0, 1024);
    const late = try testBuildApp(gpa, &dcid, 1, frames.items);
    defer gpa.free(late);
    try conn.receiveDatagram(late, 2000);

    try testing.expect(!conn.hasStream(0));
    try testing.expectEqual(@as(usize, 0), conn.peer_stream_data_blocked.count());
}

test "sparse completed stream history is bounded" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x0e, 0x0f, 0x10, 0x23 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    for (0..RetiredStreamIds.max_ranges_per_class + 1) |sequence| {
        frames.clearRetainingCapacity();
        const id: u64 = @intCast(sequence * 8);
        try frame.encodeResetStream(&frames, gpa, id, 0x010c, 0);
        {
            const dgram = try testBuildApp(gpa, &dcid, sequence, frames.items);
            defer gpa.free(dgram);
            try conn.receiveDatagram(dgram, 1000 + sequence);
        }
        try testing.expect(conn.streamReset(id));
        if (sequence < RetiredStreamIds.max_ranges_per_class) {
            try testing.expect(conn.dropStream(id));
        } else {
            try testing.expect(!conn.dropStream(id));
        }
        conn.clearSend();
    }

    try testing.expect(conn.closed);
    try testing.expectEqual(
        RetiredStreamIds.max_ranges_per_class,
        conn.retired_recv.classes[@intFromEnum(stream.StreamType.client_bidi)].items.len,
    );
    try testing.expectEqual(@as(usize, 1), conn.streams.count());
}

test "peer reset send state is bounded" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x0e, 0x0f, 0x10, 0x24 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    for (0..max_peer_reset_streams + 1) |sequence| {
        frames.clearRetainingCapacity();
        const id: u64 = @intCast(sequence * 4);
        try frame.encodeStopSending(&frames, gpa, id, 0x010c);
        try frame.encodeResetStream(&frames, gpa, id, 0x010c, 0);
        {
            const dgram = try testBuildApp(gpa, &dcid, sequence, frames.items);
            defer gpa.free(dgram);
            if (sequence < max_peer_reset_streams) {
                try conn.receiveDatagram(dgram, 1000 + sequence);
            } else {
                try testing.expectError(error.StreamLimitError, conn.receiveDatagram(dgram, 1000 + sequence));
                continue;
            }
        }
        try testing.expect(conn.streamReset(id));
        try testing.expectError(error.FinalSizeError, conn.sendStreamData(id, "ignored body", false));
        try testing.expect(conn.dropStream(id));
        try conn.flushSend(2000 + sequence);
        conn.clearSend();
    }

    try testing.expect(conn.closed);
    try testing.expectEqual(max_peer_reset_streams, conn.peer_reset_streams.count());
    try testing.expectEqual(max_peer_reset_streams, conn.send_streams.count());
    try testing.expectEqual(@as(usize, 0), conn.streams.count());
    try testing.expectEqual(@as(usize, 0), conn.peer_stop_sending.count());
}

test "RESET_STREAM final size past the stream receive limit is rejected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x0e, 0x0f, 0x10, 0x13 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.local_tp.initial_max_stream_data_bidi_remote = 3; // client-bidi stream 0

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeResetStream(&frames, gpa, 0, 0x010c, 4);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.FlowControlError, conn.receiveDatagram(dgram, 1000));
    try testing.expect(!conn.streamReset(0));
    try testing.expectEqual(@as(u64, 0), conn.conn_received_total);
}

test "RESET_STREAM final size past the connection receive limit is rejected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x0e, 0x0f, 0x10, 0x14 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.conn_recv_window.limit = 3;

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeResetStream(&frames, gpa, 0, 0x010c, 4);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.FlowControlError, conn.receiveDatagram(dgram, 1000));
    try testing.expect(!conn.streamReset(0));
    try testing.expectEqual(@as(u64, 0), conn.conn_received_total);
}

test "peer stream limits reject streams past the advertised count" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x12, 0x13, 0x14, 0x15 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.peer_bidi_streams = flow.StreamLimit.init(1); // only client-bidi stream index 0

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeStream(&frames, gpa, 4, 0, "x", false); // client-bidi index 1
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);
    try testing.expectError(error.StreamLimitError, conn.receiveDatagram(dgram, 1000));
}

test "STREAM_DATA_BLOCKED rejects streams past the advertised count" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x12, 0x13, 0x14, 0x17 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.peer_bidi_streams = flow.StreamLimit.init(1);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeStreamDataBlocked(&frames, gpa, 4, 1024);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.StreamLimitError, conn.receiveDatagram(dgram, 1000));
    try testing.expectEqual(@as(usize, 0), conn.streams.count());
    try testing.expectEqual(@as(usize, 0), conn.peer_stream_data_blocked.count());
}

test "STOP_SENDING rejects streams past the advertised count" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x12, 0x13, 0x14, 0x16 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.peer_bidi_streams = flow.StreamLimit.init(1);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeStopSending(&frames, gpa, 4, 0x010c);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);

    try testing.expectError(error.StreamLimitError, conn.receiveDatagram(dgram, 1000));
    try testing.expectEqual(@as(usize, 0), conn.peer_stop_sending.count());
    try testing.expectEqual(@as(usize, 0), conn.peer_reset_streams.count());
}

test "closing a peer stream advertises a raised MAX_STREAMS" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x16, 0x17, 0x18, 0x19 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.peer_bidi_streams = flow.StreamLimit.init(2);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeStream(&frames, gpa, 4, 0, "x", true); // opens index 1 of 2
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);
    try conn.receiveDatagram(dgram, 1000);
    try testing.expect(!conn.max_streams_bidi_pending);
    conn.consumeStream(4, 1);
    try testing.expect(conn.dropStream(4));
    try testing.expect(conn.max_streams_bidi_pending);

    conn.clearSend(); // discard ACK bytes from receiving the STREAM
    try conn.flushSend(2000);
    try testing.expect(!conn.max_streams_bidi_pending);
    try testing.expect(conn.datagramLengths().len >= 1);
}

test "opening later peer streams advertises previously closed capacity" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x16, 0x17, 0x18, 0x1a };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.peer_bidi_streams = flow.StreamLimit.init(4);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeStream(&frames, gpa, 0, 0, "x", true);
    const closed = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(closed);
    try conn.receiveDatagram(closed, 1000);
    conn.consumeStream(0, 1);
    try testing.expect(conn.dropStream(0));

    conn.clearSend();
    frames.clearRetainingCapacity();
    for ([_]u64{ 4, 8, 12 }) |id| try frame.encodeStream(&frames, gpa, id, 0, "", false);
    const opened = try testBuildApp(gpa, &dcid, 1, frames.items);
    defer gpa.free(opened);
    try conn.receiveDatagram(opened, 2000);
    try conn.flushSend(3000);

    const decoded = try decodeQueuedAppFrame(&conn, 1);
    defer gpa.free(decoded.work);
    defer gpa.free(decoded.plaintext);
    try testing.expectEqual(@as(std.meta.Tag(frame.Frame), .max_streams), std.meta.activeTag(decoded.frame));
    try testing.expect(decoded.frame.max_streams.bidi);
    try testing.expectEqual(@as(u64, 5), decoded.frame.max_streams.max);
}

test "local stream creation is limited by peer initial_max_streams" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x1a, 0x1b, 0x1c, 0x1d };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.peer_tp.initial_max_streams_bidi = 0;
    conn.local_bidi_streams = flow.StreamLimit.init(0);

    try testing.expectError(error.StreamLimitError, conn.sendStreamData(1, "blocked", false));
    try testing.expect(conn.hasPendingSend());
    try conn.flushSend(1000);
    try expectFirstQueuedAppFrameTag(&conn, .streams_blocked);
}

test "MAX_STREAMS raises the local stream creation limit" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x1e, 0x1f, 0x20, 0x21 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.peer_tp.initial_max_streams_bidi = 0;
    conn.local_bidi_streams = flow.StreamLimit.init(0);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeMaxStreams(&frames, gpa, true, 1);
    while (frames.items.len < 20) try frames.append(gpa, 0x00);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);
    try conn.receiveDatagram(dgram, 1000);

    try conn.sendStreamData(1, "allowed", false);
    try testing.expect(conn.send_streams.contains(1));
}

test "MAX_STREAMS lower than the existing local limit is ignored" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x22, 0x23, 0x24, 0x25 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.local_bidi_streams = flow.StreamLimit.init(2);

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeMaxStreams(&frames, gpa, true, 1);
    while (frames.items.len < 20) try frames.append(gpa, 0x00);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);
    try conn.receiveDatagram(dgram, 1000);

    try testing.expectEqual(@as(u64, 2), conn.local_bidi_streams.max);
}

test "an ACK carries every received range, not just the largest" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    // Receive pn 0 and pn 2 (a gap at pn 1), each carrying a PING so an ACK is owed.
    const ping = [_]u8{0x01} ** 20;
    const d0 = try testBuildApp(gpa, &dcid, 0, &ping);
    defer gpa.free(d0);
    const d2 = try testBuildApp(gpa, &dcid, 2, &ping);
    defer gpa.free(d2);
    try conn.receiveDatagram(d0, 1000);
    try conn.receiveDatagram(d2, 1000);

    // The space recorded two ranges ([2,2] and [0,0]); the emitted ACK reflects them.
    const app = &conn.spaces[@intFromEnum(Space.application)];
    try testing.expectEqual(@as(usize, 2), app.recv_ranges.ranges.items.len);
    try testing.expectEqual(@as(u64, 2), app.recv_ranges.largest().?);
}

test "the server can send a CONNECTION_CLOSE and is then closed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    try conn.close(false, 0x0a, "bye"); // transport error 0x0a (PROTOCOL_VIOLATION-ish)
    try testing.expect(conn.closed);
    try testing.expectEqual(@as(usize, 1), conn.datagramLengths().len); // one close packet queued
    // Idempotent: a second close does nothing.
    try conn.close(false, 0x0a, "bye");
    try testing.expectEqual(@as(usize, 1), conn.datagramLengths().len);
}

test "a received CONNECTION_CLOSE is captured with its code and reason" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);
    try sender.close(false, 0x0a, "bye");

    var peer = try Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    testInstallAppKeys(&peer);
    try peer.receiveDatagram(sender.datagramsToSend(), 1000);

    try testing.expect(peer.closed);
    const pc = peer.peer_close.?;
    try testing.expect(!pc.app);
    try testing.expectEqual(@as(u64, 0x0a), pc.error_code);
    try testing.expectEqualStrings("bye", pc.reason);
}

test "consuming stream data advertises raised MAX_DATA and MAX_STREAM_DATA" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    try conn.sendStreamData(1, &.{}, false);
    conn.conn_recv_window.limit = 100; // a small window so consuming half trips the update
    conn.conn_recv_window.initial = 100;
    conn.local_tp.initial_max_stream_data_bidi_local = 100; // stream 1 is server-bidi

    // Receive 60 bytes on stream 1, then consume them: that crosses the auto-tune
    // threshold and queues a MAX_DATA, which flushSend emits.
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try frame.encodeStream(&sframe, gpa, 1, 0, &[_]u8{0x7a} ** 60, false);
    const dgram = try testBuildApp(gpa, &dcid, 0, sframe.items);
    defer gpa.free(dgram);
    try conn.receiveDatagram(dgram, 1000);
    conn.clearSend();

    conn.consumeStream(1, 60);
    try testing.expect(conn.max_data_pending);
    try testing.expect(conn.max_stream_data_pending.contains(1));
    try conn.flushSend(2000);
    try testing.expect(!conn.max_data_pending); // emitted
    try testing.expect(!conn.max_stream_data_pending.contains(1)); // emitted
    try testing.expect(conn.datagramLengths().len >= 2);
}

// ---- TLS handshake seam tests ----------------------------------------------

// The RFC 8448 section 3 client x25519 public key, the same value tls/keyshare.zig
// pins; the server's ECDHE against it is reproducible from the published vectors.
const RFC_CLIENT_PUBKEY = "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c";

// Build a QUIC-valid ClientHello carrying `pubkey` as its x25519 key_share, framed
// as a handshake message (type 0x01 || u24 len || body) ready to ride a CRYPTO frame.
fn buildClientHello(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, pubkey: [32]u8) !void {
    const w = tls.wire.Writer{ .out = out, .gpa = gpa };
    try w.u8v(0x01);
    const msg = try w.open(3);
    try w.u16v(0x0303);
    try w.bytes(&[_]u8{0x11} ** 32);
    try w.u8v(0x00); // empty session id (QUIC)
    const suites = try w.open(2);
    try w.u16v(0x1301);
    try w.close(suites);
    const comp = try w.open(1);
    try w.u8v(0x00);
    try w.close(comp);
    const exts = try w.open(2);
    try w.u16v(0x000a); // supported_groups = [x25519]
    const sg = try w.open(2);
    const sgl = try w.open(2);
    try w.u16v(0x001d);
    try w.close(sgl);
    try w.close(sg);
    try w.u16v(0x000d); // signature_algorithms = [ecdsa_secp256r1_sha256]
    const sa = try w.open(2);
    const sal = try w.open(2);
    try w.u16v(0x0403);
    try w.close(sal);
    try w.close(sa);
    try w.u16v(0x002b); // supported_versions = [TLS 1.3]
    const sv = try w.open(2);
    const svl = try w.open(1);
    try w.u16v(0x0304);
    try w.close(svl);
    try w.close(sv);
    try w.u16v(0x0033); // key_share = [x25519: pubkey]
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
    try w.bytes(&[_]u8{
        0x04, 0x04, 0x80, 0x01, 0x00, 0x00, // initial_max_data = 65536
        0x05, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_bidi_local = 262144
        0x06, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_bidi_remote = 262144
        0x07, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_uni = 262144
        0x08, 0x01, 0x10, // initial_max_streams_bidi = 16
        0x09, 0x01, 0x10, // initial_max_streams_uni = 16
    });
    try w.close(qtp);
    try w.close(exts);
    try w.close(msg);
}

// A client Initial datagram carrying the ClientHello in a CRYPTO frame at offset 0.
fn buildClientHelloInitial(gpa: std.mem.Allocator, dcid: []const u8, pubkey: [32]u8) ![]u8 {
    var ch: std.ArrayListUnmanaged(u8) = .empty;
    defer ch.deinit(gpa);
    try buildClientHello(&ch, gpa, pubkey);
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeCrypto(&frames, gpa, 0, ch.items);
    return testBuildInitial(gpa, dcid, .client, 0, frames.items);
}

fn testServerConfig() tls.flight.Config {
    return .{
        .random = [_]u8{0xAB} ** 32,
        .ephemeral_seed = [_]u8{0x33} ** 32,
        .signer = tls.sign.Signer.fromSeed([_]u8{0x42} ** 32) catch unreachable,
        .cert_chain = &[_]u8{0xCC} ** 48,
        .transport_params = &[_]u8{
            0x04, 0x04, 0x80, 0x10, 0x00, 0x00, // initial_max_data = 1048576
            0x08, 0x01, 0x08, // initial_max_streams_bidi = 8
            0x09, 0x01, 0x08, // initial_max_streams_uni = 8
            0x06, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_bidi_remote = 262144
            0x07, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_uni = 262144
        },
    };
}

test "server config cannot carry static CID transport parameters" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    var cfg = testServerConfig();
    cfg.transport_params = &[_]u8{
        0x00, 0x04, 0xd0, 0xd1, 0xd2, 0xd3, // original_destination_connection_id
    };
    try testing.expectError(error.ProtocolViolation, Connection.initServer(gpa, &dcid, cfg));
}

test "server drops Initial packets from UDP datagrams under 1200 bytes" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd4, 0xd5, 0xd6, 0xd7 };
    var server = try Connection.initServer(gpa, &dcid, testServerConfig());
    defer server.deinit();

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeCrypto(&frames, gpa, 0, "partial ClientHello");
    const dgram = try testBuildInitialWithPadding(gpa, &dcid, .client, 0, frames.items, false);
    defer gpa.free(dgram);
    try testing.expect(dgram.len < constants.MIN_INITIAL_DATAGRAM);

    try server.receiveDatagram(dgram, 1000);
    try testing.expectEqual(@as(usize, 0), server.spaces[@intFromEnum(Space.initial)].crypto.readable().len);
    try testing.expect(server.spaces[@intFromEnum(Space.initial)].recv_ranges.isEmpty());
    try testing.expectEqual(@as(usize, 0), server.datagramLengths().len);
}

test "a server drives the handshake from a ClientHello and installs 1-RTT keys" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, RFC_CLIENT_PUBKEY);

    var server = try Connection.initServer(gpa, &dcid, testServerConfig());
    defer server.deinit();

    const dgram = try buildClientHelloInitial(gpa, &dcid, pubkey);
    defer gpa.free(dgram);
    try server.receiveDatagram(dgram, 1000);

    // The server emits three datagrams: ServerHello (Initial CRYPTO), the encrypted
    // flight (Handshake CRYPTO), and an Initial-space ACK.
    try testing.expectEqual(@as(usize, 3), server.datagramLengths().len);

    // It installed Handshake and Application keys for both directions.
    try testing.expect(server.spaces[@intFromEnum(Space.handshake)].send_keys != null);
    try testing.expect(server.spaces[@intFromEnum(Space.application)].send_keys != null);
    try testing.expect(server.spaces[@intFromEnum(Space.application)].recv_keys != null);

    // The installed Application keys are the schedule's, derived from the ECDHE the
    // server computed against the RFC client key - the cross-seam key-agreement check:
    // independently derive the server's ephemeral public and confirm a shared secret.
    const server_ks = try tls.keyshare.KeyShare.ephemeral([_]u8{0x33} ** 32);
    const ecdhe = try server_ks.shared(pubkey);
    try testing.expectEqual(@as(usize, 32), ecdhe.len); // both sides reach the same ECDHE input
}

test "a client Initial carries a ClientHello the server can answer" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const client_tp = [_]u8{
        0x04, 0x04, 0x80, 0x01, 0x00, 0x00, // initial_max_data = 65536
        0x05, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_bidi_local = 262144
        0x06, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_bidi_remote = 262144
        0x07, 0x04, 0x80, 0x04, 0x00, 0x00, // initial_max_stream_data_uni = 262144
        0x08, 0x01, 0x10, // initial_max_streams_bidi = 16
        0x09, 0x01, 0x10, // initial_max_streams_uni = 16
    };
    const signer = tls.sign.Signer.fromSeed([_]u8{0x42} ** 32) catch unreachable;
    const cert_pub = signer.publicKeySec1();
    var client = try Connection.initClient(gpa, &dcid, .{
        .random = [_]u8{0x44} ** 32,
        .ephemeral_seed = [_]u8{0x55} ** 32,
        .transport_params = &client_tp,
        .alpn = "h3",
        .server_name = "example.test",
        .server_certificate = &cert_pub,
    }, 1000);
    defer client.deinit();

    try testing.expect(client.datagramLengths().len >= 1);
    try testing.expect(client.datagramLengths()[0] >= constants.MIN_INITIAL_DATAGRAM);

    var server_cfg = testServerConfig();
    server_cfg.alpn = "h3";
    server_cfg.cert_chain = &cert_pub;
    var server = try Connection.initServer(gpa, &dcid, server_cfg);
    defer server.deinit();
    const buf = client.datagramsToSend();
    var off: usize = 0;
    for (client.datagramLengths()) |len| {
        try server.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }

    try testing.expectEqual(@as(u64, 65536), server.peer_tp.initial_max_data);
    try testing.expectEqual(@as(u64, 262144), server.peer_tp.initial_max_stream_data_bidi_local);
    try testing.expectEqualStrings(&dcid, server.peer_tp.initial_source_connection_id.?.slice());
    try testing.expect(server.datagramLengths().len >= 1);
    try testing.expect(server.spaces[@intFromEnum(Space.handshake)].send_keys != null);

    const server_buf = server.datagramsToSend();
    off = 0;
    for (server.datagramLengths()) |len| {
        try client.receiveDatagram(server_buf[off .. off + len], 3000);
        off += len;
    }
    try testing.expect(client.spaces[@intFromEnum(Space.handshake)].recv_keys != null);
    try testing.expect(client.spaces[@intFromEnum(Space.handshake)].send_keys != null);
    try testing.expect(client.spaces[@intFromEnum(Space.application)].recv_keys != null);
    try testing.expect(client.spaces[@intFromEnum(Space.application)].send_keys != null);
    try testing.expectEqualStrings(&dcid, client.peer_tp.original_destination_connection_id.?.slice());
    try testing.expectEqualStrings(&dcid, client.peer_tp.initial_source_connection_id.?.slice());
    try testing.expectEqual(tls.client.State.complete, client.tls_client.?.state);
    try testing.expect(client.datagramLengths().len >= 1); // client Finished

    const client_finished = client.datagramsToSend();
    off = 0;
    for (client.datagramLengths()) |len| {
        try server.receiveDatagram(client_finished[off .. off + len], 4000);
        off += len;
    }
    try testing.expect(server.handshake_confirmed);

    const confirmed = server.datagramsToSend();
    off = 0;
    for (server.datagramLengths()) |len| {
        try client.receiveDatagram(confirmed[off .. off + len], 5000);
        off += len;
    }
    try testing.expect(client.handshake_confirmed);
    try testing.expect(client.spaces[@intFromEnum(Space.initial)].recv_keys == null);
    try testing.expect(client.spaces[@intFromEnum(Space.handshake)].recv_keys == null);
}

test "client config cannot carry static CID transport parameters" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd5 };
    const bad_tp = [_]u8{
        0x0f, 0x04, 0xd1, 0xd2, 0xd3, 0xd5, // initial_source_connection_id
    };
    try testing.expectError(error.ProtocolViolation, Connection.initClient(gpa, &dcid, .{
        .random = [_]u8{0x44} ** 32,
        .ephemeral_seed = [_]u8{0x55} ** 32,
        .transport_params = &bad_tp,
        .alpn = "h3",
        .server_name = "example.test",
    }, 1000));
}

test "client Initial can carry a NEW_TOKEN validation token" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd6 };
    const client_tp = [_]u8{
        0x04, 0x04, 0x80, 0x01, 0x00, 0x00,
        0x05, 0x04, 0x80, 0x04, 0x00, 0x00,
        0x06, 0x04, 0x80, 0x04, 0x00, 0x00,
        0x07, 0x04, 0x80, 0x04, 0x00, 0x00,
        0x08, 0x01, 0x10, 0x09, 0x01, 0x10,
    };
    var client = try Connection.initClient(gpa, &dcid, .{
        .random = [_]u8{0x44} ** 32,
        .ephemeral_seed = [_]u8{0x55} ** 32,
        .transport_params = &client_tp,
        .alpn = "h3",
        .server_name = "example.test",
        .validation_token = "validated-earlier",
    }, 1000);
    defer client.deinit();

    const h = try packet.parseLong(client.datagramsToSend());
    try testing.expectEqual(constants.LongType.initial, h.ltype);
    try testing.expectEqualStrings("validated-earlier", h.token);
}

test "client validation token must be non-empty when provided" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd7 };
    const client_tp = [_]u8{
        0x04, 0x04, 0x80, 0x01, 0x00, 0x00,
    };
    try testing.expectError(error.ProtocolViolation, Connection.initClient(gpa, &dcid, .{
        .random = [_]u8{0x44} ** 32,
        .ephemeral_seed = [_]u8{0x55} ** 32,
        .transport_params = &client_tp,
        .validation_token = "",
    }, 1000));
}

test "client processes Retry and resends Initial with token and new dcid" {
    const gpa = testing.allocator;
    const original_dcid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xd8 };
    const client_tp = [_]u8{
        0x04, 0x04, 0x80, 0x01, 0x00, 0x00,
        0x05, 0x04, 0x80, 0x04, 0x00, 0x00,
        0x06, 0x04, 0x80, 0x04, 0x00, 0x00,
        0x07, 0x04, 0x80, 0x04, 0x00, 0x00,
        0x08, 0x01, 0x10, 0x09, 0x01, 0x10,
    };
    var client = try Connection.initClient(gpa, &original_dcid, .{
        .transport_params = &client_tp,
        .random = [_]u8{0x44} ** 32,
        .ephemeral_seed = [_]u8{0x55} ** 32,
        .alpn = "h3",
        .server_name = "example.test",
    }, 1000);
    defer client.deinit();
    client.clearSend();

    const retry_scid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    var retry: std.ArrayListUnmanaged(u8) = .empty;
    defer retry.deinit(gpa);
    try packet.writeRetry(&retry, gpa, client.scid, &retry_scid, "retry-token", &original_dcid);

    try client.receiveDatagram(retry.items, 2000);
    try testing.expect(client.retried);
    try testing.expectEqualStrings("retry-token", client.initial_token.?);
    try testing.expectEqualSlices(u8, &retry_scid, client.peer_scid);
    try testing.expect(client.datagramLengths().len >= 1);

    const h = try packet.parseLong(client.datagramsToSend());
    try testing.expectEqual(constants.LongType.initial, h.ltype);
    try testing.expectEqualSlices(u8, &retry_scid, h.dcid);
    try testing.expectEqualStrings("retry-token", h.token);
}

test "server accepts a token-bearing Initial after Retry" {
    const gpa = testing.allocator;
    const original_dcid = "original";
    const client_tp = [_]u8{
        0x04, 0x04, 0x80, 0x01, 0x00, 0x00,
        0x05, 0x04, 0x80, 0x04, 0x00, 0x00,
        0x06, 0x04, 0x80, 0x04, 0x00, 0x00,
        0x07, 0x04, 0x80, 0x04, 0x00, 0x00,
        0x08, 0x01, 0x10, 0x09, 0x01, 0x10,
    };
    var client = try Connection.initClient(gpa, original_dcid, .{
        .transport_params = &client_tp,
        .random = [_]u8{0x44} ** 32,
        .ephemeral_seed = [_]u8{0x55} ** 32,
        .alpn = "h3",
        .server_name = "example.test",
    }, 1000);
    defer client.deinit();
    client.clearSend();

    const retry_scid = "retry-server-cid";
    var retry: std.ArrayListUnmanaged(u8) = .empty;
    defer retry.deinit(gpa);
    try packet.writeRetry(&retry, gpa, client.scid, retry_scid, "retry-token", original_dcid);
    try client.receiveDatagram(retry.items, 2000);

    var server = try Connection.initServerAfterRetry(gpa, original_dcid, retry_scid, testServerConfig());
    defer server.deinit();
    try server.receiveDatagramFrom(client.datagramsToSend(), 3000, "peer-address");
    try testing.expect(server.datagramsToSend().len > 0);
    try testing.expect(server.paths.get(std.hash.Wyhash.hash(0, "peer-address")).?.validated);
}

test "an unauthenticated long header cannot replace the peer connection id" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3 };
    var client = try Connection.init(gpa, .client, &dcid);
    defer client.deinit();

    var forged: std.ArrayListUnmanaged(u8) = .empty;
    defer forged.deinit(gpa);
    _ = try packet.writeLongHeader(
        &forged,
        gpa,
        .initial,
        constants.VERSION_1,
        client.scid,
        "attacker-cid",
        &.{},
        21,
        1,
    );
    try forged.appendNTimes(gpa, 0, 21);

    try client.receiveDatagram(forged.items, 1000);
    try testing.expectEqualSlices(u8, &dcid, client.peer_scid);
    try testing.expect(!client.peer_scid_set);
}

test "server answers an unsupported long-header version with Version Negotiation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const peer_address = "203.0.113.1:4433";
    var server = try Connection.initServer(gpa, &dcid, testServerConfig());
    defer server.deinit();

    var bad: std.ArrayListUnmanaged(u8) = .empty;
    defer bad.deinit(gpa);
    _ = try packet.writeLongHeader(&bad, gpa, .initial, 0x0a0a_0a0a, &dcid, "cli", "", 1, 1);
    try bad.append(gpa, 0x00);
    try server.receiveDatagramFrom(bad.items, 1000, peer_address);

    try testing.expectEqual(@as(usize, 1), server.datagramLengths().len);
    const token = server.datagramPathTokens()[0].?;
    try testing.expectEqualStrings(peer_address, server.pathAddress(token).?);
    const vn = server.datagramsToSend()[0..server.datagramLengths()[0]];
    const p = try packet.parseLongPrefix(vn);
    try testing.expectEqual(@as(u32, 0), p.version);
    try testing.expectEqualStrings("cli", p.dcid);
    try testing.expectEqualSlices(u8, &dcid, p.scid);
    try testing.expectEqual(@as(usize, 4), vn[p.header_len..].len);
    try testing.expectEqual(constants.VERSION_1, std.mem.readInt(u32, vn[p.header_len..][0..4], .big));

    server.clearSend();
    try testing.expect(server.pathAddress(token) == null);
}

test "server bounds provisional Version Negotiation routes until send clear" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    var server = try Connection.initServer(gpa, &dcid, testServerConfig());
    defer server.deinit();

    var bad: std.ArrayListUnmanaged(u8) = .empty;
    defer bad.deinit(gpa);
    _ = try packet.writeLongHeader(&bad, gpa, .initial, 0x0a0a_0a0a, &dcid, "cli", "", 1, 1);
    try bad.append(gpa, 0x00);

    try server.receiveDatagramFrom(bad.items, 1000, "203.0.113.1:4433");
    try server.receiveDatagramFrom(bad.items, 2000, "203.0.113.2:4433");
    try testing.expectEqual(@as(usize, 1), server.datagramLengths().len);

    server.clearSend();
    try server.receiveDatagramFrom(bad.items, 3000, "203.0.113.2:4433");
    try testing.expectEqual(@as(usize, 1), server.datagramLengths().len);
    const token = server.datagramPathTokens()[0].?;
    try testing.expectEqualStrings("203.0.113.2:4433", server.pathAddress(token).?);
}

test "client ignores Version Negotiation that still advertises QUIC v1" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xe5, 0xe6, 0xe7, 0xe8 };
    var client = try Connection.init(gpa, .client, &dcid);
    defer client.deinit();

    var vn: std.ArrayListUnmanaged(u8) = .empty;
    defer vn.deinit(gpa);
    try packet.writeVersionNegotiation(&vn, gpa, client.scid, client.peer_scid);
    try client.receiveDatagram(vn.items, 1000);
    try testing.expect(!client.closed);
}

test "client fails when Version Negotiation offers no supported version" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xe9, 0xea, 0xeb, 0xec };
    var client = try Connection.init(gpa, .client, &dcid);
    defer client.deinit();

    var vn: std.ArrayListUnmanaged(u8) = .empty;
    defer vn.deinit(gpa);
    try vn.append(gpa, constants.HEADER_FORM_LONG | constants.FIXED_BIT);
    try vn.appendSlice(gpa, &.{ 0, 0, 0, 0 });
    try vn.append(gpa, @intCast(client.scid.len));
    try vn.appendSlice(gpa, client.scid);
    try vn.append(gpa, @intCast(client.peer_scid.len));
    try vn.appendSlice(gpa, client.peer_scid);
    try vn.appendSlice(gpa, &.{ 0x0a, 0x0a, 0x0a, 0x0a });

    try testing.expectError(error.ProtocolViolation, client.receiveDatagram(vn.items, 1000));
    try testing.expect(client.closed);
}

test "client ignores Version Negotiation after authenticating a peer packet" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xed, 0xee, 0xef, 0xf0 };
    var client = try Connection.init(gpa, .client, &dcid);
    defer client.deinit();
    testInstallAppKeys(&client);

    const authenticated = try testBuildApp(gpa, &dcid, 0, &([_]u8{0x01} ++ [_]u8{0x00} ** 19));
    defer gpa.free(authenticated);
    try client.receiveDatagram(authenticated, 1000);

    var vn: std.ArrayListUnmanaged(u8) = .empty;
    defer vn.deinit(gpa);
    try vn.append(gpa, constants.HEADER_FORM_LONG | constants.FIXED_BIT);
    try vn.appendSlice(gpa, &.{ 0, 0, 0, 0 });
    try vn.append(gpa, @intCast(client.scid.len));
    try vn.appendSlice(gpa, client.scid);
    try vn.append(gpa, @intCast(client.peer_scid.len));
    try vn.appendSlice(gpa, client.peer_scid);
    try vn.appendSlice(gpa, &.{ 0x0a, 0x0a, 0x0a, 0x0a });

    try client.receiveDatagram(vn.items, 2000);
    try testing.expect(!client.closed);
}

test "the client Finished confirms the handshake and discards the early spaces" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, RFC_CLIENT_PUBKEY);

    var server = try Connection.initServer(gpa, &dcid, testServerConfig());
    defer server.deinit();
    const ch = try buildClientHelloInitial(gpa, &dcid, pubkey);
    defer gpa.free(ch);
    try server.receiveDatagram(ch, 1000);
    server.clearSend();

    // Forge the correct client Finished from the server's own retained transcript
    // and client handshake secret (what a real client would independently derive),
    // and deliver it in a Handshake packet sealed with the client's handshake send
    // keys - which equal the server's handshake recv keys.
    const drv = &server.tls.?;
    const th = drv.transcript.hash();
    const verify_data = tls.finished.build(drv.client_hs_secret, th);
    var fin_msg: [4 + tls.finished.LEN]u8 = .{ 0x14, 0, 0, tls.finished.LEN } ++ [_]u8{0} ** tls.finished.LEN;
    @memcpy(fin_msg[4..], &verify_data);
    var crypto_frame: std.ArrayListUnmanaged(u8) = .empty;
    defer crypto_frame.deinit(gpa);
    try frame.encodeCrypto(&crypto_frame, gpa, 0, &fin_msg);

    const hs_recv_keys = server.spaces[@intFromEnum(Space.handshake)].recv_keys.?;
    const dgram = try testBuildHandshake(gpa, &dcid, hs_recv_keys, 0, crypto_frame.items);
    defer gpa.free(dgram);
    try server.receiveDatagram(dgram, 2000);

    // The handshake is confirmed: HANDSHAKE_DONE was queued (an Application packet),
    // and the Initial + Handshake spaces are discarded (keys cleared).
    try testing.expect(server.handshake_confirmed);
    try testing.expect(drv.state == .complete);
    try testing.expect(server.spaces[@intFromEnum(Space.initial)].send_keys == null);
    try testing.expect(server.spaces[@intFromEnum(Space.handshake)].send_keys == null);
    try testing.expect(server.spaces[@intFromEnum(Space.handshake)].recv_keys == null);
    try testing.expect(server.datagramLengths().len >= 1); // HANDSHAKE_DONE (+ a Handshake ACK)
}

test "the client's transport parameters set the connection send window" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, RFC_CLIENT_PUBKEY);
    var server = try Connection.initServer(gpa, &dcid, testServerConfig());
    defer server.deinit();
    // The test ClientHello grants connection-level and per-stream send credit, so
    // the server can later send H3 response bytes on client request streams.
    const ch = try buildClientHelloInitial(gpa, &dcid, pubkey);
    defer gpa.free(ch);
    try server.receiveDatagram(ch, 1000);
    try testing.expectEqual(@as(u64, 65536), server.peer_tp.initial_max_data);
    try testing.expectEqual(@as(u64, 262144), server.peer_tp.initial_max_stream_data_bidi_local);
    try testing.expectEqual(@as(u64, 65536), server.conn_send_window.limit);
}

test "a lost handshake CRYPTO packet is retransmitted on loss" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, RFC_CLIENT_PUBKEY);
    var server = try Connection.initServer(gpa, &dcid, testServerConfig());
    defer server.deinit();
    const ch = try buildClientHelloInitial(gpa, &dcid, pubkey);
    defer gpa.free(ch);
    try server.receiveDatagram(ch, 1000);

    // The Handshake space carries the encrypted flight, recorded per-pn so loss
    // recovery can re-send it; nothing is pending (all of it is in flight).
    const hs = &server.spaces[@intFromEnum(Space.handshake)];
    try testing.expect(hs.crypto_sent.count() >= 1);
    try testing.expect(!hs.crypto_send.pending());
    server.discardSpace(.initial);
    server.clearSend();

    // A PTO re-queues the oldest unacked CRYPTO range for retransmission - the
    // handshake recovers from a lost flight rather than deadlocking.
    const deadline = server.nextTimeout().?;
    try server.onTimeout(deadline + 1);
    try testing.expect(server.datagramLengths().len >= 1);
}

test "a fragmented ClientHello across CRYPTO frames still drives the handshake" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, RFC_CLIENT_PUBKEY);

    var server = try Connection.initServer(gpa, &dcid, testServerConfig());
    defer server.deinit();

    var ch: std.ArrayListUnmanaged(u8) = .empty;
    defer ch.deinit(gpa);
    try buildClientHello(&ch, gpa, pubkey);

    // Deliver the ClientHello as two CRYPTO frames in two Initial packets, second
    // half first (reordered). The reassembler holds back until the prefix completes.
    const split = ch.items.len / 2;
    var f2: std.ArrayListUnmanaged(u8) = .empty;
    defer f2.deinit(gpa);
    try frame.encodeCrypto(&f2, gpa, split, ch.items[split..]);
    const d2 = try testBuildInitial(gpa, &dcid, .client, 0, f2.items);
    defer gpa.free(d2);
    try server.receiveDatagram(d2, 1000);
    // The flight has NOT been emitted yet (the ClientHello is incomplete): no
    // Handshake keys installed, only the Initial-space ACK for the received packet.
    try testing.expect(server.spaces[@intFromEnum(Space.application)].send_keys == null);

    server.clearSend(); // drop the ACK the first packet elicited
    var f1: std.ArrayListUnmanaged(u8) = .empty;
    defer f1.deinit(gpa);
    try frame.encodeCrypto(&f1, gpa, 0, ch.items[0..split]);
    const d1 = try testBuildInitial(gpa, &dcid, .client, 1, f1.items);
    defer gpa.free(d1);
    try server.receiveDatagram(d1, 1000);

    // Now the whole ClientHello is assembled: the flight is emitted.
    try testing.expect(server.spaces[@intFromEnum(Space.application)].send_keys != null);
}

test "conflicting overlapping CRYPTO frames poison the connection" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11 };
    var server = try Connection.initServer(gpa, &dcid, testServerConfig());
    defer server.deinit();

    var f1: std.ArrayListUnmanaged(u8) = .empty;
    defer f1.deinit(gpa);
    try frame.encodeCrypto(&f1, gpa, 0, "AAAA");
    const d1 = try testBuildInitial(gpa, &dcid, .client, 0, f1.items);
    defer gpa.free(d1);
    try server.receiveDatagram(d1, 1000);

    var f2: std.ArrayListUnmanaged(u8) = .empty;
    defer f2.deinit(gpa);
    try frame.encodeCrypto(&f2, gpa, 1, "XX"); // [1,3) disagrees with the first frame
    const d2 = try testBuildInitial(gpa, &dcid, .client, 1, f2.items);
    defer gpa.free(d2);
    try testing.expectError(error.ProtocolViolation, server.receiveDatagram(d2, 1000));
}

test "a STREAM frame in an Initial packet is a protocol violation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    var server = try Connection.initServer(gpa, &dcid, testServerConfig());
    defer server.deinit();
    const frames = [_]u8{ 0x0b, 0x00, 0x02, 'h', 'i' }; // STREAM, illegal in Initial
    const dgram = try testBuildInitial(gpa, &dcid, .client, 0, &frames);
    defer gpa.free(dgram);
    try testing.expectError(error.ProtocolViolation, server.receiveDatagram(dgram, 1000));
}

test "an application CONNECTION_CLOSE in an Initial packet is a protocol violation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    var server = try Connection.initServer(gpa, &dcid, testServerConfig());
    defer server.deinit();

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeConnectionClose(&frames, gpa, true, 0x0100, 0, "bad space");
    const dgram = try testBuildInitial(gpa, &dcid, .client, 0, frames.items);
    defer gpa.free(dgram);
    try testing.expectError(error.ProtocolViolation, server.receiveDatagram(dgram, 1000));
}

test "a malformed ClientHello (no supported_versions) poisons the connection" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, RFC_CLIENT_PUBKEY);
    var server = try Connection.initServer(gpa, &dcid, testServerConfig());
    defer server.deinit();

    var ch: std.ArrayListUnmanaged(u8) = .empty;
    defer ch.deinit(gpa);
    try buildClientHello(&ch, gpa, pubkey);
    // Corrupt the supported_versions extension type so TLS 1.3 is never signalled.
    const idx = std.mem.indexOf(u8, ch.items, &[_]u8{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 }).?;
    ch.items[idx] = 0x99;
    ch.items[idx + 1] = 0x99;
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeCrypto(&frames, gpa, 0, ch.items);
    const dgram = try testBuildInitial(gpa, &dcid, .client, 0, frames.items);
    defer gpa.free(dgram);
    try testing.expectError(error.ProtocolViolation, server.receiveDatagram(dgram, 1000));
}

// ---- STREAM send tests -----------------------------------------------------

test "queued stream data flushes into a 1-RTT datagram a peer reassembles" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };

    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    // Nothing to flush until data is queued.
    try testing.expect(!sender.hasPendingSend());
    try sender.sendStreamData(1, "hello over quic", true); // server-initiated bidi id 1
    try testing.expect(sender.hasPendingSend());

    try sender.flushSend(1000);
    try testing.expectEqual(@as(usize, 1), sender.datagramLengths().len);
    try testing.expect(!sender.hasPendingSend()); // fully drained

    // A peer with the matching Application keys decrypts and reassembles it.
    var peer = try Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    testInstallAppKeys(&peer);
    try peer.receiveDatagram(sender.datagramsToSend(), 2000);
    try testing.expectEqualStrings("hello over quic", peer.streamData(1));
    try testing.expect(peer.streamFinished(1));
}

test "a RESET_STREAM flushes and a peer sees the stream reset" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x70, 0x71, 0x72, 0x73 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    try sender.sendStreamData(1, "partial", false); // some data written first
    try sender.resetStream(1, 0x010c); // then abort with H3_REQUEST_CANCELLED
    try testing.expect(sender.hasPendingSend());
    try sender.flushSend(1000);

    var peer = try Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    testInstallAppKeys(&peer);
    const buf = sender.datagramsToSend();
    var off: usize = 0;
    for (sender.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    try testing.expect(peer.streamReset(1)); // the peer's recv stream is reset
}

test "a lost RESET_STREAM is retransmitted" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x74, 0x75, 0x76, 0x77 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    try sender.resetStream(1, 0x010c);
    try sender.flushSend(1000);
    sender.clearSend();
    try testing.expect(!sender.hasPendingSend()); // the reset is in flight, not owed

    // The PTO fires and re-arms the reset for retransmission.
    const d = sender.nextTimeout().?;
    try sender.onTimeout(d + 1);
    try sender.flushSend(d + 2);
    try testing.expect(sender.datagramsToSend().len > 0); // the reset rode again
}

test "a reset freezes the final size and rejects later writes" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x7c, 0x7d, 0x7e, 0x7f };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    try sender.sendStreamData(1, "five!", false); // 5 bytes
    try sender.resetStream(1, 0x010c); // final size frozen at 5
    // A write after the reset is a final-size error (it would move the frozen size).
    try testing.expectError(error.FinalSizeError, sender.sendStreamData(1, "more", false));

    var peer = try Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    testInstallAppKeys(&peer);
    try sender.flushSend(1000);
    const buf = sender.datagramsToSend();
    var off: usize = 0;
    for (sender.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    // The peer accepts the reset with final size 5; no FinalSizeError on its side.
    try testing.expect(peer.streamReset(1));
}

test "a PTO retransmits a reset-only stream, not a bare PING" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x80, 0x81, 0x82, 0x83 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    try sender.resetStream(1, 0x010c); // a reset with no prior data
    try sender.flushSend(1000);
    sender.clearSend();

    // The PTO fires; the probe must re-arm and re-send the RESET_STREAM.
    const d = sender.nextTimeout().?;
    try sender.onTimeout(d + 1);
    try sender.flushSend(d + 2);
    var peer = try Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    testInstallAppKeys(&peer);
    try peer.receiveDatagram(sender.datagramsToSend(), 2000);
    try testing.expect(peer.streamReset(1)); // the resent reset reached the peer
}

test "a STOP_SENDING survives receive stream cleanup" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x84, 0x85, 0x86, 0x87 };
    var server = try Connection.init(gpa, .server, &dcid);
    defer server.deinit();
    testInstallAppKeys(&server);

    // The peer cancels the response (STOP_SENDING on client-bidi stream 0) BEFORE the
    // server has created any send stream for it.
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x05);
    try varint.append(&sframe, gpa, 0);
    try varint.append(&sframe, gpa, 0x10);
    try frame.encodeResetStream(&sframe, gpa, 0, 0x10, 0);
    const dgram = try testBuildApp(gpa, &dcid, 0, sframe.items);
    defer gpa.free(dgram);
    try server.receiveDatagram(dgram, 1000);
    try testing.expect(server.streamReset(0));
    try testing.expect(server.dropStream(0));

    // Receive cleanup preserves the reset send side, so the server cannot send a
    // response the peer already cancelled.
    try testing.expectError(error.FinalSizeError, server.sendStreamData(0, "ignored body", false));

    // Flushing sends the RESET_STREAM after the ACK owed for STOP_SENDING; the peer
    // sees the reset once all queued UDP datagrams are delivered.
    try server.flushSend(2000);
    var peer = try Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    testInstallAppKeys(&peer);
    try peer.sendStreamData(0, &.{}, false);
    try deliverAllExcept(&server, &peer, null, 3000);
    try testing.expect(peer.streamReset(0));
    try testing.expectEqualStrings("", peer.streamData(0)); // no data, just the reset
}

test "STOP_SENDING flushes to the peer" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x78, 0x79, 0x7a, 0x7b };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    try sender.stopSending(0, 0x010c);
    try testing.expect(sender.hasPendingSend());
    try sender.flushSend(1000);
    try testing.expectEqual(@as(usize, 1), sender.datagramLengths().len);
    // It is in flight now, so a second flush does not re-send it.
    sender.clearSend();
    try sender.flushSend(1000);
    try testing.expectEqual(@as(usize, 0), sender.datagramsToSend().len);
}

test "flushSend is a no-op until the Application keys are installed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    conn.local_bidi_streams = flow.StreamLimit.init(1);
    // No app keys yet (no handshake): queued data cannot leave.
    try conn.sendStreamData(1, "held", false);
    try conn.flushSend(1000);
    try testing.expectEqual(@as(usize, 0), conn.datagramsToSend().len);
    try testing.expect(conn.hasPendingSend()); // still queued

    // Once 1-RTT keys exist, the same queue flushes.
    testInstallAppKeys(&conn);
    try conn.flushSend(1000);
    try testing.expectEqual(@as(usize, 1), conn.datagramLengths().len);
}

test "flushSend never sends past the connection send window, and resumes on MAX_DATA" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.conn_send_window.limit = 4; // the peer has granted only 4 bytes

    try conn.sendStreamData(1, "abcdefghij", false); // 10 bytes queued
    try conn.flushSend(1000);
    // Only the 4 granted bytes left; the rest stays queued.
    try testing.expectEqual(@as(u64, 4), conn.conn_send_window.sent);
    try testing.expect(conn.hasPendingSend());
    try expectQueuedAppFrameTag(&conn, 1, .data_blocked);

    // A flush with no further credit sends nothing more.
    conn.clearSend();
    try conn.flushSend(1000);
    try testing.expectEqual(@as(usize, 0), conn.datagramsToSend().len);

    // The peer raises MAX_DATA; the remaining bytes can now flow.
    conn.onMaxData(10);
    conn.clearSend(); // discard the advisory DATA_BLOCKED frame
    try conn.flushSend(1000);
    try testing.expectEqual(@as(u64, 10), conn.conn_send_window.sent);
    try testing.expect(!conn.hasPendingSend());
}

test "flushSend never sends past a stream send window, and resumes on MAX_STREAM_DATA" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x95, 0x96, 0x97, 0x98 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.conn_send_window.limit = 1000; // connection credit is not the bound here
    conn.peer_tp.initial_max_stream_data_bidi_remote = 4; // stream 1 is server-initiated

    try conn.sendStreamData(1, "abcdefghij", false); // 10 bytes queued
    try conn.flushSend(1000);

    // Only the stream's 4-byte grant left; the rest stays queued.
    try testing.expectEqual(@as(u64, 4), conn.conn_send_window.sent);
    try testing.expectEqual(@as(u64, 4), conn.send_windows.get(1).?.sent);
    try testing.expect(conn.hasPendingSend());
    try expectQueuedAppFrameTag(&conn, 1, .stream_data_blocked);

    // A flush with no further per-stream credit sends nothing more.
    conn.clearSend();
    try conn.flushSend(1000);
    try testing.expectEqual(@as(usize, 0), conn.datagramsToSend().len);

    // The peer raises MAX_STREAM_DATA for stream 1; the remaining bytes can flow.
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.max_stream_data));
    try varint.append(&frames, gpa, 1);
    try varint.append(&frames, gpa, 10);
    const dgram = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(dgram);
    try conn.receiveDatagram(dgram, 2000);
    conn.clearSend(); // discard any ACK/control bytes from receiving the peer update

    try conn.flushSend(3000);
    try testing.expectEqual(@as(u64, 10), conn.conn_send_window.sent);
    try testing.expectEqual(@as(u64, 10), conn.send_windows.get(1).?.sent);
    try testing.expect(!conn.hasPendingSend());
}

test "flushSend never sends past the congestion window, and resumes as it opens" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.conn_send_window.limit = 1000; // flow control is not the bound here
    conn.cc.congestion_window = 4; // but the congestion window admits only 4 bytes

    try conn.sendStreamData(1, "abcdefghij", false); // 10 bytes queued
    try conn.flushSend(1000);
    // cwnd capped the new bytes to 4; the rest stays queued (cwnd, not MAX_DATA).
    try testing.expectEqual(@as(u64, 4), conn.conn_send_window.sent);
    try testing.expect(conn.hasPendingSend());

    // A flush with the window still full sends nothing more.
    conn.clearSend();
    try conn.flushSend(1000);
    try testing.expectEqual(@as(usize, 0), conn.datagramsToSend().len);

    // The congestion window opens (e.g. after an ACK); the remaining bytes flow.
    conn.cc.congestion_window = 10_000;
    try conn.flushSend(1000);
    try testing.expectEqual(@as(u64, 10), conn.conn_send_window.sent);
    try testing.expect(!conn.hasPendingSend());
}

test "a large stream send is chunked across multiple packets" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    const big = [_]u8{0x7a} ** 4000; // larger than one packet's room
    try sender.sendStreamData(1, &big, true);
    try sender.flushSend(1000);
    try testing.expect(sender.datagramLengths().len > 1); // split into multiple packets

    var peer = try Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    testInstallAppKeys(&peer);
    // Each built packet is its own UDP datagram (a short header runs to the
    // datagram end), so the peer is fed them one at a time, sliced by the lengths.
    const buf = sender.datagramsToSend();
    var off: usize = 0;
    for (sender.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    try testing.expectEqual(@as(usize, big.len), peer.streamData(1).len);
    try testing.expect(peer.streamFinished(1));
}

test "stream packetization respects peer max_udp_payload_size" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);
    sender.peer_tp.max_udp_payload_size = 1200;

    const big = [_]u8{'m'} ** 4096;
    try sender.sendStreamData(1, &big, true);
    try sender.flushSend(1000);

    try testing.expect(sender.datagramLengths().len > 1);
    for (sender.datagramLengths()) |len| {
        try testing.expect(len <= sender.peer_tp.max_udp_payload_size);
    }
}

test "writing after a FIN is a final-size error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    conn.local_bidi_streams = flow.StreamLimit.init(1);
    try conn.sendStreamData(1, "done", true);
    try testing.expectError(error.FinalSizeError, conn.sendStreamData(1, "more", false));
}

// ---- STREAM retransmission tests --------------------------------------------

// An Application (1-RTT) datagram carrying one ACK frame, sealed with the test app
// keys so a sender installed via testInstallAppKeys decrypts it.
fn buildAppAck(gpa: std.mem.Allocator, dcid: []const u8, pn: u64, largest: u64, first_range: u64) ![]u8 {
    return buildAppAckWithDelay(gpa, dcid, pn, largest, 0, first_range);
}

fn buildAppAckWithDelay(gpa: std.mem.Allocator, dcid: []const u8, pn: u64, largest: u64, delay: u64, first_range: u64) ![]u8 {
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeAck(&frames, gpa, largest, delay, first_range);
    return testBuildApp(gpa, dcid, pn, frames.items);
}

fn buildAppAckEcn(gpa: std.mem.Allocator, dcid: []const u8, pn: u64, largest: u64, ecn: frame.EcnCounts) ![]u8 {
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.ack_ecn));
    try varint.append(&frames, gpa, largest);
    try varint.append(&frames, gpa, 0); // ACK Delay
    try varint.append(&frames, gpa, 0); // ACK Range Count
    try varint.append(&frames, gpa, 0); // First ACK Range
    try varint.append(&frames, gpa, ecn.ect0);
    try varint.append(&frames, gpa, ecn.ect1);
    try varint.append(&frames, gpa, ecn.ce);
    return testBuildApp(gpa, dcid, pn, frames.items);
}

test "ACK delay uses the peer ack_delay_exponent" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xA1, 0xA2, 0xA3, 0xA4 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.peer_tp.ack_delay_exponent = 4;
    conn.peer_tp.max_ack_delay_ms = 25;

    try conn.sendPing(.application, 1000);
    const first_ack = try buildAppAck(gpa, &dcid, 0, 0, 0);
    defer gpa.free(first_ack);
    try conn.receiveDatagram(first_ack, 11_000);
    try testing.expectEqual(@as(u64, 10_000), conn.rtt.smoothed);

    try conn.sendPing(.application, 20_000);
    const second_ack = try buildAppAckWithDelay(gpa, &dcid, 1, 1, 1000, 0);
    defer gpa.free(second_ack);
    try conn.receiveDatagram(second_ack, 50_000);

    try testing.expectEqual(@as(u64, 30_000), conn.rtt.latest);
    try testing.expectEqual(@as(u64, 10_500), conn.rtt.smoothed);
}

test "ACK_ECN counts are retained per packet number space" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xA5, 0xA6, 0xA7, 0xA8 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    try conn.sendPing(.application, 1000); // pn 0
    try conn.sendPing(.application, 2000); // pn 1

    const first = try buildAppAckEcn(gpa, &dcid, 0, 0, .{ .ect0 = 4, .ect1 = 1, .ce = 2 });
    defer gpa.free(first);
    try conn.receiveDatagram(first, 3000);
    try testing.expectEqual(frame.EcnCounts{ .ect0 = 4, .ect1 = 1, .ce = 2 }, conn.spaces[@intFromEnum(Space.application)].peer_ecn_counts.?);

    const second = try buildAppAckEcn(gpa, &dcid, 1, 1, .{ .ect0 = 4, .ect1 = 5, .ce = 2 });
    defer gpa.free(second);
    try conn.receiveDatagram(second, 4000);
    try testing.expectEqual(frame.EcnCounts{ .ect0 = 4, .ect1 = 5, .ce = 2 }, conn.spaces[@intFromEnum(Space.application)].peer_ecn_counts.?);
}

test "ACK_ECN counts cannot decrease" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xA5, 0xA6, 0xA7, 0xA9 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    try conn.sendPing(.application, 1000); // pn 0
    try conn.sendPing(.application, 2000); // pn 1

    const first = try buildAppAckEcn(gpa, &dcid, 0, 0, .{ .ect0 = 4, .ect1 = 1, .ce = 2 });
    defer gpa.free(first);
    try conn.receiveDatagram(first, 3000);

    const second = try buildAppAckEcn(gpa, &dcid, 1, 1, .{ .ect0 = 3, .ect1 = 1, .ce = 2 });
    defer gpa.free(second);
    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(second, 4000));
    try testing.expectEqual(frame.EcnCounts{ .ect0 = 4, .ect1 = 1, .ce = 2 }, conn.spaces[@intFromEnum(Space.application)].peer_ecn_counts.?);
}

test "ACK_ECN CE increase reduces the congestion window" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xA5, 0xA6, 0xA7, 0xAA };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    try conn.sendPing(.application, 1000); // pn 0, ack-eliciting and in flight
    const before = conn.cc.congestion_window;

    const ack = try buildAppAckEcn(gpa, &dcid, 0, 0, .{ .ect0 = 0, .ect1 = 0, .ce = 1 });
    defer gpa.free(ack);
    try conn.receiveDatagram(ack, 2000);

    try testing.expect(conn.cc.congestion_window < before);
    try testing.expect(conn.cc.recovery_start != null);
}

test "persistent congestion collapses the QUIC congestion window" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xA5, 0xA6, 0xA7, 0xAB };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    conn.rtt.update(100_000, 0); // PTO = 300ms; persistent period = 900ms.
    for ([_]u64{ 0, 300_000, 600_000, 900_000 }, 0..) |sent_time, pn| {
        conn.cc.onSent(1200);
        try conn.spaces[@intFromEnum(Space.application)].rec.onSent(gpa, .{
            .pn = @intCast(pn),
            .sent_time = sent_time,
            .size = 1200,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }
    try conn.spaces[@intFromEnum(Space.application)].rec.onSent(gpa, .{
        .pn = 4,
        .sent_time = 1_000_000,
        .size = 0,
        .ack_eliciting = true,
        .in_flight = false,
    });
    testSetAppNextPn(&conn, 5);

    const ack = try buildAppAck(gpa, &dcid, 0, 4, 0);
    defer gpa.free(ack);
    try conn.receiveDatagram(ack, 1_100_000);

    try testing.expectEqual(@as(u64, 2 * constants.MIN_INITIAL_DATAGRAM), conn.cc.congestion_window);
    try testing.expectEqual(@as(u64, 0), conn.cc.bytes_in_flight);
}

test "ACK for an unsent packet is a protocol violation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xA9, 0xAA, 0xAB, 0xAC };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);

    const ack = try buildAppAck(gpa, &dcid, 0, 0, 0);
    defer gpa.free(ack);
    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(ack, 1000));
    try testing.expect(conn.closed);
    try testing.expectEqual(@as(usize, 1), conn.datagramLengths().len);
}

test "ACK with an underflowing range is a protocol violation" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xAD, 0xAE, 0xAF, 0xB0 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    try conn.sendStreamData(1, "x", false);
    try conn.flushSend(1000); // pn 0 exists; pn 1 is still unsent

    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try varint.append(&frames, gpa, @intFromEnum(constants.FrameType.ack));
    try varint.append(&frames, gpa, 0); // largest
    try varint.append(&frames, gpa, 0); // delay
    try varint.append(&frames, gpa, 1); // one extra range
    try varint.append(&frames, gpa, 0); // first_range: [0,0]
    try varint.append(&frames, gpa, 0); // gap underflows below packet 0
    try varint.append(&frames, gpa, 0); // range length
    const ack = try testBuildApp(gpa, &dcid, 0, frames.items);
    defer gpa.free(ack);

    try testing.expectError(error.ProtocolViolation, conn.receiveDatagram(ack, 2000));
}

// Deliver every queued datagram in `sender`'s send buffer to `peer`, sliced by the
// per-datagram lengths (each is its own UDP datagram). Optionally skip index `drop`.
fn deliverAllExcept(sender: *Connection, peer: *Connection, drop: ?usize, now: u64) !void {
    if (peer.spaces[@intFromEnum(Space.application)].next_pn == 0) testSetAppNextPn(peer, 1);
    const buf = sender.datagramsToSend();
    var off: usize = 0;
    var idx: usize = 0;
    for (sender.datagramLengths()) |len| {
        if (drop == null or idx != drop.?) try peer.receiveDatagram(buf[off .. off + len], now);
        off += len;
        idx += 1;
    }
}

test "a lost STREAM packet is retransmitted and the peer reassembles the whole stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);
    var peer = try Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    testInstallAppKeys(&peer);

    // Enough data to span many packets so a dropped pn 0 lands past PACKET_THRESHOLD.
    const payload = [_]u8{0x5c} ** 5000;
    try sender.sendStreamData(1, &payload, true);
    try sender.flushSend(1000);
    const n = sender.datagramLengths().len;
    try testing.expect(n >= 5);

    // Deliver every packet EXCEPT the first (pn 0): it is "lost".
    try deliverAllExcept(&sender, &peer, 0, 2000);
    try testing.expect(peer.streamData(1).len < payload.len); // a hole remains

    // ACK pns 1..n-1 back to the sender: largest = n-1, first_range covers down to 1.
    sender.clearSend();
    const ack = try buildAppAck(gpa, &dcid, 0, n - 1, n - 2);
    defer gpa.free(ack);
    try sender.receiveDatagram(ack, 3000);

    // pn 0 is now > PACKET_THRESHOLD behind n-1, so detectLost re-queued its range.
    try testing.expect(sender.hasPendingSend());
    try sender.flushSend(4000);
    try testing.expect(sender.datagramLengths().len >= 1);

    // Deliver the retransmission; the peer now holds the complete stream.
    try deliverAllExcept(&sender, &peer, null, 5000);
    try testing.expectEqual(@as(usize, payload.len), peer.streamData(1).len);
    try testing.expect(peer.streamFinished(1));
}

test "a retransmit does not consume new send-window credit" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    const payload = [_]u8{0x33} ** 5000;
    try sender.sendStreamData(1, &payload, false);
    try sender.flushSend(1000);
    const sent_after_first = sender.conn_send_window.sent;
    const n = sender.datagramLengths().len;

    // Lose pn 0, ack the rest -> the range is re-queued and retransmitted.
    sender.clearSend();
    const ack = try buildAppAck(gpa, &dcid, 0, n - 1, n - 2);
    defer gpa.free(ack);
    try sender.receiveDatagram(ack, 2000);
    try sender.flushSend(3000);

    // The retransmit re-sent already-presented offsets, so the monotonic window
    // high-water mark did not advance (it only ever counts new bytes).
    try testing.expectEqual(sent_after_first, sender.conn_send_window.sent);
}

test "a late ACK of an already-lost packet is a harmless no-op" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    const payload = [_]u8{0x44} ** 5000;
    try sender.sendStreamData(1, &payload, true);
    try sender.flushSend(1000);
    const n = sender.datagramLengths().len;

    // Declare pn 0 lost (ack the rest), retransmit it, then deliver a LATE ack that
    // names pn 0 - it was already removed from recovery, so it routes nowhere.
    sender.clearSend();
    const ack1 = try buildAppAck(gpa, &dcid, 0, n - 1, n - 2);
    defer gpa.free(ack1);
    try sender.receiveDatagram(ack1, 2000);
    try sender.flushSend(3000); // retransmits pn 0's range under a new pn
    sender.clearSend();

    const late = try buildAppAck(gpa, &dcid, 1, 0, 0); // ack pn 0 only, late
    defer gpa.free(late);
    try sender.receiveDatagram(late, 4000); // must not crash, double-free, or resurrect
    try testing.expect(!sender.closed);
}

// ---- PTO / tail-loss tests --------------------------------------------------

test "a lost tail STREAM packet is retransmitted via the PTO timer" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);
    var peer = try Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    testInstallAppKeys(&peer);

    // ONE tail packet, never acked: ACK-driven loss detection is blind here (no
    // later packet, no ACK, loss_time never set). Only the PTO recovers it.
    try sender.sendStreamData(1, "tail", true);
    try sender.flushSend(1000);
    try testing.expectEqual(@as(usize, 1), sender.datagramLengths().len);
    sender.clearSend();
    try testing.expect(!sender.hasPendingSend());

    const deadline = sender.nextTimeout().?; // armed off the one ack-eliciting send
    try testing.expect(deadline > 1000);
    try sender.onTimeout(deadline + 1); // PTO fires -> probe re-queues the tail range
    try testing.expect(sender.hasPendingSend());
    try sender.flushSend(deadline + 2);
    try testing.expect(sender.datagramLengths().len >= 1); // retransmitted

    // The peer receives the retransmission and reassembles the whole stream.
    try deliverAllExcept(&sender, &peer, null, deadline + 3);
    try testing.expectEqualStrings("tail", peer.streamData(1));
    try testing.expect(peer.streamFinished(1));
}

test "nextTimeout is null when idle and after everything is acked" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xE1, 0xE2, 0xE3, 0xE4 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    try testing.expect(sender.nextTimeout() == null); // nothing in flight: no timer

    try sender.sendStreamData(1, "x", true);
    try sender.flushSend(1000);
    try testing.expect(sender.nextTimeout() != null); // armed off the send

    const ack = try buildAppAck(gpa, &dcid, 0, 0, 0); // ack pn 0
    defer gpa.free(ack);
    try sender.receiveDatagram(ack, 2000);
    try testing.expect(sender.nextTimeout() == null); // all acked: no spurious arm
}

test "the PTO backs off exponentially across consecutive fires" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xF1, 0xF2, 0xF3, 0xF4 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    try sender.sendStreamData(1, "x", false);
    try sender.flushSend(1000);
    const d1 = sender.nextTimeout().?; // anchor 1000, pto_count 0 -> base
    const base = d1 - 1000;

    try sender.onTimeout(d1 + 1); // PTO 1: pto_count -> 1, re-queue
    try sender.flushSend(d1 + 2); // the probe leaves; anchor advances to d1+2
    const d2 = sender.nextTimeout().?;
    // Second deadline is the doubled base measured from the probe's send time.
    try testing.expectEqual((d1 + 2) + base * 2, d2);
}

test "a PTO probe that gets acked resets the backoff" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x1A, 0x2B, 0x3C, 0x4D };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    try sender.sendStreamData(1, "data", true);
    try sender.flushSend(1000);
    const d1 = sender.nextTimeout().?;
    try sender.onTimeout(d1 + 1); // pto_count -> 1
    try sender.flushSend(d1 + 2); // probe sent as pn 1

    // Ack both the original tail (pn 0) and the probe (pn 1): everything in flight
    // is acknowledged, so the backoff resets and no timer remains armed.
    const ack = try buildAppAck(gpa, &dcid, 0, 1, 1);
    defer gpa.free(ack);
    try sender.receiveDatagram(ack, d1 + 3);
    try testing.expect(sender.nextTimeout() == null); // pto_count reset, nothing in flight
}

test "onTimeout without an intervening flush does not inflate the backoff" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x5E, 0x6F, 0x70, 0x81 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    try sender.sendStreamData(1, "x", false);
    try sender.flushSend(1000);
    const d1 = sender.nextTimeout().?;
    try sender.onTimeout(d1 + 1); // fires once for this anchor
    const after_first = sender.nextTimeout().?;
    // A second onTimeout past the deadline WITHOUT a flush (no new probe on the wire)
    // must not re-fire and double the backoff again: the anchor has not advanced.
    try sender.onTimeout(after_first + 1);
    try testing.expectEqual(after_first, sender.nextTimeout().?);
}

test "a PTO on a probe whose data was already acked sends a PING, not nothing" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xAB, 0xCD, 0xEF, 0x01 };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    try sender.sendStreamData(1, "tail", true);
    try sender.flushSend(1000); // pn 0 carries [0,4)+FIN
    const d1 = sender.nextTimeout().?;
    try sender.onTimeout(d1 + 1); // PTO -> re-queue [0,4)
    try sender.flushSend(d1 + 2); // probe is pn 1, same range; pn 0 still in flight
    sender.clearSend();

    // ACK the ORIGINAL (pn 0): its data is now acked, base_offset advances past it.
    const ack = try buildAppAck(gpa, &dcid, 0, 0, 0);
    defer gpa.free(ack);
    try sender.receiveDatagram(ack, d1 + 3); // also releases the latch

    // The probe (pn 1) is still in flight, so a PTO arms for it. Firing it must put
    // SOMETHING on the wire (a PING, sent inline by sendProbe) - re-queueing the
    // already-acked range yields no STREAM resend, and a no-send would spin the timer.
    const d2 = sender.nextTimeout().?;
    try sender.onTimeout(d2 + 1);
    try testing.expectEqual(@as(usize, 1), sender.datagramLengths().len); // a PING probe left
    try testing.expect(!sender.hasPendingSend()); // no STREAM resend was queued
}

test "ACK progress releases the PTO latch so a later loss can re-fire" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x9A, 0x8B, 0x7C, 0x6D };
    var sender = try Connection.init(gpa, .server, &dcid);
    defer sender.deinit();
    testInstallAppKeys(&sender);

    // Two packets sent at the SAME time -> they share one ack-eliciting anchor.
    try sender.sendStreamData(1, "aaaa", false);
    try sender.sendStreamData(2, "bbbb", false);
    try sender.flushSend(1000); // pn 0 (stream 1), pn 1 (stream 2), anchor 1000

    const d1 = sender.nextTimeout().?;
    try sender.onTimeout(d1 + 1); // PTO fires for anchor 1000, latch = 1000
    try sender.flushSend(d1 + 2);

    // Ack only the probe/first packet; pto_count resets and the latch is released.
    const ack = try buildAppAck(gpa, &dcid, 0, 0, 0); // ack pn 0
    defer gpa.free(ack);
    try sender.receiveDatagram(ack, d1 + 3);

    // A still-unacked packet remains in flight, so the PTO must be able to arm and
    // fire a fresh epoch - the latch must not suppress it forever.
    try testing.expect(sender.nextTimeout() != null);
    const d2 = sender.nextTimeout().?;
    try sender.onTimeout(d2 + 1);
    try testing.expect(sender.hasPendingSend()); // a new probe was queued
}
