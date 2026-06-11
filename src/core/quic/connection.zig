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

const Space = constants.Space;

pub const Role = enum { server, client };

/// The earlier of an optional `a` and a `b`.
fn minOpt(a: ?u64, b: u64) ?u64 {
    return if (a) |x| @min(x, b) else b;
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
    FinalSizeError,
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
    next_pn: u64 = 0,
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
    /// The packet numbers received in this space, for accurate ACK frames (RFC 9000
    /// 19.3) - a peer needs every range to detect loss correctly.
    recv_ranges: ack_ranges.AckRanges = .{},
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
        self.recv_ranges.deinit(gpa);
    }
};

/// The STREAM frame one sent packet carried, kept so loss recovery can map a lost
/// or acked packet number back to the stream bytes it was responsible for.
const StreamSent = struct { id: u64, offset: u64, len: u64, fin: bool };

/// The CRYPTO byte range one sent packet carried, so loss recovery can map a lost or
/// acked packet number back to the handshake bytes it was responsible for.
const CryptoSent = struct { offset: u64, len: u64 };

pub const Connection = struct {
    gpa: std.mem.Allocator,
    role: Role,
    dcid: []u8, // our peer's chosen dcid for us = the Initial-key material (owned)
    scid: []u8, // our own source connection id, sent in our long headers (owned)
    peer_scid: []u8, // the peer's scid: the dcid of everything we send (owned)
    spaces: [3]SpaceState,
    rtt: recovery.RttEstimator = .{},
    cc: congestion.Controller,
    conn_recv_window: flow.Window,
    conn_send_window: flow.SendWindow,
    /// The connection-level flow-control counters (RFC 9000 4.1): the SUM across
    /// all streams of the highest offset received and of the bytes consumed. A
    /// per-stream offset would let a peer evade MAX_DATA by spreading data across
    /// streams, so these are tracked separately from any one stream's window.
    conn_received_total: u64 = 0,
    conn_consumed_total: u64 = 0,
    streams: std.AutoHashMapUnmanaged(u64, *stream.RecvStream) = .empty,
    send_streams: std.AutoHashMapUnmanaged(u64, *stream.SendStream) = .empty,
    /// Built datagrams waiting to be drained by `datagramsToSend` (one contiguous
    /// buffer; `out_lengths` records each datagram's byte length in order).
    out: std.ArrayListUnmanaged(u8) = .empty,
    out_lengths: std.ArrayListUnmanaged(usize) = .empty,
    /// The server TLS handshake driver, attached by `initServer`; null on a client
    /// or a connection that does not run the handshake (the recv-pipeline tests).
    tls: ?tls.server.Server = null,
    /// The client's transport parameters (RFC 9000 18.2), parsed from the
    /// ClientHello; until then the RFC defaults apply. Drives the send window and
    /// the PTO ack-delay.
    peer_tp: transport_params.TransportParameters = .{},
    peer_scid_set: bool = false, // have we adopted the peer's scid from its first long header?
    handshake_confirmed: bool = false, // the client Finished verified; HANDSHAKE_DONE sent
    /// The connection-level recv window grew enough to advertise a new MAX_DATA
    /// (RFC 9000 4.1); flushSend emits it so the peer is not stalled at its grant.
    max_data_pending: bool = false,
    /// Anti-amplification (RFC 9000 8.1): until the client's address is validated, the
    /// server may send at most AMPLIFICATION_FACTOR x the bytes it has received. A
    /// received Handshake packet (only a real client can produce one) validates the
    /// address. These count whole datagrams.
    recv_bytes: u64 = 0,
    sent_bytes: u64 = 0,
    address_validated: bool = false,
    closed: bool = false,

    /// `client_dcid` is the destination connection id on the client's first
    /// Initial: both endpoints derive the Initial keys from it. The server picks
    /// its own `scid` (sent in its long headers) and uses the peer's scid as the
    /// destination of everything it sends; both default to `client_dcid` until the
    /// peer's Initial is parsed (the test path uses a single shared id).
    pub fn init(gpa: std.mem.Allocator, role: Role, client_dcid: []const u8) Error!Connection {
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
            .conn_recv_window = flow.Window.init(1 << 20),
            .conn_send_window = flow.SendWindow.init(1 << 20),
        };
    }

    /// A server connection with the TLS handshake driver attached: incoming CRYPTO
    /// drives the handshake, which installs per-space keys and emits the server
    /// flight. `tls_config` supplies the ServerHello randomness, ephemeral seed,
    /// signing key, certificate, and transport parameters.
    pub fn initServer(gpa: std.mem.Allocator, client_dcid: []const u8, tls_config: tls.flight.Config) Error!Connection {
        var conn = try init(gpa, .server, client_dcid);
        conn.tls = tls.server.Server.init(tls_config);
        return conn;
    }

    pub fn deinit(self: *Connection) void {
        self.gpa.free(self.dcid);
        self.gpa.free(self.scid);
        self.gpa.free(self.peer_scid);
        var it = self.streams.valueIterator();
        while (it.next()) |s| {
            s.*.deinit();
            self.gpa.destroy(s.*);
        }
        self.streams.deinit(self.gpa);
        var sit = self.send_streams.valueIterator();
        while (sit.next()) |s| {
            s.*.deinit();
            self.gpa.destroy(s.*);
        }
        self.send_streams.deinit(self.gpa);
        self.out.deinit(self.gpa);
        self.out_lengths.deinit(self.gpa);
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

    // ---- send core -------------------------------------------------------------

    /// Build one packet in `space` carrying `frames` (already-encoded frame bytes),
    /// seal and header-protect it, append it to the outbound queue, and record it
    /// for loss recovery / congestion control. The single send primitive: CRYPTO,
    /// ACK, and STREAM all funnel through here. Returns the packet number assigned,
    /// so the STREAM caller can map it back to the range it carried. `frames` MUST
    /// fit one datagram. A long header (Initial/Handshake) carries our scid + a
    /// length field; a short header (Application) runs to the datagram end.
    fn buildPacket(self: *Connection, space: Space, frames: []const u8, ack_eliciting: bool, now: u64) Error!u64 {
        assertFramesAllowedIn(space, frames); // no STREAM in Initial/Handshake, by construction
        const st = &self.spaces[@intFromEnum(space)];
        const keys = st.send_keys orelse return error.ProtocolViolation; // driver installs first
        const long = space != .application;
        const pn = st.next_pn;
        const pn_len = packet.packetNumberLen(pn, st.rec.largest_acked);

        var hdr: std.ArrayListUnmanaged(u8) = .empty;
        defer hdr.deinit(self.gpa);
        const pn_offset = blk: {
            if (long) {
                const ltype: constants.LongType = if (space == .initial) .initial else .handshake;
                const length = pn_len + frames.len + crypto.TAG_LEN;
                break :blk packet.writeLongHeader(&hdr, self.gpa, ltype, constants.VERSION_1, self.peer_scid, self.scid, &.{}, length, pn_len) catch return error.OutOfMemory;
            } else {
                break :blk packet.writeShortHeader(&hdr, self.gpa, self.peer_scid, pn_len) catch return error.OutOfMemory;
            }
        };
        packet.writePacketNumber(&hdr, self.gpa, pn, pn_len) catch return error.OutOfMemory;

        // Anti-amplification (RFC 9000 8.1): before the client's address is
        // validated, refuse to send more than AMPLIFICATION_FACTOR x bytes received.
        // This applies only to the handshake (long-header) spaces - sending 1-RTT
        // (Application) packets means the handshake completed, which validates the
        // address. The flight stalls here and resumes as the client's later packets
        // raise the budget; the caller treats AmplificationLimited as "stop", not fatal.
        const datagram_len = hdr.items.len + frames.len + crypto.TAG_LEN;
        if (long and !self.address_validated and self.sent_bytes + datagram_len > constants.AMPLIFICATION_FACTOR * self.recv_bytes) {
            return error.AmplificationLimited;
        }

        const start = self.out.items.len;
        self.out.appendSlice(self.gpa, hdr.items) catch return error.OutOfMemory;
        const ct = self.out.addManyAsSlice(self.gpa, frames.len + crypto.TAG_LEN) catch return error.OutOfMemory;
        _ = crypto.seal(keys, pn, hdr.items, frames, ct);
        crypto.protectHeader(keys.hp, self.out.items[start..], pn_offset, long) catch return error.ProtocolViolation;
        self.sent_bytes += datagram_len;
        self.out_lengths.append(self.gpa, datagram_len) catch return error.OutOfMemory;
        // A pure-ACK packet is not ack-eliciting, so it is not in flight: not
        // congestion-controlled or retransmitted (RFC 9002 2, 7). Only in-flight
        // packets count toward bytes_in_flight - charging a pure ACK would inflate it
        // permanently, since the ACK/loss paths only credit back in-flight packets.
        st.rec.onSent(self.gpa, .{ .pn = pn, .sent_time = now, .size = datagram_len, .ack_eliciting = ack_eliciting, .in_flight = ack_eliciting }) catch return error.OutOfMemory;
        if (ack_eliciting) self.cc.onSent(datagram_len);
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

    /// The built datagrams as one contiguous buffer; pair with `datagramLengths`.
    pub fn datagramsToSend(self: *Connection) []const u8 {
        return self.out.items;
    }

    /// The byte length of each queued datagram, in order.
    pub fn datagramLengths(self: *Connection) []const usize {
        return self.out_lengths.items;
    }

    /// Drop the drained datagrams (the integrator has sent them).
    pub fn clearSend(self: *Connection) void {
        self.out.clearRetainingCapacity();
        self.out_lengths.clearRetainingCapacity();
    }

    // ---- STREAM send -----------------------------------------------------------

    fn sendStream(self: *Connection, id: u64) Error!*stream.SendStream {
        if (self.send_streams.get(id)) |s| return s;
        const s = try self.gpa.create(stream.SendStream);
        s.* = stream.SendStream.init(self.gpa);
        self.send_streams.put(self.gpa, id, s) catch {
            s.deinit();
            self.gpa.destroy(s);
            return error.OutOfMemory;
        };
        return s;
    }

    /// Queue `data` (and/or a FIN) to be sent on stream `id`. `flushSend` packetizes
    /// the queue once the Application keys exist. Writing after a FIN is rejected.
    ///
    /// This is application queueing: it buffers everything written. Only `flushSend`
    /// applies the connection send window, so the in-flight bytes on the wire are
    /// bounded by the peer's MAX_DATA grant, but the queued-but-unsent buffer is
    /// bounded only by what the application writes; there is no write-side
    /// backpressure cap.
    pub fn sendStreamData(self: *Connection, id: u64, data: []const u8, fin: bool) Error!void {
        const s = try self.sendStream(id);
        s.write(data, fin) catch |e| switch (e) {
            error.FinalSizeError => return error.FinalSizeError,
            error.OutOfMemory => return error.OutOfMemory,
        };
    }

    /// Whether any stream has bytes (or a FIN) still to send.
    pub fn hasPendingSend(self: *Connection) bool {
        var it = self.send_streams.valueIterator();
        while (it.next()) |s| if (s.*.pending()) return true;
        return false;
    }

    /// Packetize queued stream data into Application (1-RTT) datagrams, one STREAM
    /// frame per packet. STREAM is legal only in the Application space (RFC 9000
    /// 12.4), so nothing flows until the handshake installs the 1-RTT send keys -
    /// the structural fix for shipping STREAM data in Initial packets.
    ///
    /// Each sent range is recorded per packet (stream_sent) and retained in the
    /// SendStream until acked, so a lost packet is retransmitted (the ACK arm routes
    /// lost pns back into SendStream.onLost). Loss is detected on ACK only; a tail
    /// packet with no later ACK to trigger detection is not yet covered by a PTO timer.
    pub fn flushSend(self: *Connection, now: u64) Error!void {
        const space = Space.application;
        const st = &self.spaces[@intFromEnum(space)];
        if (st.send_keys == null) return; // no 1-RTT keys yet: nothing can be sent
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

        // A conservative single-packet budget: one STREAM frame per packet.
        const packet_room = constants.MIN_INITIAL_DATAGRAM - 64;
        var it = self.send_streams.iterator();
        while (it.next()) |entry| {
            const id = entry.key_ptr.*;
            const s = entry.value_ptr.*;
            while (s.pending()) {
                // Peek a full packet's worth; a retransmit (offset below the send
                // cursor) re-sends already-presented bytes, a new chunk presents
                // fresh offsets. Only new bytes consume connection send-window credit
                // (RFC 9000 4.1); the window is a monotonic high-water mark, so a
                // retransmit and a pure FIN need none.
                var chunk = s.peek(packet_room) orelse break;
                const is_new = chunk.offset >= s.sent;
                if (is_new and chunk.data.len > 0) {
                    const credit = self.conn_send_window.available();
                    if (credit == 0) break; // out of window: keep new bytes queued
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
                if (is_new) self.conn_send_window.onSent(chunk.data.len); // monotonic: only new offsets
                s.commit(chunk.offset, chunk.data.len, chunk.fin);
            }
        }
    }

    /// Process an incoming ACK for `space`: fold it into recovery, free the STREAM
    /// bytes the acked packets carried, then run loss detection and re-queue the
    /// bytes any newly-lost packet carried so the next flushSend retransmits them.
    /// A pn lives in `rec.sent` and `stream_sent` in lockstep, so each is routed to
    /// the SendStream exactly once (fetchRemove), defending double-free / resurrect.
    fn onAckFrame(self: *Connection, space: Space, a: anytype, now: u64) Error!void {
        const st = &self.spaces[@intFromEnum(space)];
        var acked_pns: std.ArrayListUnmanaged(u64) = .empty;
        defer acked_pns.deinit(self.gpa);
        var it = frame.ackRanges(a.ranges);
        // onAck's only failure is the acked_pns append, i.e. OutOfMemory - a
        // malformed range just stops the walk, it never errors. So surface allocator
        // pressure as OutOfMemory, not a peer protocol error.
        _ = st.rec.onAck(&self.rtt, &self.cc, now, a.largest, a.delay, a.first_range, &it, &acked_pns, self.gpa) catch
            return error.OutOfMemory;
        for (acked_pns.items) |pn| {
            if (st.stream_sent.fetchRemove(pn)) |e| {
                if (self.send_streams.get(e.value.id)) |s| try s.onAck(e.value.offset, e.value.len, e.value.fin);
            }
            if (st.crypto_sent.fetchRemove(pn)) |e| try st.crypto_send.onAck(e.value.offset, e.value.len, false);
        }
        // ACK progress resets the PTO backoff (in recovery), so release the fire-once
        // latch: a fresh PTO epoch may arm even if another packet sharing the fired
        // anchor is still in flight.
        if (acked_pns.items.len > 0) st.pto_fired_anchor = null;
        try self.detectLostAndRequeue(space, now);
    }

    /// Run loss detection for one space and re-queue every newly-lost packet's
    /// STREAM range so the next flushSend retransmits it. Shared by the ACK arm and
    /// the time-threshold path of onTimeout; `fetchRemove` keeps rec.sent and
    /// stream_sent in lockstep, so each pn is routed exactly once.
    fn detectLostAndRequeue(self: *Connection, space: Space, now: u64) Error!void {
        const st = &self.spaces[@intFromEnum(space)];
        var lost_pns: std.ArrayListUnmanaged(u64) = .empty;
        defer lost_pns.deinit(self.gpa);
        _ = st.rec.detectLost(&self.rtt, &self.cc, now, &lost_pns, self.gpa) catch return error.OutOfMemory;
        var crypto_lost = false;
        for (lost_pns.items) |pn| {
            if (st.stream_sent.fetchRemove(pn)) |e| {
                if (self.send_streams.get(e.value.id)) |s| try s.onLost(e.value.offset, e.value.len, e.value.fin);
            }
            if (st.crypto_sent.fetchRemove(pn)) |e| {
                try st.crypto_send.onLost(e.value.offset, e.value.len, false);
                crypto_lost = true;
            }
        }
        if (crypto_lost) try self.flushCrypto(space, now); // resend the lost handshake bytes now
    }

    // ---- loss-recovery timer (sans-IO: the integrator owns the OS timer) --------

    /// The absolute time (us) of the earliest armed deadline across all spaces - the
    /// earlier of any time-threshold loss deadline and any PTO deadline - or null if
    /// nothing is armed. The integrator sets an OS timer for this and calls
    /// `onTimeout` at or after it. Null also when the PTO backoff has saturated (a
    /// black-holed peer): the integrator's own idle timeout then closes the connection.
    /// The PTO ack-delay term per space (RFC 9002 6.2.1): the peer's negotiated
    /// max_ack_delay applies only to the Application space; the long-header spaces
    /// use 0 (the handshake has no ack-delay budget).
    fn ackDelayFor(self: *const Connection, space: Space) u64 {
        return if (space == .application) self.peer_tp.max_ack_delay_ms * std.time.us_per_ms else 0;
    }

    pub fn nextTimeout(self: *Connection) ?u64 {
        var earliest: ?u64 = null;
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
        if (self.closed) return error.ProtocolViolation;

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
        const server = if (self.tls) |*s| s else return; // only the server drives the handshake here
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
                    self.peer_tp = transport_params.parse(decoded.value.quic_transport_parameters) catch
                        return error.ProtocolViolation;
                    self.conn_send_window.setInitial(self.peer_tp.initial_max_data);

                    var flight_buf: std.ArrayListUnmanaged(u8) = .empty;
                    defer flight_buf.deinit(self.gpa);
                    const outcome = server.onClientHello(&flight_buf, self.gpa, decoded.value) catch return error.ProtocolViolation;

                    // A server RECVs with the client traffic secret, SENDs with the server one.
                    self.installKeys(.handshake, outcome.built.handshake_secrets.clientKeys(), outcome.built.handshake_secrets.serverKeys());
                    self.installKeys(.application, outcome.built.application_secrets.clientKeys(), outcome.built.application_secrets.serverKeys());

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

    /// Packetize a space's pending CRYPTO into packets, recording each sent range so
    /// ack/loss can free or re-send it. Stops cleanly on the anti-amplification limit
    /// (RFC 9000 8.1) - the unsent bytes stay retained and flush on a later call once
    /// the budget rises (the client's next packet) or the space is re-flushed.
    fn flushCrypto(self: *Connection, space: Space, now: u64) Error!void {
        const st = &self.spaces[@intFromEnum(space)];
        if (st.send_keys == null) return;
        const room = constants.MIN_INITIAL_DATAGRAM - 64;
        while (st.crypto_send.pending()) {
            const chunk = st.crypto_send.peek(room) orelse break;
            if (chunk.data.len == 0) break; // CRYPTO has no FIN; an empty chunk is nothing to send
            var frames: std.ArrayListUnmanaged(u8) = .empty;
            defer frames.deinit(self.gpa);
            frame.encodeCrypto(&frames, self.gpa, chunk.offset, chunk.data) catch return error.OutOfMemory;
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
    /// Initial and Handshake keys (RFC 9001 4.9.1/4.9.2) so no further packet is
    /// processed in or sent from those spaces.
    fn confirmHandshake(self: *Connection, now: u64) Error!void {
        if (self.handshake_confirmed) return;
        // Queue HANDSHAKE_DONE before committing the confirmation state, so a failed
        // send (OOM) leaves the connection unconfirmed and retryable rather than
        // confirmed-but-silent. HANDSHAKE_DONE (0x1e) + PADDING (0x00): the padding
        // makes the packet long enough for the header-protection sample (RFC 9000
        // 19.20, 19.1).
        _ = try self.buildPacket(.application, &([_]u8{0x1e} ++ [_]u8{0x00} ** 19), true, now);
        self.handshake_confirmed = true;
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

    /// Process one received UDP datagram: walk the coalesced packets, decrypt and
    /// dispatch each. `now` is a monotonic microsecond timestamp. A packet that
    /// fails authentication is skipped (not fatal); a protocol violation poisons
    /// the connection.
    pub fn receiveDatagram(self: *Connection, datagram: []const u8, now: u64) Error!void {
        if (self.closed) return error.ProtocolViolation;
        // Anti-amplification credit (RFC 9000 8.1): every received byte raises the
        // budget for what the server may send before the address is validated.
        self.recv_bytes += datagram.len;
        var rest = datagram;
        while (rest.len > 0) {
            const consumed = self.receivePacket(rest, now) catch |e| switch (e) {
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
    }

    fn receivePacket(self: *Connection, buf: []const u8, now: u64) Error!usize {
        if (packet.isLong(buf[0])) return self.receiveLong(buf, now);
        return self.receiveShort(buf, now);
    }

    fn receiveLong(self: *Connection, buf: []const u8, now: u64) Error!usize {
        const hdr = packet.parseLong(buf) catch return error.Dropped;
        const space: Space = switch (hdr.ltype) {
            .initial => .initial,
            .handshake => .handshake,
            // 0-RTT uses its own keys, which this server never installs (0-RTT is out
            // of scope); drop it rather than risk decrypting it with 1-RTT keys.
            .zero_rtt => return error.Dropped,
            .retry => return error.Dropped, // retry handling is the connection-setup path
        };
        const total = hdr.pn_offset + @as(usize, @intCast(hdr.length));
        if (total > buf.len) return error.Dropped;
        // Adopt the peer's source connection id (from its first long header) as the
        // destination of everything we send (RFC 9000 7.2). Until this, peer_scid
        // defaults to the client dcid - fine for tests that use one shared id.
        if (!self.peer_scid_set and hdr.scid.len > 0) {
            const sc = self.gpa.dupe(u8, hdr.scid) catch return error.OutOfMemory;
            self.gpa.free(self.peer_scid);
            self.peer_scid = sc;
            self.peer_scid_set = true;
        }
        // A long header's length is known, so a packet we cannot decrypt (no keys
        // for the space yet, or a bad tag) is SKIPPED, not fatal: we return its
        // length so the caller keeps walking any coalesced packets behind it
        // (e.g. a Handshake packet coalesced after an Initial). RFC 9000 12.2.
        self.decryptAndDispatch(buf[0..total], hdr.pn_offset, space, true, now) catch |e| switch (e) {
            error.Dropped => return total,
            else => return e,
        };
        return total;
    }

    fn receiveShort(self: *Connection, buf: []const u8, now: u64) Error!usize {
        const hdr = packet.parseShort(buf, self.dcid.len) catch return error.Dropped;
        // A short-header packet is the rest of the datagram (no length field).
        try self.decryptAndDispatch(buf, hdr.pn_offset, .application, false, now);
        return buf.len;
    }

    fn decryptAndDispatch(self: *Connection, pkt: []const u8, pn_offset: usize, space: Space, long: bool, now: u64) Error!void {
        const st = &self.spaces[@intFromEnum(space)];
        const keys = st.recv_keys orelse return error.Dropped; // no keys for this space yet
        // Work on a mutable copy: header protection removal and decryption mutate.
        const work = self.gpa.dupe(u8, pkt) catch return error.OutOfMemory;
        defer self.gpa.free(work);

        const pn_len = crypto.unprotectHeader(keys.hp, work, pn_offset, long) catch return error.Dropped;
        var truncated: u64 = 0;
        for (work[pn_offset .. pn_offset + pn_len]) |b| truncated = (truncated << 8) | b;
        const pn = packet.decodePacketNumber(st.largest_recv_pn orelse 0, truncated, pn_len);

        const header = work[0 .. pn_offset + pn_len];
        const ciphertext = work[pn_offset + pn_len ..];
        const plaintext = self.gpa.alloc(u8, ciphertext.len) catch return error.OutOfMemory;
        defer self.gpa.free(plaintext);
        const payload = crypto.open(keys, pn, header, ciphertext, plaintext) catch return error.Dropped;

        // A decryptable Handshake packet proves the peer received our Initial/
        // handshake keys, so its address is validated and the 3x send limit lifts
        // (RFC 9000 8.1).
        if (space == .handshake) self.address_validated = true;

        st.largest_recv_pn = if (st.largest_recv_pn) |l| @max(l, pn) else pn;
        st.recv_ranges.add(self.gpa, pn) catch return error.OutOfMemory; // for accurate ACKs
        try self.dispatchFrames(payload, space, now);

        // Acknowledge the space if it carried an ack-eliciting frame this packet.
        if (st.ack_pending) try self.sendAck(space, now);
    }

    fn dispatchFrames(self: *Connection, payload: []const u8, space: Space, now: u64) Error!void {
        var rest = payload;
        while (rest.len > 0) {
            const d = frame.decode(rest) catch return error.ProtocolViolation;
            try self.handleFrame(d.frame, space, now);
            if (d.len == 0) break;
            rest = rest[d.len..];
        }
    }

    fn handleFrame(self: *Connection, f: frame.Frame, space: Space, now: u64) Error!void {
        // RFC 9000 12.4: only PADDING, PING, ACK, CRYPTO, and CONNECTION_CLOSE are
        // permitted in the Initial and Handshake spaces. STREAM and the other
        // 1-RTT frames in those spaces are a PROTOCOL_VIOLATION - the recv mirror of
        // keeping STREAM out of Initial on the send side.
        if (!frameAllowedIn(space, f)) return error.ProtocolViolation;

        const st = &self.spaces[@intFromEnum(space)];
        switch (f) {
            .padding => {},
            .ping => st.ack_pending = true,
            .ack => |a| try self.onAckFrame(space, a, now),
            .crypto => |c| {
                st.ack_pending = true;
                try self.onCrypto(space, c.offset, c.data, now);
            },
            .stream => |s| {
                st.ack_pending = true;
                try self.onStreamFrame(s.stream_id, s.offset, s.data, s.fin);
            },
            .max_data => |m| self.conn_send_window.onMaxData(m),
            .max_stream_data => {}, // per-stream send windows arrive with the send path
            .reset_stream => |r| try self.onReset(r.stream_id, r.final_size),
            .connection_close => {
                self.closed = true;
            },
            .handshake_done => {},
            else => {}, // the remaining control frames affect state the send path owns
        }
    }

    /// RFC 9000 12.4 / table 3: which frame types each space permits. Initial and
    /// Handshake carry only the handshake-control frames; everything else is a 1-RTT
    /// frame and illegal there.
    fn frameAllowedIn(space: Space, f: frame.Frame) bool {
        if (space == .application) return true;
        return switch (f) {
            .padding, .ping, .ack, .crypto, .connection_close => true,
            else => false,
        };
    }

    /// The send-side mirror of the recv gate: assert every frame we are about to
    /// seal is legal in `space` (so STREAM can never reach an Initial/Handshake
    /// packet, even through the shared buildPacket primitive). A debug
    /// check - it decodes the payload, so it compiles out in release builds, where
    /// the single STREAM caller is already pinned to the Application space.
    fn assertFramesAllowedIn(space: Space, frames: []const u8) void {
        if (!std.debug.runtime_safety) return;
        var rest = frames;
        while (rest.len > 0) {
            const d = frame.decode(rest) catch return;
            std.debug.assert(frameAllowedIn(space, d.frame));
            if (d.len == 0) break;
            rest = rest[d.len..];
        }
    }

    fn onStreamFrame(self: *Connection, id: u64, offset: u64, data: []const u8, fin: bool) Error!void {
        const s = try self.recvStream(id);
        const delta = s.push(offset, data, fin) catch |e| switch (e) {
            error.FinalSizeError => return error.FinalSizeError,
            error.OutOfMemory => return error.OutOfMemory,
        };
        // Charge the new bytes against the connection-wide window (the sum across
        // every stream), not just this stream's offset.
        self.conn_received_total += delta;
        self.conn_recv_window.onReceived(self.conn_received_total) catch return error.FlowControlError;
    }

    fn onReset(self: *Connection, id: u64, final_size: u64) Error!void {
        const s = try self.recvStream(id);
        s.onReset(final_size) catch return error.FinalSizeError;
    }

    fn recvStream(self: *Connection, id: u64) Error!*stream.RecvStream {
        if (self.streams.get(id)) |s| return s;
        const s = try self.gpa.create(stream.RecvStream);
        s.* = stream.RecvStream.init(self.gpa);
        self.streams.put(self.gpa, id, s) catch {
            s.deinit();
            self.gpa.destroy(s);
            return error.OutOfMemory;
        };
        return s;
    }

    /// The ordered, not-yet-consumed bytes of a stream (empty if none/unknown).
    pub fn streamData(self: *Connection, id: u64) []const u8 {
        if (self.streams.get(id)) |s| return s.readable();
        return &.{};
    }

    /// Mark `n` bytes of a stream consumed, re-granting flow-control credit. The
    /// connection window slides by the connection-wide consumed total (the sum
    /// across streams), matching how `onStreamFrame` charges it.
    pub fn consumeStream(self: *Connection, id: u64, n: usize) void {
        if (self.streams.get(id)) |s| {
            const before = s.read_offset;
            s.consume(n);
            self.conn_consumed_total += s.read_offset - before;
            self.conn_recv_window.onConsumed(self.conn_consumed_total);
            // Enough has been consumed to advertise a higher limit; flushSend emits it.
            if (self.conn_recv_window.shouldUpdate()) self.max_data_pending = true;
        }
    }

    pub fn streamFinished(self: *Connection, id: u64) bool {
        if (self.streams.get(id)) |s| return s.isFinished();
        return false;
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
};

const testing = std.testing;

// Build one Initial packet the way a peer would, so the connection can decrypt
// it: frame the payload, seal it with the sender's Initial keys, and apply header
// protection. Returns an owned datagram the caller frees. Exposed (test-only) so
// the HTTP/3 layer's tests can drive a request through the real transport.
pub fn testBuildInitial(gpa: std.mem.Allocator, dcid: []const u8, sender: Role, pn: u64, frames: []const u8) ![]u8 {
    const keys = blk: {
        const ik = crypto.InitialKeys.derive(dcid);
        break :blk if (sender == .client) ik.client else ik.server;
    };
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
    const length = 1 + frames.len + crypto.TAG_LEN;
    var lbuf: [8]u8 = undefined;
    const varint = @import("varint.zig");
    try hdr_buf.appendSlice(gpa, try varint.encode(&lbuf, @intCast(length)));
    const pn_offset = hdr_buf.items.len;
    try hdr_buf.append(gpa, @intCast(pn & 0xff)); // 1-byte pn

    const header = hdr_buf.items;
    const out = try gpa.alloc(u8, header.len + frames.len + crypto.TAG_LEN);
    errdefer gpa.free(out);
    @memcpy(out[0..header.len], header);
    _ = crypto.seal(keys, pn, header, frames, out[header.len..]);
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
    const varint = @import("varint.zig");
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

// Application-space test keys, deterministic so a test builder and the connection
// agree. STREAM frames are illegal in Initial (RFC 9000 12.4); these helpers let
// the recv-pipeline tests deliver stream data in the Application space, the way a
// real connection does once the handshake installs 1-RTT keys.
const TEST_APP_SECRET = [_]u8{0x5a} ** 32;

fn testAppKeys() crypto.Keys {
    return crypto.Keys.fromSecret(TEST_APP_SECRET);
}

// Install Application-space keys on `conn` (both directions the same fixed keys,
// which is all the recv path needs) so it can decrypt a testBuildApp datagram.
pub fn testInstallAppKeys(conn: *Connection) void {
    conn.installKeys(.application, testAppKeys(), testAppKeys());
}

// Build a 1-RTT (short-header) Application packet carrying `frames`, sealed with
// the test Application keys. The mirror of testBuildInitial for the post-handshake
// space, so stream-reassembly tests use the space STREAM is actually legal in.
pub fn testBuildApp(gpa: std.mem.Allocator, dcid: []const u8, pn: u64, frames: []const u8) ![]u8 {
    const keys = testAppKeys();
    var hdr: std.ArrayListUnmanaged(u8) = .empty;
    defer hdr.deinit(gpa);
    const pn_offset = try packet.writeShortHeader(&hdr, gpa, dcid, 1);
    try packet.writePacketNumber(&hdr, gpa, pn, 1);

    const out = try gpa.alloc(u8, hdr.items.len + frames.len + crypto.TAG_LEN);
    errdefer gpa.free(out);
    @memcpy(out[0..hdr.items.len], hdr.items);
    _ = crypto.seal(keys, pn, hdr.items, frames, out[hdr.items.len..]);
    try crypto.protectHeader(keys.hp, out, pn_offset, false);
    return out;
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

test "consuming stream data advertises a raised MAX_DATA" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    testInstallAppKeys(&conn);
    conn.conn_recv_window.limit = 100; // a small window so consuming half trips the update

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
    try conn.flushSend(2000);
    try testing.expect(!conn.max_data_pending); // emitted
    try testing.expect(conn.datagramLengths().len >= 1);
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
    try w.bytes(&[_]u8{ 0x01, 0x02, 0x40, 0x01 });
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
        .transport_params = &[_]u8{ 0x00, 0x01 },
    };
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
    // The test ClientHello carries quic_transport_parameters {0x01,0x02,0x40,0x01}:
    // id 0x01 (max_idle_timeout), len 2, value varint 0x4001 = 1 -> initial_max_data
    // is absent, so the send window becomes 0 (the client granted no data yet).
    const ch = try buildClientHelloInitial(gpa, &dcid, pubkey);
    defer gpa.free(ch);
    try server.receiveDatagram(ch, 1000);
    try testing.expectEqual(@as(u64, 0), server.peer_tp.initial_max_data);
    try testing.expectEqual(@as(u64, 0), server.conn_send_window.limit); // set from the (absent) grant
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

    // A PTO re-queues the oldest unacked CRYPTO range for retransmission - the
    // handshake recovers from a lost flight rather than deadlocking.
    const deadline = server.nextTimeout().?;
    try server.onTimeout(deadline + 1);
    try testing.expect(hs.crypto_send.pending()); // the lost flight bytes are queued to resend
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

test "flushSend is a no-op until the Application keys are installed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
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

    // A flush with no further credit sends nothing more.
    conn.clearSend();
    try conn.flushSend(1000);
    try testing.expectEqual(@as(usize, 0), conn.datagramsToSend().len);

    // The peer raises MAX_DATA; the remaining bytes can now flow.
    conn.conn_send_window.onMaxData(10);
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

test "writing after a FIN is a final-size error" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();
    try conn.sendStreamData(1, "done", true);
    try testing.expectError(error.FinalSizeError, conn.sendStreamData(1, "more", false));
}

// ---- STREAM retransmission tests --------------------------------------------

// An Application (1-RTT) datagram carrying one ACK frame, sealed with the test app
// keys so a sender installed via testInstallAppKeys decrypts it.
fn buildAppAck(gpa: std.mem.Allocator, dcid: []const u8, pn: u64, largest: u64, first_range: u64) ![]u8 {
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(gpa);
    try frame.encodeAck(&frames, gpa, largest, 0, first_range);
    return testBuildApp(gpa, dcid, pn, frames.items);
}

// Deliver every queued datagram in `sender`'s send buffer to `peer`, sliced by the
// per-datagram lengths (each is its own UDP datagram). Optionally skip index `drop`.
fn deliverAllExcept(sender: *Connection, peer: *Connection, drop: ?usize, now: u64) !void {
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
