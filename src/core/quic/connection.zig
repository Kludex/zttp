//! The QUIC transport orchestrator (RFC 9000/9001/9002): ties the packet, crypto,
//! recovery, congestion, flow, and stream layers into one connection. It takes a
//! UDP datagram with `receiveDatagram` - parsing the (possibly coalesced) packets
//! inside, removing header protection, decrypting, and dispatching each frame into
//! the transport state - and exposes the ordered bytes of each stream upward to
//! the HTTP/3 layer. It is sans-IO: bytes and a monotonic `now` in, transport
//! state and (eventually) datagrams out, no socket.
//!
//! Scope: the Initial packet-number space is wired end-to-end, which exercises the
//! whole pipeline (header protection, AEAD, framing, ack/stream state) with the
//! deterministic Initial keys. The Handshake and Application spaces install their
//! keys through the same `installKeys` seam once the TLS 1.3 handshake driver
//! lands; that negotiation is the follow-up, mirroring how HTTP/2 staged its write
//! side.

const std = @import("std");
const constants = @import("constants.zig");
const packet = @import("packet.zig");
const crypto = @import("crypto.zig");
const frame = @import("frame.zig");
const recovery = @import("recovery.zig");
const congestion = @import("congestion.zig");
const flow = @import("flow.zig");
const stream = @import("stream.zig");

const Space = constants.Space;

pub const Role = enum { server, client };

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
    OutOfMemory,
};

/// One packet-number space's protection keys and recovery state. Initial keys are
/// derived up front; Handshake/Application keys arrive via `installKeys`.
const SpaceState = struct {
    recv_keys: ?crypto.Keys = null,
    send_keys: ?crypto.Keys = null,
    next_pn: u64 = 0,
    largest_recv_pn: ?u64 = null,
    rec: recovery.Space = .{},

    fn deinit(self: *SpaceState, gpa: std.mem.Allocator) void {
        self.rec.deinit(gpa);
    }
};

pub const Connection = struct {
    gpa: std.mem.Allocator,
    role: Role,
    dcid: []u8, // our peer's chosen dcid for us (owned)
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
    closed: bool = false,

    /// `client_dcid` is the destination connection id on the client's first
    /// Initial: both endpoints derive the Initial keys from it.
    pub fn init(gpa: std.mem.Allocator, role: Role, client_dcid: []const u8) Error!Connection {
        const dcid = try gpa.dupe(u8, client_dcid);
        errdefer gpa.free(dcid);
        const initial = crypto.InitialKeys.derive(client_dcid);
        var spaces = [_]SpaceState{.{}} ** 3;
        // The receiver decrypts with the opposite role's keys.
        const recv = if (role == .server) initial.client else initial.server;
        const send = if (role == .server) initial.server else initial.client;
        spaces[@intFromEnum(Space.initial)].recv_keys = recv;
        spaces[@intFromEnum(Space.initial)].send_keys = send;
        return .{
            .gpa = gpa,
            .role = role,
            .dcid = dcid,
            .spaces = spaces,
            .cc = congestion.Controller.init(constants.MIN_INITIAL_DATAGRAM),
            .conn_recv_window = flow.Window.init(1 << 20),
            .conn_send_window = flow.SendWindow.init(1 << 20),
        };
    }

    pub fn deinit(self: *Connection) void {
        self.gpa.free(self.dcid);
        var it = self.streams.valueIterator();
        while (it.next()) |s| {
            s.*.deinit();
            self.gpa.destroy(s.*);
        }
        self.streams.deinit(self.gpa);
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

    /// Process one received UDP datagram: walk the coalesced packets, decrypt and
    /// dispatch each. `now` is a monotonic microsecond timestamp. A packet that
    /// fails authentication is skipped (not fatal); a protocol violation poisons
    /// the connection.
    pub fn receiveDatagram(self: *Connection, datagram: []const u8, now: u64) Error!void {
        if (self.closed) return error.ProtocolViolation;
        var rest = datagram;
        while (rest.len > 0) {
            const consumed = self.receivePacket(rest, now) catch |e| switch (e) {
                error.Dropped => break, // cannot find the boundary of an undecryptable packet; stop
                else => return e,
            };
            if (consumed == 0 or consumed > rest.len) break;
            rest = rest[consumed..];
        }
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
            .zero_rtt => .application,
            .retry => return error.Dropped, // retry handling is the connection-setup path
        };
        const total = hdr.pn_offset + @as(usize, @intCast(hdr.length));
        if (total > buf.len) return error.Dropped;
        try self.decryptAndDispatch(buf[0..total], hdr.pn_offset, space, true, now);
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

        st.largest_recv_pn = if (st.largest_recv_pn) |l| @max(l, pn) else pn;
        try self.dispatchFrames(payload, space, now);
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
        switch (f) {
            .padding, .ping => {},
            .ack => |a| {
                var it = frame.ackRanges(a.ranges);
                _ = self.spaces[@intFromEnum(space)].rec.onAck(&self.rtt, &self.cc, now, a.largest, a.delay, a.first_range, &it) catch
                    return error.ProtocolViolation;
            },
            .crypto => {}, // handed to the TLS driver once it lands
            .stream => |s| try self.onStreamFrame(s.stream_id, s.offset, s.data, s.fin),
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

test "server decrypts a client Initial and reassembles a stream" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = try Connection.init(gpa, .server, &dcid);
    defer conn.deinit();

    // A CRYPTO-less payload: a STREAM frame (type 0x0b = OFF=0,LEN,FIN) on stream
    // 0 carrying "hi". 0x0a actually = LEN|FIN with no OFF; id=0,len=2,"hi".
    const frames = [_]u8{ 0x0b, 0x00, 0x02, 'h', 'i' }; // 0x0b = base|LEN|FIN
    const dgram = try testBuildInitial(gpa, &dcid, .client, 0, &frames);
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
    const frames = [_]u8{ 0x0a, 0x00, 0x03, 'a', 'b', 'c' }; // STREAM id0 LEN, "abc", no FIN
    const dgram = try testBuildInitial(gpa, &dcid, .client, 0, &frames);
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
    // Shrink the connection window so a small payload spread over two streams
    // exceeds it - this is exactly the evasion a per-stream check would miss.
    conn.conn_recv_window.limit = 6;
    // Two STREAM frames in one datagram: 4 bytes on stream 0, then 4 on stream 4.
    // 0x0a = STREAM|LEN (no OFF). Their sum (8) is past the 6-byte window.
    const frames = [_]u8{
        0x0a, 0x00, 0x04, 'a', 'a', 'a', 'a', // stream 0, 4 bytes
        0x0a, 0x04, 0x04, 'b', 'b', 'b', 'b', // stream 4, 4 bytes
    };
    const dgram = try testBuildInitial(gpa, &dcid, .client, 0, &frames);
    defer gpa.free(dgram);
    try testing.expectError(error.FlowControlError, conn.receiveDatagram(dgram, 1000));
}
