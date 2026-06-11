//! The HTTP/3 connection orchestrator (RFC 9114): sits on top of the QUIC
//! transport and turns the ordered bytes of each request stream into the shared
//! Request / Data / EndOfMessage events. It classifies streams (the control stream
//! carries SETTINGS; bidirectional streams carry requests), parses HTTP/3 frames,
//! QPACK-decodes a HEADERS block into a Request - collapsing the pseudo-headers
//! (:method -> method, :path -> target, :authority -> a synthesized host) exactly
//! as the HTTP/2 layer does - and drains events through a flat, arrival-ordered
//! queue, one per `nextEvent`, so HTTP/3 reaches the same pull API as H1 and H2.
//!
//! It is driven by the QUIC connection: `pump` reads whatever ordered bytes the
//! transport has for each known request stream and advances the per-stream parse.

const std = @import("std");
const ascii = @import("../ascii.zig");
const events = @import("../events.zig");
const fields = @import("../fields.zig");
const quic_conn = @import("../quic/connection.zig");
const quic_stream = @import("../quic/stream.zig");
const h3_frame = @import("frame.zig");
const h3_stream = @import("stream.zig");
const qpack = @import("qpack/decoder.zig");
const qpack_enc = @import("qpack/encoder.zig");

const Header = events.Header;
const H3Event = events.H3Event;

pub const Error = error{
    /// A malformed HTTP/3 frame, a bad QPACK block, or a missing pseudo-header:
    /// an HTTP/3 connection or stream error (RFC 9114 4.1.2 / 7).
    H3Error,
    OutOfMemory,
};

const ReqState = enum { idle, headers_done, done };

const RequestStream = struct {
    state: ReqState = .idle,
    /// The declared request body length (RFC 9114 4.1.2), or null if no
    /// Content-Length was sent. Reconciled against the DATA bytes at the FIN.
    content_length: ?u64 = null,
    body_received: u64 = 0,
};

/// Outbound (response) state per stream, so the send API cannot serialize invalid
/// HTTP/3: DATA before HEADERS, a second HEADERS, or a write after the FIN.
const SendState = enum { idle, headers_sent, fin_sent };

pub const Connection = struct {
    gpa: std.mem.Allocator,
    qc: *quic_conn.Connection,
    streams: std.AutoHashMapUnmanaged(u64, RequestStream) = .empty,
    send_state: std.AutoHashMapUnmanaged(u64, SendState) = .empty,
    qpack_dec: qpack.Decoder,
    queue: std.ArrayListUnmanaged(H3Event) = .empty,
    qpos: usize = 0,
    /// Owned copies of the strings each queued event borrows; freed when the queue
    /// is reset. QPACK's decode store is reused per call, so we materialise here.
    arena: std.heap.ArenaAllocator,

    pub fn init(gpa: std.mem.Allocator, qc: *quic_conn.Connection) Connection {
        return .{
            .gpa = gpa,
            .qc = qc,
            .qpack_dec = qpack.Decoder.init(gpa, 1 << 16),
            .arena = std.heap.ArenaAllocator.init(gpa),
        };
    }

    pub fn deinit(self: *Connection) void {
        self.streams.deinit(self.gpa);
        self.send_state.deinit(self.gpa);
        self.qpack_dec.deinit();
        self.queue.deinit(self.gpa);
        self.arena.deinit();
    }

    /// Advance the parse of request stream `id` from whatever ordered bytes the
    /// QUIC transport now has. Newly completed events are appended to the queue.
    /// The caller (the adapter) calls this when it knows a stream got data; a
    /// production driver would call it for every stream that advanced.
    /// Advance the parse of every stream the transport currently knows about.
    /// The adapter calls this after each datagram so it need not track which
    /// streams advanced. The 64-id snapshot bound is far above any realistic
    /// concurrent-stream count for a young connection.
    pub fn pumpAll(self: *Connection) Error!void {
        var ids: [64]u64 = undefined;
        const n = self.qc.streamIds(&ids);
        for (ids[0..n]) |id| try self.pump(id);
    }

    pub fn pump(self: *Connection, id: u64) Error!void {
        // Only client-initiated bidirectional streams carry requests here.
        if (quic_stream.StreamType.of(id) != .client_bidi) return;
        const gop = self.streams.getOrPut(self.gpa, id) catch return error.OutOfMemory;
        if (!gop.found_existing) gop.value_ptr.* = .{};
        const rs = gop.value_ptr;

        // Parse from the start of the ordered bytes the transport currently holds:
        // every fully-decoded frame is consumed (removed from the QUIC stream)
        // before this returns, so the next pump always begins at offset 0 with the
        // not-yet-consumed tail (a partial frame plus any newer bytes). Tracking a
        // persistent offset here would desync once consumeStream slides the buffer.
        const ready = self.qc.streamData(id);
        var consumed_total: usize = 0;
        while (consumed_total < ready.len) {
            const rest = ready[consumed_total..];
            const d = h3_frame.decode(rest) catch break; // NeedData: wait for more
            try self.onFrame(id, rs, d.frame);
            consumed_total += d.len;
        }
        if (self.qc.streamFinished(id) and rs.state == .headers_done) {
            // Fewer body bytes than the declared Content-Length is malformed (RFC
            // 9114 4.1.2); the over-count is caught per-DATA above.
            if (rs.content_length) |cl| if (rs.body_received != cl) return error.H3Error;
            try self.push(.{ .end_of_message = .{ .trailers = &.{}, .stream_id = id } });
            rs.state = .done;
        }
        if (consumed_total > 0) self.qc.consumeStream(id, consumed_total);
    }

    fn onFrame(self: *Connection, id: u64, rs: *RequestStream, f: h3_frame.Frame) Error!void {
        switch (f.ftype) {
            .headers => {
                if (rs.state != .idle) return error.H3Error; // trailers after body are a follow-up
                const req = try self.decodeRequest(id, f.payload, rs);
                try self.push(.{ .request = req });
                rs.state = .headers_done;
            },
            .data => {
                if (rs.state != .headers_done) return error.H3Error; // DATA before HEADERS (RFC 9114 4.1)
                rs.body_received = std.math.add(u64, rs.body_received, f.payload.len) catch return error.H3Error;
                // More body than the declared Content-Length is malformed (RFC 9114 4.1.2).
                if (rs.content_length) |cl| if (rs.body_received > cl) return error.H3Error;
                const body = try self.dupe(f.payload);
                try self.push(.{ .data = .{ .data = body, .stream_id = id } });
            },
            // Control-stream frames are not allowed on a request stream (RFC 9114
            // 7.1): H3_FRAME_UNEXPECTED.
            .cancel_push, .settings, .push_promise, .goaway, .max_push_id => return error.H3Error,
            // Any other (unknown) frame type, grease or not, MUST be ignored on
            // receipt (RFC 9114 9). The frame is already fully buffered, so the pump
            // loop skips it by Decoded.len.
            else => {},
        }
    }

    /// Collapse a QPACK-decoded field section into a Request, pulling the four
    /// pseudo-headers into the shared shape and keeping the rest as headers.
    fn decodeRequest(self: *Connection, id: u64, block: []const u8, rs: *RequestStream) Error!events.Request {
        const decoded = self.qpack_dec.decode(block) catch return error.H3Error;
        var method: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var authority: ?[]const u8 = null;
        var scheme: ?[]const u8 = null;
        var regular: std.ArrayListUnmanaged(Header) = .empty;
        defer regular.deinit(self.gpa);
        var seen_regular = false;

        for (decoded) |h| {
            if (h.name.len > 0 and h.name[0] == ':') {
                if (seen_regular) return error.H3Error; // pseudo after regular (RFC 9114 4.3)
                // A request pseudo-header appears at most once (RFC 9114 4.3.1 ->
                // RFC 9113 8.3); a duplicate is malformed.
                const slot = if (eql(h.name, ":method")) &method else if (eql(h.name, ":path")) &path else if (eql(h.name, ":authority")) &authority else if (eql(h.name, ":scheme")) &scheme else return error.H3Error;
                if (slot.* != null) return error.H3Error;
                slot.* = h.value;
            } else {
                seen_regular = true;
                // RFC 9114 4.2 inherits the HTTP/2 field rules: lowercase token
                // names, no connection-specific fields, and TE only "trailers".
                if (!fields.isValidFieldName(h.name)) return error.H3Error;
                if (!fields.validValue(h.value)) return error.H3Error;
                if (fields.isConnectionSpecific(h.name)) return error.H3Error;
                if (eql(h.name, "te") and !eql(h.value, "trailers")) return error.H3Error;
                if (eql(h.name, "content-length")) {
                    const cl = ascii.parseDecimal(u64, h.value) orelse return error.H3Error;
                    // A repeated Content-Length is malformed unless it agrees (RFC 9110).
                    if (rs.content_length) |prev| {
                        if (prev != cl) return error.H3Error;
                    } else rs.content_length = cl;
                }
                regular.append(self.gpa, h) catch return error.OutOfMemory;
            }
        }
        const method_v = method orelse return error.H3Error;
        const path_v = path orelse return error.H3Error;
        const scheme_v = scheme orelse return error.H3Error;
        if (method_v.len == 0 or path_v.len == 0 or scheme_v.len == 0) return error.H3Error;

        // Materialise everything into the arena so the slices outlive the next
        // QPACK decode (which clears its store).
        const a = self.arena.allocator();
        var headers: std.ArrayListUnmanaged(Header) = .empty;
        if (authority) |auth| {
            if (auth.len > 0) headers.append(a, .{ .name = "host", .value = try a.dupe(u8, auth) }) catch return error.OutOfMemory;
        }
        for (regular.items) |h| {
            headers.append(a, .{ .name = try a.dupe(u8, h.name), .value = try a.dupe(u8, h.value) }) catch return error.OutOfMemory;
        }
        const target = try a.dupe(u8, path_v);
        const q = std.mem.indexOfScalar(u8, target, '?');
        return .{
            .method = try a.dupe(u8, method_v),
            .target = target,
            .path = if (q) |i| target[0..i] else target,
            .query = if (q) |i| target[i + 1 ..] else target[target.len..],
            .http_version = "3",
            .headers = headers.items,
            .stream_id = id,
        };
    }

    fn dupe(self: *Connection, bytes: []const u8) Error![]const u8 {
        return self.arena.allocator().dupe(u8, bytes) catch return error.OutOfMemory;
    }

    fn push(self: *Connection, ev: H3Event) Error!void {
        self.queue.append(self.gpa, ev) catch return error.OutOfMemory;
    }

    /// Pull the next ready event, or `need_data` when the queue is drained. Mirrors
    /// the H1/H2 one-event-per-call contract.
    pub fn nextEvent(self: *Connection) H3Event {
        if (self.qpos >= self.queue.items.len) {
            self.queue.clearRetainingCapacity();
            self.qpos = 0;
            // Every queued event has been handed out (and, per the core's contract,
            // materialised by the caller before this call), so the strings they
            // borrowed can be reclaimed. Without this the arena grows for the life
            // of the connection - one block per request body and header set.
            _ = self.arena.reset(.retain_capacity);
            return .need_data;
        }
        const ev = self.queue.items[self.qpos];
        self.qpos += 1;
        return ev;
    }

    // ---- response send path (RFC 9114 4.1) -------------------------------------

    /// A response field is well-formed before it goes on the wire (RFC 9114 4.2):
    /// a lowercase token name (no pseudo-header - the server supplies :status), no
    /// connection-specific field, and a value with no control bytes (the write side
    /// is stricter than the read side and rejects CR/LF/NUL/HTAB and edge
    /// whitespace), so a re-serialised response cannot split or inject.
    fn validateResponseHeader(h: Header) Error!void {
        if (!fields.isValidFieldName(h.name)) return error.H3Error; // pseudo / uppercase / non-token
        if (fields.isConnectionSpecific(h.name)) return error.H3Error;
        for (h.value) |ch| if (ch < 0x20 or ch == 0x7F) return error.H3Error;
        if (h.value.len > 0) {
            const first = h.value[0];
            const last = h.value[h.value.len - 1];
            if (first == ' ' or first == '\t' or last == ' ' or last == '\t') return error.H3Error;
        }
    }

    /// Send a response head on request stream `id`: a HEADERS frame whose field
    /// section is `:status` plus `headers`, QPACK-encoded. Follow with `sendData`
    /// for the body and `endStream` to finish. Responses ride the client-initiated
    /// request stream; HEADERS must precede DATA and nothing follows the FIN, both
    /// enforced here. `headers` must not contain pseudo-headers (names beginning
    /// ":") - the server supplies :status.
    pub fn sendResponse(self: *Connection, id: u64, status: u16, headers: []const Header) Error!void {
        if (quic_stream.StreamType.of(id) != .client_bidi) return error.H3Error; // responses ride the request stream
        if (status < 100 or status > 599) return error.H3Error; // RFC 9110 status range
        if (try self.sendStateOf(id) != .idle) return error.H3Error; // HEADERS once, before DATA/FIN
        for (headers) |h| try validateResponseHeader(h);

        // The QPACK field section: prefix (RIC 0, Base 0), then :status, then headers.
        var section: std.ArrayList(u8) = .empty;
        defer section.deinit(self.gpa);
        section.appendSlice(self.gpa, &.{ 0x00, 0x00 }) catch return error.OutOfMemory;
        var status_buf: [3]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch return error.H3Error;
        qpack_enc.encodeHeader(&section, self.gpa, .{ .name = ":status", .value = status_str }) catch return error.OutOfMemory;
        for (headers) |h| qpack_enc.encodeHeader(&section, self.gpa, h) catch return error.OutOfMemory;

        var frame: std.ArrayListUnmanaged(u8) = .empty;
        defer frame.deinit(self.gpa);
        h3_frame.append(&frame, self.gpa, .headers, section.items) catch return error.OutOfMemory;
        try self.streamSend(id, frame.items, false);
        try self.setSendState(id, .headers_sent);
    }

    /// Send a chunk of response body on stream `id` as an HTTP/3 DATA frame. The
    /// response head must have been sent first (RFC 9114 4.1).
    pub fn sendData(self: *Connection, id: u64, data: []const u8) Error!void {
        if (try self.sendStateOf(id) != .headers_sent) return error.H3Error; // DATA only after HEADERS, before FIN
        var frame: std.ArrayListUnmanaged(u8) = .empty;
        defer frame.deinit(self.gpa);
        h3_frame.append(&frame, self.gpa, .data, data) catch return error.OutOfMemory;
        try self.streamSend(id, frame.items, false);
    }

    /// Finish the response on stream `id` (send the stream FIN). The head must have
    /// been sent; a second endStream is rejected.
    pub fn endStream(self: *Connection, id: u64) Error!void {
        if (try self.sendStateOf(id) != .headers_sent) return error.H3Error;
        try self.streamSend(id, &.{}, true);
        try self.setSendState(id, .fin_sent);
    }

    fn sendStateOf(self: *Connection, id: u64) Error!SendState {
        const gop = self.send_state.getOrPut(self.gpa, id) catch return error.OutOfMemory;
        if (!gop.found_existing) gop.value_ptr.* = .idle;
        return gop.value_ptr.*;
    }

    fn setSendState(self: *Connection, id: u64, s: SendState) Error!void {
        self.send_state.put(self.gpa, id, s) catch return error.OutOfMemory;
    }

    fn streamSend(self: *Connection, id: u64, bytes: []const u8, fin: bool) Error!void {
        self.qc.sendStreamData(id, bytes, fin) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.H3Error, // FinalSizeError etc.
        };
    }
};

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const testing = std.testing;

// Build a client 1-RTT datagram carrying a STREAM frame on the given bidi stream
// id whose body is the H3 frames, so a server QUIC+H3 stack decodes it. H3 request
// data is application data, so it rides the Application space (STREAM is illegal in
// Initial); the matching server installs the test app keys via testInstallAppKeys.
fn buildRequest(gpa: std.mem.Allocator, dcid: []const u8, stream_id: u64, h3_bytes: []const u8) ![]u8 {
    const varint = @import("../quic/varint.zig");
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0a); // STREAM, LEN set, no OFF, no FIN
    try varint.append(&sframe, gpa, stream_id);
    try varint.append(&sframe, gpa, h3_bytes.len);
    try sframe.appendSlice(gpa, h3_bytes);
    return @import("../quic/connection.zig").testBuildApp(gpa, dcid, 0, sframe.items);
}

test "decode a GET request over HTTP/3" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc); // H3 request data rides the Application space
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // A HEADERS frame whose QPACK block is: prefix RIC=0,Base=0; indexed :method
    // GET (idx 17), :scheme https (idx 23), :path "/" (idx 1), literal :authority.
    const qpack_block = [_]u8{
        0x00, 0x00, // prefix
        0xC0 | 17, // :method GET
        0xC0 | 23, // :scheme https
        0xC0 | 1, // :path /
        0x50 | 0, 0x03, 'e', 'x', 'y', // literal name-ref :authority = "exy"
    };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);

    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    const ev = h3.nextEvent();
    try testing.expect(ev == .request);
    try testing.expectEqualStrings("GET", ev.request.method);
    try testing.expectEqualStrings("/", ev.request.path);
    try testing.expectEqualStrings("3", ev.request.http_version);
    try testing.expectEqualStrings("host", ev.request.headers[0].name);
    try testing.expectEqualStrings("exy", ev.request.headers[0].value);
}

test "a request stream id above 2^32 is not truncated" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const qpack_block = [_]u8{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x50 | 0, 0x03, 'e', 'x', 'y' };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);

    // A client-initiated bidi stream id (0 mod 4) above the 32-bit range. A u32
    // truncation would surface it as 0, sending a later response on the wrong stream.
    const big_id: u64 = 0x1_0000_0000;
    const dgram = try buildRequest(gpa, &dcid, big_id, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(big_id);

    const ev = h3.nextEvent();
    try testing.expect(ev == .request);
    try testing.expectEqual(big_id, ev.request.stream_id);
}

// Feed a HEADERS frame whose QPACK block is `qpack_block` and return the result of
// pumping stream 0 - so a malformed-request test asserts the H3Error directly.
fn pumpHeaders(gpa: std.mem.Allocator, qpack_block: []const u8) Error!void {
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = quic_conn.Connection.init(gpa, .server, &dcid) catch return error.H3Error;
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    h3_frame.append(&h3_bytes, gpa, .headers, qpack_block) catch return error.H3Error;
    const dgram = buildRequest(gpa, &dcid, 0, h3_bytes.items) catch return error.H3Error;
    defer gpa.free(dgram);
    qc.receiveDatagram(dgram, 1000) catch return error.H3Error;
    try h3.pump(0);
}

test "a duplicate request pseudo-header is malformed" {
    // :method GET twice (RFC 9113 8.3 via RFC 9114 4.3.1).
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0xC0 | 17 }));
}

test "an uppercase field name is malformed" {
    // literal name "Te" (0x20|2), value "x": a non-lowercase token (RFC 9114 4.2).
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 2, 'T', 'e', 0x01, 'x' }));
}

test "a connection-specific field is malformed" {
    // literal name "connection" (len 10: 3-bit prefix 7 + continuation 3), value "x".
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 7, 0x03, 'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', 0x01, 'x' }));
}

test "TE with a value other than trailers is malformed" {
    // literal name "te" (0x20|2), value "gzip".
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 2, 't', 'e', 0x04, 'g', 'z', 'i', 'p' }));
}

test "TE trailers is accepted" {
    // The one legal TE value (RFC 9114 4.2): te: trailers must NOT be rejected.
    try pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 2, 't', 'e', 0x08, 't', 'r', 'a', 'i', 'l', 'e', 'r', 's' });
}

test "a control byte in a field value is malformed" {
    // literal name "x" (0x20|1), value "a\rb": CR is not a field-vchar (RFC 9110).
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1, 0x20 | 1, 'x', 0x03, 'a', '\r', 'b' }));
}

test "a non-numeric Content-Length is malformed" {
    // content-length: "x" (name length 14 = 3-bit prefix 7 + continuation 7).
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &.{ 0x00, 0x00, 0xC0 | 20, 0xC0 | 23, 0xC0 | 1, 0x20 | 7, 0x07, 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 'l', 'e', 'n', 'g', 't', 'h', 0x01, 'x' }));
}

test "two disagreeing Content-Length values are malformed" {
    // content-length: 1 then content-length: 2 (name length 14 = 7 + continuation 7).
    const cl = [_]u8{ 0x20 | 7, 0x07, 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 'l', 'e', 'n', 'g', 't', 'h' };
    try testing.expectError(error.H3Error, pumpHeaders(testing.allocator, &(.{ 0x00, 0x00, 0xC0 | 20, 0xC0 | 23, 0xC0 | 1 } ++ cl ++ .{ 0x01, '1' } ++ cl ++ .{ 0x01, '2' })));
}

test "more body than Content-Length is malformed at the DATA frame" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try postWithContentLength(&h3_bytes, gpa, "2"); // declares 2, sends 5
    try h3_frame.append(&h3_bytes, gpa, .data, "body!");
    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(0));
}

test "a request with a body yields request then data" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xab, 0xcd, 0xef, 0x01 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc); // H3 request data rides the Application space
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const qpack_block = [_]u8{ 0x00, 0x00, 0xC0 | 20, 0xC0 | 23, 0xC0 | 1 }; // POST https /
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);
    try h3_frame.append(&h3_bytes, gpa, .data, "body!");

    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);

    try testing.expect(h3.nextEvent() == .request);
    const data_ev = h3.nextEvent();
    try testing.expect(data_ev == .data);
    try testing.expectEqualStrings("body!", data_ev.data.data);
}

// Build a request datagram whose STREAM frame sets the FIN bit, so the H3 layer
// sees the stream end (needed to exercise the Content-Length reconciliation).
fn buildRequestFin(gpa: std.mem.Allocator, dcid: []const u8, h3_bytes: []const u8) ![]u8 {
    const varint = @import("../quic/varint.zig");
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0b); // STREAM, LEN|FIN set, no OFF
    try varint.append(&sframe, gpa, 0); // stream id 0
    try varint.append(&sframe, gpa, h3_bytes.len);
    try sframe.appendSlice(gpa, h3_bytes);
    return @import("../quic/connection.zig").testBuildApp(gpa, dcid, 0, sframe.items);
}

// HEADERS for POST / with a content-length header of `cl` (e.g. "5").
fn postWithContentLength(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, cl: []const u8) !void {
    var block: std.ArrayListUnmanaged(u8) = .empty;
    defer block.deinit(gpa);
    try block.appendSlice(gpa, &.{ 0x00, 0x00, 0xC0 | 20, 0xC0 | 23, 0xC0 | 1 }); // POST https /
    try block.appendSlice(gpa, &.{ 0x20 | 7, @intCast(14 - 7) }); // literal name len 14
    try block.appendSlice(gpa, "content-length");
    try block.append(gpa, @intCast(cl.len)); // value, 7-bit length prefix
    try block.appendSlice(gpa, cl);
    try h3_frame.append(out, gpa, .headers, block.items);
}

test "the body matching Content-Length is accepted, a mismatch is malformed" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };

    {
        var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
        defer qc.deinit();
        quic_conn.testInstallAppKeys(&qc);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();
        var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer h3_bytes.deinit(gpa);
        try postWithContentLength(&h3_bytes, gpa, "5");
        try h3_frame.append(&h3_bytes, gpa, .data, "body!");
        const dgram = try buildRequestFin(gpa, &dcid, h3_bytes.items);
        defer gpa.free(dgram);
        try qc.receiveDatagram(dgram, 1000);
        try h3.pump(0); // 5 bytes == content-length 5: clean EOM
    }
    {
        var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
        defer qc.deinit();
        quic_conn.testInstallAppKeys(&qc);
        var h3 = Connection.init(gpa, &qc);
        defer h3.deinit();
        var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer h3_bytes.deinit(gpa);
        try postWithContentLength(&h3_bytes, gpa, "10"); // declares 10, sends 5
        try h3_frame.append(&h3_bytes, gpa, .data, "body!");
        const dgram = try buildRequestFin(gpa, &dcid, h3_bytes.items);
        defer gpa.free(dgram);
        try qc.receiveDatagram(dgram, 1000);
        try testing.expectError(error.H3Error, h3.pump(0));
    }
}

test "an unknown non-grease frame on a request stream is ignored" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x2a, 0x2b, 0x2c, 0x2d };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    // An unknown frame type 0x2f (not a grease value, not a known control frame)
    // before the HEADERS: RFC 9114 9 says ignore it, so the request still parses.
    try h3_frame.append(&h3_bytes, gpa, @enumFromInt(0x2f), "junk");
    try h3_frame.append(&h3_bytes, gpa, .headers, &.{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 });
    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .request);
}

test "a SETTINGS frame on a request stream is unexpected" {
    const gpa = testing.allocator;
    // SETTINGS (0x04) belongs on the control stream, never a request stream.
    var block: std.ArrayListUnmanaged(u8) = .empty;
    defer block.deinit(gpa);
    h3_frame.append(&block, gpa, .settings, "") catch unreachable;
    try testing.expectError(error.H3Error, pumpFrames(gpa, block.items));
}

// Feed an arbitrary H3 frame stream (already encoded) and pump stream 0.
fn pumpFrames(gpa: std.mem.Allocator, h3_bytes: []const u8) Error!void {
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = quic_conn.Connection.init(gpa, .server, &dcid) catch return error.H3Error;
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();
    const dgram = buildRequest(gpa, &dcid, 0, h3_bytes) catch return error.H3Error;
    defer gpa.free(dgram);
    qc.receiveDatagram(dgram, 1000) catch return error.H3Error;
    try h3.pump(0);
}

test "DATA before HEADERS is rejected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x07, 0x07, 0x07, 0x07 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc); // H3 request data rides the Application space
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .data, "x");
    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try testing.expectError(error.H3Error, h3.pump(0));
}

// Build a 1-RTT packet whose STREAM frame carries `h3_bytes` at `offset` on stream
// 0 (the OFF flag is set), with packet number `pn` so a second datagram decrypts.
fn buildRequestAt(gpa: std.mem.Allocator, dcid: []const u8, offset: u64, pn: u64, h3_bytes: []const u8) ![]u8 {
    const varint = @import("../quic/varint.zig");
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0e); // STREAM, OFF|LEN set
    try varint.append(&sframe, gpa, 0); // stream id 0
    try varint.append(&sframe, gpa, offset);
    try varint.append(&sframe, gpa, h3_bytes.len);
    try sframe.appendSlice(gpa, h3_bytes);
    return @import("../quic/connection.zig").testBuildApp(gpa, dcid, pn, sframe.items);
}

test "a request split across two datagrams parses correctly (parsed-offset regression)" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc); // H3 request data rides the Application space
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const qpack_block = [_]u8{ 0x00, 0x00, 0xC0 | 20, 0xC0 | 23, 0xC0 | 1 }; // POST https /
    var headers_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer headers_bytes.deinit(gpa);
    try h3_frame.append(&headers_bytes, gpa, .headers, &qpack_block);
    var data_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer data_bytes.deinit(gpa);
    try h3_frame.append(&data_bytes, gpa, .data, "second-datagram-body");

    // Datagram 1: just the HEADERS frame.
    const dg1 = try buildRequestAt(gpa, &dcid, 0, 0, headers_bytes.items);
    defer gpa.free(dg1);
    try qc.receiveDatagram(dg1, 1000);
    try h3.pump(0);
    try testing.expect(h3.nextEvent() == .request);
    try testing.expect(h3.nextEvent() == .need_data);

    // Datagram 2: the DATA frame at the offset right after the HEADERS frame.
    const dg2 = try buildRequestAt(gpa, &dcid, headers_bytes.items.len, 1, data_bytes.items);
    defer gpa.free(dg2);
    try qc.receiveDatagram(dg2, 2000);
    try h3.pump(0);
    const data_ev = h3.nextEvent();
    try testing.expect(data_ev == .data);
    try testing.expectEqualStrings("second-datagram-body", data_ev.data.data);
}

test "the event arena is reclaimed when the queue drains" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc); // H3 request data rides the Application space
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    const qpack_block = [_]u8{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 };
    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(gpa);
    try h3_frame.append(&h3_bytes, gpa, .headers, &qpack_block);
    const dgram = try buildRequest(gpa, &dcid, 0, h3_bytes.items);
    defer gpa.free(dgram);
    try qc.receiveDatagram(dgram, 1000);
    try h3.pump(0);
    const req = h3.nextEvent();
    try testing.expect(req == .request);
    try testing.expectEqualStrings("GET", req.request.method);
    // Draining to need_data resets the arena. A second request on a new stream
    // must still decode correctly (the reset reclaims the first request's copies
    // without corrupting the decode path).
    try testing.expect(h3.nextEvent() == .need_data);

    const dgram2 = try buildRequest(gpa, &dcid, 4, h3_bytes.items); // stream 4 (client bidi)
    defer gpa.free(dgram2);
    try qc.receiveDatagram(dgram2, 2000);
    try h3.pump(4);
    const req2 = h3.nextEvent();
    try testing.expect(req2 == .request);
    try testing.expectEqualStrings("GET", req2.request.method);
}

test "a server sends a response: HEADERS then DATA then FIN" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x99, 0xaa, 0xbb, 0xcc };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // Respond 200 on server-initiated bidi stream id 1 with a body.
    const headers = [_]Header{.{ .name = "content-type", .value = "text/plain" }};
    try h3.sendResponse(0, 200, &headers);
    try h3.sendData(0, "hello");
    try h3.endStream(0);

    // The QUIC send stream now holds the HEADERS frame, the DATA frame, and a FIN.
    // Flush into a datagram and read it back through a peer to confirm reassembly.
    try qc.flushSend(1000);
    var peer = try quic_conn.Connection.init(gpa, .client, &dcid);
    defer peer.deinit();
    quic_conn.testInstallAppKeys(&peer);
    const buf = qc.datagramsToSend();
    var off: usize = 0;
    for (qc.datagramLengths()) |len| {
        try peer.receiveDatagram(buf[off .. off + len], 2000);
        off += len;
    }
    const got = peer.streamData(0);
    try testing.expect(peer.streamFinished(0));

    // The first H3 frame is HEADERS; the next is DATA carrying "hello".
    const d1 = try h3_frame.decode(got);
    try testing.expectEqual(h3_frame.FrameType.headers, d1.frame.ftype);
    const d2 = try h3_frame.decode(got[d1.len..]);
    try testing.expectEqual(h3_frame.FrameType.data, d2.frame.ftype);
    try testing.expectEqualStrings("hello", d2.frame.payload);
}

test "the response send API rejects invalid sequences and inputs" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x1a, 0x2b, 0x3c, 0x4d };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
    quic_conn.testInstallAppKeys(&qc);
    var h3 = Connection.init(gpa, &qc);
    defer h3.deinit();

    // DATA before HEADERS is rejected.
    try testing.expectError(error.H3Error, h3.sendData(0, "x"));
    // An out-of-range status is rejected.
    try testing.expectError(error.H3Error, h3.sendResponse(0, 99, &.{}));
    // A pseudo-header in the response headers is rejected (the server sets :status).
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &[_]Header{.{ .name = ":status", .value = "200" }}));
    // An uppercase / non-token field name is rejected (RFC 9114 4.2).
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &[_]Header{.{ .name = "X-Bad", .value = "x" }}));
    // A connection-specific field is rejected.
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &[_]Header{.{ .name = "connection", .value = "close" }}));
    // A CR/LF/control byte in a value is rejected (no header splitting).
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &[_]Header{.{ .name = "x", .value = "a\r\nb" }}));
    // A response on a non-client-bidi stream is rejected.
    try testing.expectError(error.H3Error, h3.sendResponse(1, 200, &.{}));

    // A valid response, then a second HEADERS is rejected, and writes after FIN too.
    try h3.sendResponse(0, 200, &.{});
    try testing.expectError(error.H3Error, h3.sendResponse(0, 200, &.{}));
    try h3.endStream(0);
    try testing.expectError(error.H3Error, h3.sendData(0, "late"));
}
