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
const events = @import("../events.zig");
const quic_conn = @import("../quic/connection.zig");
const quic_stream = @import("../quic/stream.zig");
const h3_frame = @import("frame.zig");
const h3_stream = @import("stream.zig");
const qpack = @import("qpack/decoder.zig");

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
};

pub const Connection = struct {
    gpa: std.mem.Allocator,
    qc: *quic_conn.Connection,
    streams: std.AutoHashMapUnmanaged(u64, RequestStream) = .empty,
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
        self.qpack_dec.deinit();
        self.queue.deinit(self.gpa);
        self.arena.deinit();
    }

    /// Advance the parse of request stream `id` from whatever ordered bytes the
    /// QUIC transport now has. Newly completed events are appended to the queue.
    /// The caller (the adapter) calls this when it knows a stream got data; a
    /// production driver would call it for every stream that advanced.
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
            try self.push(.{ .end_of_message = .{ .trailers = &.{}, .stream_id = @truncate(id) } });
            rs.state = .done;
        }
        if (consumed_total > 0) self.qc.consumeStream(id, consumed_total);
    }

    fn onFrame(self: *Connection, id: u64, rs: *RequestStream, f: h3_frame.Frame) Error!void {
        switch (f.ftype) {
            .headers => {
                if (rs.state != .idle) return error.H3Error; // trailers after body are a follow-up
                const req = try self.decodeRequest(id, f.payload);
                try self.push(.{ .request = req });
                rs.state = .headers_done;
            },
            .data => {
                if (rs.state != .headers_done) return error.H3Error; // DATA before HEADERS (RFC 9114 4.1)
                const body = try self.dupe(f.payload);
                try self.push(.{ .data = .{ .data = body, .stream_id = @truncate(id) } });
            },
            else => {
                if (h3_frame.isReserved(@intFromEnum(f.ftype))) return; // grease: ignore
                // SETTINGS/GOAWAY/etc. on a request stream are an error (RFC 9114 7.1).
                return error.H3Error;
            },
        }
    }

    /// Collapse a QPACK-decoded field section into a Request, pulling the four
    /// pseudo-headers into the shared shape and keeping the rest as headers.
    fn decodeRequest(self: *Connection, id: u64, block: []const u8) Error!events.Request {
        const fields = self.qpack_dec.decode(block) catch return error.H3Error;
        var method: []const u8 = "";
        var path: []const u8 = "";
        var authority: []const u8 = "";
        var scheme: []const u8 = "";
        var regular: std.ArrayListUnmanaged(Header) = .empty;
        defer regular.deinit(self.gpa);
        var seen_regular = false;

        for (fields) |h| {
            if (h.name.len > 0 and h.name[0] == ':') {
                if (seen_regular) return error.H3Error; // pseudo after regular (RFC 9114 4.3)
                if (eql(h.name, ":method")) method = h.value else if (eql(h.name, ":path")) path = h.value else if (eql(h.name, ":authority")) authority = h.value else if (eql(h.name, ":scheme")) scheme = h.value else return error.H3Error;
            } else {
                seen_regular = true;
                regular.append(self.gpa, h) catch return error.OutOfMemory;
            }
        }
        if (method.len == 0 or path.len == 0 or scheme.len == 0) return error.H3Error;

        // Materialise everything into the arena so the slices outlive the next
        // QPACK decode (which clears its store).
        const a = self.arena.allocator();
        var headers: std.ArrayListUnmanaged(Header) = .empty;
        if (authority.len > 0) {
            headers.append(a, .{ .name = "host", .value = try a.dupe(u8, authority) }) catch return error.OutOfMemory;
        }
        for (regular.items) |h| {
            headers.append(a, .{ .name = try a.dupe(u8, h.name), .value = try a.dupe(u8, h.value) }) catch return error.OutOfMemory;
        }
        const target = try a.dupe(u8, path);
        const q = std.mem.indexOfScalar(u8, target, '?');
        return .{
            .method = try a.dupe(u8, method),
            .target = target,
            .path = if (q) |i| target[0..i] else target,
            .query = if (q) |i| target[i + 1 ..] else target[target.len..],
            .http_version = "3",
            .headers = headers.items,
            .stream_id = @truncate(id),
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
};

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const testing = std.testing;

// Build a client Initial datagram carrying a STREAM frame on the given bidi
// stream id whose body is the H3 frames, so a server QUIC+H3 stack decodes it.
fn buildRequest(gpa: std.mem.Allocator, dcid: []const u8, stream_id: u64, h3_bytes: []const u8) ![]u8 {
    const varint = @import("../quic/varint.zig");
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0a); // STREAM, LEN set, no OFF, no FIN
    try varint.append(&sframe, gpa, stream_id);
    try varint.append(&sframe, gpa, h3_bytes.len);
    try sframe.appendSlice(gpa, h3_bytes);
    return @import("../quic/connection.zig").testBuildInitial(gpa, dcid, .client, 0, sframe.items);
}

test "decode a GET request over HTTP/3" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
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

test "a request with a body yields request then data" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0xab, 0xcd, 0xef, 0x01 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
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

test "DATA before HEADERS is rejected" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x07, 0x07, 0x07, 0x07 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
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

// Build an Initial whose STREAM frame carries `h3_bytes` at `offset` on stream 0
// (the OFF flag is set), with packet number `pn` so a second datagram decrypts.
fn buildRequestAt(gpa: std.mem.Allocator, dcid: []const u8, offset: u64, pn: u64, h3_bytes: []const u8) ![]u8 {
    const varint = @import("../quic/varint.zig");
    var sframe: std.ArrayListUnmanaged(u8) = .empty;
    defer sframe.deinit(gpa);
    try sframe.append(gpa, 0x0e); // STREAM, OFF|LEN set
    try varint.append(&sframe, gpa, 0); // stream id 0
    try varint.append(&sframe, gpa, offset);
    try varint.append(&sframe, gpa, h3_bytes.len);
    try sframe.appendSlice(gpa, h3_bytes);
    return @import("../quic/connection.zig").testBuildInitial(gpa, dcid, .client, pn, sframe.items);
}

test "a request split across two datagrams parses correctly (parsed-offset regression)" {
    const gpa = testing.allocator;
    const dcid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    var qc = try quic_conn.Connection.init(gpa, .server, &dcid);
    defer qc.deinit();
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
