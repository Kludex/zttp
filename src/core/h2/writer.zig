//! The HTTP/2 write side: serialize the handshake, HEADERS (HPACK-encoded), DATA
//! (split to the peer's max frame size), and the control frames. Sans-IO: it
//! appends to an owned outbound buffer that the caller drains with `pending()` /
//! `clear()`; it never does I/O and never buffers a body internally (DATA is
//! framed as given). The reverse of connection.zig - and tested by round-tripping
//! its output back through a Connection.

const std = @import("std");
const constants = @import("constants.zig");
const frame_mod = @import("frame.zig");
const encoder = @import("hpack/encoder.zig");

const Header = @import("../events.zig").Header;
const FrameType = constants.FrameType;
const Flags = constants.Flags;
const ErrorCode = constants.ErrorCode;

pub const Role = enum { server, client };

pub const WriteError = error{
    /// A send that is invalid for the protocol state, or a field that would
    /// corrupt the wire (a pseudo-header out of order, a non-token name).
    LocalProtocol,
    /// A header name/value contained a forbidden byte (CR/LF/NUL or uppercase).
    InvalidField,
    OutOfMemory,
};

pub const Writer = struct {
    gpa: std.mem.Allocator,
    role: Role,
    out: std.ArrayList(u8) = .empty,
    /// Client-initiated stream ids are odd and monotonic; this is the next one.
    next_local_id: u32,
    /// The peer's advertised max frame size, used to split DATA and HEADERS.
    peer_max_frame: u32 = constants.DEFAULT_FRAME_SIZE,

    pub fn init(gpa: std.mem.Allocator, role: Role) Writer {
        return .{
            .gpa = gpa,
            .role = role,
            .next_local_id = if (role == .client) 1 else 2,
        };
    }

    pub fn deinit(self: *Writer) void {
        self.out.deinit(self.gpa);
    }

    pub fn pending(self: *const Writer) []const u8 {
        return self.out.items;
    }

    pub fn clear(self: *Writer) void {
        self.out.clearRetainingCapacity();
    }

    /// Emit the connection preface: the 24-byte magic (client only) followed by a
    /// SETTINGS frame carrying `params` (id, value) pairs.
    pub fn sendPreface(self: *Writer, params: []const [2]u32) WriteError!void {
        if (self.role == .client) self.out.appendSlice(self.gpa, constants.CLIENT_PREFACE) catch return error.OutOfMemory;
        try self.sendSettings(params);
    }

    pub fn sendSettings(self: *Writer, params: []const [2]u32) WriteError!void {
        var payload: [6 * 64]u8 = undefined;
        if (params.len > 64) return error.LocalProtocol;
        var i: usize = 0;
        for (params) |p| {
            std.mem.writeInt(u16, payload[i..][0..2], @intCast(p[0]), .big);
            std.mem.writeInt(u32, payload[i + 2 ..][0..4], p[1], .big);
            i += 6;
        }
        try self.writeFrame(.settings, 0, 0, payload[0..i]);
    }

    pub fn sendSettingsAck(self: *Writer) WriteError!void {
        try self.writeFrame(.settings, Flags.ack, 0, &.{});
    }

    pub fn sendPingAck(self: *Writer, opaque_data: [8]u8) WriteError!void {
        try self.writeFrame(.ping, Flags.ack, 0, &opaque_data);
    }

    pub fn sendWindowUpdate(self: *Writer, stream_id: u32, increment: u32) WriteError!void {
        var p: [4]u8 = undefined;
        std.mem.writeInt(u32, &p, increment & 0x7FFF_FFFF, .big);
        try self.writeFrame(.window_update, 0, stream_id, &p);
    }

    pub fn sendRstStream(self: *Writer, stream_id: u32, code: ErrorCode) WriteError!void {
        var p: [4]u8 = undefined;
        std.mem.writeInt(u32, &p, @intFromEnum(code), .big);
        try self.writeFrame(.rst_stream, 0, stream_id, &p);
    }

    pub fn sendGoaway(self: *Writer, last_stream_id: u32, code: ErrorCode, debug: []const u8) WriteError!void {
        var head: [8]u8 = undefined;
        std.mem.writeInt(u32, head[0..4], last_stream_id & 0x7FFF_FFFF, .big);
        std.mem.writeInt(u32, head[4..8], @intFromEnum(code), .big);
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.gpa);
        payload.appendSlice(self.gpa, &head) catch return error.OutOfMemory;
        payload.appendSlice(self.gpa, debug) catch return error.OutOfMemory;
        try self.writeFrame(.goaway, 0, 0, payload.items);
    }

    /// Serialize a request head (client role). The pseudo-headers are emitted
    /// first, in the canonical order, then the regular headers. Allocates a new
    /// odd stream id and returns it. `end_stream` marks a bodyless request.
    pub fn sendRequest(self: *Writer, method: []const u8, target: []const u8, scheme: []const u8, authority: []const u8, headers: []const Header, end_stream: bool) WriteError!u32 {
        const id = self.next_local_id;
        self.next_local_id += 2;
        const pseudo = [_]Header{
            .{ .name = ":method", .value = method },
            .{ .name = ":scheme", .value = scheme },
            .{ .name = ":authority", .value = authority },
            .{ .name = ":path", .value = target },
        };
        try self.sendHeaderBlock(id, &pseudo, headers, end_stream);
        return id;
    }

    /// Serialize a response head (server role) on `stream_id`. `:status` is the
    /// only response pseudo-header.
    pub fn sendResponse(self: *Writer, stream_id: u32, status: u16, headers: []const Header, end_stream: bool) WriteError!void {
        var status_buf: [3]u8 = undefined;
        const status_str = formatStatus(status, &status_buf) orelse return error.LocalProtocol;
        const pseudo = [_]Header{.{ .name = ":status", .value = status_str }};
        try self.sendHeaderBlock(stream_id, &pseudo, headers, end_stream);
    }

    /// HPACK-encode the pseudo-headers + regular headers and frame them as HEADERS
    /// (+ CONTINUATION if the block exceeds the peer's max frame size). Validates
    /// the regular headers reject forbidden bytes / connection-specific fields.
    fn sendHeaderBlock(self: *Writer, stream_id: u32, pseudo: []const Header, headers: []const Header, end_stream: bool) WriteError!void {
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(self.gpa);
        for (pseudo) |h| {
            // The pseudo-header NAMES are fixed and known-good, but their VALUES
            // come from the caller (:path, :authority, :method, :status). Reject
            // control bytes so a CR/LF cannot be smuggled into the request line.
            try validateValue(h.value);
            encoder.encodeHeader(&block, self.gpa, h) catch return error.OutOfMemory;
        }
        for (headers) |h| {
            try validateField(h);
            encoder.encodeHeader(&block, self.gpa, h) catch return error.OutOfMemory;
        }
        try self.frameHeaderBlock(stream_id, block.items, end_stream);
    }

    /// Split an encoded field block across HEADERS + CONTINUATION at the peer's
    /// max frame size. END_HEADERS rides the last frame; END_STREAM (if any) rides
    /// the first HEADERS.
    fn frameHeaderBlock(self: *Writer, stream_id: u32, block: []const u8, end_stream: bool) WriteError!void {
        const max = self.peer_max_frame;
        var off: usize = 0;
        var first = true;
        while (true) {
            const remaining = block.len - off;
            const chunk_len = @min(remaining, max);
            const last = off + chunk_len == block.len;
            var flags: u8 = 0;
            if (last) flags |= Flags.end_headers;
            if (first and end_stream) flags |= Flags.end_stream;
            const ftype: FrameType = if (first) .headers else .continuation;
            try self.writeFrame(ftype, flags, stream_id, block[off .. off + chunk_len]);
            off += chunk_len;
            first = false;
            if (last) break;
        }
    }

    /// Serialize body bytes as DATA, split to the peer's max frame size.
    /// END_STREAM rides the final frame when `end_stream` is set. (Flow-control
    /// accounting is the caller's concern; this frames what it is given.)
    pub fn sendData(self: *Writer, stream_id: u32, data: []const u8, end_stream: bool) WriteError!void {
        const max = self.peer_max_frame;
        if (data.len == 0) {
            if (end_stream) try self.writeFrame(.data, Flags.end_stream, stream_id, &.{});
            return;
        }
        var off: usize = 0;
        while (off < data.len) {
            const chunk_len = @min(data.len - off, max);
            const last = off + chunk_len == data.len;
            const flags: u8 = if (last and end_stream) Flags.end_stream else 0;
            try self.writeFrame(.data, flags, stream_id, data[off .. off + chunk_len]);
            off += chunk_len;
        }
    }

    fn writeFrame(self: *Writer, ftype: FrameType, flags: u8, stream_id: u32, payload: []const u8) WriteError!void {
        frame_mod.write(&self.out, self.gpa, ftype, flags, stream_id, payload) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.TooLarge => return error.LocalProtocol,
        };
    }
};

/// Reject a header that would corrupt the wire or violate HTTP/2 (RFC 9113 8.2):
/// non-token / uppercase name, control bytes in the value, or a connection-
/// specific field.
fn validateField(h: Header) WriteError!void {
    if (h.name.len == 0) return error.InvalidField;
    for (h.name) |ch| {
        if (ch >= 'A' and ch <= 'Z') return error.InvalidField;
        if (!is_tchar(ch)) return error.InvalidField;
    }
    try validateValue(h.value);
    const forbidden = [_][]const u8{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" };
    for (forbidden) |f| {
        if (std.mem.eql(u8, h.name, f)) return error.LocalProtocol;
    }
}

/// A field value must contain no control bytes (CR/LF/NUL/DEL), so a value can
/// never inject a frame boundary or corrupt the decoded request line.
fn validateValue(value: []const u8) WriteError!void {
    for (value) |ch| {
        if (ch < 0x20 or ch == 0x7F) return error.InvalidField;
    }
}

fn is_tchar(ch: u8) bool {
    return @import("../tables.zig").is_tchar[ch];
}

fn formatStatus(status: u16, buf: *[3]u8) ?[]const u8 {
    if (status < 100 or status > 599) return null;
    buf[0] = '0' + @as(u8, @intCast(status / 100));
    buf[1] = '0' + @as(u8, @intCast((status / 10) % 10));
    buf[2] = '0' + @as(u8, @intCast(status % 10));
    return buf[0..3];
}

const testing = std.testing;

test "formatStatus renders three digits" {
    var buf: [3]u8 = undefined;
    try testing.expectEqualStrings("200", formatStatus(200, &buf).?);
    try testing.expectEqualStrings("404", formatStatus(404, &buf).?);
    try testing.expectEqual(@as(?[]const u8, null), formatStatus(99, &buf));
    try testing.expectEqual(@as(?[]const u8, null), formatStatus(600, &buf));
}

test "validateField rejects uppercase, control bytes, and connection-specific fields" {
    try testing.expectError(error.InvalidField, validateField(.{ .name = "X-Bad", .value = "x" }));
    try testing.expectError(error.InvalidField, validateField(.{ .name = "ok", .value = "a\r\nb" }));
    try testing.expectError(error.LocalProtocol, validateField(.{ .name = "connection", .value = "close" }));
    try validateField(.{ .name = "content-type", .value = "text/plain" });
}

test "a CRLF in a pseudo-header value (e.g. target) is rejected" {
    var w = Writer.init(testing.allocator, .client);
    defer w.deinit();
    try testing.expectError(error.InvalidField, w.sendRequest("GET", "/a\r\nX-Evil: y", "https", "h", &.{}, true));
}

test "sendData splits at the peer max frame size" {
    var w = Writer.init(testing.allocator, .server);
    defer w.deinit();
    w.peer_max_frame = 4;
    try w.sendData(3, "abcdefg", true); // 7 bytes -> 4 + 3
    // Parse the two DATA frames back.
    const f1 = try frame_mod.parse(w.pending(), 16384);
    try testing.expectEqual(@as(u24, 4), f1.header.length);
    try testing.expect(!Flags.has(f1.header.flags, Flags.end_stream));
    const rest = w.pending()[constants.FRAME_HEADER_LEN + 4 ..];
    const f2 = try frame_mod.parse(rest, 16384);
    try testing.expectEqual(@as(u24, 3), f2.header.length);
    try testing.expect(Flags.has(f2.header.flags, Flags.end_stream));
}

test "a written request round-trips through a Connection" {
    const Connection = @import("connection.zig").Connection;
    const Event = @import("../events.zig").Event;

    // Client writes the preface + SETTINGS + a request; a server Connection
    // parses it back to the same logical request.
    var w = Writer.init(testing.allocator, .client);
    defer w.deinit();
    try w.sendPreface(&.{});
    const headers = [_]Header{.{ .name = "user-agent", .value = "zttp" }};
    const id = try w.sendRequest("GET", "/path", "https", "example.com", &headers, true);
    try testing.expectEqual(@as(u32, 1), id);

    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    try c.feed(w.pending());
    // The server must ACK-less SETTINGS first.
    try testing.expectEqual(std.meta.Tag(Event).settings, std.meta.activeTag(try c.nextEvent()));
    const req = try c.nextEvent();
    try testing.expectEqual(@as(u32, 1), req.request.stream_id);
    try testing.expectEqualStrings("GET", req.request.method);
    try testing.expectEqualStrings("/path", req.request.target);
    // user-agent and the synthesized host are both present.
    var saw_ua = false;
    var saw_host = false;
    for (req.request.headers) |h| {
        if (std.mem.eql(u8, h.name, "user-agent")) saw_ua = true;
        if (std.mem.eql(u8, h.name, "host") and std.mem.eql(u8, h.value, "example.com")) saw_host = true;
    }
    try testing.expect(saw_ua and saw_host);
    try testing.expectEqual(std.meta.Tag(Event).end_of_message, std.meta.activeTag(try c.nextEvent()));
}

test "a HEADERS block larger than the peer max frame splits into CONTINUATION and round-trips" {
    const Connection = @import("connection.zig").Connection;
    const Event = @import("../events.zig").Event;

    var w = Writer.init(testing.allocator, .client);
    defer w.deinit();
    w.peer_max_frame = constants.DEFAULT_FRAME_SIZE; // server parses with the default
    try w.sendPreface(&.{});
    // A big header value forces the block past a small frame size on the wire,
    // but the server's max_frame_size is the default 16384, so set the writer's
    // split point below that to exercise CONTINUATION while staying parseable.
    w.peer_max_frame = 64;
    var big: [200]u8 = undefined;
    @memset(&big, 'v');
    const headers = [_]Header{.{ .name = "x-big", .value = &big }};
    _ = try w.sendRequest("POST", "/", "https", "h", &headers, true);

    var c = Connection.init(testing.allocator, .server);
    defer c.deinit();
    try c.feed(w.pending());
    try testing.expectEqual(std.meta.Tag(Event).settings, std.meta.activeTag(try c.nextEvent()));
    const req = try c.nextEvent();
    try testing.expectEqualStrings("POST", req.request.method);
    var saw_big = false;
    for (req.request.headers) |h| {
        if (std.mem.eql(u8, h.name, "x-big")) {
            try testing.expectEqualStrings(&big, h.value);
            saw_big = true;
        }
    }
    try testing.expect(saw_big);
}
