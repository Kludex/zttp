//! The read-side message state machine: owns a growing input buffer, parses one
//! message at a time, and yields events. This is where partial-data handling
//! lives - bytes accumulate across `feed` calls and the cursor only advances
//! past data that produced a complete event.
//!
//! Buffer strategy: a single ArrayList. `consumed` marks how far parsing has
//! progressed; `nextEvent` slices live into `buf.items[consumed..]`. We compact
//! (drop the consumed prefix) lazily, only when the consumed region grows large,
//! so steady-state parsing is append-and-advance with no per-call memmove.

const std = @import("std");
const events = @import("events.zig");
const headers_mod = @import("headers.zig");
const framing_mod = @import("framing.zig");
const chunked_mod = @import("chunked.zig");
const Scanner = @import("scanner.zig").Scanner;
const ParseError = @import("errors.zig").ParseError;

const Header = events.Header;
const Event = events.Event;
const Framing = framing_mod.Framing;

const COMPACT_THRESHOLD: usize = 64 * 1024;

pub const Role = enum { server, client };

const State = enum {
    /// Waiting for the request/status line + headers of a new message.
    head,
    /// Streaming a Content-Length-delimited body.
    body_length,
    /// Streaming a chunked body.
    body_chunked,
    /// Streaming an until-close body (response only).
    body_until_close,
    /// Body fully read; the next event is EndOfMessage (with any trailers).
    eom_pending,
    /// Message complete; awaiting reset() for the next one (or EOF).
    done,
    /// The peer closed; no more messages.
    closed,
};

pub const Limits = struct {
    max_line: usize = 16 * 1024,
    max_headers: usize = 100,
    max_header_bytes: usize = 64 * 1024,
};

pub const Reader = struct {
    gpa: std.mem.Allocator,
    role: Role,
    limits: Limits = .{},

    buf: std.ArrayList(u8) = .empty,
    consumed: usize = 0,

    state: State = .head,
    /// Header storage for the message currently being reported. Cleared on reset.
    headers: std.ArrayList(Header) = .empty,
    /// Backing copy of the head bytes (request line + headers) so the reported
    /// event's slices stay valid after the input buffer is compacted/refilled.
    head_store: std.ArrayList(u8) = .empty,
    trailers: std.ArrayList(Header) = .empty,

    body_remaining: u64 = 0,
    chunk: chunked_mod.ChunkDecoder = .{},
    /// Set by the connection layer before headers are parsed: responses to HEAD
    /// etc. have no body whatever the headers say.
    next_bodyless: bool = false,
    eof_seen: bool = false,

    pub fn init(gpa: std.mem.Allocator, role: Role) Reader {
        return .{ .gpa = gpa, .role = role };
    }

    pub fn deinit(self: *Reader) void {
        self.buf.deinit(self.gpa);
        self.headers.deinit(self.gpa);
        self.head_store.deinit(self.gpa);
        self.trailers.deinit(self.gpa);
    }

    /// Append received bytes. An empty slice signals end of input (peer close).
    pub fn feed(self: *Reader, data: []const u8) !void {
        if (data.len == 0) {
            self.eof_seen = true;
            return;
        }
        try self.buf.appendSlice(self.gpa, data);
    }

    /// Prepare to read the next message on the same connection (keep-alive).
    pub fn reset(self: *Reader) void {
        self.state = .head;
        self.headers.clearRetainingCapacity();
        self.head_store.clearRetainingCapacity();
        self.trailers.clearRetainingCapacity();
        self.body_remaining = 0;
        self.chunk = .{};
        self.next_bodyless = false;
    }

    fn compact(self: *Reader) void {
        if (self.consumed == 0) return;
        const rest = self.buf.items.len - self.consumed;
        std.mem.copyForwards(u8, self.buf.items[0..rest], self.buf.items[self.consumed..]);
        self.buf.shrinkRetainingCapacity(rest);
        self.consumed = 0;
    }

    /// Produce the next event, or `.need_data`. Slices in `request`/`response`
    /// events point into `head_store` (stable); `data` events point into the
    /// input buffer and are valid until the next `nextEvent`/`feed` call.
    pub fn nextEvent(self: *Reader) ParseError!Event {
        if (self.consumed >= COMPACT_THRESHOLD) self.compact();
        return switch (self.state) {
            .head => self.readHead(),
            .body_length => self.readBodyLength(),
            .body_chunked => self.readBodyChunked(),
            .body_until_close => self.readBodyUntilClose(),
            .eom_pending => blk: {
                self.state = .done;
                break :blk .{ .end_of_message = .{ .trailers = self.trailers.items } };
            },
            .done => .need_data,
            .closed => .connection_closed,
        };
    }

    fn avail(self: *Reader) []const u8 {
        return self.buf.items[self.consumed..];
    }

    fn readHead(self: *Reader) ParseError!Event {
        // Find the blank line that ends the header block before committing, so a
        // partial head leaves the buffer untouched.
        const region = self.avail();
        const head_len = findHeadEnd(region) orelse {
            if (region.len > self.limits.max_header_bytes) return error.MessageTooLong;
            if (self.eof_seen and region.len == 0) {
                self.state = .closed;
                return .connection_closed;
            }
            return .need_data;
        };

        // Copy the head into stable storage; the event slices reference this.
        self.head_store.clearRetainingCapacity();
        self.head_store.appendSlice(self.gpa, region[0..head_len]) catch return error.MessageTooLong;
        const head = self.head_store.items;
        self.consumed += head_len;

        var sc = Scanner.init(head);
        const first = (sc.line(self.limits.max_line) catch return error.InvalidLine).?;

        self.headers.clearRetainingCapacity();
        var header_bytes: usize = 0;
        while (sc.line(self.limits.max_line) catch return error.InvalidHeader) |hl| {
            if (hl.len == 0) break;
            header_bytes += hl.len;
            if (self.headers.items.len >= self.limits.max_headers or header_bytes > self.limits.max_header_bytes) {
                return error.MessageTooLong;
            }
            const h = try headers_mod.parseHeaderLine(hl);
            self.headers.append(self.gpa, h) catch return error.MessageTooLong;
        }

        const f = try framing_mod.determine(self.headers.items, .{
            .bodyless = self.next_bodyless,
            .until_close_default = self.role == .client,
        });
        self.enterBody(f);

        if (self.role == .server) {
            const rl = try headers_mod.parseRequestLine(first);
            return .{ .request = .{
                .method = rl.method,
                .target = rl.target,
                .http_version = rl.http_version,
                .headers = self.headers.items,
            } };
        } else {
            const st = try headers_mod.parseStatusLine(first);
            return .{ .response = .{
                .status_code = st.status_code,
                .reason = st.reason,
                .http_version = st.http_version,
                .headers = self.headers.items,
            } };
        }
    }

    fn enterBody(self: *Reader, f: Framing) void {
        switch (f) {
            .none => self.state = .eom_pending,
            .content_length => |n| {
                self.body_remaining = n;
                self.state = .body_length;
            },
            .chunked => {
                self.chunk = .{ .max_line = self.limits.max_line };
                self.state = .body_chunked;
            },
            .until_close => self.state = .body_until_close,
        }
    }

    fn readBodyLength(self: *Reader) ParseError!Event {
        if (self.body_remaining == 0) {
            self.state = .eom_pending;
            return self.nextEvent();
        }
        const region = self.avail();
        if (region.len == 0) {
            if (self.eof_seen) return error.ProtocolError; // truncated body
            return .need_data;
        }
        const take = @min(region.len, self.body_remaining);
        const span = region[0..take];
        self.consumed += take;
        self.body_remaining -= take;
        return .{ .data = .{ .data = span } };
    }

    fn readBodyChunked(self: *Reader) ParseError!Event {
        var sc = Scanner.init(self.avail());
        const out = try self.chunk.next(&sc);
        self.consumed += sc.pos;
        return switch (out) {
            .data => |d| .{ .data = .{ .data = d } },
            .trailer_line => |l| {
                const h = try headers_mod.parseHeaderLine(l);
                self.trailers.append(self.gpa, h) catch return error.MessageTooLong;
                return self.readBodyChunked();
            },
            .done => blk: {
                self.state = .eom_pending;
                break :blk self.nextEvent();
            },
            .need_data => blk: {
                if (self.eof_seen) break :blk error.ProtocolError;
                break :blk .need_data;
            },
        };
    }

    fn readBodyUntilClose(self: *Reader) ParseError!Event {
        const region = self.avail();
        if (region.len > 0) {
            self.consumed += region.len;
            return .{ .data = .{ .data = region } };
        }
        if (self.eof_seen) {
            self.state = .eom_pending;
            return self.nextEvent();
        }
        return .need_data;
    }
};

/// Find the byte offset just past the blank line terminating the header block,
/// i.e. the length of the head. Recognizes both CRLFCRLF and bare LFLF.
fn findHeadEnd(region: []const u8) ?usize {
    var i: usize = 0;
    while (i < region.len) {
        // Look for LF, then test what precedes/follows for the blank line.
        const lf = std.mem.indexOfScalarPos(u8, region, i, '\n') orelse return null;
        // Is the line ending at `lf` empty (i.e. immediately another CRLF/LF)?
        const next = lf + 1;
        if (next < region.len) {
            if (region[next] == '\n') return next + 1;
            if (region[next] == '\r' and next + 1 < region.len and region[next + 1] == '\n') return next + 2;
        }
        i = lf + 1;
    }
    return null;
}

const t = std.testing;

fn drainServer(input: []const u8) !struct { ev: std.ArrayList(EvTag), body: std.ArrayList(u8) } {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed(input);
    var tags: std.ArrayList(EvTag) = .empty;
    var body: std.ArrayList(u8) = .empty;
    while (true) {
        const e = try r.nextEvent();
        switch (e) {
            .need_data, .connection_closed => break,
            .request => try tags.append(t.allocator, .request),
            .response => try tags.append(t.allocator, .response),
            .data => |d| {
                try tags.append(t.allocator, .data);
                try body.appendSlice(t.allocator, d.data);
            },
            .end_of_message => {
                try tags.append(t.allocator, .eom);
                break;
            },
        }
    }
    return .{ .ev = tags, .body = body };
}

const EvTag = enum { request, response, data, eom };

fn expectTag(comptime tag: std.meta.Tag(Event), e: Event) !void {
    try t.expectEqual(tag, std.meta.activeTag(e));
}

test "findHeadEnd crlf" {
    try t.expectEqual(@as(?usize, 18), findHeadEnd("GET / HTTP/1.1\r\n\r\nX"));
}

test "findHeadEnd lf" {
    try t.expectEqual(@as(?usize, 16), findHeadEnd("GET / HTTP/1.1\n\nX"));
}

test "findHeadEnd partial" {
    try t.expectEqual(@as(?usize, null), findHeadEnd("GET / HTTP/1.1\r\nHost: x\r\n"));
}

test "simple GET no body" {
    var r = try drainServer("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n");
    defer r.ev.deinit(t.allocator);
    defer r.body.deinit(t.allocator);
    try t.expectEqual(@as(usize, 2), r.ev.items.len);
    try t.expectEqual(EvTag.request, r.ev.items[0]);
    try t.expectEqual(EvTag.eom, r.ev.items[1]);
}

test "POST content-length body" {
    var r = try drainServer("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello");
    defer r.ev.deinit(t.allocator);
    defer r.body.deinit(t.allocator);
    try t.expectEqualStrings("hello", r.body.items);
    try t.expectEqual(EvTag.eom, r.ev.items[r.ev.items.len - 1]);
}

test "POST chunked body with trailers" {
    var r = try drainServer("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-T: v\r\n\r\n");
    defer r.ev.deinit(t.allocator);
    defer r.body.deinit(t.allocator);
    try t.expectEqualStrings("abc", r.body.items);
}

test "request fields exposed" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("DELETE /x?y=1 HTTP/1.0\r\nHost: h\r\nAccept: */*\r\n\r\n");
    const e = try r.nextEvent();
    try t.expectEqualStrings("DELETE", e.request.method);
    try t.expectEqualStrings("/x?y=1", e.request.target);
    try t.expectEqualStrings("1.0", e.request.http_version);
    try t.expectEqual(@as(usize, 2), e.request.headers.len);
    try t.expectEqualStrings("Host", e.request.headers[0].name);
}

test "partial head then complete" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("GET / HTTP/1.1\r\nHo");
    try expectTag(.need_data, try r.nextEvent());
    try r.feed("st: x\r\n\r\n");
    const e = try r.nextEvent();
    try t.expectEqualStrings("GET", e.request.method);
    try t.expectEqualStrings("x", e.request.headers[0].value);
}

test "split body across feeds" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nhel");
    _ = try r.nextEvent(); // request
    const d1 = try r.nextEvent();
    try t.expectEqualStrings("hel", d1.data.data);
    try expectTag(.need_data, try r.nextEvent());
    try r.feed("loworld");
    const d2 = try r.nextEvent();
    try t.expectEqualStrings("loworld", d2.data.data);
    try t.expectEqual(@as(u64, 0), r.body_remaining);
}

test "keep-alive: two requests via reset" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: y\r\n\r\n");
    var e = try r.nextEvent();
    try t.expectEqualStrings("/a", e.request.target);
    try expectTag(.end_of_message, try r.nextEvent());
    r.reset();
    e = try r.nextEvent();
    try t.expectEqualStrings("/b", e.request.target);
}

test "client response until close" {
    var r = Reader.init(t.allocator, .client);
    defer r.deinit();
    try r.feed("HTTP/1.1 200 OK\r\nServer: z\r\n\r\nbody bytes here");
    const e = try r.nextEvent();
    try t.expectEqual(@as(u16, 200), e.response.status_code);
    const d = try r.nextEvent();
    try t.expectEqualStrings("body bytes here", d.data.data);
    try expectTag(.need_data, try r.nextEvent());
    try r.feed(""); // EOF
    try expectTag(.end_of_message, try r.nextEvent());
}

test "truncated content-length body errors at EOF" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort");
    _ = try r.nextEvent();
    _ = try r.nextEvent(); // "short"
    try r.feed("");
    try t.expectError(error.ProtocolError, r.nextEvent());
}
