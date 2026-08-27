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
const events = @import("../events.zig");
const headers_mod = @import("headers.zig");
const framing_mod = @import("framing.zig");
const connection_mod = @import("connection.zig");
const chunked_mod = @import("chunked.zig");
const Scanner = @import("../scanner.zig").Scanner;
const ParseError = @import("../errors.zig").ParseError;

const Header = events.Header;
const Event = events.H1Event;
const Framing = framing_mod.Framing;

const COMPACT_THRESHOLD: usize = 64 * 1024;

pub const Role = enum { server, client };

const TrailerRange = struct { off: usize, len: usize };

const HeadScan = struct {
    len: usize,
    header_count: usize,
};

/// Incrementally locates the blank line terminating an HTTP head while also
/// enforcing its line/count/byte limits. `scanned` and `line_start` are offsets
/// from the current message start, so appending another receive buffer resumes
/// at the first new byte instead of re-reading the whole partial head.
const HeadScanner = struct {
    scanned: usize = 0,
    line_start: usize = 0,
    completed_lines: usize = 0,

    fn reset(self: *HeadScanner) void {
        self.* = .{};
    }

    fn scan(self: *HeadScanner, region: []const u8, limits: Limits) ParseError!?HeadScan {
        std.debug.assert(self.scanned <= region.len);
        while (std.mem.findScalarPos(u8, region, self.scanned, '\n')) |lf| {
            const has_cr = lf > self.line_start and region[lf - 1] == '\r';
            const line_len = lf - self.line_start - @intFromBool(has_cr);
            if (line_len > limits.max_line) return error.MessageTooLong;

            const next = lf + 1;
            if (next > limits.max_header_bytes) return error.MessageTooLong;

            // A blank line terminates a head only after the request/status line.
            // This preserves the old delimiter search for malformed leading CRLF.
            if (line_len == 0 and self.completed_lines > 0) {
                const header_count = self.completed_lines - 1;
                if (header_count > limits.max_headers) return error.MessageTooLong;
                return .{ .len = next, .header_count = header_count };
            }

            self.completed_lines += 1;
            if (self.completed_lines > 1 and self.completed_lines - 1 > limits.max_headers) {
                return error.MessageTooLong;
            }
            self.scanned = next;
            self.line_start = next;
        }

        self.scanned = region.len;
        if (region.len > limits.max_header_bytes or region.len - self.line_start > limits.max_line) {
            return error.MessageTooLong;
        }
        return null;
    }
};

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
    /// A parse error occurred. The connection is poisoned: every further
    /// nextEvent re-raises rather than resuming, so a desynchronized byte
    /// stream can never be parsed as if it were valid.
    failed,
};

pub const Limits = struct {
    max_line: usize = 16 * 1024,
    max_headers: usize = 100,
    max_header_bytes: usize = 64 * 1024,
    /// Caps on the chunked trailer section, mirroring the head limits so a
    /// trailer flood cannot exhaust memory or recurse the stack.
    max_trailers: usize = 100,
    max_trailer_bytes: usize = 64 * 1024,
    /// Hard cap on bytes buffered but not yet consumed. Bounds the worst-case
    /// memory a peer can force and the cost of compaction. 0 disables the cap.
    max_buffer: usize = 8 * 1024 * 1024,
    /// Require CRLF line endings; reject a bare LF. Strict by default to avoid
    /// request-smuggling differentials with CRLF-strict intermediaries.
    strict_crlf: bool = true,
};

/// Connection semantics derived from one parsed request or response head.
/// `upgrade` borrows from the reader buffer, so adapters must consume this
/// snapshot immediately after receiving the corresponding head event.
pub const HeadInfo = struct {
    should_close: bool = false,
    upgrade: ?[]const u8 = null,
};

pub const Reader = struct {
    gpa: std.mem.Allocator,
    role: Role,
    limits: Limits = .{},

    buf: std.ArrayList(u8) = .empty,
    consumed: usize = 0,

    state: State = .head,
    head_scanner: HeadScanner = .{},
    /// Header storage for the message currently being reported. Cleared on reset.
    headers: std.ArrayList(Header) = .empty,
    trailers: std.ArrayList(Header) = .empty,
    /// Stable backing copy of the trailer field-lines, so trailer Header slices
    /// survive buffer growth/compaction. Unlike the head (which is parsed in
    /// place and materialised within one nextEvent call), trailers accrue
    /// incrementally across feeds and so must be copied to a buffer we own.
    trailer_store: std.ArrayList(u8) = .empty,
    trailer_ranges: std.ArrayList(TrailerRange) = .empty,
    trailer_bytes: usize = 0,

    body_remaining: u64 = 0,
    chunk: chunked_mod.ChunkDecoder = .{},
    /// The method the client sent for the in-flight request, so the reader can
    /// auto-frame the matching response as bodyless (HEAD / 1xx / 204 / 304 /
    /// CONNECT 2xx, RFC 9112 6.3). Empty when unknown. Server-side unused.
    request_method: [16]u8 = undefined,
    request_method_len: usize = 0,
    /// One-shot connection semantics for the most recently parsed head.
    head_info: HeadInfo = .{},
    head_info_pending: bool = false,
    eof_seen: bool = false,
    /// The error that poisoned the connection, re-raised on every later call.
    failed_with: ParseError = error.ProtocolError,

    pub fn init(gpa: std.mem.Allocator, role: Role) Reader {
        return .{ .gpa = gpa, .role = role };
    }

    pub fn deinit(self: *Reader) void {
        self.buf.deinit(self.gpa);
        self.headers.deinit(self.gpa);
        self.trailers.deinit(self.gpa);
        self.trailer_store.deinit(self.gpa);
        self.trailer_ranges.deinit(self.gpa);
    }

    /// Poison the connection with `e`. Feed and parse failures share this
    /// transition so every later operation re-raises the original error.
    fn fail(self: *Reader, e: ParseError) ParseError {
        self.state = .failed;
        self.failed_with = e;
        return e;
    }

    /// Reject and latch input that would push unconsumed bytes past
    /// `max_buffer`, whether copied into `buf` or retained by a wrapper fast path.
    pub fn checkBufferLimit(self: *Reader, data_len: usize) ParseError!void {
        if (self.state == .failed) return self.failed_with;
        if (self.limits.max_buffer == 0) return;
        const unconsumed = self.buf.items.len - self.consumed;
        if (unconsumed > self.limits.max_buffer or data_len > self.limits.max_buffer - unconsumed) {
            return self.fail(error.MessageTooLong);
        }
    }

    /// Append received bytes. An empty slice signals end of input (peer close).
    /// Rejects input that would push the unconsumed buffer past `max_buffer`,
    /// bounding peer-forced memory and compaction cost.
    pub fn feed(self: *Reader, data: []const u8) ParseError!void {
        if (self.state == .failed) return self.failed_with;
        if (data.len == 0) {
            self.eof_seen = true;
            return;
        }
        if (self.eof_seen) return self.fail(error.ProtocolError);
        try self.checkBufferLimit(data.len);
        self.buf.appendSlice(self.gpa, data) catch return self.fail(error.MessageTooLong);
    }

    /// Remember the method the client just sent, so the reader frames the
    /// matching response as bodyless for HEAD / 1xx / 204 / 304 / CONNECT 2xx
    /// (RFC 9112 6.3). A method longer than the buffer simply does not trigger
    /// the method-based rule; the status-based rule still applies.
    pub fn setRequestMethod(self: *Reader, method: []const u8) void {
        if (method.len > self.request_method.len) {
            self.request_method_len = 0;
            return;
        }
        @memcpy(self.request_method[0..method.len], method);
        self.request_method_len = method.len;
    }

    /// Prepare to read the next message on the same connection (keep-alive).
    /// The current message must have surfaced its completion event.
    pub fn reset(self: *Reader) error{MessageInProgress}!void {
        if (self.state != .done) return error.MessageInProgress;
        self.state = .head;
        self.head_scanner.reset();
        self.headers.clearRetainingCapacity();
        self.trailers.clearRetainingCapacity();
        self.trailer_store.clearRetainingCapacity();
        self.trailer_ranges.clearRetainingCapacity();
        self.trailer_bytes = 0;
        self.body_remaining = 0;
        self.chunk = .{};
        self.request_method_len = 0;
        self.head_info_pending = false;
    }

    /// Consume the connection semantics attached to the head event that was
    /// just returned. A second call yields an empty snapshot, which prevents an
    /// adapter from accidentally applying stale metadata to another message.
    pub inline fn takeHeadInfo(self: *Reader) HeadInfo {
        if (!self.head_info_pending) return .{};
        self.head_info_pending = false;
        return self.head_info;
    }

    /// True when every buffered byte has been consumed.
    pub fn backlogEmpty(self: *const Reader) bool {
        return self.buf.items.len == self.consumed;
    }

    /// True once EOF has been signalled on this read side; non-empty input after
    /// this point is a protocol/API error.
    pub fn eofSeen(self: *const Reader) bool {
        return self.eof_seen;
    }

    /// True when the reader is waiting for the head of a new message.
    pub fn atMessageStart(self: *const Reader) bool {
        return self.state == .head;
    }

    /// Bytes still expected of a Content-Length body, or null when the reader
    /// is not mid-way through one.
    pub fn bodyLengthRemaining(self: *const Reader) ?u64 {
        return if (self.state == .body_length and self.body_remaining > 0) self.body_remaining else null;
    }

    /// Account for `n` body bytes the caller delivered to the application out
    /// of band, without buffering them. Only valid while `bodyLengthRemaining`
    /// is non-null and `n` is at most that remainder.
    pub fn skipBodyLength(self: *Reader, n: u64) void {
        std.debug.assert(self.state == .body_length and n <= self.body_remaining);
        self.body_remaining -= n;
        if (self.body_remaining == 0) self.state = .eom_pending;
    }

    fn compact(self: *Reader) void {
        if (self.consumed == 0) return;
        const rest = self.buf.items.len - self.consumed;
        std.mem.copyForwards(u8, self.buf.items[0..rest], self.buf.items[self.consumed..]);
        self.buf.shrinkRetainingCapacity(rest);
        self.consumed = 0;
    }

    /// Produce the next event, or `.need_data`.
    /// `request`/`response` events borrow slices from the input buffer; they are
    /// materialised by the caller within this call (before any feed/compact), so
    /// they are valid until nextEvent returns. `data` events likewise point into
    /// the buffer and are valid until the next `nextEvent`/`feed` call.
    ///
    /// A parse error poisons the connection: it is latched, and every subsequent
    /// call re-raises it rather than resuming. This makes errors terminal (as
    /// h11 does), so a desynchronized stream can never be silently re-parsed.
    pub fn nextEvent(self: *Reader) ParseError!Event {
        if (self.state == .failed) return self.failed_with;
        return self.dispatch() catch |e| self.fail(e);
    }

    fn dispatch(self: *Reader) ParseError!Event {
        // Compact once the consumed prefix is both sizeable and a majority of the
        // buffer. The fraction test keeps total memmove work amortized O(n) over
        // a large drain rather than the O(n^2) a fixed threshold alone would give.
        if (self.consumed >= COMPACT_THRESHOLD and self.consumed * 2 >= self.buf.items.len) self.compact();
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
            .failed => self.failed_with,
        };
    }

    fn avail(self: *Reader) []const u8 {
        return self.buf.items[self.consumed..];
    }

    fn readHead(self: *Reader) ParseError!Event {
        // Find the blank line that ends the header block before committing, so a
        // partial head leaves the buffer untouched. The scanner resumes where a
        // previous call stopped and combines the terminator and limit scans.
        const region = self.avail();
        const scan = (try self.head_scanner.scan(region, self.limits)) orelse {
            if (self.eof_seen) {
                if (region.len == 0) {
                    self.state = .closed;
                    return .connection_closed;
                }
                return error.ProtocolError;
            }
            return .need_data;
        };
        self.head_scanner.reset();
        const head_len = scan.len;

        // Parse the head in place, borrowing slices directly from the input
        // buffer - no copy. This is safe because the produced request/response
        // event is fully materialised into Python bytes within the same
        // nextEvent call (before any feed/compact can move the buffer): the
        // event's slices never outlive this call. Compaction only runs at the
        // top of the NEXT dispatch, by which point the bytes are already copied.
        const head = region[0..head_len];
        self.consumed += head_len;

        var sc = Scanner.init(head);
        const strict = self.limits.strict_crlf;
        const first = (sc.line(self.limits.max_line, strict) catch |e| switch (e) {
            error.MessageTooLong => return error.MessageTooLong,
            error.BareLf => return error.InvalidLine,
        }).?;

        self.headers.clearRetainingCapacity();
        self.headers.ensureTotalCapacity(self.gpa, scan.header_count) catch return error.MessageTooLong;
        var semantics = connection_mod.HeadSemantics{};
        var header_bytes: usize = 0;
        while (sc.line(self.limits.max_line, strict) catch |e| switch (e) {
            error.MessageTooLong => return error.MessageTooLong,
            error.BareLf => return error.InvalidHeader,
        }) |hl| {
            if (hl.len == 0) break;
            header_bytes += hl.len;
            if (self.headers.items.len >= self.limits.max_headers or header_bytes > self.limits.max_header_bytes) {
                return error.MessageTooLong;
            }
            const h = try headers_mod.parseHeaderLine(hl);
            try semantics.add(h);
            self.headers.append(self.gpa, h) catch return error.MessageTooLong;
        }

        if (self.role == .server) {
            const rl = try headers_mod.parseRequestLine(first);
            try semantics.validateRequestHost(rl.http_version);
            const framing = try semantics.framing.finish(.{ .until_close_default = false });
            const end_stream = framing == .none;
            if (end_stream) {
                // The Request event itself completes a bodyless request. Avoid
                // making every server perform another parser call merely to
                // discover an empty EndOfMessage.
                self.state = .done;
            } else {
                self.enterBody(framing);
            }
            self.head_info = .{
                .should_close = semantics.shouldClose(rl.http_version),
                .upgrade = semantics.upgrade(),
            };
            self.head_info_pending = true;
            return .{ .request = .{
                .method = rl.method,
                .target = rl.target,
                .path = rl.path,
                .query = rl.query,
                .http_version = rl.http_version,
                .headers = self.headers.items,
                .expect_continue = semantics.expect_continue,
                .end_stream = end_stream,
            } };
        }

        const st = try headers_mod.parseStatusLine(first);
        if (st.status_code / 100 == 1 and st.status_code != 101) {
            // Informational responses are not the final response to the request:
            // surface the head, then keep reading the final response without
            // requiring reset() or clearing the remembered request method. 1xx
            // responses cannot carry body framing fields; reject them before the
            // interim head is surfaced as trusted metadata.
            if (semantics.framing.hasFramingHeader()) return error.InvalidFraming;
            self.state = .head;
            return .{ .response = .{
                .status_code = st.status_code,
                .reason = st.reason,
                .http_version = st.http_version,
                .headers = self.headers.items,
            } };
        }
        const method = self.request_method[0..self.request_method_len];
        const framing = try semantics.framing.finish(.{
            .bodyless = framing_mod.responseIsBodyless(method, st.status_code),
            .forbid_transfer_encoding = framing_mod.responseForbidsTransferEncoding(method, st.status_code),
            .until_close_default = true,
        });
        self.enterBody(framing);
        self.head_info = .{ .should_close = semantics.shouldClose(st.http_version) or framing == .until_close };
        self.head_info_pending = true;
        return .{ .response = .{
            .status_code = st.status_code,
            .reason = st.reason,
            .http_version = st.http_version,
            .headers = self.headers.items,
        } };
    }

    fn enterBody(self: *Reader, f: Framing) void {
        switch (f) {
            .none => self.state = .eom_pending,
            .content_length => |n| {
                self.body_remaining = n;
                self.state = .body_length;
            },
            .chunked => {
                self.chunk = .{ .max_line = self.limits.max_line, .strict = self.limits.strict_crlf };
                self.state = .body_chunked;
            },
            .until_close => self.state = .body_until_close,
        }
    }

    fn readBodyLength(self: *Reader) ParseError!Event {
        if (self.body_remaining == 0) {
            self.state = .eom_pending;
            return self.dispatch();
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
        // Loop (not recursion) so a trailer flood cannot grow the stack.
        while (true) {
            var sc = Scanner.init(self.avail());
            const out = try self.chunk.next(&sc);
            self.consumed += sc.pos;
            switch (out) {
                .data => |d| return .{ .data = .{ .data = d } },
                .trailer_line => |l| try self.storeTrailer(l),
                .done => {
                    self.materializeTrailers();
                    self.state = .eom_pending;
                    return self.dispatch();
                },
                .need_data => {
                    if (self.eof_seen) return error.ProtocolError;
                    return .need_data;
                },
            }
        }
    }

    /// Copy a trailer field-line into stable storage and remember its offset, so
    /// the parsed Header slices survive buffer growth/compaction (H-1) and are
    /// bounded in count and bytes (H-4). The slice itself is resolved later, in
    /// `materializeTrailers`, once `trailer_store` can no longer move.
    fn storeTrailer(self: *Reader, line: []const u8) ParseError!void {
        if (self.trailers.items.len >= self.limits.max_trailers) return error.MessageTooLong;
        self.trailer_bytes += line.len;
        if (self.trailer_bytes > self.limits.max_trailer_bytes) return error.MessageTooLong;
        const start = self.trailer_store.items.len;
        self.trailer_store.appendSlice(self.gpa, line) catch return error.MessageTooLong;
        // Validate now (cheap, surfaces errors early) but record only the range;
        // the borrowed slice would dangle if trailer_store reallocs on a later line.
        const h = try headers_mod.parseHeaderLine(self.trailer_store.items[start..]);
        if (!headers_mod.trailerFieldAllowed(h.name)) return error.InvalidHeader;
        self.trailers.append(self.gpa, .{ .name = "", .value = "" }) catch return error.MessageTooLong;
        self.trailer_ranges.append(self.gpa, .{ .off = start, .len = line.len }) catch return error.MessageTooLong;
    }

    /// Re-parse the stored trailer lines into Header slices into `trailer_store`,
    /// which is now stable (no further appends). Called exactly once at `.done`.
    fn materializeTrailers(self: *Reader) void {
        for (self.trailer_ranges.items, 0..) |r, i| {
            const line = self.trailer_store.items[r.off .. r.off + r.len];
            // parseHeaderLine already succeeded in storeTrailer, so it cannot fail here.
            self.trailers.items[i] = headers_mod.parseHeaderLine(line) catch unreachable;
        }
    }

    fn readBodyUntilClose(self: *Reader) ParseError!Event {
        const region = self.avail();
        if (region.len > 0) {
            self.consumed += region.len;
            return .{ .data = .{ .data = region } };
        }
        if (self.eof_seen) {
            self.state = .eom_pending;
            return self.dispatch();
        }
        return .need_data;
    }
};

/// Find the byte offset just past the blank line terminating a complete head.
/// The Python adapter uses this stateless helper only for large feeds where it
/// splits an immediately-following body into its zero-copy retention path.
pub fn findHeadEnd(region: []const u8) ?usize {
    var i: usize = 0;
    while (std.mem.findScalarPos(u8, region, i, '\n')) |lf| {
        const next = lf + 1;
        if (next < region.len) {
            if (region[next] == '\n') return next + 1;
            if (region[next] == '\r' and next + 1 < region.len and region[next + 1] == '\n') return next + 2;
        }
        i = next;
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

test "head scanner finds CRLF and bare-LF terminators" {
    var scanner = HeadScanner{};
    try t.expectEqual(@as(?HeadScan, .{ .len = 18, .header_count = 0 }), try scanner.scan("GET / HTTP/1.1\r\n\r\nX", .{}));
    scanner.reset();
    try t.expectEqual(@as(?HeadScan, .{ .len = 16, .header_count = 0 }), try scanner.scan("GET / HTTP/1.1\n\nX", .{}));
}

test "head scanner resumes partial heads without rescanning" {
    var scanner = HeadScanner{};
    const partial = "GET / HTTP/1.1\r\nHost: x\r\n";
    try t.expectEqual(@as(?HeadScan, null), try scanner.scan(partial, .{}));
    try t.expectEqual(partial.len, scanner.scanned);
    try t.expectEqual(@as(usize, 2), scanner.completed_lines);
    try t.expectEqual(
        @as(?HeadScan, .{ .len = partial.len + 2, .header_count = 1 }),
        try scanner.scan(partial ++ "\r\nbody", .{}),
    );
}

test "simple GET no body" {
    var r = try drainServer("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n");
    defer r.ev.deinit(t.allocator);
    defer r.body.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), r.ev.items.len);
    try t.expectEqual(EvTag.request, r.ev.items[0]);
}

test "HTTP/1.1 request requires exactly one Host field" {
    const invalid = [_][]const u8{
        "GET / HTTP/1.1\r\nUser-Agent: zttp\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: one.example\r\nHost: two.example\r\n\r\n",
    };
    for (invalid) |request| {
        var r = Reader.init(t.allocator, .server);
        defer r.deinit();
        try r.feed(request);
        try t.expectError(error.InvalidHeader, r.nextEvent());
    }
}

test "Host requirement permits empty HTTP/1.1 and missing HTTP/1.0 values" {
    const valid = [_][]const u8{
        "GET / HTTP/1.1\r\nHost:\r\n\r\n",
        "GET / HTTP/1.0\r\n\r\n",
    };
    for (valid) |request| {
        var r = Reader.init(t.allocator, .server);
        defer r.deinit();
        try r.feed(request);
        try expectTag(.request, try r.nextEvent());
    }
}

test "POST content-length body" {
    var r = try drainServer("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello");
    defer r.ev.deinit(t.allocator);
    defer r.body.deinit(t.allocator);
    try t.expectEqualStrings("hello", r.body.items);
    try t.expectEqual(EvTag.eom, r.ev.items[r.ev.items.len - 1]);
}

test "POST chunked body with trailers" {
    var r = try drainServer("POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-T: v\r\n\r\n");
    defer r.ev.deinit(t.allocator);
    defer r.body.deinit(t.allocator);
    try t.expectEqualStrings("abc", r.body.items);
}

test "request fields exposed" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("DELETE /x?y=1 HTTP/1.0\r\nHost: h\r\nAccept: */*\r\n\r\n");
    const e = try r.nextEvent();
    try t.expect(e.request.end_stream);
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

test "EOF during an incomplete head is a terminal protocol error" {
    const partials = [_][]const u8{
        "G",
        "GET / HTTP/1.1\r\nHost: x\r\n",
    };
    for (partials) |partial| {
        var r = Reader.init(t.allocator, .server);
        defer r.deinit();
        try r.feed(partial);
        try expectTag(.need_data, try r.nextEvent());
        try r.feed("");
        try t.expectError(error.ProtocolError, r.nextEvent());
        try t.expectError(error.ProtocolError, r.nextEvent());
    }
}

test "split body across feeds" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nhel");
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
    try t.expect(e.request.end_stream);
    try r.reset();
    e = try r.nextEvent();
    try t.expectEqualStrings("/b", e.request.target);
}

test "reset cannot un-poison a failed connection" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    // A malformed request followed by a smuggled one; the error must be terminal.
    try r.feed("GET / HTTP/1.1\nX: 1\n\nGET /smuggled HTTP/1.1\r\nHost: y\r\n\r\n");
    try t.expectError(error.InvalidLine, r.nextEvent());
    try t.expectError(error.MessageInProgress, r.reset());
    // Still poisoned: it must NOT parse /smuggled as a fresh request.
    try t.expectError(error.InvalidLine, r.nextEvent());
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

test "client auto-frames HEAD response as bodyless" {
    var r = Reader.init(t.allocator, .client);
    defer r.deinit();
    r.setRequestMethod("HEAD");
    try r.feed("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n");
    try expectTag(.response, try r.nextEvent());
    try expectTag(.end_of_message, try r.nextEvent());
}

test "client auto-frames 304 response as bodyless" {
    var r = Reader.init(t.allocator, .client);
    defer r.deinit();
    r.setRequestMethod("GET");
    try r.feed("HTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\n\r\n");
    try expectTag(.response, try r.nextEvent());
    try expectTag(.end_of_message, try r.nextEvent());
}

test "client rejects Transfer-Encoding where response semantics forbid it" {
    const cases = .{
        .{ "GET", "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n" },
        .{ "CONNECT", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" },
    };
    inline for (cases) |case| {
        var r = Reader.init(t.allocator, .client);
        defer r.deinit();
        r.setRequestMethod(case[0]);
        try r.feed(case[1]);
        try t.expectError(error.InvalidFraming, r.nextEvent());
    }
}

test "client permits chunked metadata on HEAD and 304" {
    const cases = .{
        .{ "HEAD", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" },
        .{ "GET", "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n" },
    };
    inline for (cases) |case| {
        var r = Reader.init(t.allocator, .client);
        defer r.deinit();
        r.setRequestMethod(case[0]);
        try r.feed(case[1]);
        try expectTag(.response, try r.nextEvent());
        try expectTag(.end_of_message, try r.nextEvent());
    }
}

test "client continues through informational response" {
    var r = Reader.init(t.allocator, .client);
    defer r.deinit();
    r.setRequestMethod("GET");
    try r.feed("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    const info = try r.nextEvent();
    try t.expectEqual(@as(u16, 100), info.response.status_code);
    const final = try r.nextEvent();
    try t.expectEqual(@as(u16, 200), final.response.status_code);
    try expectTag(.end_of_message, try r.nextEvent());
}

test "informational response preserves HEAD method for final response" {
    var r = Reader.init(t.allocator, .client);
    defer r.deinit();
    r.setRequestMethod("HEAD");
    try r.feed("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n");
    try t.expectEqual(@as(u16, 100), (try r.nextEvent()).response.status_code);
    try t.expectEqual(@as(u16, 200), (try r.nextEvent()).response.status_code);
    try expectTag(.end_of_message, try r.nextEvent());
}

test "informational response rejects framing headers" {
    inline for (.{ "Content-Length: 0", "Transfer-Encoding: chunked" }) |header| {
        var r = Reader.init(t.allocator, .client);
        defer r.deinit();
        r.setRequestMethod("GET");
        try r.feed("HTTP/1.1 100 Continue\r\n" ++ header ++ "\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        try t.expectError(error.InvalidFraming, r.nextEvent());
    }
}

test "client still frames a normal GET response body" {
    var r = Reader.init(t.allocator, .client);
    defer r.deinit();
    r.setRequestMethod("GET");
    try r.feed("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    try expectTag(.response, try r.nextEvent());
    const d = try r.nextEvent();
    try t.expectEqualStrings("hello", d.data.data);
    try expectTag(.end_of_message, try r.nextEvent());
}

test "client exposes response connection close signal" {
    var r = Reader.init(t.allocator, .client);
    defer r.deinit();
    try r.feed("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    try expectTag(.response, try r.nextEvent());
    try t.expect(r.takeHeadInfo().should_close);
    try t.expectEqual(HeadInfo{}, r.takeHeadInfo());
}

test "server head info is an immediate one-shot snapshot" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close, Upgrade\r\nUpgrade: websocket\r\n\r\n");
    try expectTag(.request, try r.nextEvent());

    const info = r.takeHeadInfo();
    try t.expect(info.should_close);
    try t.expectEqualStrings("websocket", info.upgrade.?);

    const consumed = r.takeHeadInfo();
    try t.expect(!consumed.should_close);
    try t.expect(consumed.upgrade == null);
}

test "client treats HTTP/1.0 response as close unless keep-alive" {
    var r = Reader.init(t.allocator, .client);
    defer r.deinit();
    try r.feed("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    try expectTag(.response, try r.nextEvent());
    try t.expect(r.takeHeadInfo().should_close);
}

test "client marks close-delimited response as closing" {
    var r = Reader.init(t.allocator, .client);
    defer r.deinit();
    try r.feed("HTTP/1.1 200 OK\r\n\r\nbody");
    try expectTag(.response, try r.nextEvent());
    try t.expect(r.takeHeadInfo().should_close);
}

test "truncated content-length body errors at EOF" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nshort");
    _ = try r.nextEvent();
    _ = try r.nextEvent(); // "short"
    try r.feed("");
    try t.expectError(error.ProtocolError, r.nextEvent());
}

// -- security regression tests ------------------------------------------------

test "H-1: trailer survives buffer realloc across feeds" {
    // Store a trailer while awaiting the terminating blank line, then feed a
    // large payload that forces buf to grow/realloc before EndOfMessage. The
    // trailer must still read back correctly (was a use-after-free).
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n");
    try expectTag(.request, try r.nextEvent());
    try r.feed("0\r\nX-Trailer: SECRET\r\n");
    try expectTag(.need_data, try r.nextEvent()); // trailer stored, no blank line yet
    const padding = "\r\n" ++ ("Z" ** (256 * 1024));
    try r.feed(padding);
    const eom = try r.nextEvent();
    try t.expectEqual(@as(usize, 1), eom.end_of_message.trailers.len);
    try t.expectEqualStrings("X-Trailer", eom.end_of_message.trailers[0].name);
    try t.expectEqualStrings("SECRET", eom.end_of_message.trailers[0].value);
}

test "H-1: multiple trailers survive trailer_store growth" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n");
    try expectTag(.request, try r.nextEvent());
    try r.feed("A: 1\r\nBee: 22\r\nCee: 333\r\n\r\n");
    var eom: Event = undefined;
    while (true) {
        const e = try r.nextEvent();
        if (e == .end_of_message) {
            eom = e;
            break;
        }
        try t.expect(e == .need_data); // no body data in this message
    }
    const tr = eom.end_of_message.trailers;
    try t.expectEqual(@as(usize, 3), tr.len);
    try t.expectEqualStrings("A", tr[0].name);
    try t.expectEqualStrings("1", tr[0].value);
    try t.expectEqualStrings("Bee", tr[1].name);
    try t.expectEqualStrings("22", tr[1].value);
    try t.expectEqualStrings("Cee", tr[2].name);
    try t.expectEqualStrings("333", tr[2].value);
}

test "H-4: trailer count cap rejected" {
    var r = Reader.init(t.allocator, .server);
    r.limits.max_trailers = 4;
    defer r.deinit();
    try r.feed("POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n");
    _ = try r.nextEvent();
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(t.allocator);
    for (0..10) |i| {
        try buf.appendSlice(t.allocator, "X: ");
        try buf.append(t.allocator, @intCast('0' + i));
        try buf.appendSlice(t.allocator, "\r\n");
    }
    try r.feed(buf.items);
    try t.expectError(error.MessageTooLong, r.nextEvent());
}

test "H-4: trailer byte cap rejected" {
    var r = Reader.init(t.allocator, .server);
    r.limits.max_trailer_bytes = 32;
    defer r.deinit();
    try r.feed("POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n");
    _ = try r.nextEvent();
    try r.feed("X-Long-Trailer-Header: aaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    try t.expectError(error.MessageTooLong, r.nextEvent());
}

test "prohibited trailers are rejected" {
    inline for (.{ "Content-Length: 0", "Trailer: Content-Length", "Content-Type: text/plain" }) |trailer| {
        var r = Reader.init(t.allocator, .server);
        defer r.deinit();
        try r.feed("POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n" ++ trailer ++ "\r\n\r\n");
        try expectTag(.request, try r.nextEvent());
        try t.expectError(error.InvalidHeader, r.nextEvent());
    }
}

test "M-1: oversized complete head rejected before full copy" {
    var r = Reader.init(t.allocator, .server);
    r.limits.max_header_bytes = 1024;
    defer r.deinit();
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(t.allocator);
    try buf.appendSlice(t.allocator, "GET / HTTP/1.1\r\n");
    while (buf.items.len < 4096) try buf.appendSlice(t.allocator, "X-Pad: aaaaaaaaaaaaaaaa\r\n");
    try buf.appendSlice(t.allocator, "\r\n"); // complete head, but oversized
    try r.feed(buf.items);
    try t.expectError(error.MessageTooLong, r.nextEvent());
}

test "feed rejects input past max_buffer" {
    var r = Reader.init(t.allocator, .server);
    r.limits.max_buffer = 1024;
    defer r.deinit();
    const big = "Z" ** 2048;
    try t.expectError(error.MessageTooLong, r.feed(big));
    try t.expectError(error.MessageTooLong, r.feed("GET / HTTP/1.1\r\n\r\n"));
    try t.expectError(error.MessageTooLong, r.nextEvent());
    try t.expectError(error.MessageInProgress, r.reset());
    try t.expectError(error.MessageTooLong, r.nextEvent());
}

test "feed rejects data after EOF" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("");
    try t.expectError(error.ProtocolError, r.feed("GET / HTTP/1.1\r\n\r\n"));
}

test "M-2: bare LF request rejected when strict" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("GET / HTTP/1.1\nHost: x\n\n");
    try t.expectError(error.InvalidLine, r.nextEvent());
}

test "M-2: bare LF request accepted when lenient" {
    var r = Reader.init(t.allocator, .server);
    r.limits.strict_crlf = false;
    defer r.deinit();
    try r.feed("GET / HTTP/1.1\nHost: x\n\n");
    const e = try r.nextEvent();
    try t.expectEqualStrings("GET", e.request.method);
    try t.expectEqualStrings("x", e.request.headers[0].value);
}

test "line length cap is reported as MessageTooLong" {
    var r = Reader.init(t.allocator, .server);
    r.limits.max_line = 4;
    defer r.deinit();
    try r.feed("GET / HTTP/1.1\r\n\r\n");
    try t.expectError(error.MessageTooLong, r.nextEvent());
}

test "line length cap applies before the head completes" {
    var r = Reader.init(t.allocator, .server);
    r.limits.max_line = 4;
    defer r.deinit();
    try r.feed("GET /");
    try t.expectError(error.MessageTooLong, r.nextEvent());
}

test "header line length cap is reported as MessageTooLong" {
    var r = Reader.init(t.allocator, .server);
    r.limits.max_line = 8;
    defer r.deinit();
    try r.feed("GET / HTTP/1.1\r\nLong: xxxxx\r\n\r\n");
    try t.expectError(error.MessageTooLong, r.nextEvent());
}

// -- fuzzing ------------------------------------------------------------------

/// Drive the reader with arbitrary input split at an arbitrary boundary, then
/// pull events to completion. The only acceptable outcomes are a clean event
/// stream or a ParseError - never a panic, OOB, or hang. Run with `zig build
/// fuzz`. The split exercises partial-data resumption, where the trailer/
/// compaction lifetime bugs lived.
fn driveReader(input: []const u8) void {
    inline for (.{ Role.server, Role.client }) |role| {
        var r = Reader.init(t.allocator, role);
        defer r.deinit();
        // Tight limits so fuzzing stays fast and exercises the caps.
        r.limits = .{ .max_buffer = 1 << 20, .max_header_bytes = 64 * 1024, .max_trailer_bytes = 64 * 1024 };
        const split = if (input.len == 0) 0 else input[0] % @as(u8, @intCast(@min(input.len, 255)));
        const feeds = [_][]const u8{ input[0..split], input[split..], "" };
        outer: for (feeds) |chunk| {
            r.feed(chunk) catch break;
            for (0..input.len + 4) |_| {
                const ev = r.nextEvent() catch continue :outer;
                switch (ev) {
                    .need_data, .connection_closed => break,
                    .end_of_message => {
                        r.reset() catch break;
                        break;
                    },
                    else => {},
                }
            }
        }
    }
}

// A deterministic property test: run many adversarial and pseudo-random inputs
// through driveReader and assert it never panics. This is the always-on
// regression net; coverage-guided fuzzing (`zig build fuzz`) layers on top.
test "skipBodyLength accounts for out-of-band body bytes" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n");
    try t.expect((try r.nextEvent()) == .request);
    try t.expectEqual(@as(?u64, 10), r.bodyLengthRemaining());
    try t.expect(r.backlogEmpty());

    r.skipBodyLength(4);
    try t.expectEqual(@as(?u64, 6), r.bodyLengthRemaining());
    r.skipBodyLength(6);
    try t.expectEqual(@as(?u64, null), r.bodyLengthRemaining());
    try t.expect((try r.nextEvent()) == .end_of_message);
}

test "skipBodyLength interleaves with buffered body bytes" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try r.feed("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\n\r\nabcd");
    try t.expect((try r.nextEvent()) == .request);
    const d = try r.nextEvent();
    try t.expectEqualStrings("abcd", d.data.data);
    try t.expect(r.backlogEmpty());
    r.skipBodyLength(4);
    try t.expect((try r.nextEvent()) == .end_of_message);
}

test "atMessageStart and backlogEmpty track parser progress" {
    var r = Reader.init(t.allocator, .server);
    defer r.deinit();
    try t.expect(r.atMessageStart());
    try r.feed("GET / HT");
    try t.expect(r.atMessageStart());
    try t.expect(!r.backlogEmpty());
    try r.feed("TP/1.1\r\nHost: x\r\n\r\n");
    try t.expect((try r.nextEvent()) == .request);
    try t.expect(!r.atMessageStart());
}

test "fuzz: reader never panics on adversarial inputs" {
    const seeds = [_][]const u8{
        "",
        "\n",
        "\r\n\r\n",
        "GET",
        "GET / HTTP/1.1\r\n\r\n",
        "POST / HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n",
        "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nfffffffffffffffff\r\n",
        "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" ++ ("0\r\nX: y\r\n" ** 3),
        "HTTP/1.1 200\r\n\r\n",
        "GET / HTTP/1.1\r\n" ++ ("A: b\r\n" ** 50) ++ "\r\n",
        "\x00\x01\x02\x03 / HTTP/1.1\r\n\r\n",
        "GET /\xff\xfe HTTP/1.1\r\nHost:\x00\r\n\r\n",
    };
    for (seeds) |s| driveReader(s);

    // Pseudo-random bytes derived from a fixed seed (Math.random is unavailable
    // and would be non-deterministic anyway). Splice in HTTP-ish tokens to reach
    // deeper states than purely random noise would.
    var prng = std.Random.DefaultPrng.init(0x7a68747470);
    const rand = prng.random();
    var buf: [512]u8 = undefined;
    for (0..2000) |_| {
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        for (buf[0..len]) |*b| {
            b.* = switch (rand.intRangeAtMost(u8, 0, 4)) {
                0 => '\r',
                1 => '\n',
                2 => rand.intRangeAtMost(u8, 'a', 'z'),
                else => rand.int(u8),
            };
        }
        driveReader(buf[0..len]);
    }
}
