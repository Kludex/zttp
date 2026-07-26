//! Incremental decoder for the chunked transfer-coding (RFC 9112 7.1). Fed a
//! Scanner positioned at the start of (more of) a chunked body, it yields body
//! spans and signals when the body ends, surviving arbitrary fragmentation -
//! a chunk size, the data, or a CRLF can each be split across feed boundaries.
//! Trailer field-lines after the last chunk are returned to the caller to parse.

const std = @import("std");
const tables = @import("../tables.zig");
const Scanner = @import("../scanner.zig").Scanner;
const ParseError = @import("../errors.zig").ParseError;

const State = enum {
    /// Reading the chunk-size hex digits (and any chunk extensions) up to CRLF.
    size,
    /// Inside a chunk's data; `remaining` bytes of payload are still expected.
    data,
    /// Expecting the CRLF that terminates a chunk's data.
    data_crlf,
    /// After the final 0-size chunk, reading trailer field-lines until a blank.
    trailer,
    /// Fully decoded; the terminating CRLF has been consumed.
    done,
};

pub const Output = union(enum) {
    /// A run of decoded body bytes (a slice into the fed buffer).
    data: []const u8,
    /// A single trailer field-line (raw, not yet split into name/value).
    trailer_line: []const u8,
    /// The body is complete.
    done,
    /// Not enough buffered bytes to make progress; feed more.
    need_data,
};

pub const ChunkDecoder = struct {
    state: State = .size,
    /// Bytes left in the current chunk's data section.
    remaining: u64 = 0,
    /// Cap on the chunk-size line and each trailer line, to bound memory.
    max_line: usize = 16 * 1024,
    /// Require CRLF (reject bare LF) for chunk framing - the secure default.
    strict: bool = true,

    /// Pull the next output from `sc`. Call repeatedly until it returns
    /// `need_data` or `done`. The scanner's cursor is advanced only past fully
    /// consumed input, so a `need_data` leaves resumable state in the buffer.
    pub fn next(self: *ChunkDecoder, sc: *Scanner) ParseError!Output {
        switch (self.state) {
            .size => {
                const save = sc.pos;
                const maybe = sc.line(self.max_line, self.strict) catch return error.InvalidChunk;
                const l = maybe orelse {
                    sc.pos = save;
                    return .need_data;
                };
                self.remaining = try parseChunkSize(l);
                if (self.remaining == 0) {
                    self.state = .trailer;
                    return self.next(sc);
                }
                self.state = .data;
                return self.next(sc);
            },
            .data => {
                if (self.remaining == 0) {
                    self.state = .data_crlf;
                    return self.next(sc);
                }
                if (sc.isEmpty()) return .need_data;
                const avail = sc.buf.len - sc.pos;
                const take = @min(avail, self.remaining);
                const span = sc.take(@intCast(take));
                self.remaining -= take;
                return .{ .data = span };
            },
            .data_crlf => {
                if (!try consumeCrlf(sc, self.strict)) return .need_data;
                self.state = .size;
                return self.next(sc);
            },
            .trailer => {
                const save = sc.pos;
                const maybe = sc.line(self.max_line, self.strict) catch return error.InvalidChunk;
                const l = maybe orelse {
                    sc.pos = save;
                    return .need_data;
                };
                if (l.len == 0) {
                    self.state = .done;
                    return .done;
                }
                return .{ .trailer_line = l };
            },
            .done => return .done,
        }
    }

    pub fn isDone(self: *const ChunkDecoder) bool {
        return self.state == .done;
    }
};

/// Parse the chunk-size line: strictly `1*HEXDIG`, then an optional `;ext` chunk
/// extension which we accept and ignore. Per RFC 9112 7.1 no whitespace is
/// permitted before `;` or the line terminator; tolerating it is a framing
/// differential, so any non-hex, non-`;` byte is rejected.
fn parseChunkSize(line: []const u8) ParseError!u64 {
    var n: u64 = 0;
    var digits: usize = 0;
    for (line, 0..) |ch, i| {
        if (ch == ';') {
            if (digits == 0) return error.InvalidChunk;
            if (!validChunkExtension(line[i + 1 ..])) return error.InvalidChunk;
            return n;
        }
        const v = tables.hex_value[ch];
        if (v == 0xFF) return error.InvalidChunk;
        if (digits >= 16) return error.InvalidChunk; // > 64 bits of hex
        n = (n << 4) | v;
        digits += 1;
    }
    if (digits == 0) return error.InvalidChunk;
    return n;
}

/// We do not interpret chunk extensions, but we still reject bytes that cannot
/// appear in HTTP field content so malformed framing cannot slip through one
/// parser and be rejected by another.
fn validChunkExtension(ext: []const u8) bool {
    for (ext) |ch| {
        if (!tables.is_field_vchar[ch]) return false;
    }
    return true;
}

/// Consume a CRLF at the cursor (a bare LF too when not strict). Returns false
/// (without advancing) if not enough bytes are buffered to decide.
fn consumeCrlf(sc: *Scanner, strict: bool) ParseError!bool {
    const r = sc.remaining();
    if (r.len == 0) return false;
    if (r[0] == '\n') {
        if (strict) return error.InvalidChunk;
        _ = sc.take(1);
        return true;
    }
    if (r[0] == '\r') {
        if (r.len < 2) return false;
        if (r[1] != '\n') return error.InvalidChunk;
        _ = sc.take(2);
        return true;
    }
    return error.InvalidChunk;
}

const t = std.testing;

fn collect(input: []const u8) !struct { body: std.ArrayList(u8), trailers: usize, done: bool } {
    var dec = ChunkDecoder{};
    var sc = Scanner.init(input);
    var body: std.ArrayList(u8) = .empty;
    var trailers: usize = 0;
    while (true) {
        const out = try dec.next(&sc);
        switch (out) {
            .data => |d| try body.appendSlice(t.allocator, d),
            .trailer_line => trailers += 1,
            .done => return .{ .body = body, .trailers = trailers, .done = true },
            .need_data => return .{ .body = body, .trailers = trailers, .done = false },
        }
    }
}

test "single chunk" {
    var r = try collect("5\r\nhello\r\n0\r\n\r\n");
    defer r.body.deinit(t.allocator);
    try t.expect(r.done);
    try t.expectEqualStrings("hello", r.body.items);
}

test "multiple chunks" {
    var r = try collect("3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
    defer r.body.deinit(t.allocator);
    try t.expect(r.done);
    try t.expectEqualStrings("abcde", r.body.items);
}

test "chunk extensions ignored" {
    var r = try collect("5;name=value\r\nhello\r\n0\r\n\r\n");
    defer r.body.deinit(t.allocator);
    try t.expect(r.done);
    try t.expectEqualStrings("hello", r.body.items);
}

test "chunk extensions reject control bytes" {
    var dec = ChunkDecoder{};
    var sc = Scanner.init("5;bad=\x00\r\nhello\r\n0\r\n\r\n");
    try t.expectError(error.InvalidChunk, dec.next(&sc));
}

test "hex chunk size" {
    var r = try collect("a\r\n0123456789\r\n0\r\n\r\n");
    defer r.body.deinit(t.allocator);
    try t.expect(r.done);
    try t.expectEqualStrings("0123456789", r.body.items);
}

test "trailers" {
    var r = try collect("3\r\nabc\r\n0\r\nX-Trailer: v\r\nX-Other: w\r\n\r\n");
    defer r.body.deinit(t.allocator);
    try t.expect(r.done);
    try t.expectEqualStrings("abc", r.body.items);
    try t.expectEqual(@as(usize, 2), r.trailers);
}

test "streaming across boundaries" {
    const full = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    var dec = ChunkDecoder{};
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(t.allocator);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(t.allocator);
    var consumed: usize = 0;
    var src: usize = 0;
    var done = false;
    while (!done) {
        // Feed one more source byte into the working buffer.
        if (src < full.len) {
            try buf.append(t.allocator, full[src]);
            src += 1;
        }
        var sc = Scanner.init(buf.items[consumed..]);
        inner: while (true) {
            const out = try dec.next(&sc);
            switch (out) {
                .data => |d| try body.appendSlice(t.allocator, d),
                .trailer_line => {},
                .done => {
                    done = true;
                    break :inner;
                },
                .need_data => break :inner,
            }
        }
        consumed += sc.pos;
        if (src >= full.len and !done and sc.pos == 0) break;
    }
    try t.expect(done);
    try t.expectEqualStrings("Wikipedia", body.items);
}

test "bad chunk size rejected" {
    var dec = ChunkDecoder{};
    var sc = Scanner.init("xyz\r\n");
    try t.expectError(error.InvalidChunk, dec.next(&sc));
}

test "empty chunk size rejected" {
    var dec = ChunkDecoder{};
    var sc = Scanner.init(";ext\r\n");
    try t.expectError(error.InvalidChunk, dec.next(&sc));
}

test "L-2: chunk size with trailing whitespace rejected" {
    var dec = ChunkDecoder{};
    var sc = Scanner.init("5 \r\nhello\r\n0\r\n\r\n");
    try t.expectError(error.InvalidChunk, dec.next(&sc));
}

test "M-2: bare LF chunk framing rejected when strict" {
    var dec = ChunkDecoder{}; // strict by default
    var sc = Scanner.init("5\nhello\n0\n\n");
    try t.expectError(error.InvalidChunk, dec.next(&sc));
}

test "M-2: bare LF chunk framing accepted when lenient" {
    var r = try collect2("5\nhello\n0\n\n", false);
    defer r.body.deinit(t.allocator);
    try t.expect(r.done);
    try t.expectEqualStrings("hello", r.body.items);
}

fn collect2(input: []const u8, strict: bool) !struct { body: std.ArrayList(u8), done: bool } {
    var dec = ChunkDecoder{ .strict = strict };
    var sc = Scanner.init(input);
    var body: std.ArrayList(u8) = .empty;
    while (true) {
        const out = try dec.next(&sc);
        switch (out) {
            .data => |d| try body.appendSlice(t.allocator, d),
            .trailer_line => {},
            .done => return .{ .body = body, .done = true },
            .need_data => return .{ .body = body, .done = false },
        }
    }
}
