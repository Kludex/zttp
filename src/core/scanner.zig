//! A cursor over a byte buffer with the low-level scans the HTTP grammar needs:
//! find a line end, slice a run of token/value characters, consume literals.
//! It never owns or copies bytes - every result is a slice into the buffer. The
//! higher-level message parser composes these; the SWAR-accelerated CRLF search
//! lives here so the rest of the parser stays branchy-but-clear.

const std = @import("std");
const tables = @import("tables.zig");

const block_len = std.simd.suggestVectorLength(u8) orelse 8;
const Block = @Vector(block_len, u8);

pub const Scanner = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Scanner {
        return .{ .buf = buf };
    }

    pub fn remaining(self: *const Scanner) []const u8 {
        return self.buf[self.pos..];
    }

    pub fn isEmpty(self: *const Scanner) bool {
        return self.pos >= self.buf.len;
    }

    /// Peek the next byte without consuming, or null at end of buffer.
    pub fn peek(self: *const Scanner) ?u8 {
        return if (self.pos < self.buf.len) self.buf[self.pos] else null;
    }

    /// Consume `n` bytes, returning the slice. Caller must ensure availability.
    pub fn take(self: *Scanner, n: usize) []const u8 {
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }

    /// If the buffer at the cursor starts with `lit`, consume it and return true.
    pub fn consume(self: *Scanner, lit: []const u8) bool {
        if (self.pos + lit.len > self.buf.len) return false;
        if (!std.mem.eql(u8, self.buf[self.pos .. self.pos + lit.len], lit)) return false;
        self.pos += lit.len;
        return true;
    }

    /// Index of the next LF (0x0A) at or after the cursor, relative to the
    /// buffer start, or null if none is buffered yet. std's findScalarPos scans
    /// two SIMD vectors (32 bytes on NEON) per iteration.
    pub fn indexOfLf(self: *const Scanner) ?usize {
        return std.mem.findScalarPos(u8, self.buf, self.pos, '\n');
    }

    pub const LineError = error{ MessageTooLong, BareLf };

    /// Read one CRLF-terminated line (excluding the terminator), advancing past
    /// the terminator. When `strict`, a bare LF (LF not preceded by CR) is
    /// rejected with error.BareLf - the secure default, since a CRLF-strict
    /// front-end and an LF-lenient backend disagreeing on line boundaries is a
    /// classic request-smuggling vector. Returns null when no full line is
    /// buffered yet - the cursor is left untouched so a later feed can retry.
    /// Lines longer than `max_len` return error.MessageTooLong.
    pub fn line(self: *Scanner, max_len: usize, strict: bool) LineError!?[]const u8 {
        const lf = self.indexOfLf() orelse {
            if (self.buf.len - self.pos > max_len) return error.MessageTooLong;
            return null;
        };
        if (lf - self.pos > max_len) return error.MessageTooLong;
        const has_cr = lf > self.pos and self.buf[lf - 1] == '\r';
        if (strict and !has_cr) return error.BareLf;
        const end = if (has_cr) lf - 1 else lf;
        const out = self.buf[self.pos..end];
        self.pos = lf + 1;
        return out;
    }

    /// Slice the maximal run of bytes for which `class[byte]` is true, starting
    /// at the cursor, and advance past it. May be empty.
    pub fn span(self: *Scanner, comptime class: [256]bool) []const u8 {
        const start = self.pos;
        var i = start;
        const buf = self.buf;
        while (i < buf.len and class[buf[i]]) : (i += 1) {}
        self.pos = i;
        return buf[start..i];
    }

    /// `span(tables.is_target_char)` with a vectorized fast path: a whole block
    /// is inside the class iff no byte is < 0x21, DEL, or DQUOTE, so clean
    /// blocks are skipped with three lane-compares and the block holding the
    /// span's end (or an invalid byte) falls back to the exact table walk.
    pub fn spanTarget(self: *Scanner) []const u8 {
        const start = self.pos;
        var i = start;
        const buf = self.buf;
        while (i + block_len <= buf.len) {
            const block: Block = buf[i..][0..block_len].*;
            const below = block < @as(Block, @splat(0x21));
            const del = block == @as(Block, @splat(0x7F));
            const quote = block == @as(Block, @splat('"'));
            if (@reduce(.Or, below) or @reduce(.Or, del) or @reduce(.Or, quote)) break;
            i += block_len;
        }
        while (i < buf.len and tables.is_target_char[buf[i]]) : (i += 1) {}
        self.pos = i;
        return buf[start..i];
    }

    /// Skip any leading optional whitespace (SP / HTAB), per RFC 9110 OWS.
    pub fn skipOws(self: *Scanner) void {
        while (self.pos < self.buf.len) : (self.pos += 1) {
            const ch = self.buf[self.pos];
            if (ch != ' ' and ch != '\t') break;
        }
    }
};

/// Strip trailing OWS (SP / HTAB) from a slice. Header values keep their
/// internal whitespace but shed surrounding OWS (RFC 9110 5.5).
pub fn trimTrailingOws(s: []const u8) []const u8 {
    var end = s.len;
    while (end > 0 and (s[end - 1] == ' ' or s[end - 1] == '\t')) end -= 1;
    return s[0..end];
}

/// Whether every byte of `s` is field-vchar / SP / HTAB (tables.is_field_vchar).
/// Vectorized fast path: a block with no byte < 0x20 and no DEL is all-valid;
/// a suspect block (which includes the rare valid HTAB) falls back to the
/// exact table walk for the remainder.
pub fn validFieldValue(s: []const u8) bool {
    var i: usize = 0;
    while (i + block_len <= s.len) {
        const block: Block = s[i..][0..block_len].*;
        const ctl = block < @as(Block, @splat(0x20));
        const del = block == @as(Block, @splat(0x7F));
        if (@reduce(.Or, ctl) or @reduce(.Or, del)) break;
        i += block_len;
    }
    while (i < s.len) : (i += 1) {
        if (!tables.is_field_vchar[s[i]]) return false;
    }
    return true;
}

test "indexOfLf finds across word boundary" {
    var sc = Scanner.init("0123456789abcdef\nrest");
    try std.testing.expectEqual(@as(?usize, 16), sc.indexOfLf());
}

test "indexOfLf returns null when absent" {
    var sc = Scanner.init("no newline here at all xx");
    try std.testing.expectEqual(@as(?usize, null), sc.indexOfLf());
}

test "line splits CRLF and advances" {
    var sc = Scanner.init("GET / HTTP/1.1\r\nHost: x\r\n");
    const l1 = try sc.line(1024, true);
    try std.testing.expectEqualStrings("GET / HTTP/1.1", l1.?);
    const l2 = try sc.line(1024, true);
    try std.testing.expectEqualStrings("Host: x", l2.?);
}

test "line rejects bare LF when strict" {
    var sc = Scanner.init("abc\ndef\n");
    try std.testing.expectError(error.BareLf, sc.line(1024, true));
}

test "line tolerates bare LF when lenient" {
    var sc = Scanner.init("abc\ndef\n");
    try std.testing.expectEqualStrings("abc", (try sc.line(1024, false)).?);
    try std.testing.expectEqualStrings("def", (try sc.line(1024, false)).?);
}

test "line returns null on partial without consuming" {
    var sc = Scanner.init("partial line no terminator");
    try std.testing.expectEqual(@as(?[]const u8, null), try sc.line(1024, true));
    try std.testing.expectEqual(@as(usize, 0), sc.pos);
}

test "line enforces max length" {
    var sc = Scanner.init("way too long for the limit\r\n");
    try std.testing.expectError(error.MessageTooLong, sc.line(5, true));
}

test "span slices a token run" {
    var sc = Scanner.init("GET /path");
    const tok = sc.span(tables.is_tchar);
    try std.testing.expectEqualStrings("GET", tok);
    try std.testing.expectEqual(@as(u8, ' '), sc.peek().?);
}

test "consume matches a literal" {
    var sc = Scanner.init("HTTP/1.1");
    try std.testing.expect(sc.consume("HTTP/"));
    try std.testing.expect(!sc.consume("2.0"));
    try std.testing.expectEqualStrings("1.1", sc.remaining());
}

test "trimTrailingOws" {
    try std.testing.expectEqualStrings("value", trimTrailingOws("value  \t "));
    try std.testing.expectEqualStrings("", trimTrailingOws("   "));
}

test "spanTarget agrees with the table for every byte at every block offset" {
    var buf: [block_len * 2 + 1]u8 = undefined;
    var b: usize = 0;
    while (b < 256) : (b += 1) {
        var offset: usize = 0;
        while (offset < buf.len) : (offset += 1) {
            @memset(&buf, 'a');
            buf[offset] = @intCast(b);
            var vec = Scanner.init(&buf);
            var scalar = Scanner.init(&buf);
            try std.testing.expectEqualStrings(scalar.span(tables.is_target_char), vec.spanTarget());
            try std.testing.expectEqual(scalar.pos, vec.pos);
        }
    }
}

test "validFieldValue agrees with the table for every byte at every block offset" {
    var buf: [block_len * 2 + 1]u8 = undefined;
    var b: usize = 0;
    while (b < 256) : (b += 1) {
        var offset: usize = 0;
        while (offset < buf.len) : (offset += 1) {
            @memset(&buf, 'a');
            buf[offset] = @intCast(b);
            try std.testing.expectEqual(tables.is_field_vchar[b], validFieldValue(&buf));
        }
    }
}

test "validFieldValue accepts HTAB inside a vector block" {
    var buf: [block_len * 2]u8 = undefined;
    @memset(&buf, 'x');
    buf[3] = '\t';
    buf[block_len + 2] = '\t';
    try std.testing.expect(validFieldValue(&buf));
}
