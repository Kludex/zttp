//! A cursor over a byte buffer with the low-level scans the HTTP grammar needs:
//! find a line end, slice a run of token/value characters, consume literals.
//! It never owns or copies bytes - every result is a slice into the buffer. The
//! higher-level message parser composes these; the SWAR-accelerated CRLF search
//! lives here so the rest of the parser stays branchy-but-clear.

const std = @import("std");
const tables = @import("tables.zig");

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
    /// buffer start, or null if none is buffered yet. SWAR-scans 8 bytes at a
    /// time: the classic "has a zero byte" bit trick applied to (word ^ LF*).
    pub fn indexOfLf(self: *const Scanner) ?usize {
        const needle: u64 = 0x0A0A0A0A0A0A0A0A;
        const ones: u64 = 0x0101010101010101;
        const high: u64 = 0x8080808080808080;
        var i = self.pos;
        const buf = self.buf;
        while (i + 8 <= buf.len) : (i += 8) {
            const word = std.mem.readInt(u64, buf[i..][0..8], .little);
            const x = word ^ needle;
            const found = (x -% ones) & ~x & high;
            if (found != 0) {
                return i + (@ctz(found) >> 3);
            }
        }
        while (i < buf.len) : (i += 1) {
            if (buf[i] == '\n') return i;
        }
        return null;
    }

    /// Read one CRLF-terminated line (excluding the terminator), advancing past
    /// the terminator. A bare LF is tolerated (and the optional preceding CR is
    /// stripped) to match what real servers accept. Returns null when no full
    /// line is buffered yet - the cursor is left untouched so a later feed can
    /// retry. Lines longer than `max_len` return error.MessageTooLong.
    pub fn line(self: *Scanner, max_len: usize) error{MessageTooLong}!?[]const u8 {
        const lf = self.indexOfLf() orelse {
            if (self.buf.len - self.pos > max_len) return error.MessageTooLong;
            return null;
        };
        if (lf - self.pos > max_len) return error.MessageTooLong;
        var end = lf;
        if (end > self.pos and self.buf[end - 1] == '\r') end -= 1;
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
    const l1 = try sc.line(1024);
    try std.testing.expectEqualStrings("GET / HTTP/1.1", l1.?);
    const l2 = try sc.line(1024);
    try std.testing.expectEqualStrings("Host: x", l2.?);
}

test "line tolerates bare LF" {
    var sc = Scanner.init("abc\ndef\n");
    try std.testing.expectEqualStrings("abc", (try sc.line(1024)).?);
    try std.testing.expectEqualStrings("def", (try sc.line(1024)).?);
}

test "line returns null on partial without consuming" {
    var sc = Scanner.init("partial line no terminator");
    try std.testing.expectEqual(@as(?[]const u8, null), try sc.line(1024));
    try std.testing.expectEqual(@as(usize, 0), sc.pos);
}

test "line enforces max length" {
    var sc = Scanner.init("way too long for the limit\r\n");
    try std.testing.expectError(error.MessageTooLong, sc.line(5));
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
