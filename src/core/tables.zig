//! Comptime-built character classification tables for HTTP/1.1 grammar
//! (RFC 9110 Appendix B). A byte's class is a single array lookup - no branches
//! in the hot scan loops.

const HTAB = 0x09;
const SP = 0x20;
const DEL = 0x7F;

/// tchar (RFC 9110 5.6.2): the set of characters allowed in a `token`, which is
/// what field-names, methods and transfer-coding names are built from.
///   token = 1*tchar
///   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
///           "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
pub const is_tchar: [256]bool = blk: {
    var t = [_]bool{false} ** 256;
    for ("!#$%&'*+-.^_`|~") |ch| t[ch] = true;
    for ('0'..'9' + 1) |ch| t[ch] = true;
    for ('a'..'z' + 1) |ch| t[ch] = true;
    for ('A'..'Z' + 1) |ch| t[ch] = true;
    break :blk t;
};

/// Characters permitted in a header field-value (RFC 9112 5.5 / 9110 5.5):
///   field-value = *field-content
///   field-vchar = VCHAR / obs-text
/// We additionally allow SP (0x20) and HTAB (0x09); leading/trailing OWS is
/// stripped by the caller. Control characters (except HTAB) are rejected to
/// defend against header injection and request smuggling.
pub const is_field_vchar: [256]bool = blk: {
    var t = [_]bool{false} ** 256;
    var ch: usize = 0x21;
    while (ch <= 0xFF) : (ch += 1) t[ch] = true; // obs-text runs to 0xFF
    t[HTAB] = true;
    t[SP] = true;
    t[DEL] = false;
    break :blk t;
};

/// Hex digit value, or 0xFF for non-hex bytes. Used by the chunk-size decoder.
pub const hex_value: [256]u8 = blk: {
    var t = [_]u8{0xFF} ** 256;
    for ('0'..'9' + 1) |ch| t[ch] = ch - '0';
    for ('a'..'f' + 1) |ch| t[ch] = ch - 'a' + 10;
    for ('A'..'F' + 1) |ch| t[ch] = ch - 'A' + 10;
    break :blk t;
};

/// Bytes allowed unescaped in a request-target. This is intentionally lenient
/// (the path component is validated more strictly by the URL splitter): it
/// rejects only CTLs, SP and DQUOTE, matching what battle-tested parsers accept
/// from real-world clients.
pub const is_target_char: [256]bool = blk: {
    var t = [_]bool{false} ** 256;
    var ch: usize = 0x21;
    while (ch <= 0xFF) : (ch += 1) t[ch] = true;
    t[DEL] = false;
    t['"'] = false;
    break :blk t;
};

/// ASCII lowercasing table: maps A-Z to a-z, everything else unchanged. Header
/// field-names are matched case-insensitively, so we fold to lowercase once.
pub const to_lower: [256]u8 = blk: {
    var t: [256]u8 = undefined;
    for (0..256) |ch| t[ch] = ch;
    for ('A'..'Z' + 1) |ch| t[ch] = ch - 'A' + 'a';
    break :blk t;
};

test "tchar excludes separators and controls" {
    const std = @import("std");
    try std.testing.expect(is_tchar['a']);
    try std.testing.expect(is_tchar['-']);
    try std.testing.expect(!is_tchar[' ']);
    try std.testing.expect(!is_tchar[':']);
    try std.testing.expect(!is_tchar['\r']);
    try std.testing.expect(!is_tchar[0]);
}

test "field-vchar allows obs-text and HTAB but not control/DEL" {
    const std = @import("std");
    try std.testing.expect(is_field_vchar['x']);
    try std.testing.expect(is_field_vchar[0x09]);
    try std.testing.expect(is_field_vchar[0x20]);
    try std.testing.expect(is_field_vchar[0xFF]);
    try std.testing.expect(!is_field_vchar[0x00]);
    try std.testing.expect(!is_field_vchar[0x1F]);
    try std.testing.expect(!is_field_vchar[0x7F]);
}

test "hex_value decodes and rejects" {
    const std = @import("std");
    try std.testing.expectEqual(@as(u8, 0), hex_value['0']);
    try std.testing.expectEqual(@as(u8, 10), hex_value['a']);
    try std.testing.expectEqual(@as(u8, 15), hex_value['F']);
    try std.testing.expectEqual(@as(u8, 0xFF), hex_value['g']);
    try std.testing.expectEqual(@as(u8, 0xFF), hex_value[' ']);
}

test "to_lower folds ascii uppercase" {
    const std = @import("std");
    try std.testing.expectEqual(@as(u8, 'a'), to_lower['A']);
    try std.testing.expectEqual(@as(u8, 'z'), to_lower['Z']);
    try std.testing.expectEqual(@as(u8, '-'), to_lower['-']);
    try std.testing.expectEqual(@as(u8, 0xFF), to_lower[0xFF]);
}
