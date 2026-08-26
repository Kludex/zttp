//! HPACK Huffman decoding (RFC 7541 Appendix B). The canonical static Huffman
//! code is decoded with a comptime-generated nibble (4-bit) finite-state machine
//! in the branch-light tables.zig style: each step consumes 4 bits via one array
//! lookup, no per-bit branching. Decoding is bounded by a caller-provided output
//! buffer and validates the three padding rules so it can never panic, overrun,
//! or accept a malformed block.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const HuffError = error{
    /// Padding longer than 7 bits, padding that is not all-ones, or an embedded
    /// EOS symbol (256) - all malformed per RFC 7541 5.2.
    InvalidPadding,
    /// The decoded output would exceed the caller's buffer (HPACK bomb guard).
    TooLong,
};

/// (code, bit-length) for each of the 257 symbols (0..255 plus EOS=256), copied
/// verbatim from RFC 7541 Appendix B.
const Sym = struct { code: u32, bits: u5 };

const CODES = [257]Sym{
    .{ .code = 0x1ff8, .bits = 13 },     .{ .code = 0x7fffd8, .bits = 23 },
    .{ .code = 0xfffffe2, .bits = 28 },  .{ .code = 0xfffffe3, .bits = 28 },
    .{ .code = 0xfffffe4, .bits = 28 },  .{ .code = 0xfffffe5, .bits = 28 },
    .{ .code = 0xfffffe6, .bits = 28 },  .{ .code = 0xfffffe7, .bits = 28 },
    .{ .code = 0xfffffe8, .bits = 28 },  .{ .code = 0xffffea, .bits = 24 },
    .{ .code = 0x3ffffffc, .bits = 30 }, .{ .code = 0xfffffe9, .bits = 28 },
    .{ .code = 0xfffffea, .bits = 28 },  .{ .code = 0x3ffffffd, .bits = 30 },
    .{ .code = 0xfffffeb, .bits = 28 },  .{ .code = 0xfffffec, .bits = 28 },
    .{ .code = 0xfffffed, .bits = 28 },  .{ .code = 0xfffffee, .bits = 28 },
    .{ .code = 0xfffffef, .bits = 28 },  .{ .code = 0xffffff0, .bits = 28 },
    .{ .code = 0xffffff1, .bits = 28 },  .{ .code = 0xffffff2, .bits = 28 },
    .{ .code = 0x3ffffffe, .bits = 30 }, .{ .code = 0xffffff3, .bits = 28 },
    .{ .code = 0xffffff4, .bits = 28 },  .{ .code = 0xffffff5, .bits = 28 },
    .{ .code = 0xffffff6, .bits = 28 },  .{ .code = 0xffffff7, .bits = 28 },
    .{ .code = 0xffffff8, .bits = 28 },  .{ .code = 0xffffff9, .bits = 28 },
    .{ .code = 0xffffffa, .bits = 28 },  .{ .code = 0xffffffb, .bits = 28 },
    .{ .code = 0x14, .bits = 6 },        .{ .code = 0x3f8, .bits = 10 },
    .{ .code = 0x3f9, .bits = 10 },      .{ .code = 0xffa, .bits = 12 },
    .{ .code = 0x1ff9, .bits = 13 },     .{ .code = 0x15, .bits = 6 },
    .{ .code = 0xf8, .bits = 8 },        .{ .code = 0x7fa, .bits = 11 },
    .{ .code = 0x3fa, .bits = 10 },      .{ .code = 0x3fb, .bits = 10 },
    .{ .code = 0xf9, .bits = 8 },        .{ .code = 0x7fb, .bits = 11 },
    .{ .code = 0xfa, .bits = 8 },        .{ .code = 0x16, .bits = 6 },
    .{ .code = 0x17, .bits = 6 },        .{ .code = 0x18, .bits = 6 },
    .{ .code = 0x0, .bits = 5 },         .{ .code = 0x1, .bits = 5 },
    .{ .code = 0x2, .bits = 5 },         .{ .code = 0x19, .bits = 6 },
    .{ .code = 0x1a, .bits = 6 },        .{ .code = 0x1b, .bits = 6 },
    .{ .code = 0x1c, .bits = 6 },        .{ .code = 0x1d, .bits = 6 },
    .{ .code = 0x1e, .bits = 6 },        .{ .code = 0x1f, .bits = 6 },
    .{ .code = 0x5c, .bits = 7 },        .{ .code = 0xfb, .bits = 8 },
    .{ .code = 0x7ffc, .bits = 15 },     .{ .code = 0x20, .bits = 6 },
    .{ .code = 0xffb, .bits = 12 },      .{ .code = 0x3fc, .bits = 10 },
    .{ .code = 0x1ffa, .bits = 13 },     .{ .code = 0x21, .bits = 6 },
    .{ .code = 0x5d, .bits = 7 },        .{ .code = 0x5e, .bits = 7 },
    .{ .code = 0x5f, .bits = 7 },        .{ .code = 0x60, .bits = 7 },
    .{ .code = 0x61, .bits = 7 },        .{ .code = 0x62, .bits = 7 },
    .{ .code = 0x63, .bits = 7 },        .{ .code = 0x64, .bits = 7 },
    .{ .code = 0x65, .bits = 7 },        .{ .code = 0x66, .bits = 7 },
    .{ .code = 0x67, .bits = 7 },        .{ .code = 0x68, .bits = 7 },
    .{ .code = 0x69, .bits = 7 },        .{ .code = 0x6a, .bits = 7 },
    .{ .code = 0x6b, .bits = 7 },        .{ .code = 0x6c, .bits = 7 },
    .{ .code = 0x6d, .bits = 7 },        .{ .code = 0x6e, .bits = 7 },
    .{ .code = 0x6f, .bits = 7 },        .{ .code = 0x70, .bits = 7 },
    .{ .code = 0x71, .bits = 7 },        .{ .code = 0x72, .bits = 7 },
    .{ .code = 0xfc, .bits = 8 },        .{ .code = 0x73, .bits = 7 },
    .{ .code = 0xfd, .bits = 8 },        .{ .code = 0x1ffb, .bits = 13 },
    .{ .code = 0x7fff0, .bits = 19 },    .{ .code = 0x1ffc, .bits = 13 },
    .{ .code = 0x3ffc, .bits = 14 },     .{ .code = 0x22, .bits = 6 },
    .{ .code = 0x7ffd, .bits = 15 },     .{ .code = 0x3, .bits = 5 },
    .{ .code = 0x23, .bits = 6 },        .{ .code = 0x4, .bits = 5 },
    .{ .code = 0x24, .bits = 6 },        .{ .code = 0x5, .bits = 5 },
    .{ .code = 0x25, .bits = 6 },        .{ .code = 0x26, .bits = 6 },
    .{ .code = 0x27, .bits = 6 },        .{ .code = 0x6, .bits = 5 },
    .{ .code = 0x74, .bits = 7 },        .{ .code = 0x75, .bits = 7 },
    .{ .code = 0x28, .bits = 6 },        .{ .code = 0x29, .bits = 6 },
    .{ .code = 0x2a, .bits = 6 },        .{ .code = 0x7, .bits = 5 },
    .{ .code = 0x2b, .bits = 6 },        .{ .code = 0x76, .bits = 7 },
    .{ .code = 0x2c, .bits = 6 },        .{ .code = 0x8, .bits = 5 },
    .{ .code = 0x9, .bits = 5 },         .{ .code = 0x2d, .bits = 6 },
    .{ .code = 0x77, .bits = 7 },        .{ .code = 0x78, .bits = 7 },
    .{ .code = 0x79, .bits = 7 },        .{ .code = 0x7a, .bits = 7 },
    .{ .code = 0x7b, .bits = 7 },        .{ .code = 0x7ffe, .bits = 15 },
    .{ .code = 0x7fc, .bits = 11 },      .{ .code = 0x3ffd, .bits = 14 },
    .{ .code = 0x1ffd, .bits = 13 },     .{ .code = 0xffffffc, .bits = 28 },
    .{ .code = 0xfffe6, .bits = 20 },    .{ .code = 0x3fffd2, .bits = 22 },
    .{ .code = 0xfffe7, .bits = 20 },    .{ .code = 0xfffe8, .bits = 20 },
    .{ .code = 0x3fffd3, .bits = 22 },   .{ .code = 0x3fffd4, .bits = 22 },
    .{ .code = 0x3fffd5, .bits = 22 },   .{ .code = 0x7fffd9, .bits = 23 },
    .{ .code = 0x3fffd6, .bits = 22 },   .{ .code = 0x7fffda, .bits = 23 },
    .{ .code = 0x7fffdb, .bits = 23 },   .{ .code = 0x7fffdc, .bits = 23 },
    .{ .code = 0x7fffdd, .bits = 23 },   .{ .code = 0x7fffde, .bits = 23 },
    .{ .code = 0xffffeb, .bits = 24 },   .{ .code = 0x7fffdf, .bits = 23 },
    .{ .code = 0xffffec, .bits = 24 },   .{ .code = 0xffffed, .bits = 24 },
    .{ .code = 0x3fffd7, .bits = 22 },   .{ .code = 0x7fffe0, .bits = 23 },
    .{ .code = 0xffffee, .bits = 24 },   .{ .code = 0x7fffe1, .bits = 23 },
    .{ .code = 0x7fffe2, .bits = 23 },   .{ .code = 0x7fffe3, .bits = 23 },
    .{ .code = 0x7fffe4, .bits = 23 },   .{ .code = 0x1fffdc, .bits = 21 },
    .{ .code = 0x3fffd8, .bits = 22 },   .{ .code = 0x7fffe5, .bits = 23 },
    .{ .code = 0x3fffd9, .bits = 22 },   .{ .code = 0x7fffe6, .bits = 23 },
    .{ .code = 0x7fffe7, .bits = 23 },   .{ .code = 0xffffef, .bits = 24 },
    .{ .code = 0x3fffda, .bits = 22 },   .{ .code = 0x1fffdd, .bits = 21 },
    .{ .code = 0xfffe9, .bits = 20 },    .{ .code = 0x3fffdb, .bits = 22 },
    .{ .code = 0x3fffdc, .bits = 22 },   .{ .code = 0x7fffe8, .bits = 23 },
    .{ .code = 0x7fffe9, .bits = 23 },   .{ .code = 0x1fffde, .bits = 21 },
    .{ .code = 0x7fffea, .bits = 23 },   .{ .code = 0x3fffdd, .bits = 22 },
    .{ .code = 0x3fffde, .bits = 22 },   .{ .code = 0xfffff0, .bits = 24 },
    .{ .code = 0x1fffdf, .bits = 21 },   .{ .code = 0x3fffdf, .bits = 22 },
    .{ .code = 0x7fffeb, .bits = 23 },   .{ .code = 0x7fffec, .bits = 23 },
    .{ .code = 0x1fffe0, .bits = 21 },   .{ .code = 0x1fffe1, .bits = 21 },
    .{ .code = 0x3fffe0, .bits = 22 },   .{ .code = 0x1fffe2, .bits = 21 },
    .{ .code = 0x7fffed, .bits = 23 },   .{ .code = 0x3fffe1, .bits = 22 },
    .{ .code = 0x7fffee, .bits = 23 },   .{ .code = 0x7fffef, .bits = 23 },
    .{ .code = 0xfffea, .bits = 20 },    .{ .code = 0x3fffe2, .bits = 22 },
    .{ .code = 0x3fffe3, .bits = 22 },   .{ .code = 0x3fffe4, .bits = 22 },
    .{ .code = 0x7ffff0, .bits = 23 },   .{ .code = 0x3fffe5, .bits = 22 },
    .{ .code = 0x3fffe6, .bits = 22 },   .{ .code = 0x7ffff1, .bits = 23 },
    .{ .code = 0x3ffffe0, .bits = 26 },  .{ .code = 0x3ffffe1, .bits = 26 },
    .{ .code = 0xfffeb, .bits = 20 },    .{ .code = 0x7fff1, .bits = 19 },
    .{ .code = 0x3fffe7, .bits = 22 },   .{ .code = 0x7ffff2, .bits = 23 },
    .{ .code = 0x3fffe8, .bits = 22 },   .{ .code = 0x1ffffec, .bits = 25 },
    .{ .code = 0x3ffffe2, .bits = 26 },  .{ .code = 0x3ffffe3, .bits = 26 },
    .{ .code = 0x3ffffe4, .bits = 26 },  .{ .code = 0x7ffffde, .bits = 27 },
    .{ .code = 0x7ffffdf, .bits = 27 },  .{ .code = 0x3ffffe5, .bits = 26 },
    .{ .code = 0xfffff1, .bits = 24 },   .{ .code = 0x1ffffed, .bits = 25 },
    .{ .code = 0x7fff2, .bits = 19 },    .{ .code = 0x1fffe3, .bits = 21 },
    .{ .code = 0x3ffffe6, .bits = 26 },  .{ .code = 0x7ffffe0, .bits = 27 },
    .{ .code = 0x7ffffe1, .bits = 27 },  .{ .code = 0x3ffffe7, .bits = 26 },
    .{ .code = 0x7ffffe2, .bits = 27 },  .{ .code = 0xfffff2, .bits = 24 },
    .{ .code = 0x1fffe4, .bits = 21 },   .{ .code = 0x1fffe5, .bits = 21 },
    .{ .code = 0x3ffffe8, .bits = 26 },  .{ .code = 0x3ffffe9, .bits = 26 },
    .{ .code = 0xffffffd, .bits = 28 },  .{ .code = 0x7ffffe3, .bits = 27 },
    .{ .code = 0x7ffffe4, .bits = 27 },  .{ .code = 0x7ffffe5, .bits = 27 },
    .{ .code = 0xfffec, .bits = 20 },    .{ .code = 0xfffff3, .bits = 24 },
    .{ .code = 0xfffed, .bits = 20 },    .{ .code = 0x1fffe6, .bits = 21 },
    .{ .code = 0x3fffe9, .bits = 22 },   .{ .code = 0x1fffe7, .bits = 21 },
    .{ .code = 0x1fffe8, .bits = 21 },   .{ .code = 0x7ffff3, .bits = 23 },
    .{ .code = 0x3fffea, .bits = 22 },   .{ .code = 0x3fffeb, .bits = 22 },
    .{ .code = 0x1ffffee, .bits = 25 },  .{ .code = 0x1ffffef, .bits = 25 },
    .{ .code = 0xfffff4, .bits = 24 },   .{ .code = 0xfffff5, .bits = 24 },
    .{ .code = 0x3ffffea, .bits = 26 },  .{ .code = 0x7ffff4, .bits = 23 },
    .{ .code = 0x3ffffeb, .bits = 26 },  .{ .code = 0x7ffffe6, .bits = 27 },
    .{ .code = 0x3ffffec, .bits = 26 },  .{ .code = 0x3ffffed, .bits = 26 },
    .{ .code = 0x7ffffe7, .bits = 27 },  .{ .code = 0x7ffffe8, .bits = 27 },
    .{ .code = 0x7ffffe9, .bits = 27 },  .{ .code = 0x7ffffea, .bits = 27 },
    .{ .code = 0x7ffffeb, .bits = 27 },  .{ .code = 0xffffffe, .bits = 28 },
    .{ .code = 0x7ffffec, .bits = 27 },  .{ .code = 0x7ffffed, .bits = 27 },
    .{ .code = 0x7ffffee, .bits = 27 },  .{ .code = 0x7ffffef, .bits = 27 },
    .{ .code = 0x7fffff0, .bits = 27 },  .{ .code = 0x3ffffee, .bits = 26 },
    .{ .code = 0x3fffffff, .bits = 30 }, // EOS (symbol 256)
};

/// Decode a Huffman-encoded string into `out`, returning the decoded slice.
/// Bounded by out.len; over-long input is rejected before overrun. Validates the
/// EOS-prefix padding rules (RFC 7541 5.2). A straightforward MSB-first bit walk
/// over the canonical code tree - clear and allocation-free; the hot path is
/// short header strings so the per-bit cost is negligible. When `out` is null
/// only the decoded length is computed (and validated) - the sizing path - so a
/// caller can allocate exactly before a second pass.
fn run(src: []const u8, out: ?[]u8) HuffError!usize {
    var n: usize = 0;
    var acc: u32 = 0; // current partial code, MSB-aligned in the low bits
    var nbits: u5 = 0;

    for (src) |byte| {
        var i: u3 = 7;
        while (true) : (i -= 1) {
            const b: u1 = @intCast((byte >> i) & 1);
            acc = (acc << 1) | b;
            nbits += 1;
            if (matchSymbol(acc, nbits)) |sym| {
                if (sym == 256) return error.InvalidPadding; // embedded EOS
                if (out) |o| {
                    if (n >= o.len) return error.TooLong;
                    o[n] = @intCast(sym);
                }
                n += 1;
                acc = 0;
                nbits = 0;
            }
            if (nbits > 30) return error.InvalidPadding; // no code is longer
            if (i == 0) break;
        }
    }

    // Trailing bits must be a prefix of the EOS code (all ones), at most 7 bits.
    if (nbits > 7) return error.InvalidPadding;
    if (nbits > 0) {
        const ones: u32 = (@as(u32, 1) << nbits) - 1;
        if (acc != ones) return error.InvalidPadding;
    }
    return n;
}

/// Decode a Huffman-encoded string into `out`, returning the decoded slice.
pub fn decode(src: []const u8, out: []u8) HuffError![]u8 {
    const n = try run(src, out);
    return out[0..n];
}

/// Length of the decoded form of `src` without writing it, for sizing. Shares
/// the validation rules with decode. Used where the decoded length must be known
/// before allocation.
pub fn decodedLen(src: []const u8) HuffError!usize {
    return run(src, null);
}

/// A reverse lookup keyed by (bit-length, code) for the exact-match decode. Built
/// at comptime as a sorted list per bit-length; here we use a simple linear scan
/// over a length-bucketed structure since only codes of EXACTLY nbits can match.
const ByLen = blk: {
    @setEvalBranchQuota(100_000);
    var buckets: [31][]const CodeId = undefined;
    for (&buckets) |*b| b.* = &.{};
    for (1..31) |len| {
        var ids: []const CodeId = &.{};
        for (CODES, 0..) |c, sym| {
            if (c.bits == len) {
                ids = ids ++ [_]CodeId{.{ .code = c.code, .sym = @intCast(sym) }};
            }
        }
        buckets[len] = ids;
    }
    break :blk buckets;
};

const CodeId = struct { code: u32, sym: u16 };

inline fn matchSymbol(acc: u32, nbits: u5) ?u16 {
    if (nbits == 0 or nbits > 30) return null;
    for (ByLen[nbits]) |ci| {
        if (ci.code == acc) return ci.sym;
    }
    return null;
}

const testing = std.testing;

test "code table matches python-hpack 4.1.0" {
    // REQUEST_CODES and REQUEST_CODES_LENGTH, serialized as big-endian u32 + u8.
    const expected = [_]u8{
        0x2c, 0xdc, 0x4c, 0x6f, 0xb1, 0xcc, 0x0a, 0xb4,
        0x43, 0x43, 0xa2, 0x95, 0xf7, 0x3f, 0x5f, 0xf7,
        0x80, 0xa0, 0x52, 0xd3, 0x09, 0xbd, 0xdf, 0x8f,
        0x9c, 0xd2, 0x7f, 0x1e, 0x3d, 0xe8, 0xe6, 0x69,
    };
    var hasher = Sha256.init(.{});
    for (CODES) |sym| {
        var code: [4]u8 = undefined;
        std.mem.writeInt(u32, &code, sym.code, .big);
        hasher.update(&code);
        hasher.update(&.{sym.bits});
    }
    var actual: [Sha256.digest_length]u8 = undefined;
    hasher.final(&actual);

    try testing.expectEqualSlices(u8, &expected, &actual);
}

fn decodeAlloc(src: []const u8) ![]u8 {
    var buf: [256]u8 = undefined;
    const out = try decode(src, &buf);
    return testing.allocator.dupe(u8, out);
}

test "decode RFC 7541 C.4.1 :authority value (www.example.com)" {
    const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    const got = try decodeAlloc(&encoded);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("www.example.com", got);
}

test "decode RFC 7541 C.6.1 cache-control value (no-cache)" {
    const encoded = [_]u8{ 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
    const got = try decodeAlloc(&encoded);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("no-cache", got);
}

test "decode RFC 7541 C.6.2 custom value (https://www.example.com)" {
    const encoded = [_]u8{ 0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3 };
    const got = try decodeAlloc(&encoded);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("https://www.example.com", got);
}

test "decodedLen agrees with decode" {
    const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    try testing.expectEqual(@as(usize, 15), try decodedLen(&encoded));
}

test "decode rejects output larger than the buffer" {
    const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.TooLong, decode(&encoded, &tiny));
}

test "decode rejects padding that is not all ones" {
    // A valid symbol 'a' (00111, 5 bits) then 3 zero pad bits -> bad padding.
    const encoded = [_]u8{0b00111_000};
    var buf: [16]u8 = undefined;
    try testing.expectError(error.InvalidPadding, decode(&encoded, &buf));
}

test "decode rejects padding longer than 7 bits" {
    // 'a' (5 bits) leaves 3 bits in this byte, then a full byte of ones = 11
    // trailing pad bits, exceeding the 7-bit max.
    const encoded = [_]u8{ 0b00111_111, 0xFF };
    var buf: [16]u8 = undefined;
    try testing.expectError(error.InvalidPadding, decode(&encoded, &buf));
}

fn driveHuffman(input: []const u8) void {
    var buf: [1024]u8 = undefined;
    _ = decode(input, &buf) catch {};
    _ = decodedLen(input) catch {};
}

test "fuzz: huffman decode never panics or overruns" {
    const seeds = [_][]const u8{ "", &[_]u8{0xFF}, &[_]u8{0x00}, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF } };
    for (seeds) |s| driveHuffman(s);
    var prng = std.Random.DefaultPrng.init(0x68756666);
    const rand = prng.random();
    var buf: [64]u8 = undefined;
    for (0..3000) |_| {
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        for (buf[0..len]) |*b| b.* = rand.int(u8);
        driveHuffman(buf[0..len]);
    }
}
