//! Coverage-instrumented drive function for the sans-IO reader, exported under
//! a C ABI as `zttp_fuzz_drive`. The libFuzzer/AFL++ entry point and the sancov
//! section registration live in the C shim (`fuzz/target.c`), which OSS-Fuzz's
//! own clang compiles and links against this object's `.fuzz` instrumentation.
//!
//! The drive loop mirrors the `driveReader` property test in `reader.zig`, but
//! uses the C allocator so the sanitizer the engine links (ASan/UBSan)
//! intercepts every allocation.

const std = @import("std");
const core = @import("core");

const Reader = core.h1.reader.Reader;
const Role = core.h1.reader.Role;
const H2Connection = core.h2.connection.Connection;
const h2_constants = core.h2.constants;
const H2Role = core.h2.connection.Role;
const Header = core.events.Header;
const hpack_encoder = core.h2.hpack_encoder;
const HpackDecoder = core.h2.hpack_decoder.Decoder;
const qpack_encoder = core.h3.qpack_encoder;
const QpackDecoder = core.h3.qpack_decoder.Decoder;

fn drive(input: []const u8) void {
    inline for (.{ Role.server, Role.client }) |role| {
        var r = Reader.init(std.heap.c_allocator, role);
        defer r.deinit();
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
                        r.reset();
                        break;
                    },
                    else => {},
                }
            }
        }
    }
}

// The connection orchestrator (and the HPACK/frame/stream parsers it drives) is
// the H2 surface with the least automated assurance; prepending a valid
// preface+SETTINGS gets the mutated tail past the handshake into that machine.
fn driveH2(input: []const u8) void {
    inline for (.{ H2Role.server, H2Role.client }) |role| {
        var conn = H2Connection.init(std.heap.c_allocator, role);
        defer conn.deinit();
        conn.limits.max_buffer = 1 << 20;
        if (role == .server) conn.feed(h2_constants.CLIENT_PREFACE) catch return;
        // An empty SETTINGS frame: 9-byte header, type=0x04, no payload.
        conn.feed(&[_]u8{ 0, 0, 0, 0x04, 0, 0, 0, 0, 0 }) catch return;
        const split = if (input.len == 0) 0 else input[0] % @as(u8, @intCast(@min(input.len, 255)));
        const feeds = [_][]const u8{ input[0..split], input[split..], "" };
        outer: for (feeds) |chunk| {
            conn.feed(chunk) catch break;
            for (0..input.len + 4) |_| {
                const ev = conn.nextEvent() catch continue :outer;
                switch (ev) {
                    .need_data => break,
                    else => {},
                }
            }
        }
    }
}

const MAX_HEADERS = 32;

// Carve the mutated input into a header list: a count byte, then per header a
// name-length byte and a value-length byte slicing the remaining bytes. Slices
// point into `input`, valid for the encode->decode->compare below. Fills `buf`
// and returns the populated prefix.
fn drawHeaders(input: []const u8, buf: *[MAX_HEADERS]Header) []const Header {
    if (input.len == 0) return buf[0..0];
    var p: usize = 0;
    const count = @min(input[p] % MAX_HEADERS, MAX_HEADERS);
    p += 1;
    var n: usize = 0;
    while (n < count and p < input.len) {
        const nlen = @min(@as(usize, input[p]) % 24, input.len - p -| 1);
        p += 1;
        if (p + nlen > input.len) break;
        const name = input[p .. p + nlen];
        p += nlen;
        if (p >= input.len) break;
        const vlen = @min(@as(usize, input[p]) % 48, input.len - p -| 1);
        p += 1;
        if (p + vlen > input.len) break;
        const value = input[p .. p + vlen];
        p += vlen;
        buf[n] = .{ .name = name, .value = value };
        n += 1;
    }
    return buf[0..n];
}

fn headersEqual(a: []const Header, b: []const Header) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!std.mem.eql(u8, x.name, y.name) or !std.mem.eql(u8, x.value, y.value)) return false;
    }
    return true;
}

// HPACK is its own inverse: whatever the encoder emits, the decoder must read
// back into the identical header list. A divergence is a write/read mismatch -
// the same bug class a smuggling vector exploits.
fn driveHpackRoundtrip(input: []const u8) void {
    var buf: [MAX_HEADERS]Header = undefined;
    const headers = drawHeaders(input, &buf);

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(std.heap.c_allocator);
    hpack_encoder.encode(&block, std.heap.c_allocator, headers) catch return;

    var d = HpackDecoder.init(std.heap.c_allocator, 4096, 1 << 20);
    defer d.deinit();
    const out = d.decodeBlock(block.items) catch return;
    std.debug.assert(headersEqual(headers, out));
}

// The QPACK encode->decode differential, mirroring the HPACK one.
fn driveQpackRoundtrip(input: []const u8) void {
    var buf: [MAX_HEADERS]Header = undefined;
    const headers = drawHeaders(input, &buf);

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(std.heap.c_allocator);
    qpack_encoder.encode(&block, std.heap.c_allocator, headers) catch return;

    var d = QpackDecoder.init(std.heap.c_allocator, 1 << 20);
    defer d.deinit();
    const out = d.decode(block.items) catch return;
    std.debug.assert(headersEqual(headers, out));
}

export fn zttp_fuzz_drive(data: [*]const u8, size: usize) callconv(.c) void {
    const input = data[0..size];
    // The low 2 bits of the first byte select the target so one corpus exercises
    // every surface (H1 read, H2 read, HPACK and QPACK encode->decode); the rest
    // is the mutated body. No build wiring changes: the `.fuzz` instrumentation
    // already covers the whole `core` import.
    if (input.len == 0) {
        drive(input);
        return;
    }
    const body = input[1..];
    switch (@as(u2, @truncate(input[0]))) {
        0 => drive(body),
        1 => driveH2(body),
        2 => driveHpackRoundtrip(body),
        3 => driveQpackRoundtrip(body),
    }
}
