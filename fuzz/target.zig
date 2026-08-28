//! Coverage-instrumented drivers for the sans-IO protocol core, exported through
//! the `zttp_fuzz_drive` C ABI. The C shim owns the libFuzzer/AFL++ entry point
//! and registers this object's sanitizer-coverage counters. Every driver uses
//! the C allocator so ASan and LeakSanitizer intercept its allocations.

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
const QuicConnection = core.quic.connection.Connection;
const quic_frame = core.quic.frame;
const H3Connection = core.h3.connection.Connection;
const h3_frame = core.h3.frame;

const MAX_FUZZ_INPUT: usize = 64 * 1024;
const MAX_STATE_INPUT: usize = 4 * 1024;
const FUZZ_DCID = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const FUZZ_ADDRESSES = [_][]const u8{ "path-a", "path-b", "path-c", "path-d" };

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
                        r.reset() catch continue :outer;
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

fn deliverAppPacket(conn: *QuicConnection, pn: u64, frames: []const u8, address: []const u8) bool {
    const datagram = core.quic.connection.test_support.buildApp(std.heap.c_allocator, &FUZZ_DCID, pn, frames) catch return false;
    defer std.heap.c_allocator.free(datagram);
    conn.receiveDatagramFrom(datagram, pn + 1, address) catch return false;
    conn.clearSend();
    return true;
}

fn driveQuic(input: []const u8) void {
    const body = input[0..@min(input.len, MAX_STATE_INPUT)];

    var unauthenticated = QuicConnection.init(std.heap.c_allocator, .server, &FUZZ_DCID) catch return;
    defer unauthenticated.deinit();
    core.quic.connection.test_support.installAppKeys(&unauthenticated);
    unauthenticated.receiveDatagramFrom(body, 0, FUZZ_ADDRESSES[0]) catch {};

    var conn = QuicConnection.init(std.heap.c_allocator, .server, &FUZZ_DCID) catch return;
    defer conn.deinit();
    core.quic.connection.test_support.installAppKeys(&conn);
    core.quic.connection.test_support.confirmHandshake(&conn);

    const split = if (body.len == 0) 0 else @as(usize, body[0]) % (body.len + 1);
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(std.heap.c_allocator);

    quic_frame.encodeStream(&frames, std.heap.c_allocator, 0, split, body[split..], true) catch return;
    if (!deliverAppPacket(&conn, 0, frames.items, FUZZ_ADDRESSES[0])) return;
    frames.clearRetainingCapacity();
    quic_frame.encodeStream(&frames, std.heap.c_allocator, 0, 0, body[0..split], false) catch return;
    if (!deliverAppPacket(&conn, 1, frames.items, FUZZ_ADDRESSES[1])) return;

    frames.clearRetainingCapacity();
    const reset_code = if (body.len == 0) 0 else body[0];
    const reset_size = if (body.len < 2) body.len else @as(u64, body[1]) * 16;
    quic_frame.encodeResetStream(&frames, std.heap.c_allocator, 4, reset_code, reset_size) catch return;
    if (!deliverAppPacket(&conn, 2, frames.items, FUZZ_ADDRESSES[2])) return;

    const ping = [_]u8{0x01} ++ [_]u8{0x00} ** 19;
    const tampered = core.quic.connection.test_support.buildApp(std.heap.c_allocator, &FUZZ_DCID, 3, &ping) catch return;
    defer std.heap.c_allocator.free(tampered);
    tampered[tampered.len - 1] ^= if (body.len == 0) 1 else body[0] | 1;
    conn.receiveDatagramFrom(tampered, 4, FUZZ_ADDRESSES[3]) catch {};
}

fn driveH3(input: []const u8) void {
    const body = input[0..@min(input.len, MAX_STATE_INPUT)];
    var qc = QuicConnection.init(std.heap.c_allocator, .server, &FUZZ_DCID) catch return;
    defer qc.deinit();
    core.quic.connection.test_support.installAppKeys(&qc);
    core.quic.connection.test_support.confirmHandshake(&qc);
    var h3 = H3Connection.init(std.heap.c_allocator, &qc);
    defer h3.deinit();

    var h3_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer h3_bytes.deinit(std.heap.c_allocator);
    h3_bytes.append(std.heap.c_allocator, 0) catch return;
    h3_frame.append(&h3_bytes, std.heap.c_allocator, .settings, &.{}) catch return;
    var frames: std.ArrayListUnmanaged(u8) = .empty;
    defer frames.deinit(std.heap.c_allocator);
    quic_frame.encodeStream(&frames, std.heap.c_allocator, 2, 0, h3_bytes.items, false) catch return;
    if (!deliverAppPacket(&qc, 0, frames.items, FUZZ_ADDRESSES[0])) return;
    h3.pump(2) catch return;

    h3_bytes.clearRetainingCapacity();
    const qpack_block = [_]u8{ 0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1 };
    h3_frame.append(&h3_bytes, std.heap.c_allocator, .headers, &qpack_block) catch return;
    h3_frame.append(&h3_bytes, std.heap.c_allocator, .data, body) catch return;
    const split = (if (body.len == 0) 0 else @as(usize, body[0])) %
        (h3_bytes.items.len + 1);

    frames.clearRetainingCapacity();
    quic_frame.encodeStream(
        &frames,
        std.heap.c_allocator,
        0,
        split,
        h3_bytes.items[split..],
        false,
    ) catch return;
    if (!deliverAppPacket(&qc, 1, frames.items, FUZZ_ADDRESSES[1])) return;
    h3.pump(0) catch return;
    frames.clearRetainingCapacity();
    quic_frame.encodeStream(&frames, std.heap.c_allocator, 0, 0, h3_bytes.items[0..split], false) catch return;
    if (!deliverAppPacket(&qc, 2, frames.items, FUZZ_ADDRESSES[2])) return;
    h3.pump(0) catch return;

    frames.clearRetainingCapacity();
    const reset_code = if (body.len < 2) 0 else body[1];
    quic_frame.encodeResetStream(&frames, std.heap.c_allocator, 0, reset_code, h3_bytes.items.len) catch return;
    if (deliverAppPacket(&qc, 3, frames.items, FUZZ_ADDRESSES[3])) h3.pump(0) catch {};

    for (0..64) |_| switch (h3.nextEvent()) {
        .need_data => break,
        else => {},
    };
}

export fn zttp_fuzz_drive(data: [*]const u8, size: usize) callconv(.c) void {
    const input = data[0..size];
    if (input.len == 0) {
        drive(input);
        return;
    }
    const body = input[1..@min(input.len, MAX_FUZZ_INPUT + 1)];
    switch (input[0] % 6) {
        0 => drive(body),
        1 => driveH2(body),
        2 => driveHpackRoundtrip(body),
        3 => driveQpackRoundtrip(body),
        4 => driveQuic(body),
        5 => driveH3(body),
        else => unreachable,
    }
}

test "stateful fuzz drivers accept bounded seeds" {
    const quic_seed = "(reordered stream data and a reset";
    zttp_fuzz_drive(quic_seed.ptr, quic_seed.len);
    const h3_seed = ")headers, data, reset, and path changes";
    zttp_fuzz_drive(h3_seed.ptr, h3_seed.len);
}
