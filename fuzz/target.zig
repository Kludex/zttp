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

export fn zttp_fuzz_drive(data: [*]const u8, size: usize) callconv(.c) void {
    const input = data[0..size];
    // First byte selects the parser so one corpus exercises both H1 and H2; the
    // rest is the mutated body. No build wiring changes: `.fuzz` already
    // instruments the whole `core` import, H2 included.
    if (input.len != 0 and input[0] & 1 == 1) {
        driveH2(input[1..]);
    } else {
        drive(if (input.len == 0) input else input[1..]);
    }
}
