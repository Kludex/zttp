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

const Reader = core.reader.Reader;
const Role = core.reader.Role;

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

export fn zttp_fuzz_drive(data: [*]const u8, size: usize) callconv(.c) void {
    drive(data[0..size]);
}
