//! The HTTP/2 layer: frame codec, HPACK, stream state, and the connection
//! orchestrator. Aggregates the submodules and pulls their tests, mirroring
//! src/core/root.zig so `zig build test`/`zig build fuzz` cover H2 with no new
//! build step.

pub const constants = @import("constants.zig");
pub const frame = @import("frame.zig");

test {
    _ = constants;
    _ = frame;
}
