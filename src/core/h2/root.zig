//! The HTTP/2 layer: frame codec, HPACK, stream state, and the connection
//! orchestrator. Aggregates the submodules and pulls their tests, mirroring
//! src/core/root.zig so `zig build test`/`zig build fuzz` cover H2 with no new
//! build step.

pub const constants = @import("constants.zig");
pub const frame = @import("frame.zig");
pub const static_table = @import("hpack/static_table.zig");
pub const huffman = @import("hpack/huffman.zig");
pub const hpack_decoder = @import("hpack/decoder.zig");
pub const settings = @import("settings.zig");
pub const stream = @import("stream.zig");
pub const connection = @import("connection.zig");

test {
    _ = constants;
    _ = frame;
    _ = static_table;
    _ = huffman;
    _ = hpack_decoder;
    _ = settings;
    _ = stream;
    _ = connection;
}
