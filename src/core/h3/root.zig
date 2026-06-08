//! The HTTP/3 layer: the frame codec, stream typing and SETTINGS, and QPACK,
//! sitting on the ordered QUIC stream bytes the transport hands up. Aggregates the
//! submodules and pulls their tests, mirroring src/core/h2/root.zig so
//! `zig build test` covers H3 with no new build step.

pub const frame = @import("frame.zig");
pub const stream = @import("stream.zig");
pub const qpack_static_table = @import("qpack/static_table.zig");
pub const qpack_decoder = @import("qpack/decoder.zig");

test {
    _ = frame;
    _ = stream;
    _ = qpack_static_table;
    _ = qpack_decoder;
}
