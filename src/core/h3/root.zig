//! The HTTP/3 layer: the frame codec, stream typing and SETTINGS, and QPACK,
//! sitting on the ordered QUIC stream bytes the transport hands up. Aggregates the
//! submodules and pulls their tests, mirroring src/core/h2/root.zig so
//! `zig build test` covers H3 with no new build step.

pub const frame = @import("frame.zig");
pub const stream = @import("stream.zig");
pub const errors = @import("error.zig");
pub const qpack_static_table = @import("qpack/static_table.zig");
pub const qpack_decoder = @import("qpack/decoder.zig");
pub const qpack_encoder = @import("qpack/encoder.zig");
pub const connection = @import("connection.zig");

test {
    _ = frame;
    _ = stream;
    _ = errors;
    _ = qpack_static_table;
    _ = qpack_decoder;
    _ = qpack_encoder;
    _ = connection;
}
