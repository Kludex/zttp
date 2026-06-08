//! The QUIC transport layer (RFC 9000/9001/9002): the bytes-in, bytes-out
//! transport HTTP/3 runs over. Aggregates the submodules and pulls their tests,
//! mirroring src/core/h2/root.zig so `zig build test` covers QUIC with no new
//! build step. Built bottom-up; modules are added here as each layer lands.

pub const varint = @import("varint.zig");

test {
    _ = varint;
}
