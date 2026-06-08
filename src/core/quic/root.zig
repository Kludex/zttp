//! The QUIC transport layer (RFC 9000/9001/9002): the bytes-in, bytes-out
//! transport HTTP/3 runs over. Aggregates the submodules and pulls their tests,
//! mirroring src/core/h2/root.zig so `zig build test` covers QUIC with no new
//! build step. Built bottom-up; modules are added here as each layer lands.

pub const varint = @import("varint.zig");
pub const constants = @import("constants.zig");
pub const frame = @import("frame.zig");
pub const packet = @import("packet.zig");
pub const crypto = @import("crypto.zig");
pub const congestion = @import("congestion.zig");
pub const recovery = @import("recovery.zig");
pub const flow = @import("flow.zig");
pub const stream = @import("stream.zig");

test {
    _ = varint;
    _ = constants;
    _ = frame;
    _ = packet;
    _ = crypto;
    _ = congestion;
    _ = recovery;
    _ = flow;
    _ = stream;
}
