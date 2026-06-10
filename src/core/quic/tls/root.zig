//! The TLS 1.3 server handshake, sans-IO: a bytes-in/bytes-out state machine
//! driven by QUIC CRYPTO frames (RFC 9001 4). It derives the Handshake and
//! Application packet-protection secrets the QUIC transport installs per space.
//! Aggregates the submodules and pulls their tests, mirroring the other roots.

pub const transcript = @import("transcript.zig");
pub const schedule = @import("schedule.zig");
pub const keyshare = @import("keyshare.zig");
pub const sign = @import("sign.zig");
pub const finished = @import("finished.zig");
pub const wire = @import("wire.zig");
pub const extension = @import("extension.zig");
pub const handshake = @import("handshake.zig");
pub const client_hello = @import("client_hello.zig");
pub const flight = @import("flight.zig");
pub const codec = @import("codec.zig");

test {
    _ = @import("codec_test.zig");
    _ = transcript;
    _ = schedule;
    _ = keyshare;
    _ = sign;
    _ = finished;
    _ = wire;
    _ = extension;
    _ = handshake;
    _ = client_hello;
    _ = flight;
    _ = codec;
}
