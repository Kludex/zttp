//! The TLS 1.3 server handshake, sans-IO: a bytes-in/bytes-out state machine
//! driven by QUIC CRYPTO frames (RFC 9001 4). It derives the Handshake and
//! Application packet-protection secrets the QUIC transport installs per space.
//! Aggregates the submodules and pulls their tests, mirroring the other roots.

pub const transcript = @import("transcript.zig");
pub const schedule = @import("schedule.zig");
pub const keyshare = @import("keyshare.zig");
pub const sign = @import("sign.zig");
pub const finished = @import("finished.zig");

test {
    _ = transcript;
    _ = schedule;
    _ = keyshare;
    _ = sign;
    _ = finished;
}
