//! The TLS 1.3 handshake transcript hash (RFC 8446 4.4.1): a running SHA-256 over
//! every handshake message, from ClientHello onward, in the order they appear on
//! the wire. The key schedule and the CertificateVerify/Finished computations read
//! the digest at precise points (after ServerHello, after the server's
//! Certificate, after each Finished), so `hash()` returns the current digest
//! WITHOUT consuming the hasher - more messages still get appended afterward.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
pub const LEN = Sha256.digest_length;

pub const Transcript = struct {
    hasher: Sha256 = Sha256.init(.{}),

    /// Append one raw handshake message (the wire bytes: type + u24 length + body).
    /// Pass the bytes exactly as received or as they will be sent - never a
    /// re-serialization, so the digest matches both peers byte for byte.
    pub fn update(self: *Transcript, message: []const u8) void {
        self.hasher.update(message);
    }

    /// The transcript hash over every message appended so far. Non-consuming:
    /// `peek` snapshots without finalizing, so the running hash continues.
    pub fn hash(self: *const Transcript) [LEN]u8 {
        return self.hasher.peek();
    }
};

const testing = std.testing;

test "the empty transcript is SHA-256 of the empty string" {
    var t = Transcript{};
    var want: [LEN]u8 = undefined;
    Sha256.hash("", &want, .{});
    try testing.expectEqualSlices(u8, &want, &t.hash());
}

test "hash is non-consuming - more messages keep extending it" {
    var t = Transcript{};
    t.update("hello");
    const after_hello = t.hash();
    t.update(" world");
    const after_world = t.hash();
    // The two digests differ, and re-reading after_hello's point is impossible now
    // (the hasher moved on), proving update accumulates rather than resetting.
    try testing.expect(!std.mem.eql(u8, &after_hello, &after_world));
    var want: [LEN]u8 = undefined;
    Sha256.hash("hello world", &want, .{});
    try testing.expectEqualSlices(u8, &want, &after_world);
}
