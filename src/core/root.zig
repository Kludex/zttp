//! Pure-Zig core: the sans-IO HTTP parser, independent of CPython.

pub const tables = @import("tables.zig");
pub const errors = @import("errors.zig");
pub const events = @import("events.zig");
pub const scanner = @import("scanner.zig");
pub const headers = @import("headers.zig");
pub const framing = @import("framing.zig");
pub const chunked = @import("chunked.zig");
pub const connection = @import("connection.zig");
pub const reader = @import("reader.zig");
pub const writer = @import("writer.zig");
pub const h2 = @import("h2/root.zig");
pub const quic = @import("quic/root.zig");

test {
    _ = tables;
    _ = errors;
    _ = events;
    _ = scanner;
    _ = headers;
    _ = framing;
    _ = chunked;
    _ = connection;
    _ = reader;
    _ = writer;
    _ = h2;
    _ = quic;
}
