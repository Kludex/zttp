//! Pure-Zig core: the sans-IO HTTP parser, independent of CPython.

pub const tables = @import("tables.zig");
pub const ascii = @import("ascii.zig");
pub const errors = @import("errors.zig");
pub const events = @import("events.zig");
pub const fields = @import("fields.zig");
pub const scanner = @import("scanner.zig");
pub const h1 = @import("h1/root.zig");
pub const h2 = @import("h2/root.zig");
pub const quic = @import("quic/root.zig");
pub const h3 = @import("h3/root.zig");

test {
    _ = tables;
    _ = ascii;
    _ = errors;
    _ = events;
    _ = fields;
    _ = scanner;
    _ = h1;
    _ = h2;
    _ = quic;
    _ = h3;
}
