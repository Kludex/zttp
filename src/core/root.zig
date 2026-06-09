//! Pure-Zig core: the sans-IO HTTP parser, independent of CPython.

pub const tables = @import("tables.zig");
pub const errors = @import("errors.zig");
pub const events = @import("events.zig");
pub const scanner = @import("scanner.zig");
pub const h1 = @import("h1/root.zig");

test {
    _ = tables;
    _ = errors;
    _ = events;
    _ = scanner;
    _ = h1;
}
