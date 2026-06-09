//! The HTTP/1.1 layer: connection state, the pull-API reader, the writer, and
//! the framing/chunked/header codecs. Aggregates the submodules and pulls their
//! tests, mirroring src/core/h2/root.zig so `zig build test`/`zig build fuzz`
//! cover H1 with no new build step.

pub const headers = @import("headers.zig");
pub const framing = @import("framing.zig");
pub const chunked = @import("chunked.zig");
pub const connection = @import("connection.zig");
pub const reader = @import("reader.zig");
pub const writer = @import("writer.zig");

test {
    _ = headers;
    _ = framing;
    _ = chunked;
    _ = connection;
    _ = reader;
    _ = writer;
}
