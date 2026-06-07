//! Copy a translate-c output file, removing the unused
//! `const extern_local_<name>_s = struct { ... };` blocks that Zig 0.16's
//! translate-c emits for the MSVC secure-CRT functions (wcscat_s, wcscpy_s,
//! ...). They are unused, which Zig treats as a hard error, and nothing in the
//! CPython API references them. Run as: `fix_cimport <input.zig> <output.zig>`.
//!
//! Each target block starts with a line like
//!     const extern_local_wcscpy_s = struct {
//! and ends at the matching `};` at the same brace depth. We replace the whole
//! block with a comment so byte offsets in error messages still roughly line up
//! and the file stays valid Zig.

const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const cwd = std.Io.Dir.cwd();

    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 3) return error.UsageNeedsInputAndOutputPaths;
    const in_path = args[1];
    const out_path = args[2];

    const src = try cwd.readFileAlloc(io, in_path, gpa, .limited(64 * 1024 * 1024));

    var out: std.ArrayList(u8) = .empty;
    var removed: usize = 0;

    var line_it = std.mem.splitScalar(u8, src, '\n');
    var skipping_depth: ?i32 = null;
    while (line_it.next()) |line| {
        if (skipping_depth) |*depth| {
            // Inside a block being removed: track braces until we return to 0.
            for (line) |ch| {
                if (ch == '{') depth.* += 1;
                if (ch == '}') depth.* -= 1;
            }
            if (depth.* <= 0) skipping_depth = null;
            continue;
        }
        if (isTargetStart(line)) {
            removed += 1;
            var depth: i32 = 0;
            for (line) |ch| {
                if (ch == '{') depth += 1;
                if (ch == '}') depth -= 1;
            }
            // A one-line block (`... = struct {};`) is already balanced.
            if (depth > 0) skipping_depth = depth;
            try out.appendSlice(gpa, "// removed by fix_cimport: unused translate-c secure-CRT block\n");
            continue;
        }
        if (isTargetDiscard(line)) {
            // translate-c also emits a `_ = &extern_local_<name>_s;` discard for
            // each block; drop it too, or it dangles once the block is gone.
            try out.appendSlice(gpa, "// removed by fix_cimport: discard of stripped secure-CRT block\n");
            continue;
        }
        try out.appendSlice(gpa, line);
        try out.append(gpa, '\n');
    }
    // splitScalar yields a trailing empty element for a trailing newline; the
    // loop re-added one per line, so trim the doubled final newline.
    if (out.items.len > 0 and out.items[out.items.len - 1] == '\n') _ = out.pop();

    try cwd.writeFile(io, .{ .sub_path = out_path, .data = out.items });
    std.debug.print("fix_cimport: removed {d} unused secure-CRT block(s) -> {s}\n", .{ removed, out_path });
}

/// A line that opens an unused secure-CRT extern block, e.g.
/// `        const extern_local_wcscpy_s = struct {`
fn isTargetStart(line: []const u8) bool {
    const trimmed = std.mem.trim(u8, line, " \t");
    if (!std.mem.startsWith(u8, trimmed, "const extern_local_")) return false;
    // Only the secure (_s) variants are the broken/unused ones we must drop.
    const name_start = "const extern_local_".len;
    const eq = std.mem.indexOfScalar(u8, trimmed[name_start..], ' ') orelse return false;
    const name = trimmed[name_start .. name_start + eq];
    return std.mem.endsWith(u8, name, "_s");
}

/// The discard translate-c pairs with each block, e.g.
/// `    _ = &extern_local___mingw_call_memcpy_s;`. Strip the ones whose
/// referenced name ends in `_s` - exactly the blocks isTargetStart removes - so
/// the discard never outlives its (now-deleted) definition.
fn isTargetDiscard(line: []const u8) bool {
    const trimmed = std.mem.trim(u8, line, " \t");
    const prefix = "_ = &extern_local_";
    if (!std.mem.startsWith(u8, trimmed, prefix)) return false;
    const name = std.mem.trimEnd(u8, trimmed[prefix.len..], ";");
    return std.mem.endsWith(u8, name, "_s");
}
