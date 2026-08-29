//! Patch a translate-c output file, removing the unused
//! `const extern_local_<name>_s = struct { ... };` blocks that Zig 0.16's
//! translate-c emits for the MSVC secure-CRT functions (wcscat_s, wcscpy_s,
//! ...), and restoring dllimport metadata on Windows data declarations.
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
    const dll_import_data = args.len == 4 and std.mem.eql(u8, args[1], "--dll-import-data");
    if ((!dll_import_data and args.len != 3) or (dll_import_data and args.len != 4))
        return error.UsageNeedsInputAndOutputPaths;
    const path_offset: usize = if (dll_import_data) 2 else 1;
    const in_path = args[path_offset];
    const out_path = args[path_offset + 1];

    const src = try cwd.readFileAlloc(io, in_path, gpa, .limited(64 * 1024 * 1024));

    var imported_data = std.StringHashMap(void).init(gpa);
    defer imported_data.deinit();
    if (dll_import_data) {
        var declaration_it = std.mem.splitScalar(u8, src, '\n');
        while (declaration_it.next()) |line| {
            const declaration = externVariable(line) orelse continue;
            if (!isPythonData(declaration.name)) continue;
            try imported_data.put(declaration.name, {});
        }
    }

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
        if (dll_import_data) {
            if (externVariable(line)) |declaration| {
                if (imported_data.contains(declaration.name)) {
                    const replacement = try std.fmt.allocPrint(
                        gpa,
                        "pub inline fn {s}() *{s} {{ return @extern(*{s}, .{{ .name = \"{s}\", .is_dll_import = true }}); }}",
                        .{ declaration.name, declaration.type, declaration.type, declaration.name },
                    );
                    try out.appendSlice(gpa, replacement);
                    try out.append(gpa, '\n');
                    continue;
                }
            }
            try appendImportedDataLine(gpa, &out, line, &imported_data);
        } else {
            try out.appendSlice(gpa, line);
        }
        try out.append(gpa, '\n');
    }
    // splitScalar yields a trailing empty element for a trailing newline; the
    // loop re-added one per line, so trim the doubled final newline.
    if (out.items.len > 0 and out.items[out.items.len - 1] == '\n') _ = out.pop();

    try cwd.writeFile(io, .{ .sub_path = out_path, .data = out.items });
    std.debug.print(
        "fix_cimport: removed {d} unused secure-CRT block(s), patched {d} DLL import(s) -> {s}\n",
        .{ removed, imported_data.count(), out_path },
    );
}

const ExternVariable = struct {
    name: []const u8,
    type: []const u8,
};

fn externVariable(line: []const u8) ?ExternVariable {
    const trimmed = std.mem.trim(u8, line, " \t");
    const prefix = "pub extern var ";
    if (!std.mem.startsWith(u8, trimmed, prefix) or !std.mem.endsWith(u8, trimmed, ";")) return null;
    const colon = std.mem.indexOfScalarPos(u8, trimmed, prefix.len, ':') orelse return null;
    const name = std.mem.trim(u8, trimmed[prefix.len..colon], " \t");
    const variable_type = std.mem.trim(u8, trimmed[colon + 1 .. trimmed.len - 1], " \t");
    if (name.len == 0 or variable_type.len == 0) return null;
    return .{ .name = name, .type = variable_type };
}

fn appendImportedDataLine(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    line: []const u8,
    imported_data: *const std.StringHashMap(void),
) !void {
    var index: usize = 0;
    while (index < line.len) {
        if (line[index] == '"') {
            const start = index;
            index += 1;
            while (index < line.len) : (index += 1) {
                if (line[index] == '\\') {
                    index += 1;
                } else if (line[index] == '"') {
                    index += 1;
                    break;
                }
            }
            try out.appendSlice(gpa, line[start..index]);
            continue;
        }
        if (index + 1 < line.len and line[index] == '/' and line[index + 1] == '/') {
            try out.appendSlice(gpa, line[index..]);
            return;
        }
        if (isIdentifierStart(line[index])) {
            const start = index;
            index += 1;
            while (index < line.len and isIdentifierContinue(line[index])) : (index += 1) {}
            const identifier = line[start..index];
            try out.appendSlice(gpa, identifier);
            if (imported_data.contains(identifier)) try out.appendSlice(gpa, "().*");
            continue;
        }
        try out.append(gpa, line[index]);
        index += 1;
    }
}

fn isIdentifierStart(byte: u8) bool {
    return byte == '_' or std.ascii.isAlphabetic(byte);
}

fn isIdentifierContinue(byte: u8) bool {
    return isIdentifierStart(byte) or std.ascii.isDigit(byte);
}

fn isPythonData(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "Py") or std.mem.startsWith(u8, name, "_Py");
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
