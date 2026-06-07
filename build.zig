const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Pure-Zig unit tests for the parser core. Defined first so `zig build test`
    // works without any Python configuration.
    const core_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_core_tests = b.addRunArtifact(core_tests);
    const test_step = b.step("test", "Run pure-Zig core unit tests");
    test_step.dependOn(&run_core_tests.step);

    // Python build configuration is discovered by build_ext.sh and passed in as
    // -D options or environment variables. Resolved lazily so the test step
    // above never requires a Python toolchain.
    const py_include = b.option([]const u8, "python-include", "Path to the CPython include dir") orelse
        (b.graph.environ_map.get("ZHTTP_PYTHON_INCLUDE") orelse return);
    const ext_suffix = b.option([]const u8, "ext-suffix", "Extension module suffix") orelse
        (b.graph.environ_map.get("ZHTTP_EXT_SUFFIX") orelse return);

    const core_mod = b.createModule(.{
        .root_source_file = b.path("src/core/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const mod = b.createModule(.{
        .root_source_file = b.path("src/python/module.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addIncludePath(.{ .cwd_relative = py_include });
    mod.addImport("core", core_mod);

    const lib = b.addLibrary(.{
        .name = "_zhttp",
        .root_module = mod,
        .linkage = .dynamic,
    });

    // CPython extensions resolve interpreter symbols at load time. On macOS this
    // requires undefined symbols to be allowed; on Linux they are global.
    if (target.result.os.tag == .macos) {
        lib.linker_allow_shlib_undefined = true;
    }

    // Install the shared object into the python package directory under the name
    // CPython expects so it imports as `zhttp._zhttp`.
    const out_name = b.fmt("_zhttp{s}", .{ext_suffix});
    const install = b.addInstallFileWithDir(lib.getEmittedBin(), .{ .custom = "../zhttp" }, out_name);
    b.getInstallStep().dependOn(&install.step);
}
