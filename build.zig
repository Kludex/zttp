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

    // The parser-core property test ("fuzz: reader never panics ...") runs as
    // part of `zig build test`; `zig build fuzz` is an alias that runs the same
    // suite, kept as an explicit entry point for the adversarial-input net.
    const fuzz_step = b.step("fuzz", "Run the parser-core adversarial-input property test");
    fuzz_step.dependOn(&run_core_tests.step);

    // Python build configuration is discovered by build_ext.sh and passed in as
    // -D options or environment variables. Resolved lazily so the test step
    // above never requires a Python toolchain.
    const py_include = b.option([]const u8, "python-include", "Path to the CPython include dir") orelse
        (b.graph.environ_map.get("ZTTP_PYTHON_INCLUDE") orelse return);
    const ext_suffix = b.option([]const u8, "ext-suffix", "Extension module suffix") orelse
        (b.graph.environ_map.get("ZTTP_EXT_SUFFIX") orelse return);
    // Windows only: the directory holding pythonXY.lib (the import library the
    // .pyd must link against). On POSIX, interpreter symbols resolve at load.
    const py_libdir = b.option([]const u8, "python-libdir", "Path to the CPython libs dir (Windows)") orelse
        b.graph.environ_map.get("ZTTP_PYTHON_LIBDIR");
    // Windows only: the import library to link, e.g. "python314" (no extension).
    const py_lib = b.option([]const u8, "python-lib", "CPython import library name (Windows)") orelse
        b.graph.environ_map.get("ZTTP_PYTHON_LIB");

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
        .name = "_zttp",
        .root_module = mod,
        .linkage = .dynamic,
    });

    switch (target.result.os.tag) {
        // macOS: interpreter symbols resolve at load time; allow them undefined.
        .macos => lib.linker_allow_shlib_undefined = true,
        // Windows: a .pyd must resolve Py* symbols at link time against the
        // interpreter's import library (pythonXY.lib in the `libs` dir).
        .windows => {
            const libdir = py_libdir orelse @panic("python-libdir / ZTTP_PYTHON_LIBDIR is required on Windows");
            const libname = py_lib orelse @panic("python-lib / ZTTP_PYTHON_LIB is required on Windows");
            mod.addLibraryPath(.{ .cwd_relative = libdir });
            mod.linkSystemLibrary(libname, .{});
        },
        // Linux/BSD: interpreter symbols are global at load; nothing extra.
        else => {},
    }

    // Install the shared object into the python package directory under the name
    // CPython expects so it imports as `zttp._zttp`.
    const out_name = b.fmt("_zttp{s}", .{ext_suffix});
    const install = b.addInstallFileWithDir(lib.getEmittedBin(), .{ .custom = "../zttp" }, out_name);
    b.getInstallStep().dependOn(&install.step);
}
