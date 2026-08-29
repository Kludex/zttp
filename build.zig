const std = @import("std");

fn defaultTarget(b: *std.Build) std.Target.Query {
    const triple = b.graph.environ_map.get("HATCH_ZIG_TARGET") orelse return .{ .cpu_model = .baseline };
    if (triple.len == 0) return .{ .cpu_model = .baseline };
    return std.Target.Query.parse(.{ .arch_os_abi = triple }) catch @panic("invalid HATCH_ZIG_TARGET");
}

pub fn build(b: *std.Build) void {
    // Wheels must run on CPUs other than the machine that built them. Keep a
    // conservative default while still allowing an explicit -Dcpu override.
    const target = b.standardTargetOptions(.{
        .default_target = defaultTarget(b),
    });
    const optimize = b.standardOptimizeOption(.{});
    // DWARF debug info is ~3 MB per extension (vs ~450 KB of code); shipped
    // wheels don't need it. Keep it for Debug builds.
    const strip = optimize != .Debug;

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

    const fuzz_driver_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("fuzz/target.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    fuzz_driver_tests.root_module.addImport("core", b.createModule(.{
        .root_source_file = b.path("src/core/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    }));
    const run_fuzz_driver_tests = b.addRunArtifact(fuzz_driver_tests);
    const fuzz_step = b.step("fuzz", "Run core property tests and fuzz-driver smoke tests");
    fuzz_step.dependOn(&run_core_tests.step);
    fuzz_step.dependOn(&run_fuzz_driver_tests.step);

    // A coverage-instrumented object exporting the `zttp_fuzz_drive` C ABI. The
    // C shim (fuzz/target.c) owns the libFuzzer entry point and registers this
    // object's sancov counters; the final link is done by the C compiler against
    // `$LIB_FUZZING_ENGINE` (locally via scripts/fuzz-libfuzzer, or an OSS-Fuzz
    // build.sh). ReleaseSafe keeps the parser's safety checks but drops the
    // Debug-mode threaded panic machinery, whose thread-local accesses otherwise
    // overflow 32-bit TLS relocations when OSS-Fuzz links its large binary.
    const fuzz_core = b.createModule(.{
        .root_source_file = b.path("src/core/root.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .link_libc = true,
        .single_threaded = true,
        .stack_check = false,
    });
    const fuzz_obj = b.addObject(.{
        .name = "zttp_fuzz_reader",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fuzz/target.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
            .link_libc = true,
            .fuzz = true,
            // single_threaded drops the thread-local panic/threading machinery
            // whose local-dynamic TLS relocations overflow when the engine links;
            // stack_check avoids Zig's __zig_probe_stack helper, which the C
            // toolchain doing the final link does not provide.
            .single_threaded = true,
            .stack_check = false,
        }),
    });
    // `.fuzz` instruments the whole object, not just its root module, so the
    // imported `core` parser carries sancov coverage too - that is the surface
    // the fuzzer actually explores.
    fuzz_obj.root_module.addImport("core", fuzz_core);
    const install_fuzz = b.addInstallBinFile(fuzz_obj.getEmittedBin(), "zttp_fuzz_reader.o");
    const fuzz_obj_step = b.step("fuzz-obj", "Emit the libFuzzer object (zig-out/bin/zttp_fuzz_reader.o)");
    fuzz_obj_step.dependOn(&install_fuzz.step);

    const stream_benchmark = b.addExecutable(.{
        .name = "quic_stream_benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("benchmarks/quic_stream.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    stream_benchmark.root_module.addImport("quic_stream", b.createModule(.{
        .root_source_file = b.path("src/core/quic/stream.zig"),
        .target = target,
        .optimize = optimize,
    }));
    const run_stream_benchmark = b.addRunArtifact(stream_benchmark);
    const stream_benchmark_step = b.step("bench-stream", "Benchmark QUIC stream buffer compaction");
    stream_benchmark_step.dependOn(&run_stream_benchmark.step);

    // Python build configuration is discovered by the hatch-ziglang hook and
    // passed in as -D options or environment variables. Resolved lazily so the
    // test step above never requires a Python toolchain.
    const py_include = b.option([]const u8, "python-include", "Path to the CPython include dir") orelse
        (b.graph.environ_map.get("HATCH_ZIG_PYTHON_INCLUDE") orelse return);
    const ext_suffix = b.option([]const u8, "ext-suffix", "Extension module suffix") orelse
        (b.graph.environ_map.get("HATCH_ZIG_EXT_SUFFIX") orelse return);
    // Windows only: the directory holding pythonXY.lib (the import library the
    // .pyd must link against). On POSIX, interpreter symbols resolve at load.
    const py_libdir = b.option([]const u8, "python-libdir", "Path to the CPython libs dir (Windows)") orelse
        b.graph.environ_map.get("HATCH_ZIG_PYTHON_LIBDIR");
    // Windows only: the import library to link, e.g. "python314" (no extension).
    const py_lib = b.option([]const u8, "python-lib", "CPython import library name (Windows)") orelse
        b.graph.environ_map.get("HATCH_ZIG_PYTHON_LIB");
    // The free-threaded ABI tag ("cp314t") is carried in the extension suffix -
    // e.g. "_zttp.cp314t-win_amd64.pyd" - which every backend must get right for
    // the module to be importable at all.
    const free_threaded = std.mem.indexOf(u8, ext_suffix, "t-") != null;

    const core_mod = b.createModule(.{
        .root_source_file = b.path("src/core/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = strip,
    });

    // Translate the CPython C-API to Zig from a real header, then patch the
    // result. Zig 0.16's translate-c emits the MSVC secure-CRT `_s` forwarders
    // (wcscat_s/wcscpy_s) as unused local constants and rejects them; @cImport
    // output can't be patched, but a translate-c file artifact can. `fix_cimport`
    // strips those unused blocks; on glibc/macOS there are none and it's a no-op.
    const translate = b.addTranslateC(.{
        .root_source_file = b.path("src/python/cimport.h"),
        .target = target,
        .optimize = optimize,
    });
    translate.addIncludePath(.{ .cwd_relative = py_include });
    // A free-threaded interpreter's headers describe a different ABI (extra
    // PyObject fields, different inline bodies). POSIX pyconfig.h defines
    // Py_GIL_DISABLED itself, but PC/pyconfig.h only ever *tests* it and relies
    // on the build backend to pass it - so on Windows the translation silently
    // targets the GIL ABI unless we define it here.
    if (free_threaded and target.result.os.tag == .windows) translate.defineCMacro("Py_GIL_DISABLED", "1");

    const fixer = b.addExecutable(.{
        .name = "fix_cimport",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/fix_cimport.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const fix = b.addRunArtifact(fixer);
    // Aro drops dllimport from data declarations; restore it before MSVC linking.
    if (target.result.os.tag == .windows and target.result.cpu.arch == .aarch64) fix.addArg("--dll-import-data");
    fix.addFileArg(translate.getOutput());
    // The patched copy fix_cimport writes out, used as the `pyc` module source.
    const pyc_file = fix.addOutputFileArg("cimport.zig");

    const pyc_mod = b.createModule(.{
        .root_source_file = pyc_file,
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = strip,
    });
    pyc_mod.addIncludePath(.{ .cwd_relative = py_include });

    const mod = b.createModule(.{
        .root_source_file = b.path("src/python/module.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = strip,
    });
    mod.addIncludePath(.{ .cwd_relative = py_include });
    mod.addImport("core", core_mod);
    mod.addImport("pyc", pyc_mod);

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
            const libdir = py_libdir orelse @panic("python-libdir / HATCH_ZIG_PYTHON_LIBDIR is required on Windows");
            const libname = py_lib orelse @panic("python-lib / HATCH_ZIG_PYTHON_LIB is required on Windows");
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
