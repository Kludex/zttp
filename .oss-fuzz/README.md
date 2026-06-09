# OSS-Fuzz integration

Files for continuous fuzzing on [OSS-Fuzz](https://github.com/google/oss-fuzz),
Google's free service that runs the fuzz target around the clock and files bugs.

`project.yaml`, `Dockerfile`, and `build.sh` go into `projects/zttp/` in the
OSS-Fuzz repo. They are kept here so they version with the code; copy them over
when submitting.

## Submitting

1. Confirm `zttp` clears the acceptance bar (significant user base or critical
   infrastructure - being a dependency of an accepted project, e.g. uvicorn, is
   the strongest case).
2. Fork `google/oss-fuzz`, copy these three files into `projects/zttp/`, and set
   `primary_contact` to a project committer's Google-linked email.
3. Validate locally before opening the PR:

   ```sh
   python infra/helper.py build_image zttp
   python infra/helper.py build_fuzzers --sanitizer address zttp
   python infra/helper.py check_build zttp
   python infra/helper.py run_fuzzer zttp zttp_fuzz_reader
   ```

## How the build works

`build.sh` runs `zig build fuzz-obj` to emit the coverage-instrumented Zig
object, then compiles `fuzz/target.c` (no coverage of its own) and links it
against `$LIB_FUZZING_ENGINE`. See `fuzz/README.md` for why the C shim is needed
to bridge Zig's SanitizerCoverage to the engine.

The Zig object is built `single_threaded` with stack-check off so the C
toolchain's final link resolves cleanly (no thread-local relocation overflow, no
`__zig_probe_stack`); the link uses `lld` to handle Zig's DWARF.
