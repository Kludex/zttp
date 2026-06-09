// Bridges the Zig core's SanitizerCoverage data to a libFuzzer/AFL++ runtime.
//
// Zig 0.16 emits inline-8bit counters into the `__sancov_cntrs` section but -
// unlike clang - never calls the `__sanitizer_cov_8bit_counters_init` hook the
// engine relies on. Zig's own fuzzer finds the section by its linker-generated
// boundary symbols; we do the same and register it, so libFuzzer/AFL++ see the
// parser's coverage instead of running blind. Only the counters drive feedback;
// Zig's `__sancov_pcs1` table uses a one-word-per-PC layout incompatible with
// libFuzzer's two-word `pcs_init`, so we leave it unregistered - PCs only
// improve crash symbolization, which ASan already provides.
//
// `LLVMFuzzerTestOneInput` forwards to `zttp_fuzz_drive`, the C-ABI entry the
// Zig target exports.

#include <stddef.h>
#include <stdint.h>

extern void zttp_fuzz_drive(const uint8_t *data, size_t size);

extern uint8_t __start___sancov_cntrs[];
extern uint8_t __stop___sancov_cntrs[];

void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop);

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    __sanitizer_cov_8bit_counters_init(__start___sancov_cntrs, __stop___sancov_cntrs);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    zttp_fuzz_drive(data, size);
    return 0;
}
