/* The single C entry point translated into Zig for the CPython C-API. Kept as a
 * real header (translated by build.zig via addTranslateC) rather than an inline
 * @cImport so the generated Zig can be patched: Zig 0.16's translate-c emits the
 * MSVC secure-CRT `_s` forwarders as unused local constants and then rejects
 * them. build.zig strips those before compiling. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
