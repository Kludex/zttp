/* The single C entry point translated into Zig for the CPython C-API. Kept as a
 * real header (translated by build.zig via addTranslateC) rather than an inline
 * @cImport so the generated Zig can be patched: Zig 0.16's translate-c emits the
 * MSVC secure-CRT `_s` forwarders as unused local constants and then rejects
 * them. build.zig strips those before compiling. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
/* The Py_T_* / Py_READONLY member-def constants are 3.12+. On 3.10/3.11 the
 * equivalents (T_OBJECT_EX / T_BOOL / READONLY) live in structmember.h, which
 * Python.h does not pull in. Include it so both spellings are visible; py.zig
 * picks whichever the running interpreter's headers provide. */
#include <structmember.h>
