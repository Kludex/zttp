/* The single C entry point translated into Zig for the CPython C-API. Kept as a
 * real header (translated by build.zig via addTranslateC) rather than an inline
 * @cImport so the generated Zig can be patched: Zig 0.16's translate-c emits the
 * MSVC secure-CRT `_s` forwarders as unused local constants and then rejects
 * them. build.zig strips those before compiling. */
/* Release-build the translated C-API: C extensions are normally compiled with
 * -DNDEBUG, and without it the translated static inlines (PyList_SET_ITEM,
 * PyTuple_SET_ITEM, ...) carry live assert() branches on the hot path. */
#ifndef NDEBUG
#define NDEBUG 1
#endif
#define PY_SSIZE_T_CLEAN
/* 3.15's free-threaded object.h wraps ob_tid in
 * _Py_ALIGNED_DEF(_PyObject_MIN_ALIGNMENT, uintptr_t), whose C11 expansion is
 * `_Alignas(4) _Alignas(uintptr_t)`. Zig's translate-c rejects the first
 * specifier as under-aligned instead of combining them, so pre-define the macro
 * (pymacro.h honors an existing definition) with CPython's own GCC/Clang
 * fallback: `aligned` never decreases alignment, giving the same layout. */
#ifndef _Py_ALIGNED_DEF
#define _Py_ALIGNED_DEF(N, T) __attribute__((aligned(N))) T
#endif
#if defined(_WIN32) && defined(_M_ARM64)
/* Skip MSVC extensions and ARM intrinsics unsupported by translate-c. */
#define __pragma(...)
#define __ptr32
#define __ptr64
#define _M_CEE
#include <wchar.h>
#undef _M_CEE
#include <stdint.h>
#undef UINT32_MAX
#define UINT32_MAX 0xffffffffU
#endif
#include <Python.h>
/* The Py_T_* / Py_READONLY member-def constants are 3.12+. On 3.10/3.11 the
 * equivalents (T_OBJECT_EX / T_BOOL / READONLY) live in structmember.h, which
 * Python.h does not pull in. Include it so both spellings are visible; py.zig
 * picks whichever the running interpreter's headers provide. */
#include <structmember.h>
