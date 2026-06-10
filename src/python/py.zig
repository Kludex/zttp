//! Ergonomic helpers over the CPython C-API. This is the only place besides the
//! type definitions that touches Python.h. It centralises refcounting, error
//! raising, bytes/list building and type construction so the rest of the
//! adapter reads close to Python.

const std = @import("std");

// The translated CPython C-API. build.zig translates Python.h (via the
// `cimport.h` shim) to a Zig file, strips a couple of broken declarations that
// Zig 0.16's translate-c emits on Windows (unused `extern_local_*_s` secure-CRT
// constants), and wires the result in as the `pyc` module. Using @cImport
// directly is not an option there: the generated unused constants are a hard
// error and @cImport output can't be patched.
pub const c = @import("pyc");

pub const Object = [*c]c.PyObject;
pub const ssize = c.Py_ssize_t;

// -- member-def constants (3.12 renamed these with a Py_ prefix) ---------------
//
// 3.12+ exposes Py_T_OBJECT_EX / Py_T_BOOL / Py_READONLY from Python.h; on
// 3.10/3.11 only the legacy T_OBJECT_EX / T_BOOL / READONLY exist, and only via
// structmember.h (pulled in by cimport.h). Prefer the new spelling, fall back to
// the old one, so the same Zig compiles against every supported interpreter.
pub const T_OBJECT_EX: c_int = if (@hasDecl(c, "Py_T_OBJECT_EX")) c.Py_T_OBJECT_EX else c.T_OBJECT_EX;
pub const T_BOOL: c_int = if (@hasDecl(c, "Py_T_BOOL")) c.Py_T_BOOL else c.T_BOOL;
pub const T_UINT: c_int = if (@hasDecl(c, "Py_T_UINT")) c.Py_T_UINT else c.T_UINT;
pub const READONLY: c_int = if (@hasDecl(c, "Py_READONLY")) c.Py_READONLY else c.READONLY;

// -- reference counting -------------------------------------------------------

// On 3.14+ GIL builds the translated Py_INCREF / Py_DECREF inlines compile to a
// couple of instructions (immortality check + direct ob_refcnt store) inside
// this compilation unit, so the hot path skips the out-of-line libpython call.
// The 3.12/3.13 split ob_refcnt and the free-threaded build's atomic path both
// break under translate-c, so everything else keeps the NULL-safe function
// forms (Py_IncRef / Py_DecRef), which take a plain PyObject* on every version.
const inline_refcount = @hasDecl(c, "Py_INCREF") and !@hasDecl(c, "Py_GIL_DISABLED") and c.PY_VERSION_HEX >= 0x030E0000;

pub inline fn incref(o: anytype) void {
    if (comptime inline_refcount) c.Py_INCREF(@ptrCast(o)) else c.Py_IncRef(@ptrCast(o));
}
pub inline fn decref(o: anytype) void {
    if (comptime inline_refcount) c.Py_DECREF(@ptrCast(o)) else c.Py_DecRef(@ptrCast(o));
}
pub inline fn xdecref(o: anytype) void {
    if (comptime inline_refcount) c.Py_XDECREF(@ptrCast(o)) else c.Py_DecRef(@ptrCast(o));
}
/// Steal a reference into a temporary and decref it (for "use then drop").
pub inline fn clear(slot: *Object) void {
    const tmp = slot.*;
    slot.* = null;
    xdecref(tmp);
}

pub inline fn newRef(o: anytype) Object {
    if (comptime inline_refcount) {
        const p: Object = @ptrCast(o);
        c.Py_INCREF(p);
        return p;
    }
    return c.Py_NewRef(@ptrCast(o));
}

// -- singletons ---------------------------------------------------------------

pub inline fn none() Object {
    return newRef(c.Py_None());
}
pub inline fn boolean(v: bool) Object {
    return newRef(if (v) c.Py_True() else c.Py_False());
}
pub inline fn isNone(o: Object) bool {
    return o == c.Py_None();
}

// -- errors -------------------------------------------------------------------

/// Sentinel returned to CPython on error after PyErr is set.
pub const err: Object = null;

pub fn raise(exc: Object, msg: [*c]const u8) Object {
    c.PyErr_SetString(exc, msg);
    return null;
}
pub fn raiseType(msg: [*c]const u8) Object {
    return raise(c.PyExc_TypeError, msg);
}
pub fn raiseValue(msg: [*c]const u8) Object {
    return raise(c.PyExc_ValueError, msg);
}
pub fn raiseRuntime(msg: [*c]const u8) Object {
    return raise(c.PyExc_RuntimeError, msg);
}
pub fn errOccurred() bool {
    return c.PyErr_Occurred() != null;
}

// -- numbers / strings / bytes ------------------------------------------------

pub fn fromI64(v: i64) Object {
    return c.PyLong_FromLongLong(v);
}
pub fn fromU16(v: u16) Object {
    return c.PyLong_FromUnsignedLong(v);
}
pub fn fromStr(s: []const u8) Object {
    return c.PyUnicode_FromStringAndSize(s.ptr, @intCast(s.len));
}
pub fn fromStrZ(s: [*c]const u8) Object {
    return c.PyUnicode_FromString(s);
}
/// Build an immutable bytes object copying `s`. The core only hands out slices
/// into a buffer it may reuse, so events must copy here to be safe in Python.
pub fn fromBytes(s: []const u8) Object {
    return c.PyBytes_FromStringAndSize(s.ptr, @intCast(s.len));
}

/// Borrow the buffer behind a Python `bytes`/`bytearray`/buffer-protocol object.
/// Returns null and sets a TypeError if `o` is not bytes-like.
pub fn asBytes(o: Object) ?[]const u8 {
    var ptr: [*c]u8 = undefined;
    var len: ssize = undefined;
    if (c.PyBytes_AsStringAndSize(o, @ptrCast(&ptr), &len) != 0) return null;
    return ptr[0..@intCast(len)];
}

// -- containers ---------------------------------------------------------------

pub fn newList(len: ssize) Object {
    return c.PyList_New(len);
}
// SET_ITEM on a fresh, fully-overwritten container is a direct ob_item store -
// the same store the C macros perform. The macros themselves translate
// unreliably (3.10's macro form and PyTuple's flexible-array ob_item both
// defeat translate-c), so the store is written out against the translated
// structs, which are plain declarations on every supported version.
const inline_list_set = @hasDecl(c, "PyListObject");
const inline_tuple_set = @hasDecl(c, "PyTupleObject");

/// Store `item` at `idx`, stealing its reference (PyList_SET_ITEM semantics).
/// Only valid for freshly created, not-yet-shared lists with empty slots.
pub fn listSet(list: Object, idx: ssize, item: Object) void {
    if (comptime inline_list_set) {
        const l: [*c]c.PyListObject = @ptrCast(list);
        l.*.ob_item[@as(usize, @intCast(idx))] = item;
    } else _ = c.PyList_SetItem(list, idx, item);
}
pub fn tupleNew(len: ssize) Object {
    return c.PyTuple_New(len);
}
/// Store `item` at `idx`, stealing its reference (PyTuple_SET_ITEM semantics).
/// Only valid for freshly created, not-yet-shared tuples with empty slots.
pub fn tupleSet(tuple: Object, idx: ssize, item: Object) void {
    if (comptime inline_tuple_set) {
        const t: [*c]c.PyTupleObject = @ptrCast(tuple);
        const items: [*c]Object = @ptrCast(&t.*.ob_item);
        items[@as(usize, @intCast(idx))] = item;
    } else _ = c.PyTuple_SetItem(tuple, idx, item);
}

// -- attribute & call helpers -------------------------------------------------

pub fn getAttr(o: Object, name: [*c]const u8) Object {
    return c.PyObject_GetAttrString(o, name);
}
pub fn callNoArgs(callable: Object) Object {
    return c.PyObject_CallNoArgs(callable);
}
pub fn callOneArg(callable: Object, arg: Object) Object {
    return c.PyObject_CallOneArg(callable, arg);
}

// -- imports ------------------------------------------------------------------

pub fn import(name: [*c]const u8) Object {
    return c.PyImport_ImportModule(name);
}
pub fn importFrom(module: [*c]const u8, attr: [*c]const u8) Object {
    const m = import(module);
    if (m == null) return null;
    defer decref(m);
    return getAttr(m, attr);
}

// -- type construction (heap types via spec/slots) ----------------------------

pub const Slot = c.PyType_Slot;
pub const Spec = c.PyType_Spec;
pub const MethodDef = c.PyMethodDef;
pub const MemberDef = c.PyMemberDef;

pub fn typeFromSpec(spec: *Spec) Object {
    return c.PyType_FromSpec(spec);
}

/// Create a type from `spec` deriving from `base` (a single base type). Uses
/// PyType_FromSpecWithBases (stable API) with a one-tuple of bases. Returns null
/// on failure. The caller owns the returned reference.
pub fn typeFromSpecWithBase(spec: *Spec, base: Object) Object {
    const bases = c.PyTuple_Pack(1, base);
    if (bases == null) return null;
    defer decref(bases);
    return c.PyType_FromSpecWithBases(spec, bases);
}

/// Allocate a new instance of `tp` (a type object) with its memory zeroed by
/// tp_alloc. Returns the new object or null on error.
pub fn allocInstance(tp: Object) Object {
    const type_obj: [*c]c.PyTypeObject = @ptrCast(tp);
    const alloc = type_obj.*.tp_alloc.?;
    return alloc(type_obj, 0);
}

pub fn freeInstance(self: Object) void {
    const tp: [*c]c.PyTypeObject = c.Py_TYPE(self);
    const free = tp.*.tp_free.?;
    free(@ptrCast(self));
}

/// Create a new exception type `module.name` deriving from `base` (or Exception
/// if base is null). Returns a new reference, or null on error.
pub fn newException(name: [*c]const u8, base: Object) Object {
    return c.PyErr_NewException(name, base, null);
}

// -- free threading -----------------------------------------------------------

/// Declare that the module is safe to import without the GIL. On free-threaded
/// builds this keeps the GIL disabled; without it CPython re-enables the GIL at
/// import time. The symbol only exists on 3.13+, so it's a no-op on 3.12.
pub fn declareGilNotUsed(m: Object) void {
    if (@hasDecl(c, "PyUnstable_Module_SetGIL")) {
        _ = c.PyUnstable_Module_SetGIL(m, c.Py_MOD_GIL_NOT_USED);
    }
}

// -- cyclic GC (for container types that hold PyObject references) -------------

pub inline fn gcTrack(o: anytype) void {
    c.PyObject_GC_Track(@ptrCast(o));
}
pub inline fn gcUntrack(o: anytype) void {
    c.PyObject_GC_UnTrack(@ptrCast(o));
}
