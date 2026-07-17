const std = @import("std");
const py = @import("py.zig");
const c = py.c;
const connection = @import("connection_obj.zig");
const events_obj = @import("events_obj.zig");
const exceptions = @import("exceptions.zig");

comptime {
    @export(&PyInit__zttp, .{ .name = "PyInit__zttp", .linkage = .strong });
}

var module_def: c.PyModuleDef = blk: {
    var def = c.PyModuleDef{
        .m_name = "_zttp",
        .m_doc = "zttp: a sans-IO HTTP parser with a Zig core.",
        .m_size = -1,
        .m_methods = &connection.module_methods,
    };
    // 3.15's free-threaded PyModuleDef_Init rejects a zero-initialized def:
    // ob_flags must carry _Py_STATICALLY_ALLOCATED_FLAG or import fails with
    // "invalid PyModuleDef". Mirror C's PyModuleDef_HEAD_INIT, which stamps the
    // flag and the immortal local refcount on Py_GIL_DISABLED builds.
    if (@hasDecl(c, "Py_GIL_DISABLED") and @hasDecl(c, "_Py_STATICALLY_ALLOCATED_FLAG")) {
        def.m_base.ob_base.ob_flags = c._Py_STATICALLY_ALLOCATED_FLAG;
        def.m_base.ob_base.ob_ref_local = c._Py_IMMORTAL_REFCNT_LOCAL;
    }
    break :blk def;
};

fn PyInit__zttp() callconv(.c) ?*c.PyObject {
    const m = c.PyModule_Create(&module_def);
    if (m == null) return null;

    if (!exceptions.register(m) or !events_obj.register(m) or !connection.register(m)) {
        py.decref(m);
        return null;
    }
    py.declareGilNotUsed(m);
    return m;
}
