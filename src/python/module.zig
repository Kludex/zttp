const std = @import("std");
const py = @import("py.zig");
const c = py.c;
const connection = @import("connection_obj.zig");
const events_obj = @import("events_obj.zig");
const exceptions = @import("exceptions.zig");

comptime {
    @export(&PyInit__zttp, .{ .name = "PyInit__zttp", .linkage = .strong });
}

var module_def = c.PyModuleDef{
    .m_name = "_zttp",
    .m_doc = "zttp: a sans-IO HTTP parser with a Zig core.",
    .m_size = -1,
    .m_methods = null,
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
