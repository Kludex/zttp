//! Module-level exception types. The core's ParseError variants map onto these
//! so Python callers can catch a meaningful, specific exception.

const py = @import("py.zig");
const c = py.c;
const ParseError = @import("core").errors.ParseError;

pub var ProtocolError: py.Object = null;
pub var RemoteProtocolError: py.Object = null;
pub var LocalProtocolError: py.Object = null;

pub fn register(module: py.Object) bool {
    ProtocolError = py.newException("zhttp.ProtocolError", null);
    if (ProtocolError == null) return false;
    // Remote: the peer sent something malformed. Local: we were misused.
    RemoteProtocolError = py.newException("zhttp.RemoteProtocolError", ProtocolError);
    if (RemoteProtocolError == null) return false;
    LocalProtocolError = py.newException("zhttp.LocalProtocolError", ProtocolError);
    if (LocalProtocolError == null) return false;

    _ = c.PyModule_AddObjectRef(module, "ProtocolError", ProtocolError);
    _ = c.PyModule_AddObjectRef(module, "RemoteProtocolError", RemoteProtocolError);
    _ = c.PyModule_AddObjectRef(module, "LocalProtocolError", LocalProtocolError);
    return true;
}

/// Set a RemoteProtocolError matching the parse error and return the error
/// sentinel. All parse failures are the remote peer's fault by construction.
pub fn raiseParse(e: ParseError) py.Object {
    const msg: [*c]const u8 = switch (e) {
        error.InvalidLine => "malformed request/status line",
        error.InvalidHeader => "malformed header field",
        error.InvalidFraming => "ambiguous or conflicting message framing",
        error.InvalidChunk => "malformed chunked encoding",
        error.MessageTooLong => "message exceeded configured size limit",
        error.ProtocolError => "unexpected end of data",
    };
    return py.raise(RemoteProtocolError, msg);
}
