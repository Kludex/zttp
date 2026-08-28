//! Module-level exception types. The core's ParseError variants map onto these
//! so Python callers can catch a meaningful, specific exception.

const py = @import("py.zig");
const c = py.c;
const core = @import("core");
const ParseError = core.errors.ParseError;
const H2Error = core.h2.connection.H2Error;
const QuicError = core.quic.connection.Error;
const H3Error = core.h3.connection.Error;

pub var ProtocolError: py.Object = null;
pub var RemoteProtocolError: py.Object = null;
pub var LocalProtocolError: py.Object = null;

pub fn register(module: py.Object) bool {
    ProtocolError = py.newException("zttp.ProtocolError", null);
    if (ProtocolError == null) return false;
    // Remote: the peer sent something malformed. Local: we were misused.
    RemoteProtocolError = py.newException("zttp.RemoteProtocolError", ProtocolError);
    if (RemoteProtocolError == null) return false;
    LocalProtocolError = py.newException("zttp.LocalProtocolError", ProtocolError);
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

/// Map an HTTP/2 connection error onto RemoteProtocolError. Every H2Error is a
/// peer-induced fault (a malformed frame, a flood, a desync), so they are all
/// remote, mirroring raiseParse.
pub fn raiseH2(e: H2Error) py.Object {
    const msg: [*c]const u8 = switch (e) {
        error.ProtocolError => "HTTP/2 protocol error",
        error.FrameSizeError => "HTTP/2 frame size error",
        error.CompressionError => "HPACK compression error",
        error.FlowControlError => "HTTP/2 flow-control error",
        error.MessageTooLong => "message exceeded configured size limit",
        error.EnhanceYourCalm => "HTTP/2 flood detected (enhance your calm)",
    };
    return py.raise(RemoteProtocolError, msg);
}

/// Map a QUIC transport error onto RemoteProtocolError. OutOfMemory becomes a
/// MemoryError; the rest are remote protocol violations (a dropped packet is not
/// surfaced here - the connection swallows it - so it never reaches this).
pub fn raiseQuic(e: QuicError) py.Object {
    const msg: [*c]const u8 = switch (e) {
        error.OutOfMemory => return c.PyErr_NoMemory(),
        error.Dropped => "QUIC packet dropped",
        error.ProtocolViolation => "QUIC protocol violation",
        error.FlowControlError => "QUIC flow-control error",
        error.StreamLimitError => "QUIC stream limit exceeded",
        error.StreamStateError => "QUIC stream-state error",
        error.StreamBufferExceeded => "QUIC stream buffer exceeded",
        error.FinalSizeError => "QUIC final size error",
        error.CryptoError => "QUIC TLS handshake failed (CRYPTO_ERROR)",
        // A send-side backpressure signal the send paths handle (defer the bytes), so
        // it never escapes to here; mapped only to keep the switch exhaustive.
        error.AmplificationLimited => "QUIC anti-amplification limit",
    };
    return py.raise(RemoteProtocolError, msg);
}

/// Map an HTTP/3 connection error onto RemoteProtocolError.
pub fn raiseH3(e: H3Error) py.Object {
    return switch (e) {
        error.OutOfMemory => c.PyErr_NoMemory(),
        error.H3Error => py.raise(RemoteProtocolError, "HTTP/3 protocol error"),
        error.EventQueueFull => py.raise(
            LocalProtocolError,
            "drain pending HTTP/3 events before receiving more data",
        ),
        error.Blocked => py.raise(RemoteProtocolError, "HTTP/3 stream blocked"),
    };
}
