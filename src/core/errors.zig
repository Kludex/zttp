//! The single error set the parser core can produce. The Python adapter maps
//! each variant onto a concrete exception type; keeping them distinct here lets
//! callers (and tests) discriminate without string matching.

pub const ParseError = error{
    /// The request/status line was malformed (bad method, target, or version).
    InvalidLine,
    /// A header field-name, value, or the field-line structure was malformed.
    InvalidHeader,
    /// Transfer-Encoding and Content-Length disagree, Content-Length is not a
    /// valid number, or duplicate/ambiguous framing was seen. Defends against
    /// request smuggling (RFC 9112 6.1).
    InvalidFraming,
    /// A chunk size, chunk extension, or chunk framing byte was malformed.
    InvalidChunk,
    /// A configured limit was exceeded (header block too large, line too long).
    MessageTooLong,
    /// Bytes arrived in a connection state that cannot accept them (e.g. data
    /// after the message completed on a connection marked to close).
    ProtocolError,
};
