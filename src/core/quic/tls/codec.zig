//! The TLS handshake codec entry point: the parse and build surface the QUIC
//! driver imports. Re-exports the pieces so callers depend on one module, not the
//! internal split between wire/extension/client_hello/handshake/flight.

const client_hello = @import("client_hello.zig");
const handshake = @import("handshake.zig");
const flight = @import("flight.zig");
const wire = @import("wire.zig");

pub const Error = wire.Error;

pub const ClientHello = client_hello.ClientHello;
pub const parseClientHello = client_hello.parse;

pub const Message = handshake.Message;
pub const MsgType = handshake.MsgType;
pub const peek = handshake.peek;
pub const finishedBody = handshake.finishedBody;
pub const firstCertificate = handshake.firstCertificate;

pub const Config = flight.Config;
pub const Built = flight.Built;
pub const ClientHelloView = flight.ClientHelloView;
pub const buildServerFlight = flight.build;
