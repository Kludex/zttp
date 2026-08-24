from __future__ import annotations

from zttp._zttp import (
    CLIENT,
    CONNECTION_CLOSED,
    HTTP1,
    HTTP2,
    HTTP3,
    NEED_DATA,
    SERVER,
    Connection,
    ConnectionClosed,
    Data,
    EndOfMessage,
    GoAway,
    H1Connection,
    H2Connection,
    H3Connection,
    HeaderBlock,
    LocalProtocolError,
    NeedData,
    Ping,
    ProtocolError,
    RemoteProtocolError,
    Request,
    Response,
    RstStream,
    Settings,
    Stream,
    WindowUpdate,
    parse_datagram_header,
)
from zttp.config import QuicTransportParameters, SessionResumption, TlsCredentials
from zttp.endpoint import ConnectionIDFactory, QuicEndpoint
from zttp.results import CloseInfo, DatagramHeader, LocalConnectionId, OutboundDatagram, SessionTicket
from zttp.settings import H2Settings

Event = (
    Request
    | Response
    | Data
    | EndOfMessage
    | RstStream
    | GoAway
    | Settings
    | Ping
    | WindowUpdate
    | NeedData
    | ConnectionClosed
)

__all__ = [
    "CLIENT",
    "CONNECTION_CLOSED",
    "SERVER",
    "HTTP1",
    "HTTP2",
    "HTTP3",
    "NEED_DATA",
    "CloseInfo",
    "Connection",
    "ConnectionClosed",
    "ConnectionIDFactory",
    "Data",
    "DatagramHeader",
    "EndOfMessage",
    "Event",
    "GoAway",
    "HeaderBlock",
    "H2Settings",
    "H1Connection",
    "H2Connection",
    "H3Connection",
    "LocalConnectionId",
    "LocalProtocolError",
    "OutboundDatagram",
    "NeedData",
    "Ping",
    "ProtocolError",
    "QuicEndpoint",
    "QuicTransportParameters",
    "RemoteProtocolError",
    "Request",
    "Response",
    "RstStream",
    "SessionResumption",
    "SessionTicket",
    "Settings",
    "Stream",
    "TlsCredentials",
    "WindowUpdate",
    "parse_datagram_header",
]
