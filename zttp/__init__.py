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
    Goaway,
    H1Connection,
    H2Connection,
    H3Connection,
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
    generate_self_signed,
    parse_datagram_header,
)
from zttp.config import SessionResumption, TlsCredentials
from zttp.results import CloseInfo, DatagramHeader, SessionTicket
from zttp.settings import H2Settings

Event = (
    Request
    | Response
    | Data
    | EndOfMessage
    | RstStream
    | Goaway
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
    "generate_self_signed",
    "ConnectionClosed",
    "Data",
    "DatagramHeader",
    "EndOfMessage",
    "Event",
    "Goaway",
    "H2Settings",
    "H1Connection",
    "H2Connection",
    "H3Connection",
    "LocalProtocolError",
    "NeedData",
    "Ping",
    "ProtocolError",
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
