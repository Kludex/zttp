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
)
from zttp.config import SessionResumption, TlsCredentials, h3_client, h3_server

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
    "Connection",
    "ConnectionClosed",
    "Data",
    "EndOfMessage",
    "Event",
    "Goaway",
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
    "Settings",
    "Stream",
    "TlsCredentials",
    "WindowUpdate",
    "h3_client",
    "h3_server",
]
