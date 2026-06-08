from __future__ import annotations

from zttp._zttp import (
    CLIENT,
    CONNECTION_CLOSED,
    HTTP1,
    HTTP2,
    NEED_DATA,
    SERVER,
    Connection,
    ConnectionClosed,
    Data,
    EndOfMessage,
    Goaway,
    LocalProtocolError,
    NeedData,
    Ping,
    ProtocolError,
    RemoteProtocolError,
    Request,
    Response,
    RstStream,
    Settings,
    WindowUpdate,
)

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
    "NEED_DATA",
    "Connection",
    "ConnectionClosed",
    "Data",
    "EndOfMessage",
    "Event",
    "Goaway",
    "LocalProtocolError",
    "NeedData",
    "Ping",
    "ProtocolError",
    "RemoteProtocolError",
    "Request",
    "Response",
    "RstStream",
    "Settings",
    "WindowUpdate",
]
