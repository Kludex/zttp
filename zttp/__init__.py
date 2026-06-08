from __future__ import annotations

from zttp._zttp import (
    CLIENT,
    NEED_DATA,
    SERVER,
    Connection,
    ConnectionClosed,
    Data,
    EndOfMessage,
    LocalProtocolError,
    NeedData,
    ProtocolError,
    RemoteProtocolError,
    Request,
    Response,
)

Event = Request | Response | Data | EndOfMessage | NeedData | ConnectionClosed

__all__ = [
    "CLIENT",
    "SERVER",
    "NEED_DATA",
    "Connection",
    "ConnectionClosed",
    "Data",
    "EndOfMessage",
    "Event",
    "LocalProtocolError",
    "NeedData",
    "ProtocolError",
    "RemoteProtocolError",
    "Request",
    "Response",
]
