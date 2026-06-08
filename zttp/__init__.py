from __future__ import annotations

from typing import TYPE_CHECKING

from zttp._zttp import (
    CLIENT,
    NEED_DATA,
    SERVER,
    Connection,
    ConnectionClosed,
    Data,
    EndOfMessage,
    LocalProtocolError,
    ProtocolError,
    RemoteProtocolError,
    Request,
    Response,
)

if TYPE_CHECKING:
    # The type checker reads the alias from the extension's stub, where it's a
    # proper union; at runtime it's the value below (a `types.UnionType`), which
    # mypy would otherwise reject in annotation position.
    from zttp._zttp import Event as Event
else:
    Event = Request | Response | Data | EndOfMessage | type(NEED_DATA) | type(ConnectionClosed)

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
    "ProtocolError",
    "RemoteProtocolError",
    "Request",
    "Response",
]
