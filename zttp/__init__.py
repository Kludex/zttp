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
    build_retry,
    parse_datagram_header,
)
from zttp.config import QuicTransportParameters, SessionResumption, TlsCredentials
from zttp.results import CloseInfo, DatagramHeader, SessionTicket
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
    "LocalProtocolError",
    "NeedData",
    "Ping",
    "ProtocolError",
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
    "build_retry",
    "parse_datagram_header",
]
