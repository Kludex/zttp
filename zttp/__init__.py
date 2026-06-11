from __future__ import annotations

from typing import TypedDict

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


class Limits(TypedDict, total=False):
    """Overrides for a Connection's DoS bounds, passed as `limits=`.

    One dict spans both protocols: keys not relevant to the constructed protocol
    are ignored, so the same dict works regardless of protocol. An unknown key
    raises ValueError. Omitted keys keep the secure default. `max_buffer` applies
    to both protocols.
    """

    max_line: int
    max_headers: int
    max_header_bytes: int
    max_trailers: int
    max_trailer_bytes: int
    strict_crlf: bool
    max_buffer: int
    max_concurrent_streams: int
    max_header_list_size: int
    header_table_size: int
    max_frame_size: int
    max_field_block_bytes: int
    max_continuation_frames: int
    max_streams: int
    max_stream_resets: int


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
    "Limits",
    "LocalProtocolError",
    "NeedData",
    "Ping",
    "ProtocolError",
    "RemoteProtocolError",
    "Request",
    "Response",
    "RstStream",
    "Settings",
    "Stream",
    "WindowUpdate",
]
