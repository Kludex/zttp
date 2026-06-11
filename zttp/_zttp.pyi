"""Type stubs for the Zig-backed `_zttp` extension module."""

from __future__ import annotations

from typing import Final, Literal, overload

from typing_extensions import TypedDict

SERVER: Final[int]
CLIENT: Final[int]
# Literal-typed so Connection(role, HTTP2) selects the H2Connection __new__ overload.
HTTP1: Final = 1
HTTP2: Final = 2
HTTP3: Final = 3

class Limits(TypedDict, total=False):
    """Overrides for the DoS bounds, passed to a Connection as `limits=`.

    One dict spans both protocols: keys not relevant to the constructed protocol
    are ignored, so the same dict works regardless of protocol. An unknown key
    raises ValueError. Omitted keys keep the secure default. `max_buffer` applies
    to both protocols.
    """

    # HTTP/1.1
    max_line: int
    max_headers: int
    max_header_bytes: int
    max_trailers: int
    max_trailer_bytes: int
    strict_crlf: bool
    # Both protocols
    max_buffer: int
    # HTTP/2
    max_concurrent_streams: int
    max_header_list_size: int
    header_table_size: int
    max_frame_size: int
    max_field_block_bytes: int
    max_continuation_frames: int
    max_streams: int
    max_stream_resets: int

class Request:
    method: bytes
    target: bytes
    path: bytes
    query: bytes
    http_version: bytes
    headers: list[tuple[bytes, bytes]]
    stream_id: int
    expect_continue: bool

class Response:
    status_code: int
    reason: bytes
    http_version: bytes
    headers: list[tuple[bytes, bytes]]
    stream_id: int

class Data:
    data: bytes
    stream_id: int

class EndOfMessage:
    trailers: list[tuple[bytes, bytes]]
    stream_id: int

class RstStream:
    stream_id: int
    error_code: int

class Goaway:
    last_stream_id: int
    error_code: int
    debug: bytes

class Settings:
    params: list[tuple[int, int]]

class Ping:
    ack: bool
    data: bytes

class WindowUpdate:
    stream_id: int
    increment: int

class NeedData: ...
class ConnectionClosed: ...

NEED_DATA: Final[NeedData]
CONNECTION_CLOSED: Final[ConnectionClosed]

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

class ProtocolError(Exception): ...
class RemoteProtocolError(ProtocolError): ...
class LocalProtocolError(ProtocolError): ...

class Stream:
    stream_id: int
    def send_response(self, status: int, headers: list[tuple[bytes, bytes]] | None = ..., /) -> None: ...
    def send_data(self, data: bytes) -> None: ...
    def end_message(self, trailers: list[tuple[bytes, bytes]] | None = ..., /) -> None: ...

class Connection:
    # The read API, shared by every protocol. Constructing a Connection returns the
    # protocol-specific subtype (H1Connection / H2Connection / H3Connection): the
    # send surface differs, so each is its own type rather than methods that raise
    # at runtime.
    @overload
    def __new__(cls, role: int, protocol: Literal[3], *, limits: Limits | None = ...) -> H3Connection: ...
    @overload
    def __new__(cls, role: int, protocol: Literal[2], *, limits: Limits | None = ...) -> H2Connection: ...
    @overload
    def __new__(cls, role: int, protocol: Literal[1] = ..., *, limits: Limits | None = ...) -> H1Connection: ...
    def receive_data(self, data: bytes) -> None: ...
    def next_event(self) -> Event: ...
    def data_to_send(self) -> bytes: ...

class H1Connection(Connection):
    def __new__(cls, role: int, protocol: Literal[1] = ..., *, limits: Limits | None = ...) -> H1Connection: ...
    def start_next_cycle(self) -> None: ...
    def send_request(
        self, method: bytes, target: bytes, version: bytes, headers: list[tuple[bytes, bytes]]
    ) -> None: ...
    def send_response(self, status: int, headers: list[tuple[bytes, bytes]] | None = ..., /) -> None: ...
    def send_informational(self, status: int, headers: list[tuple[bytes, bytes]] | None = ..., /) -> None: ...
    def send_data(self, data: bytes) -> None: ...
    def end_message(self, trailers: list[tuple[bytes, bytes]] | None = ...) -> None: ...
    def should_close(self) -> bool: ...
    def upgrade(self) -> bytes | None: ...

class H2Connection(Connection):
    def __new__(cls, role: int, protocol: Literal[2] = ..., *, limits: Limits | None = ...) -> H2Connection: ...
    def send_request(
        self, method: bytes, target: bytes, version: bytes, headers: list[tuple[bytes, bytes]]
    ) -> Stream: ...
    def stream(self, stream_id: int, /) -> Stream: ...

class H3Connection(Connection):
    # Server read path only: fed by UDP datagrams rather than a byte stream.
    def __new__(cls, role: int, protocol: Literal[3] = ..., *, limits: Limits | None = ...) -> H3Connection: ...
    def receive_datagram(self, datagram: bytes, /) -> None: ...
