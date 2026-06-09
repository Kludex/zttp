"""Type stubs for the Zig-backed `_zttp` extension module."""

from __future__ import annotations

from typing import Final, Literal, overload

SERVER: Final[int]
CLIENT: Final[int]
BUILD_MODE: Final[str]
# Literal-typed so Connection(role, HTTP2) selects the H2Connection __new__ overload.
HTTP1: Final = 1
HTTP2: Final = 2

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
    # The read API, shared by both protocols. Constructing a Connection returns
    # the protocol-specific subtype (H1Connection / H2Connection): the send surface
    # differs, so each is its own type rather than methods that raise at runtime.
    @overload
    def __new__(cls, role: int, protocol: Literal[2]) -> H2Connection: ...
    @overload
    def __new__(cls, role: int, protocol: Literal[1] = ...) -> H1Connection: ...
    def receive_data(self, data: bytes) -> None: ...
    def next_event(self) -> Event: ...
    def data_to_send(self) -> bytes: ...

class H1Connection(Connection):
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
    def send_request(
        self, method: bytes, target: bytes, version: bytes, headers: list[tuple[bytes, bytes]]
    ) -> Stream: ...
    def stream(self, stream_id: int, /) -> Stream: ...
