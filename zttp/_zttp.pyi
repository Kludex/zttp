"""Type stubs for the Zig-backed `_zttp` extension module."""

from __future__ import annotations

from typing import Final

SERVER: Final[int]
CLIENT: Final[int]
HTTP1: Final[int]
HTTP2: Final[int]
HTTP3: Final[int]

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

class Connection:
    def __init__(self, role: int, protocol: int = ...) -> None: ...
    def receive_data(self, data: bytes) -> None: ...
    def receive_datagram(self, datagram: bytes) -> None: ...
    def next_event(self) -> Event: ...
    def start_next_cycle(self) -> None: ...
    def send_request(
        self, method: bytes, target: bytes, version: bytes, headers: list[tuple[bytes, bytes]]
    ) -> None: ...
    def send_response(
        self,
        version: bytes,
        status: int,
        reason: bytes,
        headers: list[tuple[bytes, bytes]],
    ) -> None: ...
    def send_data(self, data: bytes) -> None: ...
    def end_message(self, trailers: list[tuple[bytes, bytes]] | None = ...) -> None: ...
    def data_to_send(self) -> bytes: ...
    def should_close(self) -> bool: ...
    def upgrade(self) -> bytes | None: ...
