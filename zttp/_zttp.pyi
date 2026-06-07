"""Type stubs for the Zig-backed `_zttp` extension module."""

from __future__ import annotations

from typing import Final

SERVER: Final[int]
CLIENT: Final[int]

class Request:
    method: bytes
    target: bytes
    http_version: bytes
    headers: list[tuple[bytes, bytes]]

class Response:
    status_code: int
    reason: bytes
    http_version: bytes
    headers: list[tuple[bytes, bytes]]

class Data:
    data: bytes

class EndOfMessage:
    trailers: list[tuple[bytes, bytes]]

class _NeedData: ...
class _ConnectionClosed: ...

NEED_DATA: Final[_NeedData]
ConnectionClosed: Final[_ConnectionClosed]

Event = Request | Response | Data | EndOfMessage | _NeedData | _ConnectionClosed

class ProtocolError(Exception): ...
class RemoteProtocolError(ProtocolError): ...
class LocalProtocolError(ProtocolError): ...

class Connection:
    def __init__(self, role: int) -> None: ...
    def receive_data(self, data: bytes) -> None: ...
    def next_event(self) -> Event: ...
    def start_next_cycle(self) -> None: ...
    def expect_bodyless(self) -> None: ...
    def send_request(
        self, method: bytes, target: bytes, version: bytes, headers: list[tuple[bytes, bytes]]
    ) -> None: ...
    def send_response(
        self,
        version: bytes,
        status: int,
        reason: bytes,
        headers: list[tuple[bytes, bytes]],
        bodyless: bool = ...,
    ) -> None: ...
    def send_data(self, data: bytes) -> None: ...
    def end_message(self, trailers: list[tuple[bytes, bytes]] | None = ...) -> None: ...
    def data_to_send(self) -> bytes: ...
