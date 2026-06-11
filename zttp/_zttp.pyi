"""Type stubs for the Zig-backed `_zttp` extension module."""

from __future__ import annotations

from typing import Final, Literal, overload

SERVER: Final[int]
CLIENT: Final[int]
# Literal-typed so Connection(role, HTTP2) selects the H2Connection __new__ overload.
HTTP1: Final = 1
HTTP2: Final = 2
HTTP3: Final = 3

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
    # A borrowed, re-validated handle to one multiplexed stream - the single send
    # surface for both HTTP/2 and HTTP/3. Obtained via conn.stream(stream_id).
    stream_id: int
    send_window: int | None
    pending_bytes: int | None
    def send_response(
        self, status: int, headers: list[tuple[bytes, bytes]] | None = ..., end_stream: bool = ...
    ) -> None: ...
    def send_informational(self, status: int, headers: list[tuple[bytes, bytes]] | None = ..., /) -> None: ...
    def send_data(self, data: bytes) -> None: ...
    def end_message(self, trailers: list[tuple[bytes, bytes]] | None = ..., /) -> None: ...
    def reset(self, error_code: int = ..., /) -> None: ...

class Connection:
    # The read API, shared by every protocol. Constructing a Connection returns the
    # protocol-specific subtype (H1Connection / H2Connection / H3Connection): the
    # send surface differs, so each is its own type rather than methods that raise
    # at runtime.
    @overload
    def __new__(
        cls,
        role: int,
        protocol: Literal[3],
        *,
        certificate: bytes,
        private_key: bytes,
        transport_params: bytes,
        random: bytes,
        ephemeral_seed: bytes,
        alpn: bytes | None = ...,
    ) -> H3Connection: ...
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
    send_window: int
    def initiate_connection(self) -> None: ...
    def send_request(
        self, method: bytes, target: bytes, version: bytes, headers: list[tuple[bytes, bytes]]
    ) -> Stream: ...
    def initiate_upgrade_connection(
        self,
        method: bytes,
        target: bytes,
        headers: list[tuple[bytes, bytes]],
        settings_header: bytes | None = ...,
    ) -> Stream: ...
    def stream(self, stream_id: int, /) -> Stream: ...
    def close(self, error_code: int = ..., last_stream_id: int | None = ..., /) -> None: ...
    def has_pending_send(self) -> bool: ...

class H3Connection(Connection):
    # Fed by UDP datagrams rather than a byte stream. The QUIC handshake is driven
    # from the server credentials passed at construction. `now` is the integrator's
    # monotonic clock. data_to_send returns one bytes per UDP datagram (QUIC datagram
    # boundaries are semantic), not the byte stream the base returns. Sends go through
    # a Stream handle (conn.stream(req.stream_id)), the same surface HTTP/2 uses; a
    # Stream send packetises against the most recent `now`.
    def data_to_send(self) -> list[bytes]: ...  # type: ignore[override]
    def receive_datagram(self, datagram: bytes, now: int = ..., /) -> None: ...
    def initiate_connection(self) -> None: ...
    def shutdown(self, stream_id: int, /) -> None: ...
    def stream(self, stream_id: int, /) -> Stream: ...
    def next_timeout(self) -> int | None: ...
    def handle_timeout(self, now: int, /) -> None: ...
    def is_closed(self) -> bool: ...
    def close_info(self) -> tuple[int, bytes, bool] | None: ...
    def peer_settings(self) -> dict[str, int] | None: ...
