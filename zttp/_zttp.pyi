"""Type stubs for the Zig-backed `_zttp` extension module."""

from __future__ import annotations

from typing import Final, Literal, overload

SERVER: Final = 1
CLIENT: Final = 2
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
    # A borrowed, re-validated handle to one stream - the single send surface across
    # every protocol. Obtained via conn.stream(stream_id): a multiplexed stream on
    # HTTP/2 and HTTP/3, or the single in-flight message (stream 0) on HTTP/1.1.
    # send_window / pending_bytes are None on HTTP/1.1 (no per-stream flow control),
    # and reset() raises there (HTTP/1.1 has no per-stream cancel).
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
    # A factory base: constructing a Connection returns the protocol-specific subtype
    # (H1Connection / H2Connection / H3Connection). Only next_event() is common to
    # every transport. The read/write *byte* surface is transport-specific and lives
    # on the subtypes - HTTP/1.1 and HTTP/2 are byte streams (receive_data +
    # data_to_send() -> bytes), HTTP/3 rides UDP datagrams (receive_datagram +
    # data_to_send() -> list[bytes]) - so the base does not promise a surface a given
    # transport cannot honour.
    @overload
    def __new__(
        cls,
        role: Literal[1],
        protocol: Literal[3],
        *,
        certificate: bytes | None = ...,
        private_key: bytes | None = ...,
        transport_params: bytes | None = ...,
        random: bytes | None = ...,
        ephemeral_seed: bytes | None = ...,
        alpn: bytes | None = ...,
        resumption_identity: bytes | None = ...,
        resumption_psk: bytes | None = ...,
    ) -> H3Connection: ...
    @overload
    def __new__(
        cls,
        role: Literal[2],
        protocol: Literal[3],
        *,
        transport_params: bytes | None = ...,
        random: bytes | None = ...,
        ephemeral_seed: bytes | None = ...,
        connection_id: bytes | None = ...,
        alpn: bytes | None = ...,
        server_name: bytes | None = ...,
        resumption_identity: bytes | None = ...,
        resumption_psk: bytes | None = ...,
        obfuscated_ticket_age: int = ...,
        early_data: bool = ...,
        remembered_transport_params: bytes | None = ...,
        validation_token: bytes | None = ...,
    ) -> H3Connection: ...
    @overload
    def __new__(cls, role: int, protocol: Literal[2]) -> H2Connection: ...
    @overload
    def __new__(cls, role: int, protocol: Literal[1] = ...) -> H1Connection: ...
    def next_event(self) -> Event: ...

class H1Connection(Connection):
    def receive_data(self, data: bytes, /) -> None: ...
    def data_to_send(self) -> bytes: ...
    def start_next_cycle(self) -> None: ...
    def send_request(
        self, method: bytes, target: bytes, version: bytes, headers: list[tuple[bytes, bytes]]
    ) -> None: ...
    def send_response(self, status: int, headers: list[tuple[bytes, bytes]] | None = ..., /) -> None: ...
    def send_informational(self, status: int, headers: list[tuple[bytes, bytes]] | None = ..., /) -> None: ...
    def send_data(self, data: bytes) -> None: ...
    def end_message(self, trailers: list[tuple[bytes, bytes]] | None = ...) -> None: ...
    def stream(self, stream_id: int, /) -> Stream: ...
    def should_close(self) -> bool: ...
    def upgrade(self) -> bytes | None: ...

class H2Connection(Connection):
    send_window: int
    def receive_data(self, data: bytes, /) -> None: ...
    def data_to_send(self) -> bytes: ...
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
    # Fed by UDP datagrams rather than a byte stream. Server credentials default
    # to an ephemeral local identity; `alpn` defaults to b"h3" (ALPN is mandatory
    # in QUIC - the parameter overrides the token, e.g. for an interop draft name,
    # it is not an opt-out). `now` is the integrator's
    # monotonic clock. data_to_send returns one bytes per UDP datagram (QUIC datagram
    # boundaries are semantic), rather than the single byte string the H1/H2 stream
    # transports return. Sends go through
    # a Stream handle (conn.stream(req.stream_id)), the same surface HTTP/2 uses; a
    # Stream send packetises against the most recent `now`.
    def data_to_send(self) -> list[bytes]: ...
    def receive_datagram(self, datagram: bytes, now: int = ..., peer_address: bytes | None = ..., /) -> None: ...
    def data_to_send_with_addresses(self) -> list[tuple[bytes, bytes | None]]: ...
    def challenge_path(self, peer_address: bytes, data: bytes, /) -> None: ...
    def use_peer_connection_id(self, sequence_number: int, /) -> None: ...
    def issue_connection_id(
        self,
        sequence_number: int,
        connection_id: bytes,
        stateless_reset_token: bytes,
        retire_prior_to: int = ...,
        /,
    ) -> None: ...
    def request_key_update(self) -> None: ...
    def initiate_connection(self) -> None: ...
    def send_request(
        self, method: bytes, target: bytes, version: bytes, headers: list[tuple[bytes, bytes]]
    ) -> Stream: ...
    def send_session_ticket(
        self,
        ticket: bytes,
        lifetime: int = ...,
        age_add: int = ...,
        nonce: bytes = ...,
        extensions: bytes = ...,
        max_early_data_size: int | None = ...,
        /,
    ) -> bytes | None: ...
    def send_new_token(self, token: bytes, /) -> None: ...
    def session_tickets(self) -> list[tuple[int, int, bytes, bytes, bytes, int | None, bytes | None]]: ...
    def validation_tokens(self) -> list[bytes]: ...
    def shutdown(self, stream_id: int, /) -> None: ...
    def close(self, app: bool = ..., error_code: int = ..., reason: bytes = ...) -> None: ...
    def stream(self, stream_id: int, /) -> Stream: ...
    def next_timeout(self) -> int | None: ...
    def handle_timeout(self, now: int, /) -> None: ...
    def is_closed(self) -> bool: ...
    def idle_timed_out(self) -> bool: ...
    def close_info(self) -> tuple[int, bytes, bool] | None: ...
    def peer_settings(self) -> dict[str, int] | None: ...
    def goaway_received(self) -> int | None: ...
