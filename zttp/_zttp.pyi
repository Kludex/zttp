"""Type stubs for the Zig-backed `_zttp` extension module."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Final, Literal, TypeVar, final, overload

from typing_extensions import Buffer, disjoint_base

from zttp.config import QuicTransportParameters, SessionResumption, TlsCredentials
from zttp.results import CloseInfo, DatagramHeader, LocalConnectionId, OutboundDatagram, SessionTicket

SERVER: Final[Literal[1]] = 1
CLIENT: Final[Literal[2]] = 2
# Literal-typed so Connection(role, HTTP2) selects the H2Connection __new__ overload.
HTTP1: Final[Literal[1]] = 1
HTTP2: Final[Literal[2]] = 2
HTTP3: Final[Literal[3]] = 3

_DefaultT = TypeVar("_DefaultT")

def _build_version_negotiation(client_destination_connection_id: bytes, client_source_connection_id: bytes, /) -> bytes:
    """Build a stateless QUIC Version Negotiation packet for `QuicEndpoint`."""

def _build_retry(
    original_destination_connection_id: bytes,
    client_source_connection_id: bytes,
    server_source_connection_id: bytes,
    token: bytes,
    version: int = ...,
) -> bytes:
    """Build a stateless QUIC v1 Retry packet for `QuicEndpoint`."""

def parse_datagram_header(datagram: Buffer, /) -> DatagramHeader:
    """Parse the routable prefix of a received QUIC datagram (RFC 9000 17).

    Reads no connection state and does not decrypt - it just exposes the form bit,
    version, and connection ids so a server sharing one UDP socket can demultiplex
    datagrams onto per-connection state by destination connection id. A short (1-RTT)
    header does not encode the destination id's length, so `is_long_header` is `False`
    and the ids are empty; match those against the connection ids you already track.
    Raises `RemoteProtocolError` on a truncated or malformed header.
    """

@final
class HeaderBlock:
    """A packed, immutable view of HTTP/1 header fields with lazy access."""

    def __len__(self) -> int: ...
    def __iter__(self) -> Iterator[tuple[bytes, bytes]]: ...
    @overload
    def __getitem__(self, index: int, /) -> tuple[bytes, bytes]: ...
    @overload
    def __getitem__(self, index: slice, /) -> list[tuple[bytes, bytes]]: ...
    @overload
    def get(self, name: bytes, /) -> bytes | None: ...
    @overload
    def get(self, name: bytes, default: _DefaultT, /) -> bytes | _DefaultT:
        """Return the first case-insensitive match, or `default`."""

    def getall(self, name: bytes, /) -> list[bytes]:
        """Return every case-insensitive match in received order."""

    def to_list(self, *, lowercase_names: bool = False) -> list[tuple[bytes, bytes]]:
        """Materialize all fields, optionally with lowercase names."""

@final
class Request:
    """A parsed request head: the request line and all headers.

    Yielded by `next_event()` on a server connection once the head is complete,
    before any body `Data`. Every value is raw `bytes`, exactly as received - zttp
    does not percent-decode the target.

    Attributes:
        method: The request method, e.g. `b"GET"`.
        target: The raw request-target, e.g. `b"/path?q=1"`.
        path: `target` up to the first `?` (not percent-decoded).
        query: `target` after the first `?`, or `b""` (not percent-decoded).
        http_version: The version, e.g. `b"1.1"` (`b"2"` / `b"3"` on HTTP/2 and HTTP/3).
        headers: The header fields as `(name, value)` byte pairs, in received order.
        stream_id: The stream the request arrived on (`0` on HTTP/1.1).
        expect_continue: Whether the client sent `Expect: 100-continue`.
        end_stream: Whether this head also completes the request. When true, no
            `Data` or `EndOfMessage` event follows.
    """

    method: bytes
    target: bytes
    path: bytes
    query: bytes
    http_version: bytes
    headers: list[tuple[bytes, bytes]] | HeaderBlock
    stream_id: int
    expect_continue: bool
    end_stream: bool

@final
class Response:
    """A parsed response head: the status line and all headers.

    Yielded by `next_event()` on a client connection once the head is complete,
    before any body `Data`.

    Attributes:
        status_code: The status code, e.g. `200`.
        reason: The reason phrase, e.g. `b"OK"` (empty on HTTP/2 and HTTP/3).
        http_version: The version, e.g. `b"1.1"`.
        headers: The header fields as `(name, value)` byte pairs, in received order.
        stream_id: The stream the response arrived on (`0` on HTTP/1.1).
    """

    status_code: int
    reason: bytes
    http_version: bytes
    headers: list[tuple[bytes, bytes]] | HeaderBlock
    stream_id: int

@final
class Data:
    """A run of decoded body bytes.

    One or more `Data` events arrive between the head and `EndOfMessage`; chunked
    and content-length bodies both surface the same way, already decoded.

    Attributes:
        data: Owned body bytes that are safe to keep. Qualifying HTTP/1 spans
            reuse the immutable `bytes` supplied to `receive_data()` or
            `receive_event()`; other paths copy out of the parse buffer.
        stream_id: The stream the body belongs to (`0` on HTTP/1.1). For HTTP/3,
            call `connection.consume_data(stream_id, len(data))` after delivering
            these bytes to the application.
    """

    data: bytes
    stream_id: int

@final
class EndOfMessage:
    """The end of a message, with any trailers.

    Attributes:
        trailers: Trailer fields as `(name, value)` byte pairs, or `[]`.
        stream_id: The stream that finished (`0` on HTTP/1.1).
    """

    trailers: list[tuple[bytes, bytes]]
    stream_id: int

@final
class RstStream:
    """An HTTP/2 `RST_STREAM`: the peer abruptly cancelled a stream.

    Attributes:
        stream_id: The cancelled stream.
        error_code: The RFC 9113 error code the peer sent.
    """

    stream_id: int
    error_code: int

@final
class GoAway:
    """An HTTP/2 `GOAWAY`: the peer is shutting the connection down.

    Attributes:
        last_stream_id: The highest stream the peer will still process.
        error_code: The RFC 9113 error code.
        debug: Optional opaque debug data, or `b""`.
    """

    last_stream_id: int
    error_code: int
    debug: bytes

@final
class Settings:
    """An HTTP/2 `SETTINGS` frame from the peer. zttp acks it for you.

    Attributes:
        params: The settings as `(identifier, value)` integer pairs; see
            [`zttp.H2Settings`][zttp.H2Settings] for the identifier names.
    """

    params: list[tuple[int, int]]

@final
class Ping:
    """An HTTP/2 `PING`. zttp replies to a non-ack ping for you.

    Attributes:
        ack: Whether this is an ack of a ping zttp sent.
        data: The 8 opaque payload bytes.
    """

    ack: bool
    data: bytes

@final
class WindowUpdate:
    """An HTTP/2 `WINDOW_UPDATE`: the peer granted more flow-control credit.

    Attributes:
        stream_id: The stream credited, or `0` for the whole connection.
        increment: The number of bytes added to the send window.
    """

    stream_id: int
    increment: int

@final
class NeedData:
    """The type of the [`NEED_DATA`][zttp.NEED_DATA] sentinel."""

@final
class ConnectionClosed:
    """The type of the [`CONNECTION_CLOSED`][zttp.CONNECTION_CLOSED] sentinel."""

NEED_DATA: Final[NeedData]
CONNECTION_CLOSED: Final[ConnectionClosed]

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

class ProtocolError(Exception):
    """Base class for the two protocol errors. Catch this to handle both."""

class RemoteProtocolError(ProtocolError):
    """The peer sent something malformed. Raised by the read API."""

class LocalProtocolError(ProtocolError):
    """You used the send API in a way that cannot produce a valid message."""

@final
class Stream:
    """A borrowed, re-validated handle to one stream - the single send surface for
    HTTP/2 and HTTP/3. Obtained via `conn.stream(stream_id)`.

    Attributes:
        stream_id: The stream this handle sends on.
        send_window: The stream's remaining send window in bytes, or `None`.
        pending_bytes: Body bytes parked waiting for flow-control credit, or `None`.
    """

    stream_id: int
    send_window: int | None
    pending_bytes: int | None
    def send_response(
        self, status: int, headers: list[tuple[bytes, bytes]] | None = ..., end_stream: bool = ...
    ) -> None:
        """Send a response head on this stream. Set `end_stream` for a bodyless response."""

    def send_informational(self, status: int, headers: list[tuple[bytes, bytes]] | None = ..., /) -> None:
        """Send an interim 1xx response; the real response still follows."""

    def send_data(self, data: bytes, /) -> None:
        """Send a run of body bytes, subject to the peer's flow-control window."""

    def end_message(self, trailers: list[tuple[bytes, bytes]] | None = ..., /) -> None:
        """End the message on this stream, with optional trailers."""

    def reset(self, error_code: int = ..., /) -> None:
        """Abruptly cancel this stream (`RST_STREAM` / `STOP_SENDING`)."""

@disjoint_base
class Connection:
    """A factory for a protocol-specific connection, and the shared read API.

    Constructing a `Connection` returns the subtype for the protocol you pick -
    `H1Connection` (the default), `H2Connection`, or `H3Connection` - so the send
    surface matches the wire. `Connection` itself is not instantiable directly and
    cannot be subclassed; only `next_event()` is common to every transport, since
    the read/write *byte* surface is transport-specific (HTTP/1.1 and HTTP/2 are
    byte streams; HTTP/3 rides UDP datagrams).
    """

    @overload
    def __new__(
        cls,
        role: Literal[1],
        protocol: Literal[3],
        *,
        credentials: TlsCredentials | None = ...,
        transport_params: QuicTransportParameters | None = ...,
        random: bytes | None = ...,
        ephemeral_seed: bytes | None = ...,
        alpn: bytes | None = ...,
        resumption: SessionResumption | None = ...,
    ) -> H3Connection: ...
    @overload
    def __new__(
        cls,
        role: Literal[2],
        protocol: Literal[3],
        *,
        transport_params: QuicTransportParameters | None = ...,
        random: bytes | None = ...,
        ephemeral_seed: bytes | None = ...,
        connection_id: bytes | None = ...,
        alpn: bytes | None = ...,
        server_name: bytes | None = ...,
        server_certificate: bytes | None = ...,
        resumption: SessionResumption | None = ...,
        obfuscated_ticket_age: int = ...,
        early_data: bool = ...,
        remembered_transport_params: bytes | None = ...,
        validation_token: bytes | None = ...,
    ) -> H3Connection: ...
    @overload
    def __new__(cls, role: int, protocol: Literal[2]) -> H2Connection: ...
    @overload
    def __new__(cls, role: int, protocol: Literal[1] = ...) -> H1Connection: ...
    def next_event(self) -> Event:
        """Return the next parse event, or the `NEED_DATA` sentinel if more bytes are needed."""

@final
class H1Connection(Connection):
    """An HTTP/1.1 connection: a byte-stream transport with a message-scoped API."""

    def receive_data(self, data: Buffer, /) -> None:
        """Append a contiguous buffer to the parse buffer (an empty buffer signals EOF)."""

    def receive_event(self, data: Buffer, /) -> Request | Response | Data | EndOfMessage | NeedData | ConnectionClosed:
        """Feed a contiguous buffer and return the first available event, or `NEED_DATA`."""

    def data_to_send(self) -> bytes:
        """Return and clear the bytes queued to send."""

    def start_next_cycle(self) -> None:
        """Reset to read the next message on a kept-alive connection."""

    def send_request(self, method: bytes, target: bytes, version: bytes, headers: list[tuple[bytes, bytes]]) -> None:
        """Serialize a request head (client role)."""

    def send_response(self, status: int, headers: list[tuple[bytes, bytes]] | None = ..., /) -> None:
        """Serialize a response head; the reason phrase is derived from `status` and the version is 1.1."""

    def send_informational(self, status: int, headers: list[tuple[bytes, bytes]] | None = ..., /) -> None:
        """Serialize an interim 1xx response; the real response still follows."""

    def send_data(self, data: bytes, /) -> None:
        """Serialize a run of body bytes (chunk-framed if the head declared `chunked`)."""

    def end_message(self, trailers: list[tuple[bytes, bytes]] | None = ...) -> None:
        """End the outgoing message, with optional trailers (chunked bodies only)."""

    def should_close(self) -> bool:
        """Whether the connection must close after this message (`Connection: close` / HTTP/1.0)."""

    def upgrade(self) -> bytes | None:
        """The request's `Upgrade` token if it asked to upgrade (`Connection: upgrade`), else `None`."""

@final
class H2Connection(Connection):
    """An HTTP/2 connection: many streams multiplexed over one byte stream.

    Attributes:
        send_window: The connection-level send window in bytes (may go negative
            after a `SETTINGS` shrink).
    """

    send_window: int
    def receive_data(self, data: Buffer, /) -> None:
        """Append a contiguous buffer to the parse buffer (an empty buffer signals EOF)."""

    def data_to_send(self) -> bytes:
        """Return and clear the HTTP/2 frames queued to send."""

    def initiate_connection(self) -> None:
        """Emit the connection preface (client preface + SETTINGS, or the server's SETTINGS) now."""

    def send_request(self, method: bytes, target: bytes, version: bytes, headers: list[tuple[bytes, bytes]]) -> Stream:
        """Open a request stream and return its `Stream` (client role)."""

    def initiate_upgrade_connection(
        self,
        method: bytes,
        target: bytes,
        headers: list[tuple[bytes, bytes]],
        settings_header: bytes | None = ...,
    ) -> Stream:
        """Seed an h2c-upgraded connection: replay the parsed HTTP/1.1 request as stream 1."""

    def stream(self, stream_id: int, /) -> Stream:
        """Return the `Stream` handle for `stream_id` - the send surface for that stream."""

    def close(self, error_code: int = ..., last_stream_id: int | None = ..., /) -> None:
        """Send `GOAWAY` to shut the connection down."""

    def has_pending_send(self) -> bool:
        """Whether any stream still has body bytes (or a FIN) parked for the send window."""

@final
class H3Connection(Connection):
    """An HTTP/3 connection: the same streams over a from-scratch QUIC transport.

    Fed UDP datagrams with `receive_datagram` rather than a byte stream, and
    `data_to_send()` returns a datagram per element (QUIC datagram boundaries are
    semantic). Responses go through a `Stream` handle, exactly as on HTTP/2. Server
    credentials default to an ephemeral local identity; `now` is the integrator's
    monotonic clock, in the unit later fed to `handle_timeout`.
    """

    def data_to_send(self) -> list[bytes]:
        """Return and clear the pending outgoing UDP datagrams, one per list element."""

    def consume_data(self, stream_id: int, length: int, /) -> None:
        """Return receive-window credit after the application consumes DATA bytes.

        Reading a `Data` event does not return its payload credit. Call this after
        the application accepts some or all of that event's bytes. Frame overhead
        and non-DATA frames are credited internally.
        """

    def receive_datagram(self, datagram: Buffer, now: int = ..., peer_address: bytes | None = ..., /) -> None:
        """Feed one received UDP datagram. `peer_address` is an opaque key for path validation.

        Drain events regularly. Once 1024 events are pending, this raises
        `LocalProtocolError` until `next_event()` reduces the backlog.
        """

    def data_to_send_with_addresses(self) -> list[OutboundDatagram]:
        """Return queued datagrams with their opaque destination address keys."""

    def _set_endpoint_context(
        self,
        server_connection_id: bytes,
        original_destination_connection_id: bytes | None = ...,
        address_validated: bool = ...,
    ) -> None:
        """Configure endpoint-selected connection IDs before the first Initial."""

    def _endpoint_ready(self) -> bool:
        """Return whether the first Initial was authenticated."""

    def _endpoint_connection_id_generation(self) -> int:
        """Return the active local connection ID generation."""

    def _endpoint_peer_address(self) -> bytes | None:
        """Return the authenticated default peer address."""

    def _endpoint_issue_connection_id(
        self,
        sequence_number: int,
        connection_id: bytes,
        stateless_reset_token: bytes,
        retire_prior_to: int = ...,
        /,
    ) -> None:
        """Queue a connection ID owned by `QuicEndpoint`."""

    def challenge_path(self, peer_address: bytes, data: bytes, /) -> None:
        """Queue a QUIC `PATH_CHALLENGE` to a peer address (`data` must be 8 unpredictable bytes)."""

    def use_peer_connection_id(self, sequence_number: int, /) -> None:
        """Switch outgoing packets to a peer-issued `NEW_CONNECTION_ID` sequence."""

    def local_connection_ids(self) -> list[LocalConnectionId]:
        """Return a snapshot of every active local destination connection ID.

        A newly issued ID appears before `issue_connection_id()` returns. An ID is
        removed after `receive_datagram()` processes the peer's
        `RETIRE_CONNECTION_ID`.
        """

    def issue_connection_id(
        self,
        sequence_number: int,
        connection_id: bytes,
        stateless_reset_token: bytes,
        retire_prior_to: int = ...,
        /,
    ) -> None:
        """Queue a QUIC `NEW_CONNECTION_ID` for a local connection ID."""

    def request_key_update(self) -> None:
        """Advance the QUIC 1-RTT send keys; the next packet carries the new key phase."""

    def initiate_connection(self) -> None:
        """Open the control stream and send `SETTINGS` now, rather than lazily on the first response."""

    def send_request(self, method: bytes, target: bytes, version: bytes, headers: list[tuple[bytes, bytes]]) -> Stream:
        """Open a request stream and return its `Stream` (client role)."""

    def send_session_ticket(
        self,
        ticket: bytes,
        lifetime: int = ...,
        age_add: int = ...,
        nonce: bytes = ...,
        extensions: bytes = ...,
        max_early_data_size: int | None = ...,
        /,
    ) -> bytes | None:
        """Queue a TLS `NewSessionTicket` on a confirmed server connection; returns its PSK when available."""

    def send_new_token(self, token: bytes, /) -> None:
        """Queue a QUIC `NEW_TOKEN` address-validation token (server role)."""

    def session_tickets(self) -> list[SessionTicket]:
        """The TLS session tickets received from the peer, as [`SessionTicket`][zttp.SessionTicket]s."""

    def validation_tokens(self) -> list[bytes]:
        """The `NEW_TOKEN` address-validation tokens received, for reuse on a future connection."""

    def shutdown(self, stream_id: int, /) -> None:
        """Begin a graceful shutdown by sending `GOAWAY` (RFC 9114 5.2)."""

    def close(self, app: bool = ..., error_code: int = ..., reason: bytes = ...) -> None:
        """Send a QUIC `CONNECTION_CLOSE`. `app=True` sends an HTTP/3 application close."""

    def stream(self, stream_id: int, /) -> Stream:
        """Return the `Stream` handle for `stream_id` (the request's `stream_id`)."""

    def next_timeout(self) -> int | None:
        """The next idle/loss/PTO deadline (same clock as `now`), or `None` if no timer is armed."""

    def handle_timeout(self, now: int, /) -> None:
        """Fire the timer at time `now`: close on idle timeout, or re-queue loss probes."""

    def is_closed(self) -> bool:
        """Whether the connection has closed (peer `CONNECTION_CLOSE` or idle timeout)."""

    def idle_timed_out(self) -> bool:
        """Whether the connection was silently closed by the idle timeout (RFC 9000 10.1)."""

    def close_info(self) -> CloseInfo | None:
        """The peer's `CONNECTION_CLOSE` as a [`CloseInfo`][zttp.CloseInfo], or `None`."""

    def peer_settings(self) -> dict[str, int] | None:
        """The peer's HTTP/3 `SETTINGS` as a dict, or `None` until its SETTINGS frame arrives."""

    def goaway_received(self) -> int | None:
        """The id of a `GOAWAY` received from the peer (RFC 9114 5.2), or `None`."""
