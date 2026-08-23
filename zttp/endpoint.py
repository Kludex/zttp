from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from typing_extensions import Protocol, TypedDict

from zttp._tokens import AddressValidationContext, RetryContext, TokenCodec
from zttp._zttp import (
    HTTP3,
    SERVER,
    Connection,
    H3Connection,
    RemoteProtocolError,
    _build_retry,
    _build_version_negotiation,
    parse_datagram_header,
)
from zttp.config import QuicTransportParameters, SessionResumption, TlsCredentials
from zttp.results import OutboundDatagram


class ConnectionIDFactory(Protocol):
    """Create an unpredictable QUIC connection ID of the requested length."""

    def __call__(self, length: int) -> bytes: ...  # pragma: no cover - typing contract


def _random_connection_id(length: int) -> bytes:
    return secrets.token_bytes(length)


class _AcceptanceParameters(TypedDict):
    datagram: bytes
    peer_address: bytes
    now: int
    initial_destination_connection_id: bytes
    server_connection_id: bytes
    original_destination_connection_id: bytes | None
    address_validated: bool


@dataclass
class _ConnectionState:
    connection: H3Connection
    initial_destination_connection_id: bytes
    peer_address: bytes
    connection_ids: set[bytes] = field(default_factory=set)


class QuicEndpoint:
    """Route server QUIC datagrams without owning a socket or event loop."""

    def __init__(
        self,
        *,
        credentials: TlsCredentials | None = None,
        transport_params: QuicTransportParameters | None = None,
        alpn: bytes | None = None,
        resumption: SessionResumption | None = None,
        retry: bool = False,
        token_secret: bytes | None = None,
        token_ttl: int = 10_000_000,
        connection_id_length: int = 16,
        connection_id_factory: ConnectionIDFactory = _random_connection_id,
        max_connections: int = 1024,
    ) -> None:
        if connection_id_length < 8 or connection_id_length > 20:
            raise ValueError("connection_id_length must be 8..20")
        if max_connections <= 0:
            raise ValueError("max_connections must be positive")
        self._credentials = credentials
        self._transport_params = transport_params
        self._alpn = alpn
        self._resumption = resumption
        self._retry = retry
        self._connection_id_length = connection_id_length
        self._connection_id_factory = connection_id_factory
        self._max_connections = max_connections
        self._token_codec = TokenCodec(token_secret if token_secret is not None else secrets.token_bytes(32), token_ttl)
        self._long_routes: dict[bytes, _ConnectionState] = {}
        self._short_routes: dict[bytes, _ConnectionState] = {}
        self._connections: list[_ConnectionState] = []
        self._outgoing: list[OutboundDatagram] = []

    def receive_datagram(self, datagram: bytes, peer_address: bytes, now: int) -> H3Connection | None:
        """Route a datagram and return its connection, or `None` when dropped."""
        if not peer_address:
            raise ValueError("peer_address must not be empty")
        if now < 0 or now > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("now must fit in an unsigned 64-bit integer")
        try:
            header = parse_datagram_header(datagram)
        except RemoteProtocolError:
            return None
        if header.is_long_header:
            state = self._long_routes.get(header.destination_connection_id)
        else:
            cid_end = 1 + self._connection_id_length
            state = self._short_routes.get(datagram[1:cid_end]) if len(datagram) >= cid_end else None

        if state is not None:
            state.connection.receive_datagram(datagram, now, peer_address)
            state.peer_address = peer_address
            self._sync_routes(state)
            return state.connection
        if header.is_long_header and header.version not in {0, 1}:
            if len(datagram) < 1200:
                return None
            packet = _build_version_negotiation(
                header.destination_connection_id,
                header.source_connection_id,
            )
            self._outgoing.append(OutboundDatagram(packet, peer_address))
            return None
        if not header.is_initial or len(self._connections) >= self._max_connections:
            return None

        context = self._token_codec.validate(peer_address, header.token, now) if header.token else None
        if isinstance(context, AddressValidationContext):
            return self._accept(
                {
                    "datagram": datagram,
                    "peer_address": peer_address,
                    "now": now,
                    "initial_destination_connection_id": header.destination_connection_id,
                    "server_connection_id": self._new_connection_id(),
                    "original_destination_connection_id": None,
                    "address_validated": True,
                }
            )
        if not self._retry:
            return self._accept(
                {
                    "datagram": datagram,
                    "peer_address": peer_address,
                    "now": now,
                    "initial_destination_connection_id": header.destination_connection_id,
                    "server_connection_id": self._new_connection_id(),
                    "original_destination_connection_id": None,
                    "address_validated": False,
                }
            )
        if len(header.destination_connection_id) < 8:
            return None
        if not header.token:
            retry_scid = self._new_connection_id()
            token = self._token_codec.create(peer_address, header.destination_connection_id, retry_scid, now)
            packet = _build_retry(
                original_destination_connection_id=header.destination_connection_id,
                client_source_connection_id=header.source_connection_id,
                server_source_connection_id=retry_scid,
                token=token,
            )
            self._outgoing.append(OutboundDatagram(packet, peer_address))
            return None

        if (
            not isinstance(context, RetryContext)
            or context.retry_source_connection_id != header.destination_connection_id
        ):
            return None
        return self._accept(
            {
                "datagram": datagram,
                "peer_address": peer_address,
                "now": now,
                "initial_destination_connection_id": header.destination_connection_id,
                "server_connection_id": header.destination_connection_id,
                "original_destination_connection_id": context.original_destination_connection_id,
                "address_validated": True,
            }
        )

    def issue_connection_id(
        self,
        connection: H3Connection,
        sequence_number: int,
        retire_prior_to: int = 0,
    ) -> bytes:
        """Issue and route a new connection ID for an accepted connection."""
        state = next((item for item in self._connections if item.connection is connection), None)
        if state is None:
            raise ValueError("connection does not belong to this endpoint")
        connection_id = self._new_connection_id()
        connection.issue_connection_id(sequence_number, connection_id, secrets.token_bytes(16), retire_prior_to)
        self._sync_routes(state)
        return connection_id

    def issue_token(self, connection: H3Connection, now: int) -> None:
        """Queue a NEW_TOKEN bound to the connection's current peer address."""
        if now < 0 or now > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("now must fit in an unsigned 64-bit integer")
        state = next((item for item in self._connections if item.connection is connection), None)
        if state is None:
            raise ValueError("connection does not belong to this endpoint")
        connection.send_new_token(self._token_codec.create_address_token(state.peer_address, now))

    def data_to_send(self) -> list[OutboundDatagram]:
        """Return and clear outbound QUIC datagrams."""
        outgoing = self._outgoing
        self._outgoing = []
        for state in self._connections:
            outgoing.extend(state.connection.data_to_send_with_addresses())
        return outgoing

    def connections(self) -> list[H3Connection]:
        """Return the accepted HTTP/3 connections."""
        return [state.connection for state in self._connections]

    def discard(self, connection: H3Connection) -> None:
        """Remove a closed connection and all of its routes."""
        state = next((item for item in self._connections if item.connection is connection), None)
        if state is None:
            raise ValueError("connection does not belong to this endpoint")
        self._connections.remove(state)
        self._long_routes = {cid: item for cid, item in self._long_routes.items() if item is not state}
        self._short_routes = {cid: item for cid, item in self._short_routes.items() if item is not state}

    def next_timeout(self) -> int | None:
        """Return the earliest connection deadline, or `None`."""
        deadlines = [
            deadline for state in self._connections if (deadline := state.connection.next_timeout()) is not None
        ]
        return min(deadlines, default=None)

    def handle_timeout(self, now: int) -> None:
        """Fire every connection timer due at `now`."""
        for state in self._connections:
            deadline = state.connection.next_timeout()
            if deadline is not None and deadline <= now:
                state.connection.handle_timeout(now)

    def _new_connection_id(self) -> bytes:
        connection_id = self._connection_id_factory(self._connection_id_length)
        if not isinstance(connection_id, bytes) or len(connection_id) != self._connection_id_length:
            raise ValueError("connection_id_factory must return bytes of connection_id_length")
        if connection_id in self._long_routes or connection_id in self._short_routes:
            raise RuntimeError("connection_id_factory returned an active connection ID")
        return connection_id

    def _accept(self, parameters: _AcceptanceParameters) -> H3Connection | None:
        connection = Connection(
            SERVER,
            HTTP3,
            credentials=self._credentials,
            transport_params=self._transport_params,
            alpn=self._alpn,
            resumption=self._resumption,
        )
        connection._set_endpoint_context(
            parameters["server_connection_id"],
            parameters["original_destination_connection_id"],
            parameters["address_validated"],
        )
        connection.receive_datagram(parameters["datagram"], parameters["now"], parameters["peer_address"])
        if not connection._endpoint_ready():
            return None
        state = _ConnectionState(
            connection,
            parameters["initial_destination_connection_id"],
            parameters["peer_address"],
        )
        self._connections.append(state)
        self._sync_routes(state)
        return connection

    def _sync_routes(self, state: _ConnectionState) -> None:
        connection_ids = {item.connection_id for item in state.connection.local_connection_ids()}
        for connection_id in state.connection_ids - connection_ids:
            self._long_routes.pop(connection_id, None)
            self._short_routes.pop(connection_id, None)
        self._long_routes[state.initial_destination_connection_id] = state
        for connection_id in connection_ids - state.connection_ids:
            if len(connection_id) != self._connection_id_length:
                raise RuntimeError(
                    "endpoint connection IDs must use connection_id_length"
                )  # pragma: no cover - caller bypassed issue_connection_id()
            long_route = self._long_routes.get(connection_id)
            short_route = self._short_routes.get(connection_id)
            if (long_route is not None and long_route is not state) or (
                short_route is not None and short_route is not state
            ):
                raise RuntimeError("connection issued an active connection ID")  # pragma: no cover - API bypass
            self._long_routes[connection_id] = state
            self._short_routes[connection_id] = state
        state.connection_ids = connection_ids
