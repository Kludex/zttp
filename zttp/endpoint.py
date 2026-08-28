from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from typing_extensions import Buffer, Protocol, TypedDict

from zttp._tokens import AddressValidationContext, RetryContext, TokenCodec
from zttp._zttp import (
    HTTP3,
    SERVER,
    Connection,
    H3Connection,
    LocalProtocolError,
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


@dataclass(eq=False)
class _ConnectionState:
    connection: H3Connection
    initial_destination_connection_id: bytes
    peer_address: bytes
    connection_id_generation: int = -1
    connection_ids: set[bytes] = field(default_factory=set)
    timer_deadline: int | None = None
    timer_index: int = -1
    active: bool = True


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
        self._connections: dict[H3Connection, _ConnectionState] = {}
        self._ready: dict[_ConnectionState, None] = {}
        self._timer_dirty: dict[_ConnectionState, None] = {}
        self._timeouts: list[_ConnectionState] = []
        self._outgoing: list[OutboundDatagram] = []

    def receive_datagram(self, datagram: Buffer, peer_address: bytes, now: int) -> H3Connection | None:
        """Route a datagram and return its connection, or `None` when dropped."""
        datagram = bytes(datagram)
        if not datagram:
            return None
        if not datagram[0] & 0x80:
            if not datagram[0] & 0x40:
                return None
            cid_end = 1 + self._connection_id_length
            state = self._short_routes.get(datagram[1:cid_end]) if len(datagram) >= cid_end else None
            return self._receive(state, datagram, peer_address, now) if state is not None else None
        try:
            header = parse_datagram_header(datagram)
        except RemoteProtocolError:
            return None
        state = self._long_routes.get(header.destination_connection_id)
        if state is not None:
            return self._receive(state, datagram, peer_address, now)
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
        if len(datagram) < 1200:
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
        state = self._connection_state(connection)
        connection_id = self._new_connection_id()
        connection._endpoint_issue_connection_id(
            sequence_number,
            connection_id,
            secrets.token_bytes(16),
            retire_prior_to,
        )
        self._sync_routes(state)
        self._mark_ready(state)
        self._mark_timer_dirty(state)
        return connection_id

    def issue_token(self, connection: H3Connection, now: int) -> None:
        """Queue a NEW_TOKEN bound to the connection's current peer address."""
        state = self._connection_state(connection)
        connection.send_new_token(self._token_codec.create_address_token(state.peer_address, now))
        self._mark_ready(state)
        self._mark_timer_dirty(state)

    def data_to_send(self, connection: H3Connection | None = None) -> list[OutboundDatagram]:
        """Drain ready connections, optionally marking `connection` as ready."""
        if connection is not None:
            self._mark_ready(self._connection_state(connection))
        outgoing = self._outgoing
        self._outgoing = []
        ready = list(self._ready)
        self._ready.clear()
        for state in ready:
            outgoing.extend(state.connection.data_to_send_with_addresses())
            self._mark_timer_dirty(state)
        return outgoing

    def connections(self) -> list[H3Connection]:
        """Return the accepted HTTP/3 connections."""
        return list(self._connections)

    def discard(self, connection: H3Connection) -> None:
        """Remove a closed connection and all of its routes."""
        state = self._connection_state(connection)
        del self._connections[connection]
        state.active = False
        self._remove_timeout(state)
        self._ready.pop(state, None)
        self._timer_dirty.pop(state, None)
        for connection_id in state.connection_ids | {state.initial_destination_connection_id}:
            self._long_routes.pop(connection_id, None)
            self._short_routes.pop(connection_id, None)

    def next_timeout(self) -> int | None:
        """Return the earliest connection deadline, or `None`."""
        self._sync_timeouts()
        return self._timeouts[0].timer_deadline if self._timeouts else None

    def handle_timeout(self, now: int) -> None:
        """Fire every connection timer due at `now`."""
        while (deadline := self.next_timeout()) is not None and deadline <= now:
            state = self._timeouts[0]
            self._remove_timeout(state)
            try:
                state.connection.handle_timeout(now)
            finally:
                self._mark_ready(state)
                self._mark_timer_dirty(state)

    def _connection_state(self, connection: H3Connection) -> _ConnectionState:
        state = self._connections.get(connection)
        if state is None:
            raise LocalProtocolError("connection does not belong to this endpoint")
        return state

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
        self._connections[connection] = state
        self._sync_routes(state)
        self._mark_ready(state)
        self._mark_timer_dirty(state)
        return connection

    def _receive(
        self,
        state: _ConnectionState,
        datagram: bytes,
        peer_address: bytes,
        now: int,
    ) -> H3Connection:
        try:
            state.connection.receive_datagram(datagram, now, peer_address)
            authenticated_address = state.connection._endpoint_peer_address()
            if authenticated_address is None:  # pragma: no cover - accepted connections have an authenticated Initial
                raise RuntimeError("endpoint connection has no authenticated peer address")
            state.peer_address = authenticated_address
        finally:
            if state.connection_id_generation != state.connection._endpoint_connection_id_generation():
                self._sync_routes(state)
            self._mark_ready(state)
            self._mark_timer_dirty(state)
        return state.connection

    def _mark_ready(self, state: _ConnectionState) -> None:
        self._ready[state] = None

    def _mark_timer_dirty(self, state: _ConnectionState) -> None:
        self._timer_dirty[state] = None

    def _sync_timeouts(self) -> None:
        dirty = list(self._timer_dirty)
        self._timer_dirty.clear()
        for state in dirty:
            self._schedule_timeout(state)

    def _schedule_timeout(self, state: _ConnectionState) -> None:
        deadline = state.connection.next_timeout() if state.active else None
        if deadline == state.timer_deadline:
            return
        if deadline is None:
            self._remove_timeout(state)
            return
        previous = state.timer_deadline
        state.timer_deadline = deadline
        if state.timer_index < 0:
            state.timer_index = len(self._timeouts)
            self._timeouts.append(state)
            self._sift_timeout_up(state.timer_index)
        elif previous is not None and deadline < previous:
            self._sift_timeout_up(state.timer_index)
        else:
            self._sift_timeout_down(state.timer_index)

    def _remove_timeout(self, state: _ConnectionState) -> None:
        index = state.timer_index
        state.timer_index = -1
        state.timer_deadline = None
        if index < 0:
            return
        last = self._timeouts.pop()
        if index == len(self._timeouts):
            return
        self._timeouts[index] = last
        last.timer_index = index
        self._sift_timeout_up(index)
        self._sift_timeout_down(last.timer_index)

    def _sift_timeout_up(self, index: int) -> None:
        while index > 0:
            parent = (index - 1) // 2
            if self._timeout_before(self._timeouts[parent], self._timeouts[index]):
                return
            self._swap_timeouts(parent, index)
            index = parent

    def _sift_timeout_down(self, index: int) -> None:
        size = len(self._timeouts)
        while (left := 2 * index + 1) < size:
            right = left + 1
            child = (
                right if right < size and self._timeout_before(self._timeouts[right], self._timeouts[left]) else left
            )
            if self._timeout_before(self._timeouts[index], self._timeouts[child]):
                return
            self._swap_timeouts(index, child)
            index = child

    def _swap_timeouts(self, first: int, second: int) -> None:
        self._timeouts[first], self._timeouts[second] = self._timeouts[second], self._timeouts[first]
        self._timeouts[first].timer_index = first
        self._timeouts[second].timer_index = second

    @staticmethod
    def _timeout_before(first: _ConnectionState, second: _ConnectionState) -> bool:
        assert first.timer_deadline is not None
        assert second.timer_deadline is not None
        return first.timer_deadline <= second.timer_deadline

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
        state.connection_id_generation = state.connection._endpoint_connection_id_generation()
        state.connection_ids = connection_ids
