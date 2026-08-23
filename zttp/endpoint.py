from __future__ import annotations

import secrets
from typing import cast

from typing_extensions import Protocol

from zttp._retry import _RetryTokenCodec
from zttp._zttp import (
    HTTP3,
    SERVER,
    Connection,
    H3Connection,
    RemoteProtocolError,
    _build_retry,
    parse_datagram_header,
)
from zttp.config import QuicTransportParameters, SessionResumption, TlsCredentials


class ConnectionIdFactory(Protocol):
    """Create an unpredictable QUIC connection ID of the requested length."""

    def __call__(self, length: int) -> bytes: ...  # pragma: no cover - typing contract


def _random_connection_id(length: int) -> bytes:
    return secrets.token_bytes(length)


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
        retry_secret: bytes | None = None,
        retry_token_ttl: int = 10_000_000,
        connection_id_length: int = 16,
        connection_id_factory: ConnectionIdFactory = _random_connection_id,
        max_connections: int = 1024,
    ) -> None:
        if connection_id_length < 8 or connection_id_length > 20:
            raise ValueError("connection_id_length must be 8..20")
        if max_connections <= 0:
            raise ValueError("max_connections must be positive")
        if retry_secret is not None and not retry:
            raise ValueError("retry_secret requires retry=True")
        self._credentials = credentials
        self._transport_params = transport_params
        self._alpn = alpn
        self._resumption = resumption
        self._connection_id_length = connection_id_length
        self._connection_id_factory = connection_id_factory
        self._max_connections = max_connections
        self._token_codec = (
            _RetryTokenCodec(retry_secret if retry_secret is not None else secrets.token_bytes(32), retry_token_ttl)
            if retry
            else None
        )
        self._long_routes: dict[bytes, H3Connection] = {}
        self._short_routes: dict[bytes, H3Connection] = {}
        self._connections: list[H3Connection] = []
        self._outgoing: list[tuple[bytes, bytes]] = []

    def receive_datagram(self, datagram: bytes, peer_address: bytes, now: int = 0) -> H3Connection | None:
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
            connection = self._long_routes.get(header.destination_connection_id)
        else:
            cid_end = 1 + self._connection_id_length
            connection = self._short_routes.get(datagram[1:cid_end]) if len(datagram) >= cid_end else None

        if connection is not None:
            connection.receive_datagram(datagram, now, peer_address)
            return connection
        if not header.is_initial or len(self._connections) >= self._max_connections:
            return None

        codec = self._token_codec
        if codec is None:
            return self._accept(
                datagram,
                peer_address,
                now,
                header.destination_connection_id,
                self._new_connection_id(),
                None,
            )
        if len(header.destination_connection_id) < 8:
            return None
        if not header.token:
            retry_scid = self._new_connection_id()
            token = codec.create(peer_address, header.destination_connection_id, retry_scid, now)
            packet = _build_retry(
                original_destination_connection_id=header.destination_connection_id,
                client_source_connection_id=header.source_connection_id,
                server_source_connection_id=retry_scid,
                token=token,
            )
            self._outgoing.append((packet, peer_address))
            return None

        context = codec.validate(peer_address, header.token, now)
        if context is None or context.retry_source_connection_id != header.destination_connection_id:
            return None
        return self._accept(
            datagram,
            peer_address,
            now,
            header.destination_connection_id,
            header.destination_connection_id,
            context.original_destination_connection_id,
        )

    def data_to_send(self) -> list[tuple[bytes, bytes]]:
        """Return and clear outbound `(datagram, peer_address)` pairs."""
        outgoing = self._outgoing
        self._outgoing = []
        for connection in self._connections:
            for datagram, peer_address in connection.data_to_send_with_addresses():
                outgoing.append((datagram, cast(bytes, peer_address)))
        return outgoing

    def connections(self) -> tuple[H3Connection, ...]:
        """Return the accepted HTTP/3 connections."""
        return tuple(self._connections)

    def discard(self, connection: H3Connection) -> None:
        """Remove a closed connection and all of its routes."""
        if not any(item is connection for item in self._connections):
            raise ValueError("connection does not belong to this endpoint")
        self._connections.remove(connection)
        self._long_routes = {cid: item for cid, item in self._long_routes.items() if item is not connection}
        self._short_routes = {cid: item for cid, item in self._short_routes.items() if item is not connection}

    def next_timeout(self) -> int | None:
        """Return the earliest connection deadline, or `None`."""
        deadlines = [
            deadline for connection in self._connections if (deadline := connection.next_timeout()) is not None
        ]
        return min(deadlines, default=None)

    def handle_timeout(self, now: int) -> None:
        """Fire every connection timer due at `now`."""
        for connection in self._connections:
            deadline = connection.next_timeout()
            if deadline is not None and deadline <= now:
                connection.handle_timeout(now)

    def _new_connection_id(self) -> bytes:
        connection_id = self._connection_id_factory(self._connection_id_length)
        if not isinstance(connection_id, bytes) or len(connection_id) != self._connection_id_length:
            raise ValueError("connection_id_factory must return bytes of connection_id_length")
        if connection_id in self._long_routes or connection_id in self._short_routes:
            raise RuntimeError("connection_id_factory returned an active connection ID")
        return connection_id

    def _accept(
        self,
        datagram: bytes,
        peer_address: bytes,
        now: int,
        initial_dcid: bytes,
        server_cid: bytes,
        original_dcid: bytes | None,
    ) -> H3Connection:
        connection = Connection(
            SERVER,
            HTTP3,
            credentials=self._credentials,
            transport_params=self._transport_params,
            alpn=self._alpn,
            resumption=self._resumption,
        )
        connection._set_endpoint_context(server_cid, original_dcid)
        connection.receive_datagram(datagram, now, peer_address)
        self._connections.append(connection)
        self._long_routes[initial_dcid] = connection
        self._long_routes[server_cid] = connection
        self._short_routes[server_cid] = connection
        return connection
