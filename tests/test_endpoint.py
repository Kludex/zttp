from __future__ import annotations

from typing import Any, cast

import pytest

import zttp


@pytest.fixture
def initial() -> bytes:
    connection = zttp.Connection(
        zttp.CLIENT,
        zttp.HTTP3,
        connection_id=b"original",
        server_name=b"localhost",
    )
    return connection.data_to_send()[0]


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"connection_id_length": 7}, "connection_id_length"),
        ({"connection_id_length": 21}, "connection_id_length"),
        ({"max_connections": 0}, "max_connections"),
        ({"token_secret": b"short"}, "token secret must contain at least 32 bytes"),
        ({"token_ttl": 0}, "token_ttl must be positive"),
    ],
)
def test_quic_endpoint_rejects_invalid_configuration(kwargs: dict[str, Any], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        zttp.QuicEndpoint(**kwargs)


def test_quic_endpoint_accepts_without_retry_and_manages_the_connection(initial: bytes) -> None:
    endpoint = zttp.QuicEndpoint(
        transport_params=zttp.QuicTransportParameters(max_idle_timeout=1),
        connection_id_factory=lambda length: b"s" * length,
        max_connections=1,
    )
    server = endpoint.receive_datagram(initial, b"address", 1000)
    assert server is not None
    assert endpoint.receive_datagram(initial, b"address", 1001) is server
    another = zttp.Connection(
        zttp.CLIENT,
        zttp.HTTP3,
        connection_id=b"another!",
        server_name=b"localhost",
    )
    assert endpoint.receive_datagram(another.data_to_send()[0], b"address", 1002) is None
    assert endpoint.receive_datagram(b"", b"address", 1003) is None
    assert endpoint.receive_datagram(b"\x00" + b"x" * 16, b"address", 1004) is None
    assert endpoint.receive_datagram(b"\x40short", b"address", 1005) is None
    assert endpoint.receive_datagram(b"\x40" + b"x" * 16, b"address", 1006) is None
    assert endpoint.receive_datagram(b"\xc0\x00", b"address", 1007) is None

    outgoing = endpoint.data_to_send()
    assert outgoing
    assert all(datagram.peer_address == b"address" for datagram in outgoing)
    deadline = endpoint.next_timeout()
    assert deadline is not None
    endpoint.handle_timeout(deadline - 1)
    assert not server.is_closed()
    endpoint.handle_timeout(deadline)
    assert server.is_closed()

    other = zttp.QuicEndpoint()
    with pytest.raises(zttp.LocalProtocolError, match="does not belong"):
        other.discard(server)
    endpoint.discard(server)
    assert endpoint.connections() == []
    assert endpoint.next_timeout() is None


def test_quic_endpoint_accepts_bytearray_input(initial: bytes) -> None:
    endpoint = zttp.QuicEndpoint(connection_id_factory=lambda length: b"s" * length)

    assert endpoint.receive_datagram(bytearray(initial), b"address", 0) is not None


def test_quic_endpoint_does_not_retain_an_unauthenticated_initial(initial: bytes) -> None:
    corrupted = initial[:-1] + bytes((initial[-1] ^ 1,))
    endpoint = zttp.QuicEndpoint(
        connection_id_factory=lambda length: b"s" * length,
        max_connections=1,
    )

    assert endpoint.receive_datagram(corrupted, b"address", 0) is None
    assert endpoint.connections() == []
    assert endpoint.receive_datagram(initial, b"address", 0) is not None


def test_quic_endpoint_sends_version_negotiation() -> None:
    endpoint = zttp.QuicEndpoint()
    header = b"\xc0\x00\x00\x00\x02\x08original\x04peer"

    assert endpoint.receive_datagram(header, b"address", 0) is None
    assert endpoint.data_to_send() == []
    assert endpoint.receive_datagram(header.ljust(1200, b"\x00"), b"address", 1) is None
    [response] = endpoint.data_to_send()
    header = zttp.parse_datagram_header(response.data)
    assert response.peer_address == b"address"
    assert header.version == 0
    assert header.destination_connection_id == b"peer"
    assert header.source_connection_id == b"original"


def test_quic_endpoint_uses_random_connection_ids_by_default(initial: bytes) -> None:
    endpoint = zttp.QuicEndpoint()
    assert endpoint.receive_datagram(initial, b"address", 0) is not None


@pytest.mark.parametrize(
    "factory",
    [
        cast(zttp.ConnectionIDFactory, lambda length: b"x" * (length - 1)),
        cast(zttp.ConnectionIDFactory, lambda length: "x" * length),
    ],
)
def test_quic_endpoint_validates_generated_connection_ids(factory: zttp.ConnectionIDFactory, initial: bytes) -> None:
    endpoint = zttp.QuicEndpoint(connection_id_factory=factory)
    with pytest.raises(ValueError, match="connection_id_factory"):
        endpoint.receive_datagram(initial, b"address", 0)


def test_quic_endpoint_rejects_an_active_generated_connection_id(initial: bytes) -> None:
    endpoint = zttp.QuicEndpoint(connection_id_factory=lambda length: b"s" * length)
    assert endpoint.receive_datagram(initial, b"address", 0) is not None
    another = zttp.Connection(
        zttp.CLIENT,
        zttp.HTTP3,
        connection_id=b"another!",
        server_name=b"localhost",
    )
    with pytest.raises(RuntimeError, match="active connection ID"):
        endpoint.receive_datagram(another.data_to_send()[0], b"address", 0)


def test_quic_endpoint_rejects_connections_from_another_endpoint() -> None:
    endpoint = zttp.QuicEndpoint()
    connection = zttp.Connection(zttp.SERVER, zttp.HTTP3)
    with pytest.raises(zttp.LocalProtocolError, match="does not belong"):
        endpoint.issue_token(connection, 0)
    with pytest.raises(zttp.LocalProtocolError, match="does not belong"):
        endpoint.issue_connection_id(connection, 1)


def test_quic_endpoint_accepts_an_empty_peer_address(initial: bytes) -> None:
    endpoint = zttp.QuicEndpoint()
    assert endpoint.receive_datagram(initial, b"", 0) is not None


def test_quic_endpoint_limits_retry_address_size(initial: bytes) -> None:
    endpoint = zttp.QuicEndpoint(retry=True, token_secret=b"s" * 32)
    with pytest.raises(ValueError, match="peer_address"):
        endpoint.receive_datagram(initial, b"x" * 257, 0)


def test_quic_endpoint_drops_a_retry_initial_with_a_short_destination_id() -> None:
    endpoint = zttp.QuicEndpoint(retry=True, token_secret=b"s" * 32)
    connection = zttp.Connection(
        zttp.CLIENT,
        zttp.HTTP3,
        connection_id=b"short",
        server_name=b"localhost",
    )
    assert endpoint.receive_datagram(connection.data_to_send()[0], b"address", 0) is None
    assert endpoint.data_to_send() == []
