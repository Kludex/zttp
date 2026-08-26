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


def test_quic_endpoint_drains_application_output_without_scanning_idle_connections(initial: bytes) -> None:
    endpoint = zttp.QuicEndpoint(connection_id_factory=lambda length: b"s" * length)
    connection = endpoint.receive_datagram(initial, b"address", 0)
    assert connection is not None
    assert endpoint.data_to_send()
    assert endpoint.next_timeout() is not None

    connection.close(app=False)
    assert endpoint.data_to_send() == []
    assert endpoint.data_to_send(connection)
    assert endpoint.next_timeout() is None


def test_quic_endpoint_does_not_retain_an_unauthenticated_initial(initial: bytes) -> None:
    corrupted = initial[:-1] + bytes((initial[-1] ^ 1,))
    endpoint = zttp.QuicEndpoint(
        connection_id_factory=lambda length: b"s" * length,
        max_connections=1,
    )

    assert endpoint.receive_datagram(corrupted, b"address", 0) is None
    assert endpoint.connections() == []
    assert endpoint.receive_datagram(initial, b"address", 0) is not None


def test_quic_endpoint_drops_an_undersized_initial_before_retry() -> None:
    endpoint = zttp.QuicEndpoint(
        retry=True,
        token_secret=b"s" * 32,
        connection_id_factory=lambda length: b"r" * length,
    )
    datagram = b"\xc0\x00\x00\x00\x01\x08original\x00\x00"

    assert endpoint.receive_datagram(datagram, b"address", 0) is None
    assert endpoint.data_to_send() == []


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


def test_quic_endpoint_updates_connection_timeouts() -> None:
    endpoint = zttp.QuicEndpoint(
        transport_params=zttp.QuicTransportParameters(max_idle_timeout=1),
        connection_id_factory=lambda length: b"s" * length,
    )
    client = zttp.Connection(
        zttp.CLIENT,
        zttp.HTTP3,
        connection_id=b"original",
        server_name=b"localhost",
    )
    initial = client.data_to_send()[0]
    connection = endpoint.receive_datagram(initial, b"address", 1000)
    assert connection is not None
    first_deadline = endpoint.next_timeout()
    assert first_deadline is not None

    client_deadline = client.next_timeout()
    assert client_deadline is not None
    client.handle_timeout(client_deadline)
    assert endpoint.receive_datagram(client.data_to_send()[0], b"address", 2000) is connection
    later_deadline = endpoint.next_timeout()
    assert later_deadline is not None
    assert later_deadline > first_deadline

    client_deadline = client.next_timeout()
    assert client_deadline is not None
    client.handle_timeout(client_deadline)
    assert endpoint.receive_datagram(client.data_to_send()[0], b"address", 500) is connection
    earlier_deadline = endpoint.next_timeout()
    assert earlier_deadline is not None
    assert earlier_deadline < later_deadline
    endpoint.handle_timeout(earlier_deadline)
    assert connection.is_closed()
    assert endpoint.next_timeout() is None


def test_quic_endpoint_orders_connection_timeouts() -> None:
    connection_ids = iter((b"a" * 16, b"b" * 16, b"c" * 16))
    endpoint = zttp.QuicEndpoint(
        transport_params=zttp.QuicTransportParameters(max_idle_timeout=1),
        connection_id_factory=lambda length: next(connection_ids),
    )
    first_client = zttp.Connection(
        zttp.CLIENT,
        zttp.HTTP3,
        connection_id=b"first-id",
        server_name=b"localhost",
    )
    second_client = zttp.Connection(
        zttp.CLIENT,
        zttp.HTTP3,
        connection_id=b"secondid",
        server_name=b"localhost",
    )
    third_client = zttp.Connection(
        zttp.CLIENT,
        zttp.HTTP3,
        connection_id=b"third-id",
        server_name=b"localhost",
    )
    first = endpoint.receive_datagram(first_client.data_to_send()[0], b"first", 2000)
    second_initial = second_client.data_to_send()[0]
    second = endpoint.receive_datagram(second_initial, b"second", 1000)
    third = endpoint.receive_datagram(third_client.data_to_send()[0], b"third", 4000)
    assert first is not None
    assert second is not None
    assert third is not None
    assert endpoint.next_timeout() == 2000
    client_deadline = second_client.next_timeout()
    assert client_deadline is not None
    second_client.handle_timeout(client_deadline)
    assert endpoint.receive_datagram(second_client.data_to_send()[0], b"second", 1500) is second
    assert endpoint.next_timeout() == 2500

    endpoint.discard(second)
    assert endpoint.next_timeout() == 3000
    assert endpoint.connections() == [first, third]


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


def test_quic_endpoint_requires_endpoint_connection_id_issuance(initial: bytes) -> None:
    endpoint = zttp.QuicEndpoint(connection_id_factory=lambda length: b"s" * length)
    connection = endpoint.receive_datagram(initial, b"address", 0)
    assert connection is not None

    with pytest.raises(zttp.LocalProtocolError, match=r"QuicEndpoint\.issue_connection_id"):
        connection.issue_connection_id(1, b"replacement-cid", b"t" * 16)


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
