from __future__ import annotations

import dataclasses
import pickle

import pytest
from typing_extensions import TypedDict

import zttp

# The deterministic server credentials the Zig handshake tests use (testServerConfig):
# a fixed signing-key seed, ServerHello random, ephemeral seed, and a stub cert. Real
# entropy would be per-connection; these are fixed so the captured client datagrams
# below decrypt reproducibly.
SERVER_PUBLIC_KEY = bytes.fromhex(
    "04"
    "2ca00e33928e5b66cc63a70e91c78f5d9e0db34711f9108778151912d389c5"
    "89c6c886572fd6dad9d01e0b98c5fec3276e9a2e4b89705140f564f7eb65016b95"
)
SERVER_TRANSPORT_PARAMS = (
    b"\x04\x04\x80\x10\x00\x00"  # initial_max_data = 1048576
    b"\x08\x01\x08"  # initial_max_streams_bidi = 8
    b"\x09\x01\x08"  # initial_max_streams_uni = 8
    b"\x06\x04\x80\x04\x00\x00"  # initial_max_stream_data_bidi_remote = 262144
    b"\x07\x04\x80\x04\x00\x00"  # initial_max_stream_data_uni = 262144
)


class ServerConfig(TypedDict):
    credentials: zttp.TlsCredentials
    transport_params: zttp.QuicTransportParameters
    random: bytes
    ephemeral_seed: bytes


class RetryTokenCase(TypedDict):
    token_change: str


class ClientConfig(TypedDict):
    transport_params: zttp.QuicTransportParameters
    random: bytes
    ephemeral_seed: bytes
    connection_id: bytes
    alpn: bytes
    server_name: bytes


class ResumedClientConfig(ClientConfig, total=False):
    resumption: zttp.SessionResumption
    obfuscated_ticket_age: int
    early_data: bool
    remembered_transport_params: bytes


class ResumedServerConfig(ServerConfig, total=False):
    resumption: zttp.SessionResumption


SERVER_CONFIG: ResumedServerConfig = {
    "credentials": zttp.TlsCredentials(certificate=SERVER_PUBLIC_KEY, private_key=b"\x42" * 32),
    "transport_params": zttp.QuicTransportParameters(
        initial_max_data=1048576,
        initial_max_streams_bidi=8,
        initial_max_streams_uni=8,
        initial_max_stream_data_bidi_remote=262144,
        initial_max_stream_data_uni=262144,
    ),
    "random": b"\xab" * 32,
    "ephemeral_seed": b"\x33" * 32,
}

CLIENT_CONFIG: ResumedClientConfig = {
    "transport_params": zttp.QuicTransportParameters(
        initial_max_data=65536,
        initial_max_stream_data_bidi_local=262144,
        initial_max_stream_data_bidi_remote=262144,
        initial_max_stream_data_uni=262144,
        initial_max_streams_bidi=16,
        initial_max_streams_uni=16,
    ),
    "random": b"\x44" * 32,
    "ephemeral_seed": b"\x55" * 32,
    "connection_id": b"\x11\x22\x33\x44",
    "alpn": b"h3",
    "server_name": b"example.test",
}


def _build_client_vectors() -> tuple[bytes, bytes, tuple[bytes, ...]]:
    # Real datagrams produced by the deterministic client against SERVER_CONFIG.
    # The Finished and GET packets are sealed with keys from the actual TLS/QUIC
    # handshake, so the server-only tests below do not forge 1-RTT traffic.
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **CLIENT_CONFIG)
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **SERVER_CONFIG)
    client_hello = client.data_to_send()[0]
    server.receive_datagram(client_hello, 1000)
    for dgram in server.data_to_send():
        client.receive_datagram(dgram, 2000)
    client_finished = client.data_to_send()[1]  # Handshake-space Finished.
    client.send_request(b"GET", b"/", b"3", [(b"host", b"exy")])
    get_request = tuple(client.data_to_send())
    return client_hello, client_finished, get_request


CLIENT_HELLO, CLIENT_FINISHED, GET_REQUEST = _build_client_vectors()


def make_server() -> zttp.H3Connection:
    return zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **SERVER_CONFIG)


def make_client() -> zttp.H3Connection:
    return zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **CLIENT_CONFIG)


def transfer(src: zttp.H3Connection, dst: zttp.H3Connection, now: int) -> list[bytes]:
    datagrams = src.data_to_send()
    for dgram in datagrams:
        dst.receive_datagram(dgram, now)
    return datagrams


def handshake_pair() -> tuple[zttp.H3Connection, zttp.H3Connection]:
    client = make_client()
    server = make_server()
    transfer(client, server, 1000)
    transfer(server, client, 2000)
    transfer(client, server, 3000)
    return client, server


def drain_events(conn: zttp.H3Connection) -> list[object]:
    events: list[object] = []
    while (ev := conn.next_event()) is not zttp.NEED_DATA:
        events.append(ev)
    return events


def obfuscated_ticket_age(age_add: int, issued_at: int, now: int) -> int:
    return ((now - issued_at) // 1000 + age_add) & 0xFFFFFFFF


def test_http3_constant_exists() -> None:
    assert isinstance(zttp.HTTP3, int)
    assert zttp.HTTP3 not in (zttp.HTTP1, zttp.HTTP2)


def test_parse_datagram_header_routes_a_client_initial() -> None:
    client = zttp.Connection(
        zttp.CLIENT, protocol=zttp.HTTP3, server_name=b"localhost", connection_id=b"\xaa\xbb\xcc\xdd"
    )
    initial = client.data_to_send()[0]
    header = zttp.parse_datagram_header(bytearray(initial))
    assert isinstance(header, zttp.DatagramHeader)
    assert header.is_long_header
    assert header.is_initial
    assert header.version == 1
    assert header.destination_connection_id == b"\xaa\xbb\xcc\xdd"
    assert header.token == b""


def test_quic_endpoint_completes_retry_and_routes_the_connection() -> None:
    connection_ids = iter((b"r" * 16, b"n" * 16))
    endpoint = zttp.QuicEndpoint(
        credentials=zttp.TlsCredentials(certificate=SERVER_PUBLIC_KEY, private_key=b"\x42" * 32),
        transport_params=zttp.QuicTransportParameters(
            initial_max_data=1048576,
            initial_max_streams_bidi=8,
            initial_max_streams_uni=8,
            initial_max_stream_data_bidi_remote=262144,
            initial_max_stream_data_uni=262144,
        ),
        retry=True,
        token_secret=b"s" * 32,
        connection_id_factory=lambda length: next(connection_ids),
    )
    config: ResumedClientConfig = CLIENT_CONFIG.copy()
    config["connection_id"] = b"original"
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **config)
    [initial] = client.data_to_send()

    assert endpoint.receive_datagram(initial, b"client-address", 1000) is None
    [retry] = endpoint.data_to_send()
    assert retry.peer_address == b"client-address"
    retry_header = zttp.parse_datagram_header(retry.data)
    assert retry_header.source_connection_id == b"r" * 16

    client.receive_datagram(retry.data, 2000)
    [retried_initial] = client.data_to_send()
    retried_header = zttp.parse_datagram_header(retried_initial)
    assert retried_header.destination_connection_id == b"r" * 16
    assert retried_header.token

    server = endpoint.receive_datagram(retried_initial, b"client-address", 3000)
    assert server is not None
    assert endpoint.connections() == [server]
    for datagram in endpoint.data_to_send():
        assert datagram.peer_address == b"client-address"
        client.receive_datagram(datagram.data, 4000)
    for datagram in client.data_to_send():
        assert endpoint.receive_datagram(datagram, b"client-address", 5000) is server
    for datagram in endpoint.data_to_send():
        client.receive_datagram(datagram.data, 6000)
    client.send_request(b"GET", b"/", b"3", [(b"host", b"example.test")])
    for datagram in client.data_to_send():
        assert endpoint.receive_datagram(datagram, b"client-address", 7000) is server
    assert any(isinstance(event, zttp.Request) for event in drain_events(server))

    replacement_connection_id = endpoint.issue_connection_id(server, 1, retire_prior_to=1)
    assert replacement_connection_id == b"n" * 16
    for datagram in endpoint.data_to_send():
        client.receive_datagram(datagram.data, 8000)
    for datagram in client.data_to_send():
        assert endpoint.receive_datagram(datagram, b"client-address", 9000) is server
    endpoint.data_to_send()

    client.use_peer_connection_id(1)
    client.send_request(b"GET", b"/rotated", b"3", [(b"host", b"example.test")])
    routed = [endpoint.receive_datagram(datagram, b"client-address", 11_000) for datagram in client.data_to_send()]
    assert routed
    assert all(connection is server for connection in routed)

    endpoint.issue_token(server, 12_000)
    for datagram in endpoint.data_to_send():
        client.receive_datagram(datagram.data, 13_000)
    [validation_token] = client.validation_tokens()
    returning_client = zttp.Connection(
        zttp.CLIENT,
        zttp.HTTP3,
        connection_id=b"returning",
        server_name=b"localhost",
        validation_token=validation_token,
    )
    returning_endpoint = zttp.QuicEndpoint(
        retry=True,
        token_secret=b"s" * 32,
        connection_id_factory=lambda length: b"v" * length,
    )
    assert (
        returning_endpoint.receive_datagram(returning_client.data_to_send()[0], b"client-address", 14_000) is not None
    )
    assert endpoint.next_timeout() is not None


@pytest.mark.parametrize(
    "case",
    [
        {"token_change": token_change}
        for token_change in ("address", "expired", "future", "tampered", "short", "destination")
    ],
)
def test_quic_endpoint_rejects_invalid_retry_tokens(case: RetryTokenCase) -> None:
    token_change = case["token_change"]
    endpoint = zttp.QuicEndpoint(
        retry=True,
        token_secret=b"s" * 32,
        token_ttl=10,
        connection_id_factory=lambda length: b"r" * length,
    )
    client = zttp.Connection(
        zttp.CLIENT,
        protocol=zttp.HTTP3,
        connection_id=b"original",
        server_name=b"localhost",
    )
    [initial] = client.data_to_send()
    endpoint.receive_datagram(initial, b"address", 1000)
    [retry] = endpoint.data_to_send()
    client.receive_datagram(retry.data, 1001)
    [retried_initial] = client.data_to_send()
    address = b"other" if token_change == "address" else b"address"
    now = 1011 if token_change == "expired" else 999 if token_change == "future" else 1002
    if token_change == "tampered":
        token = zttp.parse_datagram_header(retried_initial).token
        tampered = token[:-1] + bytes((token[-1] ^ 1,))
        retried_initial = retried_initial.replace(token, tampered, 1)
    elif token_change in {"short", "destination"}:
        token = b"short" if token_change == "short" else zttp.parse_datagram_header(retried_initial).token
        other = zttp.Connection(
            zttp.CLIENT,
            protocol=zttp.HTTP3,
            connection_id=b"different" if token_change == "destination" else b"r" * 16,
            server_name=b"localhost",
            validation_token=token,
        )
        [retried_initial] = other.data_to_send()
    assert endpoint.receive_datagram(retried_initial, address, now) is None
    assert endpoint.connections() == []


def test_parse_datagram_header_reports_a_short_header() -> None:
    header = zttp.parse_datagram_header(b"\x40\x01\x02\x03")  # form bit clear = short header
    assert not header.is_long_header
    assert not header.is_initial
    assert header.destination_connection_id == b""
    assert header.source_connection_id == b""
    assert header.token == b""


def test_parse_datagram_header_rejects_a_malformed_datagram() -> None:
    with pytest.raises(zttp.RemoteProtocolError):
        zttp.parse_datagram_header(b"")
    with pytest.raises(zttp.RemoteProtocolError):
        zttp.parse_datagram_header(b"\xc0\x00")  # long header truncated mid-prefix
    with pytest.raises(zttp.RemoteProtocolError):
        zttp.parse_datagram_header(b"\x00\xaa\xbb")  # short header with the fixed bit clear


def test_parse_datagram_header_does_not_trust_an_unsupported_version() -> None:
    # Type bits 00 resemble an Initial, but only under QUIC v1; an unsupported
    # version must not be reported as one.
    header = zttp.parse_datagram_header(b"\xc0\x0a\x0a\x0a\x0a\x03dst\x00")
    assert header.is_long_header
    assert not header.is_initial
    assert header.version == 0x0A0A0A0A


def test_parse_datagram_header_result_is_frozen() -> None:
    header = zttp.parse_datagram_header(b"\x40\x00")
    with pytest.raises(dataclasses.FrozenInstanceError):
        header.version = 9  # ty: ignore[invalid-assignment]


def test_http3_client_construction_emits_an_initial() -> None:
    conn = make_client()
    assert type(conn) is zttp.H3Connection
    datagrams = conn.data_to_send()
    assert len(datagrams) == 1
    assert len(datagrams[0]) == 1200
    assert datagrams[0][0] & 0x80
    assert conn.data_to_send() == []


def test_http3_client_initial_can_carry_validation_token() -> None:
    config = CLIENT_CONFIG.copy()
    config["connection_id"] = b"\x11\x22\x33\x4d"
    conn = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **config, validation_token=b"validated-earlier")
    [initial] = conn.data_to_send()
    assert len(initial) == 1200
    assert b"validated-earlier" in initial


def test_http3_validation_tokens_starts_empty() -> None:
    conn = make_client()
    assert conn.validation_tokens() == []


def test_http3_validation_token_must_not_be_empty() -> None:
    config = CLIENT_CONFIG.copy()
    with pytest.raises(ValueError):
        zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **config, validation_token=b"")


def test_http3_validation_token_is_client_only() -> None:
    with pytest.raises(ValueError):
        zttp.Connection(  # ty: ignore[no-matching-overload]
            zttp.SERVER, protocol=zttp.HTTP3, **SERVER_CONFIG, validation_token=b"token"
        )


def test_http3_client_defaults_transport_settings_and_connection_id() -> None:
    conn = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, server_name=b"example.test")
    datagrams = conn.data_to_send()
    assert len(datagrams) == 1
    assert len(datagrams[0]) == 1200


def test_http3_default_client_and_server_exchange_request() -> None:
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, server_name=b"example.test")
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3)

    assert transfer(client, server, 1000)
    assert transfer(server, client, 2000)
    assert transfer(client, server, 3000)

    stream = client.send_request(b"GET", b"/default", b"3", [(b"host", b"example.test")])
    stream.end_message()
    assert transfer(client, server, 4000)

    events = drain_events(server)
    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.method == b"GET"
    assert req.path == b"/default"
    assert any(isinstance(e, zttp.EndOfMessage) for e in events)


def test_http3_server_rejects_unverifiable_certificate() -> None:
    config = SERVER_CONFIG.copy()
    config["credentials"] = zttp.TlsCredentials(certificate=b"\xcc" * 48, private_key=b"\x42" * 32)
    with pytest.raises(ValueError, match="leaf certificate must contain a P-256 public key"):
        zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **config)


def test_http3_server_rejects_a_mismatched_private_key_scalar() -> None:
    config = SERVER_CONFIG.copy()
    config["credentials"] = zttp.TlsCredentials(
        certificate=SERVER_PUBLIC_KEY,
        private_key_scalar=b"\x42" * 32,
    )
    with pytest.raises(ValueError, match="leaf certificate public key does not match the signing key"):
        zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **config)


def test_http3_client_server_request_response() -> None:
    client = make_client()
    server = make_server()

    assert transfer(client, server, 1000)  # ClientHello
    assert transfer(server, client, 2000)  # ServerHello + server flight
    assert transfer(client, server, 3000)  # client Finished
    assert transfer(server, client, 4000)  # HANDSHAKE_DONE

    stream = client.send_request(b"GET", b"/from-client?x=1", b"3", [(b"host", b"example.test")])
    assert stream.stream_id == 0
    assert transfer(client, server, 5000)

    events = drain_events(server)
    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.method == b"GET"
    assert req.path == b"/from-client"
    assert req.query == b"x=1"
    assert req.stream_id == 0

    response_stream = server.stream(req.stream_id)
    response_stream.send_informational(103, [(b"link", b"</style.css>; rel=preload")])
    response_stream.send_response(200, [(b"content-length", b"0")])
    response_stream.end_message()
    assert transfer(server, client, 6000)

    response_events = []
    while (ev := client.next_event()) is not zttp.NEED_DATA:
        response_events.append(ev)
    responses = [e for e in response_events if isinstance(e, zttp.Response)]
    assert [r.status_code for r in responses] == [103, 200]
    resp = responses[-1]
    assert resp.http_version == b"3"
    assert resp.stream_id == 0
    assert any(isinstance(e, zttp.EndOfMessage) for e in response_events)


def test_http3_server_can_send_session_ticket() -> None:
    client = make_client()
    server = make_server()

    assert transfer(client, server, 1000)
    assert transfer(server, client, 2000)
    assert transfer(client, server, 3000)
    assert transfer(server, client, 4000)
    assert client.session_tickets() == []

    issued_psk = server.send_session_ticket(
        b"ticket-bytes",
        7200,
        0x01020304,
        b"\xaa\xbb",
        b"\xfa\xce\x00\x00",
        4096,
    )
    assert isinstance(issued_psk, bytes)
    assert len(issued_psk) == 32
    assert transfer(server, client, 5000)
    tickets = client.session_tickets()
    assert len(tickets) == 1
    ticket = tickets[0]
    assert ticket.lifetime == 7200
    assert ticket.age_add == 0x01020304
    assert ticket.nonce == b"\xaa\xbb"
    assert ticket.ticket == b"ticket-bytes"
    assert ticket.extensions == b"\xfa\xce\x00\x00\x00\x2a\x00\x04\x00\x00\x10\x00"
    assert ticket.max_early_data_size == 4096
    assert isinstance(ticket.psk, bytes)
    assert len(ticket.psk) == 32
    assert ticket.psk != b"\x00" * 32
    assert ticket.psk == issued_psk


def test_http3_received_session_ticket_psk_resumes_later_connection() -> None:
    first_client = make_client()
    first_server = make_server()

    assert transfer(first_client, first_server, 1000)
    assert transfer(first_server, first_client, 2000)
    assert transfer(first_client, first_server, 3000)
    assert transfer(first_server, first_client, 4000)

    issued_psk = first_server.send_session_ticket(
        b"ticket-identity",
        7200,
        0x01020304,
        b"\x01",
        b"",
        4096,
    )
    assert isinstance(issued_psk, bytes)
    assert len(issued_psk) == 32
    assert transfer(first_server, first_client, 5000)
    [ticket] = first_client.session_tickets()
    identity, age_add, psk = ticket.ticket, ticket.age_add, ticket.psk
    assert ticket.lifetime == 7200
    assert ticket.age_add == 0x01020304
    assert ticket.nonce == b"\x01"
    assert ticket.max_early_data_size == 4096
    assert isinstance(psk, bytes)
    assert len(psk) == 32
    assert psk == issued_psk

    client_config: ResumedClientConfig = CLIENT_CONFIG.copy()
    client_config.update(
        {
            "connection_id": b"\x11\x22\x33\x47",
            "resumption": zttp.SessionResumption(identity=identity, psk=psk),
            "obfuscated_ticket_age": obfuscated_ticket_age(age_add, 3000, 6000),
        }
    )
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **client_config)
    server = make_server()

    assert transfer(client, server, 6000)
    assert transfer(server, client, 7000)
    assert transfer(client, server, 8000)
    assert transfer(server, client, 9000)

    stream = client.send_request(b"GET", b"/ticket-resumed", b"3", [(b"host", b"example.test")])
    assert stream.stream_id == 0
    assert transfer(client, server, 10000)
    events = []
    while (ev := server.next_event()) is not zttp.NEED_DATA:
        events.append(ev)
    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.method == b"GET"
    assert req.path == b"/ticket-resumed"


def test_http3_server_ticket_store_remains_valid_after_eviction() -> None:
    first_client = make_client()
    first_server = make_server()

    assert transfer(first_client, first_server, 1000)
    assert transfer(first_server, first_client, 2000)
    assert transfer(first_client, first_server, 3000)
    assert transfer(first_server, first_client, 4000)

    identity = b""
    psk = b""
    age_add = 0x01020304
    for index in range(65):
        identity = f"store-rotation-{index}".encode()
        issued = first_server.send_session_ticket(identity, 7200, age_add, bytes([index]), b"", 4096)
        assert isinstance(issued, bytes)
        psk = issued

    client_config: ResumedClientConfig = CLIENT_CONFIG.copy()
    client_config.update(
        {
            "connection_id": b"\x11\x22\x33\x57",
            "resumption": zttp.SessionResumption(identity=identity, psk=psk),
            "obfuscated_ticket_age": obfuscated_ticket_age(age_add, 3000, 6000),
            "early_data": True,
            "remembered_transport_params": SERVER_TRANSPORT_PARAMS,
        }
    )
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **client_config)
    server = make_server()
    client.send_request(b"GET", b"/after-rotation", b"3", [(b"host", b"example.test")])

    for datagram in client.data_to_send():
        server.receive_datagram(datagram, 6000)

    events = drain_events(server)
    assert any(isinstance(event, zttp.Request) and event.path == b"/after-rotation" for event in events)


def test_http3_ticket_age_mismatch_does_not_accept_zero_rtt() -> None:
    first_client = make_client()
    first_server = make_server()

    assert transfer(first_client, first_server, 1000)
    assert transfer(first_server, first_client, 2000)
    assert transfer(first_client, first_server, 3000)
    assert transfer(first_server, first_client, 4000)

    first_server.send_session_ticket(
        b"age-mismatch-ticket",
        7200,
        0x01020304,
        b"\x02",
        b"",
        4096,
    )
    assert transfer(first_server, first_client, 5000)
    [ticket] = first_client.session_tickets()
    identity, psk = ticket.ticket, ticket.psk
    assert isinstance(psk, bytes)

    client_config: ResumedClientConfig = CLIENT_CONFIG.copy()
    client_config.update(
        {
            "connection_id": b"\x11\x22\x33\x48",
            "resumption": zttp.SessionResumption(identity=identity, psk=psk),
            "obfuscated_ticket_age": 0,
            "early_data": True,
            "remembered_transport_params": SERVER_TRANSPORT_PARAMS,
        }
    )
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **client_config)
    server = make_server()

    client.send_request(b"GET", b"/not-early", b"3", [(b"host", b"example.test")])
    for dgram in client.data_to_send():
        server.receive_datagram(dgram, 6000)

    events = drain_events(server)
    assert not any(isinstance(e, zttp.Request) for e in events)


def test_http3_expired_ticket_does_not_accept_zero_rtt() -> None:
    first_client = make_client()
    first_server = make_server()

    assert transfer(first_client, first_server, 1000)
    assert transfer(first_server, first_client, 2000)
    assert transfer(first_client, first_server, 3000)
    assert transfer(first_server, first_client, 4000)

    first_server.send_session_ticket(
        b"expired-ticket",
        1,
        0x01020304,
        b"\x03",
        b"",
        4096,
    )
    assert transfer(first_server, first_client, 5000)
    [ticket] = first_client.session_tickets()
    age_add, identity, psk = ticket.age_add, ticket.ticket, ticket.psk
    assert isinstance(psk, bytes)

    resume_at = 2_500_000
    client_config: ResumedClientConfig = CLIENT_CONFIG.copy()
    client_config.update(
        {
            "connection_id": b"\x11\x22\x33\x49",
            "resumption": zttp.SessionResumption(identity=identity, psk=psk),
            "obfuscated_ticket_age": obfuscated_ticket_age(age_add, 3000, resume_at),
            "early_data": True,
            "remembered_transport_params": SERVER_TRANSPORT_PARAMS,
        }
    )
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **client_config)
    server = make_server()

    client.send_request(b"GET", b"/expired-early", b"3", [(b"host", b"example.test")])
    for dgram in client.data_to_send():
        server.receive_datagram(dgram, resume_at)

    events = drain_events(server)
    assert not any(isinstance(e, zttp.Request) for e in events)


def test_http3_ticket_without_early_data_extension_does_not_accept_zero_rtt() -> None:
    first_client = make_client()
    first_server = make_server()

    assert transfer(first_client, first_server, 1000)
    assert transfer(first_server, first_client, 2000)
    assert transfer(first_client, first_server, 3000)
    assert transfer(first_server, first_client, 4000)

    first_server.send_session_ticket(
        b"one-rtt-only-ticket",
        7200,
        0x01020304,
        b"\x04",
        b"",
        None,
    )
    assert transfer(first_server, first_client, 5000)
    [ticket] = first_client.session_tickets()
    age_add, identity, psk = ticket.age_add, ticket.ticket, ticket.psk
    assert isinstance(psk, bytes)
    assert ticket.max_early_data_size is None

    client_config: ResumedClientConfig = CLIENT_CONFIG.copy()
    client_config.update(
        {
            "connection_id": b"\x11\x22\x33\x4a",
            "resumption": zttp.SessionResumption(identity=identity, psk=psk),
            "obfuscated_ticket_age": obfuscated_ticket_age(age_add, 3000, 6000),
            "early_data": True,
            "remembered_transport_params": SERVER_TRANSPORT_PARAMS,
        }
    )
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **client_config)
    server = make_server()

    client.send_request(b"GET", b"/not-allowed-early", b"3", [(b"host", b"example.test")])
    for dgram in client.data_to_send():
        server.receive_datagram(dgram, 6000)

    events = drain_events(server)
    assert not any(isinstance(e, zttp.Request) for e in events)


def test_http3_zero_rtt_ticket_is_single_use() -> None:
    first_client = make_client()
    first_server = make_server()

    assert transfer(first_client, first_server, 1000)
    assert transfer(first_server, first_client, 2000)
    assert transfer(first_client, first_server, 3000)
    assert transfer(first_server, first_client, 4000)

    first_server.send_session_ticket(
        b"single-use-early-ticket",
        7200,
        0x01020304,
        b"\x05",
        b"",
        4096,
    )
    assert transfer(first_server, first_client, 5000)
    [ticket] = first_client.session_tickets()
    age_add, identity, psk = ticket.age_add, ticket.ticket, ticket.psk
    assert isinstance(psk, bytes)

    def make_early_client(connection_id: bytes, now: int) -> zttp.H3Connection:
        client_config: ResumedClientConfig = CLIENT_CONFIG.copy()
        client_config.update(
            {
                "connection_id": connection_id,
                "resumption": zttp.SessionResumption(identity=identity, psk=psk),
                "obfuscated_ticket_age": obfuscated_ticket_age(age_add, 3000, now),
                "early_data": True,
                "remembered_transport_params": SERVER_TRANSPORT_PARAMS,
            }
        )
        return zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **client_config)

    first_early = make_early_client(b"\x11\x22\x33\x4b", 6000)
    first_replay_target = make_server()
    first_early.send_request(b"GET", b"/accepted-once", b"3", [(b"host", b"example.test")])
    for dgram in first_early.data_to_send():
        first_replay_target.receive_datagram(dgram, 6000)
    first_events = []
    while (ev := first_replay_target.next_event()) is not zttp.NEED_DATA:
        first_events.append(ev)
    assert any(isinstance(e, zttp.Request) and e.path == b"/accepted-once" for e in first_events)

    replay = make_early_client(b"\x11\x22\x33\x4c", 7000)
    replay_target = make_server()
    replay.send_request(b"GET", b"/replayed", b"3", [(b"host", b"example.test")])
    for dgram in replay.data_to_send():
        replay_target.receive_datagram(dgram, 7000)
    replay_events = drain_events(replay_target)
    assert not any(isinstance(e, zttp.Request) for e in replay_events)


def test_http3_client_server_resumed_handshake() -> None:
    psk = b"\x7b" * 32
    client_config: ResumedClientConfig = CLIENT_CONFIG.copy()
    client_config.update(
        {
            "connection_id": b"\x11\x22\x33\x45",
            "resumption": zttp.SessionResumption(identity=b"ticket-identity", psk=psk),
            "obfuscated_ticket_age": 0x01020304,
        }
    )
    server_config: ResumedServerConfig = SERVER_CONFIG.copy()
    server_config.update(
        {
            "resumption": zttp.SessionResumption(identity=b"ticket-identity", psk=psk),
        }
    )
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **client_config)
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **server_config)

    assert transfer(client, server, 1000)
    assert transfer(server, client, 2000)
    assert transfer(client, server, 3000)
    assert transfer(server, client, 4000)

    stream = client.send_request(b"GET", b"/resumed", b"3", [(b"host", b"example.test")])
    assert stream.stream_id == 0
    assert transfer(client, server, 5000)
    events = []
    while (ev := server.next_event()) is not zttp.NEED_DATA:
        events.append(ev)
    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.method == b"GET"
    assert req.path == b"/resumed"


def test_http3_static_resumption_credentials_do_not_accept_zero_rtt() -> None:
    psk = b"\x7b" * 32
    client_config: ResumedClientConfig = CLIENT_CONFIG.copy()
    client_config.update(
        {
            "connection_id": b"\x11\x22\x33\x46",
            "resumption": zttp.SessionResumption(identity=b"ticket-identity", psk=psk),
            "obfuscated_ticket_age": 0x01020304,
            "early_data": True,
            "remembered_transport_params": SERVER_TRANSPORT_PARAMS,
        }
    )
    server_config: ResumedServerConfig = SERVER_CONFIG.copy()
    server_config.update(
        {
            "resumption": zttp.SessionResumption(identity=b"ticket-identity", psk=psk),
        }
    )
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **client_config)
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **server_config)

    stream = client.send_request(b"GET", b"/early", b"3", [(b"host", b"example.test")])
    assert stream.stream_id == 0
    first_flight = client.data_to_send()
    assert len(first_flight) >= 2
    for dgram in first_flight:
        server.receive_datagram(dgram, 1000)

    events = drain_events(server)
    assert not any(isinstance(e, zttp.Request) for e in events)


def test_http3_session_ticket_requires_established_server() -> None:
    server = make_server()
    with pytest.raises(zttp.LocalProtocolError):
        server.send_session_ticket(b"ticket")


def test_http3_server_can_send_new_token() -> None:
    client, server = handshake_pair()

    server.send_new_token(b"resume-token")
    assert transfer(server, client, 4000)

    assert client.validation_tokens() == [b"resume-token"]


def test_http3_send_new_token_requires_established_server_and_nonempty_token() -> None:
    server = make_server()
    with pytest.raises(zttp.LocalProtocolError):
        server.send_new_token(b"resume-token")

    client, server = handshake_pair()
    with pytest.raises(zttp.LocalProtocolError):
        client.send_new_token(b"client-token")
    with pytest.raises(zttp.LocalProtocolError):
        server.send_new_token(b"")


def test_http3_client_server_connect_request() -> None:
    client = make_client()
    server = make_server()

    assert transfer(client, server, 1000)
    assert transfer(server, client, 2000)
    assert transfer(client, server, 3000)
    assert transfer(server, client, 4000)

    stream = client.send_request(b"CONNECT", b"example.test:443", b"3", [(b"host", b"example.test:443")])
    assert stream.stream_id == 0
    assert transfer(client, server, 5000)

    events = []
    while (ev := server.next_event()) is not zttp.NEED_DATA:
        events.append(ev)
    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.method == b"CONNECT"
    assert req.target == b"example.test:443"
    assert req.path == b"example.test:443"
    assert req.query == b""
    assert req.headers == [(b"host", b"example.test:443")]


def test_http3_head_response_does_not_require_body_bytes() -> None:
    client = make_client()
    server = make_server()

    assert transfer(client, server, 1000)
    assert transfer(server, client, 2000)
    assert transfer(client, server, 3000)
    assert transfer(server, client, 4000)

    stream = client.send_request(b"HEAD", b"/metadata", b"3", [(b"host", b"example.test")])
    assert transfer(client, server, 5000)

    events = []
    while (ev := server.next_event()) is not zttp.NEED_DATA:
        events.append(ev)
    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.method == b"HEAD"

    response_stream = server.stream(stream.stream_id)
    response_stream.send_response(200, [(b"content-length", b"5")])
    with pytest.raises(zttp.RemoteProtocolError):
        response_stream.send_data(b"x")
    response_stream.end_message()
    assert transfer(server, client, 6000)

    response_events = []
    while (ev := client.next_event()) is not zttp.NEED_DATA:
        response_events.append(ev)
    assert any(isinstance(e, zttp.Response) and e.status_code == 200 for e in response_events)
    assert not any(isinstance(e, zttp.Data) for e in response_events)
    assert any(isinstance(e, zttp.EndOfMessage) for e in response_events)


def test_http3_client_request_trailers() -> None:
    client = make_client()
    server = make_server()

    assert transfer(client, server, 1000)
    assert transfer(server, client, 2000)
    assert transfer(client, server, 3000)
    assert transfer(server, client, 4000)

    stream = client.send_request(
        b"POST",
        b"/upload",
        b"3",
        [(b"host", b"example.test"), (b"content-length", b"4")],
    )
    stream.send_data(b"body")
    stream.end_message([(b"x-checksum", b"abc")])
    assert transfer(client, server, 5000)

    events = []
    while (ev := server.next_event()) is not zttp.NEED_DATA:
        events.append(ev)

    assert any(isinstance(e, zttp.Request) for e in events)
    data = next(e for e in events if isinstance(e, zttp.Data))
    assert data.data == b"body"
    eom = next(e for e in events if isinstance(e, zttp.EndOfMessage))
    assert eom.trailers == [(b"x-checksum", b"abc")]
    server.consume_data(data.stream_id, len(data.data))
    with pytest.raises(ValueError, match="unknown stream or length exceeds its unconsumed DATA"):
        server.consume_data(data.stream_id, 1)


def test_http3_receive_credit_waits_for_application_consumption() -> None:
    config: ResumedServerConfig = SERVER_CONFIG.copy()
    config["transport_params"] = zttp.QuicTransportParameters(
        initial_max_data=512,
        initial_max_stream_data_bidi_remote=512,
        initial_max_stream_data_uni=262144,
        initial_max_streams_bidi=8,
        initial_max_streams_uni=8,
    )
    client = make_client()
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **config)
    transfer(client, server, 1000)
    transfer(server, client, 2000)
    transfer(client, server, 3000)

    stream = client.send_request(
        b"POST",
        b"/slow",
        b"3",
        [(b"host", b"example.test"), (b"content-length", b"1024")],
    )
    for _ in range(4):
        stream.send_data(b"x" * 256)
    stream.end_message()
    assert stream.pending_bytes is not None
    assert stream.pending_bytes > 0
    transfer(client, server, 4000)
    events = drain_events(server)
    request = next(event for event in events if isinstance(event, zttp.Request))
    server.initiate_connection()
    transfer(server, client, 5000)
    client.initiate_connection()
    transfer(client, server, 6000)
    events.extend(drain_events(server))
    data = b"".join(event.data for event in events if isinstance(event, zttp.Data))
    assert data
    assert len(data) < 1024

    pending = stream.pending_bytes
    server.initiate_connection()
    transfer(server, client, 7000)
    client.initiate_connection()
    transfer(client, server, 8000)
    assert stream.pending_bytes == pending

    with pytest.raises(ValueError, match="unknown stream or length exceeds its unconsumed DATA"):
        server.consume_data(request.stream_id, len(data) + 1)
    server.consume_data(request.stream_id, len(data))
    transfer(server, client, 9000)
    client.initiate_connection()
    transfer(client, server, 10_000)
    assert stream.pending_bytes is not None
    assert stream.pending_bytes < pending


def test_http3_stream_send_window_and_pending_bytes_track_backpressure() -> None:
    client, server = handshake_pair()

    request_stream = client.send_request(b"GET", b"/flow", b"3", [(b"host", b"example.test")])
    assert transfer(client, server, 5000)
    events = []
    while (ev := server.next_event()) is not zttp.NEED_DATA:
        events.append(ev)
    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.stream_id == request_stream.stream_id

    stream = server.stream(req.stream_id)
    assert stream.send_window is None
    assert stream.pending_bytes is None

    stream.send_response(200)
    initial_window = stream.send_window
    assert isinstance(initial_window, int)
    assert initial_window > 0
    assert stream.pending_bytes == 0

    stream.send_data(b"x" * (initial_window + 1024))
    assert isinstance(stream.send_window, int)
    assert stream.send_window < initial_window
    assert isinstance(stream.pending_bytes, int)
    assert stream.pending_bytes > 0


def test_http3_send_window_and_pending_bytes_are_none_for_unknown_stream() -> None:
    _client, server = handshake_pair()
    handle = server.stream(99)
    assert handle.send_window is None
    assert handle.pending_bytes is None


def test_http3_server_defaults_transport_settings_and_credentials() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3)
    assert type(conn) is zttp.H3Connection


def test_http3_accepts_typed_transport_parameters() -> None:
    client_config = CLIENT_CONFIG.copy()
    client_config["transport_params"] = zttp.QuicTransportParameters(
        initial_max_data=65536,
        initial_max_stream_data_bidi_local=4096,
        initial_max_stream_data_bidi_remote=262144,
        initial_max_stream_data_uni=262144,
        initial_max_streams_bidi=16,
        initial_max_streams_uni=16,
        max_idle_timeout=30_000,
        max_udp_payload_size=1200,
        disable_active_migration=True,
    )
    server_config = SERVER_CONFIG.copy()
    server_config["transport_params"] = zttp.QuicTransportParameters(
        initial_max_data=1048576,
        initial_max_stream_data_bidi_remote=262144,
        initial_max_stream_data_uni=262144,
        initial_max_streams_bidi=8,
        initial_max_streams_uni=8,
        active_connection_id_limit=2,
    )
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **client_config)
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **server_config)

    transfer(client, server, 1000)
    transfer(server, client, 2000)
    transfer(client, server, 3000)
    client.send_request(b"GET", b"/typed", b"3", [(b"host", b"example.test")])
    transfer(client, server, 4000)

    request = next(event for event in drain_events(server) if isinstance(event, zttp.Request))
    stream = server.stream(request.stream_id)
    stream.send_response(200, [(b"content-length", b"0")])
    assert stream.send_window is not None
    assert 0 <= stream.send_window < 4096


def test_http3_typed_transport_parameters_preserve_role_defaults() -> None:
    config = SERVER_CONFIG.copy()
    config["transport_params"] = zttp.QuicTransportParameters(max_idle_timeout=30_000)
    client = make_client()
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **config)

    transfer(client, server, 1000)
    transfer(server, client, 2000)
    transfer(client, server, 3000)
    client.send_request(b"GET", b"/defaults", b"3", [(b"host", b"example.test")])
    transfer(client, server, 4000)

    assert any(isinstance(event, zttp.Request) for event in drain_events(server))


def test_http3_typed_transport_parameters_validate_in_the_extension() -> None:
    with pytest.raises(TypeError):
        zttp.Connection(  # ty: ignore[no-matching-overload]
            zttp.CLIENT, zttp.HTTP3, transport_params=b"raw"
        )
    with pytest.raises(ValueError, match="unknown field"):
        zttp.Connection(  # ty: ignore[no-matching-overload]
            zttp.CLIENT,
            zttp.HTTP3,
            transport_params={"unknown": 1},  # ty: ignore[invalid-key]
        )
    with pytest.raises(ValueError, match="outside the QUIC range"):
        zttp.Connection(zttp.CLIENT, zttp.HTTP3, transport_params={"max_udp_payload_size": 1199})
    with pytest.raises(ValueError, match="only valid for HTTP/3 servers"):
        zttp.Connection(
            zttp.CLIENT,
            zttp.HTTP3,
            transport_params=zttp.QuicTransportParameters(stateless_reset_token=b"\x00" * 16),
        )


def test_http3_server_accepts_a_certificate_chain() -> None:
    config: ResumedServerConfig = SERVER_CONFIG.copy()
    config["credentials"] = zttp.TlsCredentials(
        certificates=(SERVER_PUBLIC_KEY, b"intermediate-certificate"),
        private_key=b"\x42" * 32,
    )
    client = make_client()
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **config)

    transfer(client, server, 1000)
    transfer(server, client, 2000)
    transfer(client, server, 3000)
    client.send_request(b"GET", b"/chain", b"3", [(b"host", b"example.test")])
    transfer(client, server, 4000)

    assert any(isinstance(event, zttp.Request) for event in drain_events(server))


def test_http3_rejects_a_wrong_size_key() -> None:
    with pytest.raises(ValueError):
        zttp.Connection(
            zttp.SERVER,
            protocol=zttp.HTTP3,
            credentials=zttp.TlsCredentials(certificate=b"\xcc" * 48, private_key=b"\x42" * 16),
            transport_params=zttp.QuicTransportParameters(),
            random=b"\xab" * 32,
            ephemeral_seed=b"\x33" * 32,
        )


def test_http3_construction_picks_the_subtype() -> None:
    conn = make_server()
    assert type(conn) is zttp.H3Connection
    assert isinstance(conn, zttp.Connection)


def test_http3_accepts_a_positional_protocol() -> None:
    conn = zttp.Connection(zttp.SERVER, zttp.HTTP3, **SERVER_CONFIG)
    assert type(conn) is zttp.H3Connection


def test_receive_datagram_only_on_http3() -> None:
    # receive_datagram is an H3Connection method - it simply isn't on the others.
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    assert not hasattr(conn, "receive_datagram")


def test_first_datagram_must_be_an_initial() -> None:
    conn = make_server()
    with pytest.raises(zttp.RemoteProtocolError):
        conn.receive_datagram(b"\x40not-a-long-header")


def test_a_non_conformant_client_hello_is_rejected() -> None:
    # Wrong ALPN - the server requires HTTP/3 clients to negotiate "h3".
    config = CLIENT_CONFIG.copy()
    config["alpn"] = b"http/1.1"
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **config)
    conn = make_server()
    with pytest.raises(zttp.RemoteProtocolError):
        conn.receive_datagram(client.data_to_send()[0], 1000)


def test_handshake_emits_a_flight() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    # The server answers the ClientHello with its handshake flight (ServerHello +
    # encrypted Certificate/Finished) and an ACK, as separate UDP datagrams.
    datagrams = conn.data_to_send()
    assert isinstance(datagrams, list)
    assert len(datagrams) >= 1
    assert all(isinstance(d, bytes) and d for d in datagrams)


def test_receive_datagram_accepts_memoryview_input() -> None:
    conn = make_server()

    conn.receive_datagram(memoryview(CLIENT_HELLO), 1000)

    assert conn.data_to_send()


def test_receive_datagram_accepts_peer_address_key() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000, b"203.0.113.10:4433")
    datagrams = conn.data_to_send()
    assert len(datagrams) >= 1
    assert all(isinstance(d, bytes) and d for d in datagrams)


def test_data_to_send_with_addresses_preserves_peer_address_key() -> None:
    conn = make_server()
    peer = b"203.0.113.10:4433"
    conn.receive_datagram(CLIENT_HELLO, 1000, peer)
    datagrams = conn.data_to_send_with_addresses()
    assert len(datagrams) >= 1
    assert all(isinstance(datagram.data, bytes) and datagram.data for datagram in datagrams)
    assert all(datagram.peer_address == peer for datagram in datagrams)
    assert conn.data_to_send_with_addresses() == []


def test_data_to_send_with_addresses_uses_none_without_peer_address_key() -> None:
    conn = make_client()
    datagrams = conn.data_to_send_with_addresses()
    assert len(datagrams) == 1
    [datagram] = datagrams
    assert isinstance(datagram.data, bytes)
    assert datagram.peer_address is None
    assert conn.data_to_send() == []


def test_response_datagrams_keep_latest_peer_address_key() -> None:
    conn = make_server()
    peer = b"203.0.113.10:4433"
    conn.receive_datagram(CLIENT_HELLO, 1000, peer)
    conn.data_to_send_with_addresses()
    conn.receive_datagram(CLIENT_FINISHED, 2000, peer)
    conn.data_to_send_with_addresses()
    for dgram in GET_REQUEST:
        conn.receive_datagram(dgram, 3000, peer)
    conn.data_to_send_with_addresses()

    events = []
    while (ev := conn.next_event()) is not zttp.NEED_DATA:
        events.append(ev)
    req = next(e for e in events if isinstance(e, zttp.Request))

    stream = conn.stream(req.stream_id)
    stream.send_response(200, [(b"content-length", b"0")])
    stream.end_message()
    datagrams = conn.data_to_send_with_addresses()
    assert len(datagrams) >= 1
    assert all(datagram.peer_address == peer for datagram in datagrams)


def test_unvalidated_migrated_peer_address_does_not_become_default_route() -> None:
    conn = make_server()
    addr_a = b"203.0.113.10:4433"
    addr_b = b"203.0.113.11:4433"

    conn.receive_datagram(CLIENT_HELLO, 1000, addr_a)
    conn.data_to_send_with_addresses()
    conn.receive_datagram(CLIENT_FINISHED, 2000, addr_a)
    conn.data_to_send_with_addresses()
    for dgram in GET_REQUEST:
        conn.receive_datagram(dgram, 3000, addr_b)
    acks = conn.data_to_send_with_addresses()
    assert acks
    assert all(datagram.peer_address == addr_b for datagram in acks)

    events = []
    while (ev := conn.next_event()) is not zttp.NEED_DATA:
        events.append(ev)
    req = next(e for e in events if isinstance(e, zttp.Request))

    stream = conn.stream(req.stream_id)
    stream.send_response(200, [(b"content-length", b"0")])
    stream.end_message()
    datagrams = conn.data_to_send_with_addresses()
    assert datagrams
    assert all(datagram.peer_address == addr_a for datagram in datagrams)


def test_challenge_path_emits_addressed_datagram() -> None:
    conn = make_server()
    addr_a = b"203.0.113.10:4433"
    addr_b = b"203.0.113.11:4433"

    conn.receive_datagram(CLIENT_HELLO, 1000, addr_a)
    conn.data_to_send_with_addresses()
    conn.receive_datagram(CLIENT_FINISHED, 2000, addr_a)
    conn.data_to_send_with_addresses()
    for dgram in GET_REQUEST:
        conn.receive_datagram(dgram, 3000, addr_b)
    conn.data_to_send_with_addresses()

    conn.challenge_path(addr_b, b"12345678")
    datagrams = conn.data_to_send_with_addresses()
    assert datagrams
    assert all(datagram.peer_address == addr_b for datagram in datagrams)


def test_migrated_peer_address_is_challenged_automatically() -> None:
    client = make_client()
    server = make_server()
    server_addr = b"198.51.100.1:4433"
    addr_a = b"203.0.113.10:4433"
    addr_b = b"203.0.113.11:4433"

    for dgram in client.data_to_send():
        server.receive_datagram(dgram, 1000, addr_a)
    for outbound in server.data_to_send_with_addresses():
        assert outbound.peer_address == addr_a
        client.receive_datagram(outbound.data, 2000, server_addr)
    for outbound in client.data_to_send_with_addresses():
        assert outbound.peer_address == server_addr
        server.receive_datagram(outbound.data, 3000, addr_a)
    for outbound in server.data_to_send_with_addresses():
        assert outbound.peer_address == addr_a
        client.receive_datagram(outbound.data, 4000, server_addr)

    client.send_request(b"GET", b"/auto-migrated", b"3", [(b"host", b"example.test")])
    for dgram in client.data_to_send():
        server.receive_datagram(dgram, 5000, addr_b)

    challenge_datagrams = server.data_to_send_with_addresses()
    assert challenge_datagrams
    assert all(datagram.peer_address == addr_b for datagram in challenge_datagrams)
    for outbound in challenge_datagrams:
        client.receive_datagram(outbound.data, 6000, server_addr)

    responses = client.data_to_send_with_addresses()
    assert responses
    assert all(datagram.peer_address == server_addr for datagram in responses)
    for outbound in responses:
        server.receive_datagram(outbound.data, 7000, addr_b)
    server.data_to_send_with_addresses()

    events = []
    while (ev := server.next_event()) is not zttp.NEED_DATA:
        events.append(ev)
    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.path == b"/auto-migrated"

    stream = server.stream(req.stream_id)
    stream.send_response(200, [(b"content-length", b"0")])
    stream.end_message()
    datagrams = server.data_to_send_with_addresses()
    assert datagrams
    assert all(datagram.peer_address == addr_b for datagram in datagrams)


def test_validated_migrated_peer_address_becomes_default_route() -> None:
    client = make_client()
    server = make_server()
    server_addr = b"198.51.100.1:4433"
    addr_a = b"203.0.113.10:4433"
    addr_b = b"203.0.113.11:4433"

    for dgram in client.data_to_send():
        server.receive_datagram(dgram, 1000, addr_a)
    for outbound in server.data_to_send_with_addresses():
        assert outbound.peer_address == addr_a
        client.receive_datagram(outbound.data, 2000, server_addr)
    for outbound in client.data_to_send_with_addresses():
        assert outbound.peer_address == server_addr
        server.receive_datagram(outbound.data, 3000, addr_a)
    for outbound in server.data_to_send_with_addresses():
        assert outbound.peer_address == addr_a
        client.receive_datagram(outbound.data, 4000, server_addr)

    client.send_request(b"GET", b"/migrated", b"3", [(b"host", b"example.test")])
    for dgram in client.data_to_send():
        server.receive_datagram(dgram, 5000, addr_b)
    acks = server.data_to_send_with_addresses()
    assert acks
    assert all(datagram.peer_address == addr_b for datagram in acks)

    server.challenge_path(addr_b, b"abcdefgh")
    challenges = server.data_to_send_with_addresses()
    assert challenges
    assert all(datagram.peer_address == addr_b for datagram in challenges)
    for outbound in challenges:
        client.receive_datagram(outbound.data, 6000, server_addr)

    responses = client.data_to_send_with_addresses()
    assert responses
    assert all(datagram.peer_address == server_addr for datagram in responses)
    for outbound in responses:
        server.receive_datagram(outbound.data, 7000, addr_b)
    server.data_to_send_with_addresses()

    events = []
    while (ev := server.next_event()) is not zttp.NEED_DATA:
        events.append(ev)
    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.path == b"/migrated"

    stream = server.stream(req.stream_id)
    stream.send_response(200, [(b"content-length", b"0")])
    stream.end_message()
    datagrams = server.data_to_send_with_addresses()
    assert datagrams
    assert all(datagram.peer_address == addr_b for datagram in datagrams)


def test_challenge_path_requires_eight_bytes() -> None:
    conn = make_server()
    addr = b"203.0.113.10:4433"
    conn.receive_datagram(CLIENT_HELLO, 1000, addr)
    conn.data_to_send_with_addresses()

    with pytest.raises(ValueError):
        conn.challenge_path(addr, b"short")


def test_use_peer_connection_id_rejects_unknown_sequence() -> None:
    conn = make_client()
    with pytest.raises(ValueError):
        conn.use_peer_connection_id(1)


def test_local_connection_ids_track_issue_and_peer_retirement() -> None:
    client, server = handshake_pair()
    initial = server.local_connection_ids()
    assert len(initial) == 1
    assert initial[0].sequence_number == 0

    server.issue_connection_id(1, b"server-cid-1", b"\x5a" * 16)
    assert {(item.sequence_number, item.connection_id) for item in server.local_connection_ids()} == {
        (0, initial[0].connection_id),
        (1, b"server-cid-1"),
    }
    transfer(server, client, 4000)
    transfer(client, server, 5000)

    server.issue_connection_id(2, b"server-cid-2", b"\x6a" * 16, 1)
    transfer(server, client, 6000)
    client.initiate_connection()
    transfer(client, server, 7000)

    assert {(item.sequence_number, item.connection_id) for item in server.local_connection_ids()} == {
        (1, b"server-cid-1"),
        (2, b"server-cid-2"),
    }


def test_local_connection_ids_route_two_connections_on_one_endpoint() -> None:
    pairs: list[tuple[zttp.H3Connection, zttp.H3Connection, bytes]] = []
    routes: dict[bytes, zttp.H3Connection] = {}
    for index, original in enumerate((b"client-a", b"client-b"), start=1):
        config: ResumedClientConfig = CLIENT_CONFIG.copy()
        config["connection_id"] = original
        client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **config)
        server = make_server()
        transfer(client, server, index * 1000)
        transfer(server, client, index * 1000 + 100)
        transfer(client, server, index * 1000 + 200)
        rotated = f"server-cid-{index}".encode()
        server.issue_connection_id(1, rotated, bytes((index,)) * 16)
        issued = next(item for item in server.local_connection_ids() if item.sequence_number == 1)
        routes[issued.connection_id] = server
        transfer(server, client, index * 1000 + 300)
        transfer(client, server, index * 1000 + 400)
        client.use_peer_connection_id(1)
        pairs.append((client, server, rotated))

    for index, (client, _server, rotated) in enumerate(pairs, start=1):
        client.send_request(b"GET", f"/connection-{index}".encode(), b"3", [(b"host", b"example.test")])
        for datagram in client.data_to_send():
            connection_id_length = len(rotated)
            destination = datagram[1 : 1 + connection_id_length]
            assert destination in routes
            routes[destination].receive_datagram(datagram, 5000 + index)

    for index, (_client, server, rotated) in enumerate(pairs, start=1):
        assert routes[rotated] is server
        requests = [event for event in drain_events(server) if isinstance(event, zttp.Request)]
        assert requests[-1].path == f"/connection-{index}".encode()


def test_local_connection_ids_require_an_established_connection() -> None:
    with pytest.raises(zttp.LocalProtocolError):
        make_server().local_connection_ids()


def test_issue_connection_id_queues_new_connection_id_datagram() -> None:
    _client, server = handshake_pair()

    server.issue_connection_id(1, b"server-cid-1", b"\x5a" * 16)
    datagrams = server.data_to_send()
    assert datagrams
    assert all(isinstance(dgram, bytes) and dgram for dgram in datagrams)


def test_issue_connection_id_validates_inputs() -> None:
    _client, server = handshake_pair()

    with pytest.raises(ValueError):
        server.issue_connection_id(0, b"server-cid-1", b"\x5a" * 16)
    with pytest.raises(ValueError):
        server.issue_connection_id(1, b"", b"\x5a" * 16)
    with pytest.raises(ValueError):
        server.issue_connection_id(1, b"server-cid-1", b"short")
    with pytest.raises(TypeError):
        server.issue_connection_id(1, object(), b"\x5a" * 16)  # ty: ignore[invalid-argument-type]


def test_request_key_update_requires_application_keys() -> None:
    client = make_client()

    with pytest.raises(zttp.LocalProtocolError):
        client.request_key_update()


def test_request_key_update_applies_to_next_http3_packet() -> None:
    client, server = handshake_pair()

    client.request_key_update()
    client.send_request(b"GET", b"/key-update", b"3", [(b"host", b"example.test")])
    assert transfer(client, server, 4000)

    events = []
    while (ev := server.next_event()) is not zttp.NEED_DATA:
        events.append(ev)
    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.path == b"/key-update"


def test_disable_active_migration_rejects_new_peer_address_after_handshake() -> None:
    client = make_client()
    config = SERVER_CONFIG.copy()
    transport_params = SERVER_CONFIG["transport_params"].copy()
    transport_params["disable_active_migration"] = True
    config["transport_params"] = transport_params
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **config)
    addr_a = b"203.0.113.10:4433"
    addr_b = b"203.0.113.11:4433"

    for dgram in client.data_to_send():
        server.receive_datagram(dgram, 1000, addr_a)
    for dgram in server.data_to_send():
        client.receive_datagram(dgram, 2000)
    for dgram in client.data_to_send():
        server.receive_datagram(dgram, 3000, addr_a)
    server.data_to_send()

    client.send_request(b"GET", b"/moved", b"3", [(b"host", b"example.test")])
    with pytest.raises(zttp.RemoteProtocolError):
        server.receive_datagram(client.data_to_send()[0], 4000, addr_b)
    assert server.is_closed() is True
    assert server.data_to_send()


def test_receive_datagram_peer_address_must_be_bytes() -> None:
    conn = make_server()
    with pytest.raises(TypeError):
        conn.receive_datagram(CLIENT_HELLO, 1000, object())  # ty: ignore[invalid-argument-type]


def test_http3_reads_a_get_request_after_a_real_handshake() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    conn.data_to_send()
    conn.receive_datagram(CLIENT_FINISHED, 2000)
    conn.data_to_send()
    for dgram in GET_REQUEST:
        conn.receive_datagram(dgram, 3000)

    events = []
    while (ev := conn.next_event()) is not zttp.NEED_DATA:
        events.append(ev)

    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.method == b"GET"
    assert req.path == b"/"
    assert req.http_version == b"3"
    assert (b"host", b"exy") in req.headers


def test_http3_surfaces_peer_settings_event() -> None:
    client, server = handshake_pair()

    client.send_request(b"GET", b"/settings-event", b"3", [(b"host", b"example.test")])
    assert transfer(client, server, 5000)

    events = []
    while (ev := server.next_event()) is not zttp.NEED_DATA:
        events.append(ev)

    settings = next(e for e in events if isinstance(e, zttp.Settings))
    assert settings.params == [(1, 4096), (7, 16), (6, 65536)]


def test_http3_sends_a_response() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    conn.data_to_send()
    conn.receive_datagram(CLIENT_FINISHED, 2000)
    conn.data_to_send()
    for dgram in GET_REQUEST:
        conn.receive_datagram(dgram, 3000)
    conn.data_to_send()

    stream = conn.stream(0)
    stream.send_response(200, [(b"content-length", b"0")])
    stream.end_message()
    # The response leaves as one or more 1-RTT datagrams.
    datagrams = conn.data_to_send()
    assert len(datagrams) >= 1
    assert all(isinstance(d, bytes) for d in datagrams)


def _handshaken_with_request() -> zttp.H3Connection:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    conn.data_to_send()
    conn.receive_datagram(CLIENT_FINISHED, 2000)
    conn.data_to_send()
    for dgram in GET_REQUEST:
        conn.receive_datagram(dgram, 3000)
    conn.data_to_send()
    return conn


def test_http3_sends_an_interim_response() -> None:
    conn = _handshaken_with_request()
    stream = conn.stream(0)
    # 103 Early Hints (an interim 1xx), then the final response on the same stream.
    stream.send_informational(103, [(b"link", b"</s.css>; rel=preload")])
    stream.send_response(200, [(b"content-length", b"0")])
    stream.end_message()
    assert len(conn.data_to_send()) >= 1


def test_http3_rejects_a_non_interim_informational_status() -> None:
    conn = _handshaken_with_request()
    with pytest.raises(ValueError):
        conn.stream(0).send_informational(200)


def test_http3_sends_response_trailers() -> None:
    conn = _handshaken_with_request()
    stream = conn.stream(0)
    stream.send_response(200)
    stream.send_data(b"hi")
    stream.end_message([(b"x-checksum", b"ok")])
    assert len(conn.data_to_send()) >= 1


def test_http3_rejects_a_pseudo_header_in_trailers() -> None:
    conn = _handshaken_with_request()
    stream = conn.stream(0)
    stream.send_response(200)
    # A pseudo-header is illegal in trailers; the H3 send path surfaces the violation
    # as a protocol error (the whole H3 error set maps through RemoteProtocolError).
    with pytest.raises(zttp.RemoteProtocolError):
        stream.end_message([(b":status", b"200")])


@pytest.mark.parametrize(
    "name",
    [
        b"content-length",
        b"transfer-encoding",
        b"trailer",
        b"host",
        b"connection",
        b"upgrade",
        b"te",
        b"content-encoding",
        b"content-type",
        b"content-range",
    ],
)
def test_http3_rejects_forbidden_fields_in_trailers(name: bytes) -> None:
    conn = _handshaken_with_request()
    stream = conn.stream(0)
    stream.send_response(200)

    with pytest.raises(zttp.RemoteProtocolError):
        stream.end_message([(name, b"value")])


def test_http3_final_response_rejects_informational_status() -> None:
    conn = _handshaken_with_request()

    stream = conn.stream(0)
    with pytest.raises(zttp.RemoteProtocolError):
        stream.send_response(100)
    stream.send_informational(100)
    stream.send_response(200, [(b"content-length", b"0")])


def test_http3_stream_reset() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    conn.data_to_send()
    conn.receive_datagram(CLIENT_FINISHED, 2000)
    conn.data_to_send()
    for dgram in GET_REQUEST:
        conn.receive_datagram(dgram, 3000)
    conn.data_to_send()

    # Cancel the request stream (RFC 9114 4.4): RESET_STREAM + STOP_SENDING leave as
    # a 1-RTT datagram. The default code is H3_REQUEST_CANCELLED; a code is optional.
    stream = conn.stream(0)
    stream.reset()
    assert len(conn.data_to_send()) >= 1
    stream.reset(0x010C)  # an explicit code is accepted (a second reset is a no-op)
    # An error code past the 62-bit QUIC range is rejected.
    with pytest.raises(ValueError):
        conn.stream(4).reset(1 << 62)


def test_http3_reset_reclaims_unconsumed_data() -> None:
    client, server = handshake_pair()
    stream = client.send_request(b"POST", b"/cancel", b"3", [(b"host", b"example.test")])
    stream.send_data(b"body")
    transfer(client, server, 4000)
    data = next(event for event in drain_events(server) if isinstance(event, zttp.Data))

    server.stream(data.stream_id).reset()

    with pytest.raises(ValueError, match="unknown stream or length exceeds its unconsumed DATA"):
        server.consume_data(data.stream_id, 1)


def test_http3_initiate_connection_sends_the_control_stream() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    conn.data_to_send()
    conn.receive_datagram(CLIENT_FINISHED, 2000)
    conn.data_to_send()

    # The control stream + SETTINGS and the two QPACK streams (RFC 9204 4.2) leave as
    # 1-RTT datagrams; idempotent. The byte-level stream contents are asserted in the
    # Zig core test - here we only confirm the flush happens once.
    conn.initiate_connection()
    datagrams = conn.data_to_send()
    assert len(datagrams) >= 1
    conn.initiate_connection()  # no second set of streams
    assert conn.data_to_send() == []


def test_http3_shutdown_sends_a_goaway() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    conn.data_to_send()
    conn.receive_datagram(CLIENT_FINISHED, 2000)
    conn.data_to_send()

    conn.shutdown(8)
    assert len(conn.data_to_send()) >= 1
    # A later GOAWAY may only lower the id.
    with pytest.raises(zttp.RemoteProtocolError):
        conn.shutdown(12)


def test_http3_close_sends_a_connection_close() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    conn.data_to_send()
    conn.receive_datagram(CLIENT_FINISHED, 2000)
    conn.data_to_send()

    # A caller-chosen application CONNECTION_CLOSE (RFC 9114) leaves as a 1-RTT
    # datagram; the connection is then closed. The default code is H3_NO_ERROR.
    conn.close()
    assert len(conn.data_to_send()) >= 1
    assert conn.is_closed() is True
    # An explicit code and reason are accepted; a second close is a no-op.
    conn.close(error_code=0x0101, reason=b"bye")
    assert conn.data_to_send() == []


def test_http3_close_rejects_an_out_of_range_code() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    conn.data_to_send()
    conn.receive_datagram(CLIENT_FINISHED, 2000)
    conn.data_to_send()
    # A code past the 62-bit QUIC range cannot be encoded.
    with pytest.raises(ValueError):
        conn.close(error_code=1 << 62)


def test_http3_close_before_a_datagram_is_a_protocol_error() -> None:
    conn = make_server()
    with pytest.raises(zttp.LocalProtocolError):
        conn.close()


def test_http3_client_shutdown_uses_push_id_namespace() -> None:
    client, _server = handshake_pair()

    client.shutdown(1)
    client.shutdown(0)
    with pytest.raises(zttp.RemoteProtocolError):
        client.shutdown(2)


def test_http3_goaway_event_preserves_large_stream_id() -> None:
    client, server = handshake_pair()
    big_id = 1 << 34

    server.shutdown(big_id)
    transfer(server, client, 4000)

    events = []
    while (ev := client.next_event()) is not zttp.NEED_DATA:
        events.append(ev)
    goaways = [ev for ev in events if isinstance(ev, zttp.GoAway)]
    assert len(goaways) == 1
    assert goaways[0].last_stream_id == big_id
    assert client.goaway_received() == big_id


def test_next_event_before_any_datagram_is_need_data() -> None:
    conn = make_server()
    assert conn.next_event() is zttp.NEED_DATA


def test_http3_sends_through_a_stream_like_http2() -> None:
    conn = make_server()
    stream = conn.stream(0)
    assert isinstance(stream, zttp.Stream)
    assert stream.stream_id == 0


def test_http3_send_request_is_exposed_but_requires_client_establishment() -> None:
    conn = make_server()
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_request(b"GET", b"/", b"3", [(b"host", b"example.com")])


def test_http3_send_request_rejects_conflicting_authority_headers() -> None:
    client, _server = handshake_pair()
    with pytest.raises(zttp.LocalProtocolError):
        client.send_request(
            b"GET",
            b"/",
            b"3",
            [(b"host", b"example.test"), (b":authority", b"other.test")],
        )
    assert client.data_to_send() == []


def test_send_before_a_datagram_is_a_protocol_error() -> None:
    conn = make_server()
    stream = conn.stream(0)
    with pytest.raises(zttp.LocalProtocolError):
        stream.send_response(200)


def test_is_closed_starts_false() -> None:
    conn = make_server()
    assert conn.is_closed() is False
    conn.receive_datagram(CLIENT_HELLO, 1000)
    assert conn.is_closed() is False


def test_idle_timed_out_starts_false() -> None:
    # The server config advertises no max_idle_timeout, so the connection never idle
    # times out; the query is exposed and reports a plain bool.
    conn = make_server()
    assert conn.idle_timed_out() is False
    conn.receive_datagram(CLIENT_HELLO, 1000)
    assert conn.idle_timed_out() is False


def test_close_info_is_none_until_the_peer_closes() -> None:
    conn = make_server()
    assert conn.close_info() is None
    conn.receive_datagram(CLIENT_HELLO, 1000)
    assert conn.close_info() is None


def test_http3_close_sends_application_connection_close() -> None:
    client, server = handshake_pair()

    client.close(error_code=0x0100, reason=b"done")
    assert client.is_closed() is True
    transfer(client, server, 4000)

    assert server.is_closed() is True
    assert server.close_info() == zttp.CloseInfo(0x0100, b"done", True)
    assert server.next_event() is zttp.CONNECTION_CLOSED


def test_http3_close_can_send_transport_connection_close() -> None:
    client, server = handshake_pair()

    server.close(False, 0x0A, b"transport")
    transfer(server, client, 4000)

    assert client.is_closed() is True
    assert client.close_info() == zttp.CloseInfo(0x0A, b"transport", False)
    assert client.next_event() is zttp.CONNECTION_CLOSED


def test_http3_close_rejects_out_of_range_error_code() -> None:
    client, _server = handshake_pair()
    with pytest.raises(ValueError):
        client.close(error_code=1 << 62)


def test_peer_settings_is_none_until_the_control_stream_arrives() -> None:
    conn = make_server()
    assert conn.peer_settings() is None
    conn.receive_datagram(CLIENT_HELLO, 1000)
    assert conn.peer_settings() is None


def test_goaway_received_is_none_until_the_peer_sends_one() -> None:
    conn = make_server()
    assert conn.goaway_received() is None
    conn.receive_datagram(CLIENT_HELLO, 1000)
    assert conn.goaway_received() is None


def test_next_timeout_arms_after_the_handshake_flight() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    # The handshake flight is in flight, so a loss/PTO timer is armed.
    assert conn.next_timeout() is not None


def test_idle_timeout_closes_http3_connection() -> None:
    config = SERVER_CONFIG.copy()
    config["transport_params"] = zttp.QuicTransportParameters(max_idle_timeout=5)
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **config)

    conn.receive_datagram(CLIENT_HELLO, 1000)
    conn.handle_timeout(5999)
    assert conn.is_closed() is False
    conn.handle_timeout(6000)
    assert conn.is_closed() is True


def test_close_info_exposes_named_fields() -> None:
    client, server = handshake_pair()
    client.close(error_code=0x0100, reason=b"done")
    transfer(client, server, 4000)

    info = server.close_info()
    assert info is not None
    # A frozen dataclass: named access, no positional/tuple semantics.
    assert info.error_code == 0x0100
    assert info.reason == b"done"
    assert info.is_application is True
    assert isinstance(info, zttp.CloseInfo)
    assert not isinstance(info, tuple)
    assert info == zttp.CloseInfo(0x0100, b"done", True)


def test_h3_result_rows_are_frozen_dataclasses() -> None:
    assert dataclasses.is_dataclass(zttp.SessionTicket)
    assert [f.name for f in dataclasses.fields(zttp.SessionTicket)] == [
        "lifetime",
        "age_add",
        "nonce",
        "ticket",
        "extensions",
        "max_early_data_size",
        "psk",
    ]
    row = zttp.SessionTicket(1, 2, b"n", b"t", b"e", None, None)
    assert row.lifetime == 1
    assert row.max_early_data_size is None
    with pytest.raises(dataclasses.FrozenInstanceError):
        row.lifetime = 2  # ty: ignore[invalid-assignment]


def test_h3_result_rows_are_picklable() -> None:
    # Defined in zttp.results, so __module__ is correct and pickle finds them by
    # reference (the plain tuples they replaced pickled too).
    ticket = zttp.SessionTicket(7200, 1, b"nonce", b"ticket", b"", 4096, b"\x00" * 32)
    info = zttp.CloseInfo(0x0100, b"done", True)
    assert pickle.loads(pickle.dumps(ticket)) == ticket
    assert pickle.loads(pickle.dumps(info)) == info
    assert zttp.SessionTicket.__module__ == "zttp.results"
    assert zttp.CloseInfo.__module__ == "zttp.results"


def test_http3_many_sequential_requests_on_one_connection() -> None:
    # Regression: request/response round-trips past the second failed with a
    # "QUIC final size error". A completed (.done) response stream lingered while its
    # send half awaited an ack, got re-pumped, and pumpResponse re-entered the
    # stream-finished block - whose negative state check also matched .done - and
    # wrongly re-rejected the finished stream (message_error), sending a RESET_STREAM
    # with a stale final size.
    client, server = make_client(), make_server()
    now = 1000
    for _ in range(4):
        transfer(client, server, now)
        transfer(server, client, now)
        now += 1000

    for i in range(10):
        now += 1000
        stream = client.send_request(b"GET", b"/req", b"3", [(b"host", b"example.test")])
        stream.end_message()
        transfer(client, server, now)
        requests = [e for e in drain_events(server) if isinstance(e, zttp.Request)]
        assert len(requests) == 1, (i, requests)
        response = server.stream(requests[0].stream_id)
        response.send_response(200, [(b"content-length", b"0")])
        response.end_message()
        transfer(server, client, now)
        statuses = [e.status_code for e in drain_events(client) if isinstance(e, zttp.Response)]
        assert statuses == [200], (i, statuses)
