from __future__ import annotations

import pytest

import zttp

# The deterministic server credentials the Zig handshake tests use (testServerConfig):
# a fixed signing-key seed, ServerHello random, ephemeral seed, and a stub cert. Real
# entropy would be per-connection; these are fixed so the captured client datagrams
# below decrypt reproducibly.
SERVER_CONFIG = {
    "certificate": b"\xcc" * 48,
    "private_key": b"\x42" * 32,
    "transport_params": b"\x08\x01\x08",
    "random": b"\xab" * 32,
    "ephemeral_seed": b"\x33" * 32,
}

# Real handshake datagrams a client produces against SERVER_CONFIG, captured from the
# Zig transport's test builders (RFC 8448 client key share). The client offers ALPN h3
# and sends initial_max_data 65536 plus an empty initial_source_connection_id (matching
# its zero-length Initial scid); the server advertises initial_max_streams_bidi 8 plus
# the auto-injected original_destination/initial_source connection ids, ALPN h3. The
# ClientHello rides an Initial, the Finished a Handshake packet, the GET request a
# 1-RTT packet - each sealed with the keys the real handshake derives, so nothing is
# forged with test keys. dcid is 11 22 33 44.
CLIENT_HELLO = bytes.fromhex(
    "c30000000104112233440000409a4d3e11647baf556326a75f6008b3bd937f3813bffcd39197feb9abf2d8e61aa5539d39a5ad06de38a6dc8d18f8fce9149a9ff0d6ccfed7b594a6ba97093d0bb9c28a356e228c80d2cb5b9d032fc90398e3d954fe2ae7920f670e3c6f5cdffb8c35d5c75e16582b613c34d322445b10160480d791fe88128cdec68e34fd7fd61b26e8fa1cc07be4f74f73a9c70ecfbb1b97070125376ff97745d8"
)
CLIENT_FINISHED = bytes.fromhex(
    "e30000000104112233440038521018f79775a3640f2215b80d21cc2fc497a8218eb66c61b7f32c2cf3ef87f008a094742f77ba82ce447bf75e9cc43b899b1e4b29776e44"
)
GET_REQUEST = bytes.fromhex("59112233445eade7548c087d84f41357686d9338e06a82c87b33299a3cdccdb9ed483eccf2")

# The pre-conformance ClientHello: no ALPN offer and no initial_source_connection_id,
# both of which the server now requires.
LEGACY_CLIENT_HELLO = bytes.fromhex(
    "c50000000104112233440000408f483e116484af5563d1a75f6008b3bd937f3813bffcd39197feb9abf2d8e61aa5539d39a5ad06de38a6dc8d18f8fce9149a9ff0cbccfed7b594a6ba97093d0bb9c28a356e228c80d2cb5b9d032fc90398e3d954fe2ae7920f670e3c6f5cdffb8c35d5c75e16582b613c34d322445b10160480d791fe883b8cddc289b6944cd68dfb2ecf25008c78255eef81817c25a8"
)


def make_server() -> zttp.H3Connection:
    return zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **SERVER_CONFIG)


def test_http3_constant_exists() -> None:
    assert isinstance(zttp.HTTP3, int)
    assert zttp.HTTP3 not in (zttp.HTTP1, zttp.HTTP2)


def test_http3_requires_server_role() -> None:
    with pytest.raises(ValueError):
        zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, **SERVER_CONFIG)


def test_http3_requires_server_config() -> None:
    with pytest.raises(TypeError):
        zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3)


def test_http3_rejects_a_wrong_size_key() -> None:
    with pytest.raises(ValueError):
        zttp.Connection(
            zttp.SERVER,
            protocol=zttp.HTTP3,
            certificate=b"\xcc" * 48,
            private_key=b"\x42" * 16,
            transport_params=b"\x00\x01",
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
    # No ALPN and no initial_source_connection_id - both now mandatory.
    conn = make_server()
    with pytest.raises(zttp.RemoteProtocolError):
        conn.receive_datagram(LEGACY_CLIENT_HELLO, 1000)


def test_handshake_emits_a_flight() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    # The server answers the ClientHello with its handshake flight (ServerHello +
    # encrypted Certificate/Finished) and an ACK, as separate UDP datagrams.
    datagrams = conn.data_to_send()
    assert isinstance(datagrams, list)
    assert len(datagrams) >= 1
    assert all(isinstance(d, bytes) and d for d in datagrams)


def test_http3_reads_a_get_request_after_a_real_handshake() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    conn.data_to_send()
    conn.receive_datagram(CLIENT_FINISHED, 2000)
    conn.data_to_send()
    conn.receive_datagram(GET_REQUEST, 3000)

    events = []
    while (ev := conn.next_event()) is not zttp.NEED_DATA:
        events.append(ev)

    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.method == b"GET"
    assert req.path == b"/"
    assert req.http_version == b"3"
    assert (b"host", b"exy") in req.headers


def test_http3_sends_a_response() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    conn.data_to_send()
    conn.receive_datagram(CLIENT_FINISHED, 2000)
    conn.data_to_send()
    conn.receive_datagram(GET_REQUEST, 3000)
    conn.data_to_send()

    stream = conn.stream(0)
    stream.send_response(200, [(b"content-length", b"0")])
    stream.end_message()
    # The response leaves as one or more 1-RTT datagrams.
    datagrams = conn.data_to_send()
    assert len(datagrams) >= 1
    assert all(isinstance(d, bytes) for d in datagrams)


def test_http3_stream_reset() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    conn.data_to_send()
    conn.receive_datagram(CLIENT_FINISHED, 2000)
    conn.data_to_send()
    conn.receive_datagram(GET_REQUEST, 3000)
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


def test_http3_initiate_connection_sends_the_control_stream() -> None:
    conn = make_server()
    conn.receive_datagram(CLIENT_HELLO, 1000)
    conn.data_to_send()
    conn.receive_datagram(CLIENT_FINISHED, 2000)
    conn.data_to_send()

    # The control stream + SETTINGS leaves as a 1-RTT datagram; idempotent.
    conn.initiate_connection()
    datagrams = conn.data_to_send()
    assert len(datagrams) >= 1
    conn.initiate_connection()  # no second control stream
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


def test_next_event_before_any_datagram_is_need_data() -> None:
    conn = make_server()
    assert conn.next_event() is zttp.NEED_DATA


def test_http3_sends_through_a_stream_like_http2() -> None:
    conn = make_server()
    stream = conn.stream(0)
    assert isinstance(stream, zttp.Stream)
    assert stream.stream_id == 0


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


def test_close_info_is_none_until_the_peer_closes() -> None:
    conn = make_server()
    assert conn.close_info() is None
    conn.receive_datagram(CLIENT_HELLO, 1000)
    assert conn.close_info() is None


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
