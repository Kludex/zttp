from __future__ import annotations

import pytest

import zttp

# A QUIC datagram coalescing a bootstrap Initial (a PING, which establishes the
# client dcid 11 22 33 44) and a 1-RTT packet carrying a complete HTTP/3 GET
# request on stream 0 (HEADERS: :method GET, :scheme https, :path /, :authority
# "x"). STREAM frames are illegal in Initial (RFC 9000 12.4), so request data
# rides the Application space; the adapter installs the deterministic test 1-RTT
# keys until it drives the real handshake. Generated from the Zig transport's
# test builders (testBuildInitial + testBuildApp).
GET_DATAGRAM = bytes.fromhex("cb00000001041122334400002503391124feae5563a7a45c7119a2ac826e2902aeed3285921485b19e31d5895764ce99219b4111223344d5873c1ca2ad7e827da34fc75fb850c4431c3430c66c9b3844ba46ebfb0f")


def test_http3_constant_exists() -> None:
    assert isinstance(zttp.HTTP3, int)
    assert zttp.HTTP3 not in (zttp.HTTP1, zttp.HTTP2)


def test_http3_requires_server_role() -> None:
    with pytest.raises(ValueError):
        zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3)


def test_http3_construction_picks_the_subtype() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3)
    assert type(conn) is zttp.H3Connection
    assert isinstance(conn, zttp.Connection)


def test_receive_datagram_only_on_http3() -> None:
    # receive_datagram is an H3Connection method - it simply isn't on the others,
    # so feeding datagrams to an HTTP/2 connection is a type error / AttributeError.
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    assert not hasattr(conn, "receive_datagram")


def test_first_datagram_must_be_an_initial() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3)
    with pytest.raises(zttp.RemoteProtocolError):
        conn.receive_datagram(b"\x40not-a-long-header")


def test_http3_reads_a_get_request() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3)
    conn.receive_datagram(GET_DATAGRAM)

    events = []
    while (ev := conn.next_event()) is not zttp.NEED_DATA:
        events.append(ev)

    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.method == b"GET"
    assert req.path == b"/"
    assert req.http_version == b"3"
    assert (b"host", b"x") in req.headers


def test_next_event_before_any_datagram_is_need_data() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3)
    assert conn.next_event() is zttp.NEED_DATA
