from __future__ import annotations

import pytest

import zttp

# A real QUIC Initial datagram carrying a complete HTTP/3 GET request on stream 0:
# the client dcid is 11 22 33 44, and the HEADERS frame's QPACK block is
# :method GET, :scheme https, :path /, :authority "x". Generated from the Zig
# transport's test builder (testBuildInitial) so it decrypts under the RFC 9001
# Initial keys the adapter derives from the dcid in the packet.
GET_DATAGRAM = bytes.fromhex("cf00000001041122334400001eec32112effa6556376739d2118dab345addaf64c2a56d1b6ff7a76860c06")


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
