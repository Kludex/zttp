from __future__ import annotations

import pytest

import zttp
from tests.conftest import drain, drain_all


def test_event_and_sentinels_public() -> None:
    # Event and the two sentinels (constant + type) are importable from the
    # package, not zttp._zttp.
    for name in ("Event", "NeedData", "ConnectionClosed", "NEED_DATA", "CONNECTION_CLOSED"):
        assert name in zttp.__all__
    # Each sentinel is a singleton compared with `is`, and its type is named.
    assert type(zttp.NEED_DATA) is zttp.NeedData
    assert type(zttp.CONNECTION_CLOSED) is zttp.ConnectionClosed
    ev: zttp.Event = zttp.Connection(zttp.SERVER).next_event()
    assert ev is zttp.NEED_DATA


def test_connection_closed_is_a_singleton() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"")
    assert conn.next_event() is zttp.CONNECTION_CLOSED


def test_request_repr() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET /p HTTP/1.1\r\nHost: x\r\n\r\n")
    req = conn.next_event()
    assert repr(req) == "Request(method=b'GET', target=b'/p', http_version=b'1.1', headers=[(b'Host', b'x')])"


def test_request_path_and_query() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET /api/users?page=2&q=x HTTP/1.1\r\nHost: x\r\n\r\n")
    req = conn.next_event()
    assert isinstance(req, zttp.Request)
    assert req.target == b"/api/users?page=2&q=x"
    assert req.path == b"/api/users"
    assert req.query == b"page=2&q=x"


def test_request_path_without_query() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET /plain HTTP/1.1\r\nHost: x\r\n\r\n")
    req = conn.next_event()
    assert isinstance(req, zttp.Request)
    assert req.path == b"/plain"
    assert req.query == b""


def test_endofmessage_and_data_repr() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi")
    conn.next_event()  # Request
    assert repr(conn.next_event()) == "Data(data=b'hi')"
    assert repr(conn.next_event()) == "EndOfMessage(trailers=[])"


def test_response_repr() -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.receive_data(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
    resp = conn.next_event()
    assert repr(resp) == (
        "Response(status_code=404, reason=b'Not Found', http_version=b'1.1', headers=[(b'Content-Length', b'0')])"
    )


def test_events_compare_by_value() -> None:
    def parse(data: bytes) -> object:
        conn = zttp.Connection(zttp.SERVER)
        conn.receive_data(data)
        return conn.next_event()

    a = parse(b"GET /p HTTP/1.1\r\nHost: x\r\n\r\n")
    b = parse(b"GET /p HTTP/1.1\r\nHost: x\r\n\r\n")
    c = parse(b"GET /other HTTP/1.1\r\nHost: x\r\n\r\n")
    assert a == b
    assert a != c
    assert a != "not an event"  # different type -> not equal, no error


def test_parse_error_poisons_connection() -> None:
    # After a malformed message, next_event must keep raising - never resume and
    # parse the following bytes as a fresh (smuggled) request.
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET / HTTP/1.1\nX: 1\n\nGET /smuggled HTTP/1.1\r\nHost: y\r\n\r\n")
    with pytest.raises(zttp.RemoteProtocolError):
        drain_all(conn)
    # The connection is poisoned: it re-raises rather than returning /smuggled.
    with pytest.raises(zttp.RemoteProtocolError):
        conn.next_event()


@pytest.mark.parametrize("version", [b"1.1", b"HTTP/1.1"])
def test_send_version_accepts_bare_and_prefixed(version: bytes) -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.send_request(b"GET", b"/", version, [(b"Host", b"x")])
    conn.end_message()
    assert conn.data_to_send() == b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"


@pytest.mark.parametrize("bad", [b"2", b"1.1.1", b"garbage", b""])
def test_send_invalid_version_rejected(bad: bytes) -> None:
    conn = zttp.Connection(zttp.CLIENT)
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_request(b"GET", b"/", bad, [])


def test_client_auto_derives_head_response_bodyless() -> None:
    # A response to HEAD carries Content-Length but no body. Sending the HEAD
    # through the connection lets it frame the response without phantom bytes.
    conn = zttp.Connection(zttp.CLIENT)
    conn.send_request(b"HEAD", b"/", b"1.1", [(b"Host", b"x")])
    conn.end_message()
    conn.data_to_send()
    conn.receive_data(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")
    assert [type(e).__name__ for e in drain(conn)] == ["Response", "EndOfMessage"]


def test_client_auto_derives_304_bodyless() -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.send_request(b"GET", b"/", b"1.1", [(b"Host", b"x")])
    conn.end_message()
    conn.data_to_send()
    conn.receive_data(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\n\r\n")
    assert [type(e).__name__ for e in drain(conn)] == ["Response", "EndOfMessage"]


def test_bodyless_resets_after_cycle() -> None:
    # The remembered method applies only to the next message; the following one
    # frames its body normally again.
    conn = zttp.Connection(zttp.CLIENT)
    conn.send_request(b"HEAD", b"/", b"1.1", [(b"Host", b"x")])
    conn.end_message()
    conn.data_to_send()
    conn.receive_data(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n")
    assert [type(e).__name__ for e in drain(conn)] == ["Response", "EndOfMessage"]
    conn.start_next_cycle()
    conn.send_request(b"GET", b"/", b"1.1", [(b"Host", b"x")])
    conn.end_message()
    conn.data_to_send()
    conn.receive_data(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
    body = b"".join(e.data for e in drain(conn) if isinstance(e, zttp.Data))
    assert body == b"abc"


def test_client_still_frames_normal_response_body() -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.send_request(b"GET", b"/", b"1.1", [(b"Host", b"x")])
    conn.end_message()
    conn.data_to_send()
    conn.receive_data(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
    body = b"".join(e.data for e in drain(conn) if isinstance(e, zttp.Data))
    assert body == b"hello"


def test_server_auto_derives_head_response_bodyless() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
    list(drain(conn))
    conn.send_response(b"1.1", 200, b"OK", [(b"Content-Length", b"1234")])
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_data(b"body")
    conn.end_message()
    assert conn.data_to_send() == b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"
