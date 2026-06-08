from __future__ import annotations

import pytest

import zttp
from tests.conftest import drain, drain_all, parse_request


def test_simple_get() -> None:
    events = parse_request(b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert len(events) == 2
    req, eom = events
    assert isinstance(req, zttp.Request)
    assert req.method == b"GET"
    assert req.target == b"/path?q=1"
    assert req.http_version == b"1.1"
    assert req.headers == [(b"Host", b"example.com")]
    assert isinstance(eom, zttp.EndOfMessage)
    assert eom.trailers == []


def test_post_content_length() -> None:
    events = parse_request(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello")
    assert isinstance(events[0], zttp.Request)
    body = b"".join(e.data for e in events if isinstance(e, zttp.Data))
    assert body == b"hello"
    assert isinstance(events[-1], zttp.EndOfMessage)


def test_zero_content_length_has_no_data() -> None:
    events = parse_request(b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
    assert not any(isinstance(e, zttp.Data) for e in events)
    assert isinstance(events[-1], zttp.EndOfMessage)


def test_no_body_get_emits_end_of_message() -> None:
    events = parse_request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert isinstance(events[-1], zttp.EndOfMessage)


def test_chunked_body() -> None:
    events = parse_request(
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    )
    body = b"".join(e.data for e in events if isinstance(e, zttp.Data))
    assert body == b"hello world"


def test_chunked_with_trailers() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-T: v\r\n\r\n")
    events = list(drain(conn))
    eom = events[-1]
    assert isinstance(eom, zttp.EndOfMessage)
    assert eom.trailers == [(b"X-T", b"v")]


def test_multiple_headers_preserved_in_order() -> None:
    events = parse_request(b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nA: 3\r\n\r\n")
    req = events[0]
    assert isinstance(req, zttp.Request)
    assert req.headers == [(b"A", b"1"), (b"B", b"2"), (b"A", b"3")]


def test_header_value_whitespace_stripped() -> None:
    events = parse_request(b"GET / HTTP/1.1\r\nX:   spaced   \r\n\r\n")
    req = events[0]
    assert isinstance(req, zttp.Request)
    assert req.headers == [(b"X", b"spaced")]


def test_partial_head_then_complete() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET / HTTP/1.1\r\nHo")
    assert conn.next_event() is zttp.NEED_DATA
    conn.receive_data(b"st: x\r\n\r\n")
    req = conn.next_event()
    assert isinstance(req, zttp.Request)
    assert req.headers == [(b"Host", b"x")]


def test_body_split_across_feeds() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nhel")
    assert isinstance(conn.next_event(), zttp.Request)
    assert conn.next_event().data == b"hel"
    assert conn.next_event() is zttp.NEED_DATA
    conn.receive_data(b"loworld")
    assert conn.next_event().data == b"loworld"
    assert isinstance(conn.next_event(), zttp.EndOfMessage)


def test_keep_alive_two_requests() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: y\r\n\r\n")
    assert conn.next_event().target == b"/a"
    assert isinstance(conn.next_event(), zttp.EndOfMessage)
    conn.start_next_cycle()
    assert conn.next_event().target == b"/b"


def test_response_parsing() -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.receive_data(b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nxyz")
    resp = conn.next_event()
    assert isinstance(resp, zttp.Response)
    assert resp.status_code == 404
    assert resp.reason == b"Not Found"
    assert resp.http_version == b"1.1"
    assert conn.next_event().data == b"xyz"


def test_response_until_close() -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.receive_data(b"HTTP/1.1 200 OK\r\nServer: z\r\n\r\nbody here")
    assert isinstance(conn.next_event(), zttp.Response)
    assert conn.next_event().data == b"body here"
    assert conn.next_event() is zttp.NEED_DATA
    conn.receive_data(b"")  # EOF
    assert isinstance(conn.next_event(), zttp.EndOfMessage)


def test_eof_on_empty_connection_yields_closed() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"")
    assert conn.next_event() is zttp.CONNECTION_CLOSED


@pytest.mark.parametrize(
    "bad",
    [
        b"GET / HTTP/1.1\r\nBad Header\r\n\r\n",
        b"GET  /  HTTP/1.1\r\n\r\n",
        b"GET / FTP/1.1\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
    ],
)
def test_malformed_raises_remote_protocol_error(bad: bytes) -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(bad)
    with pytest.raises(zttp.RemoteProtocolError):
        drain_all(conn)


def test_drain_reaches_need_data_on_partial() -> None:
    # Exercises the NEED_DATA exit paths of the drain helpers (a valid but
    # incomplete request yields no events and stops at NEED_DATA).
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET / HTTP/1.1\r\nHost: ")  # no terminating blank line
    assert list(drain(conn)) == []
    drain_all(conn)  # returns cleanly (NEED_DATA), no exception


def test_invalid_role_rejected() -> None:
    with pytest.raises(ValueError):
        zttp.Connection(99)


def test_remote_is_subclass_of_protocol_error() -> None:
    assert issubclass(zttp.RemoteProtocolError, zttp.ProtocolError)
    assert issubclass(zttp.LocalProtocolError, zttp.ProtocolError)
