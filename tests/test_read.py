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


def test_headers_are_owned_and_sequence_compatible() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET /one HTTP/1.1\r\nHost: first\r\nX-Test: a\r\nX-Test: b\r\n\r\n")
    req = conn.next_event()

    assert isinstance(req.headers, zttp.HeaderBlock)
    assert len(req.headers) == 3
    assert req.headers[0] == (b"Host", b"first")
    assert req.headers[-1] == (b"X-Test", b"b")
    assert req.headers[1:] == [(b"X-Test", b"a"), (b"X-Test", b"b")]
    assert req.headers[::-1] == [(b"X-Test", b"b"), (b"X-Test", b"a"), (b"Host", b"first")]
    assert req.headers.get(b"HOST") == b"first"
    assert req.headers.getall(b"x-test") == [b"a", b"b"]
    marker = object()
    assert req.headers.get(b"missing", marker) is marker
    assert list(req.headers) == [(b"Host", b"first"), (b"X-Test", b"a"), (b"X-Test", b"b")]
    assert req.headers.to_list() == list(req.headers)

    # The view owns its packed bytes; a later receive/cycle cannot invalidate it.
    conn.next_event()
    conn.start_next_cycle()
    conn.receive_data(b"GET /two HTTP/1.1\r\nHost: second\r\n\r\n")
    conn.next_event()
    assert req.headers.get(b"host") == b"first"


def test_h1_headers_are_immutable_by_default() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    req = conn.next_event()
    assert isinstance(req.headers, zttp.HeaderBlock)
    with pytest.raises(AttributeError):
        req.headers.append((b"X", b"y"))  # type: ignore[attr-defined]
    with pytest.raises(TypeError, match="created by HTTP/1 parsing"):
        zttp.HeaderBlock()  # type: ignore[call-arg]


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
    assert isinstance(resp.headers, zttp.HeaderBlock)
    assert resp.headers.get(b"content-length") == b"3"
    assert conn.next_event().data == b"xyz"


@pytest.mark.parametrize(
    ("method", "status", "reason"),
    [(b"GET", 204, b"No Content"), (b"CONNECT", 200, b"OK")],
)
def test_response_rejects_forbidden_transfer_encoding(method: bytes, status: int, reason: bytes) -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.send_request(method, b"/", b"1.1", [(b"Host", b"example.com")])
    conn.end_message()
    conn.data_to_send()
    conn.receive_data(b"HTTP/1.1 " + str(status).encode() + b" " + reason + b"\r\nTransfer-Encoding: chunked\r\n\r\n")
    with pytest.raises(zttp.RemoteProtocolError):
        conn.next_event()


@pytest.mark.parametrize(
    ("method", "status", "reason"),
    [(b"HEAD", 200, b"OK"), (b"GET", 304, b"Not Modified")],
)
def test_bodyless_response_accepts_chunked_metadata(method: bytes, status: int, reason: bytes) -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.send_request(method, b"/", b"1.1", [(b"Host", b"example.com")])
    conn.end_message()
    conn.data_to_send()
    conn.receive_data(b"HTTP/1.1 " + str(status).encode() + b" " + reason + b"\r\nTransfer-Encoding: chunked\r\n\r\n")
    assert isinstance(conn.next_event(), zttp.Response)
    assert isinstance(conn.next_event(), zttp.EndOfMessage)


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


def test_data_after_eof_rejected_before_body_fast_path() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n")
    assert isinstance(conn.next_event(), zttp.Request)
    assert conn.next_event() is zttp.NEED_DATA
    conn.receive_data(b"")
    with pytest.raises(zttp.RemoteProtocolError):
        conn.receive_data(b"hello")


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


def test_body_and_pipelined_request_in_one_feed() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(
        b"POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nfirstPOST /b HTTP/1.1\r\nContent-Length: 6\r\n\r\nsecond"
    )
    events = list(drain(conn))
    assert events[0].target == b"/a"
    assert b"".join(e.data for e in events if isinstance(e, zttp.Data)) == b"first"
    conn.start_next_cycle()
    events = list(drain(conn))
    assert events[0].target == b"/b"
    assert b"".join(e.data for e in events if isinstance(e, zttp.Data)) == b"second"


def test_second_feed_arrives_before_first_is_drained() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nhello")
    conn.receive_data(b"world")
    events = list(drain(conn))
    assert b"".join(e.data for e in events if isinstance(e, zttp.Data)) == b"helloworld"
    assert isinstance(events[-1], zttp.EndOfMessage)


def test_body_fed_in_pieces_with_draining_between() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"POST / HTTP/1.1\r\nContent-Length: 9\r\n\r\n")
    assert isinstance(next(drain(conn)), zttp.Request)
    body = b""
    for piece in (b"abc", b"def", b"ghi"):
        conn.receive_data(piece)
        body += b"".join(e.data for e in drain(conn) if isinstance(e, zttp.Data))
    assert body == b"abcdefghi"


def test_garbage_after_complete_message_raises_on_next_cycle() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nokNOT HTTP\x00\r\n\r\n")
    events = list(drain(conn))
    assert isinstance(events[-1], zttp.EndOfMessage)
    conn.start_next_cycle()
    with pytest.raises(zttp.RemoteProtocolError):
        drain_all(conn)


def test_query_carries_a_body() -> None:
    events = parse_request(b"QUERY /search HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
    req = events[0]
    assert isinstance(req, zttp.Request)
    assert req.method == b"QUERY"
    assert b"".join(e.data for e in events if isinstance(e, zttp.Data)) == b"hello"
    assert isinstance(events[-1], zttp.EndOfMessage)


def test_query_response_is_not_bodyless() -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.send_request(b"QUERY", b"/search", b"1.1", [(b"Host", b"example.com")])
    conn.receive_data(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
    events = list(drain(conn))
    assert b"".join(e.data for e in events if isinstance(e, zttp.Data)) == b"abc"
    assert isinstance(events[-1], zttp.EndOfMessage)


def test_standard_methods_are_interned() -> None:
    def method_of(raw: bytes) -> bytes:
        req = parse_request(raw + b" / HTTP/1.1\r\nHost: x\r\n\r\n")[0]
        assert isinstance(req, zttp.Request)
        return req.method

    assert method_of(b"QUERY") is method_of(b"QUERY")
    assert method_of(b"FROBNICATE") is not method_of(b"FROBNICATE")


def test_large_body_round_trips_unchanged() -> None:
    body = bytes(range(256)) * 256  # 64KB, every byte value
    raw = b"POST /up HTTP/1.1\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    events = parse_request(raw)
    assert b"".join(e.data for e in events if isinstance(e, zttp.Data)) == body
    assert isinstance(events[-1], zttp.EndOfMessage)
