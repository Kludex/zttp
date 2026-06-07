from __future__ import annotations

import pytest

import zhttp


def test_send_response_content_length() -> None:
    conn = zhttp.Connection(zhttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [(b"Content-Type", b"text/plain"), (b"Content-Length", b"5")])
    conn.send_data(b"hello")
    conn.end_message()
    assert conn.data_to_send() == (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")


def test_send_request() -> None:
    conn = zhttp.Connection(zhttp.CLIENT)
    conn.send_request(b"GET", b"/", b"1.1", [(b"Host", b"example.com")])
    conn.end_message()
    assert conn.data_to_send() == b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


def test_chunked_response() -> None:
    conn = zhttp.Connection(zhttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [(b"Transfer-Encoding", b"chunked")])
    conn.send_data(b"Wiki")
    conn.send_data(b"pedia")
    conn.end_message()
    assert conn.data_to_send() == (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    )


def test_chunked_with_trailers() -> None:
    conn = zhttp.Connection(zhttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [(b"Transfer-Encoding", b"chunked")])
    conn.send_data(b"data")
    conn.end_message([(b"X-Checksum", b"abc")])
    assert conn.data_to_send() == (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\nX-Checksum: abc\r\n\r\n"
    )


def test_bodyless_response() -> None:
    conn = zhttp.Connection(zhttp.SERVER)
    conn.send_response(b"1.1", 204, b"No Content", [], True)
    conn.end_message()
    assert conn.data_to_send() == b"HTTP/1.1 204 No Content\r\n\r\n"


def test_status_code_formatting() -> None:
    conn = zhttp.Connection(zhttp.SERVER)
    conn.send_response(b"1.1", 404, b"Not Found", [], True)
    conn.end_message()
    assert conn.data_to_send().startswith(b"HTTP/1.1 404 Not Found")


def test_data_to_send_clears_buffer() -> None:
    conn = zhttp.Connection(zhttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [], True)
    conn.end_message()
    assert conn.data_to_send() != b""
    assert conn.data_to_send() == b""


def test_data_before_head_is_local_protocol_error() -> None:
    conn = zhttp.Connection(zhttp.SERVER)
    with pytest.raises(zhttp.LocalProtocolError):
        conn.send_data(b"x")


def test_two_heads_without_ending_is_local_protocol_error() -> None:
    conn = zhttp.Connection(zhttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [], True)
    with pytest.raises(zhttp.LocalProtocolError):
        conn.send_response(b"1.1", 200, b"OK", [], True)


def test_status_out_of_range() -> None:
    conn = zhttp.Connection(zhttp.SERVER)
    with pytest.raises(ValueError):
        conn.send_response(b"1.1", 1000, b"X", [], True)


def test_round_trip_server_reads_client_output() -> None:
    client = zhttp.Connection(zhttp.CLIENT)
    client.send_request(b"POST", b"/x", b"1.1", [(b"Host", b"h"), (b"Content-Length", b"4")])
    client.send_data(b"data")
    client.end_message()
    wire = client.data_to_send()

    server = zhttp.Connection(zhttp.SERVER)
    server.receive_data(wire)
    req = server.next_event()
    assert isinstance(req, zhttp.Request)
    assert req.method == b"POST"
    assert req.target == b"/x"
    body = b""
    while True:
        ev = server.next_event()
        if isinstance(ev, zhttp.Data):
            body += ev.data
        elif isinstance(ev, zhttp.EndOfMessage):
            break
    assert body == b"data"
