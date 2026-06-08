from __future__ import annotations

import pytest

import zttp
from tests.conftest import drain


def test_send_response_content_length() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [(b"Content-Type", b"text/plain"), (b"Content-Length", b"5")])
    conn.send_data(b"hello")
    conn.end_message()
    assert conn.data_to_send() == (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")


def test_oversized_body_rejected() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [(b"Content-Length", b"5")])
    with pytest.raises(zttp.LocalProtocolError, match="more body than the declared Content-Length"):
        conn.send_data(b"too long")


def test_oversized_body_rejected_across_writes() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [(b"Content-Length", b"5")])
    conn.send_data(b"abc")
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_data(b"def")


def test_undersized_body_rejected_at_end() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [(b"Content-Length", b"5")])
    conn.send_data(b"abc")
    with pytest.raises(zttp.LocalProtocolError, match="ended before the declared Content-Length"):
        conn.end_message()


def test_exact_length_body_accepted() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [(b"Content-Length", b"5")])
    conn.send_data(b"ab")
    conn.send_data(b"cde")
    conn.end_message()
    assert conn.data_to_send() == b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde"


def test_trailers_rejected_on_content_length_body() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [(b"Content-Length", b"3")])
    conn.send_data(b"abc")
    with pytest.raises(zttp.LocalProtocolError, match="trailers can only follow a chunked body"):
        conn.end_message([(b"X-Checksum", b"abc")])


def test_trailers_rejected_on_bodyless_message() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(b"1.1", 204, b"No Content", [])
    with pytest.raises(zttp.LocalProtocolError, match="trailers can only follow a chunked body"):
        conn.end_message([(b"X-Checksum", b"abc")])


def test_all_send_misuses_share_one_exception_class() -> None:
    # Distinct messages, but every send-side misuse is a single catchable type.
    cases = [
        lambda c: c.send_data(b"x"),  # no head yet
        lambda c: (c.send_response(b"1.1", 200, b"OK", []), c.send_response(b"1.1", 200, b"OK", [])),
        lambda c: c.end_message(),  # nothing in progress
    ]
    messages = set()
    for case in cases:
        conn = zttp.Connection(zttp.SERVER)
        with pytest.raises(zttp.ProtocolError) as exc_info:  # base class catches all
            case(conn)
        messages.add(str(exc_info.value))
    assert len(messages) == len(cases)  # each misuse has its own message


def test_send_request() -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.send_request(b"GET", b"/", b"1.1", [(b"Host", b"example.com")])
    conn.end_message()
    assert conn.data_to_send() == b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


def test_chunked_response() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [(b"Transfer-Encoding", b"chunked")])
    conn.send_data(b"Wiki")
    conn.send_data(b"pedia")
    conn.end_message()
    assert conn.data_to_send() == (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    )


def test_chunked_with_trailers() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [(b"Transfer-Encoding", b"chunked")])
    conn.send_data(b"data")
    conn.end_message([(b"X-Checksum", b"abc")])
    assert conn.data_to_send() == (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\nX-Checksum: abc\r\n\r\n"
    )


def test_204_response_is_bodyless() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(b"1.1", 204, b"No Content", [])
    conn.end_message()
    assert conn.data_to_send() == b"HTTP/1.1 204 No Content\r\n\r\n"


def test_head_response_is_bodyless_despite_content_length() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
    list(drain(conn))
    conn.send_response(b"1.1", 200, b"OK", [(b"Content-Length", b"1234")])
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_data(b"body")
    conn.end_message()
    assert conn.data_to_send() == b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"


def test_status_code_formatting() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(b"1.1", 404, b"Not Found", [])
    conn.end_message()
    assert conn.data_to_send().startswith(b"HTTP/1.1 404 Not Found")


def test_data_to_send_clears_buffer() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [])
    conn.end_message()
    assert conn.data_to_send() != b""
    assert conn.data_to_send() == b""


def test_data_before_head_is_local_protocol_error() -> None:
    conn = zttp.Connection(zttp.SERVER)
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_data(b"x")


def test_two_heads_without_ending_is_local_protocol_error() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(b"1.1", 200, b"OK", [])
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_response(b"1.1", 200, b"OK", [])


def test_status_out_of_range() -> None:
    conn = zttp.Connection(zttp.SERVER)
    with pytest.raises(ValueError):
        conn.send_response(b"1.1", 1000, b"X", [])


def test_round_trip_server_reads_client_output() -> None:
    client = zttp.Connection(zttp.CLIENT)
    client.send_request(b"POST", b"/x", b"1.1", [(b"Host", b"h"), (b"Content-Length", b"4")])
    client.send_data(b"data")
    client.end_message()
    wire = client.data_to_send()

    server = zttp.Connection(zttp.SERVER)
    server.receive_data(wire)
    events = list(drain(server))
    req = events[0]
    assert isinstance(req, zttp.Request)
    assert req.method == b"POST"
    assert req.target == b"/x"
    body = b"".join(e.data for e in events if isinstance(e, zttp.Data))
    assert body == b"data"
    assert isinstance(events[-1], zttp.EndOfMessage)
