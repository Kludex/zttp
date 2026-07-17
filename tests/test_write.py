from __future__ import annotations

import pytest

import zttp
from tests.conftest import drain


def test_send_response_content_length() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(200, [(b"Content-Type", b"text/plain"), (b"Content-Length", b"5")])
    conn.send_data(b"hello")
    conn.end_message()
    assert conn.data_to_send() == (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")


def test_oversized_body_rejected() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(200, [(b"Content-Length", b"5")])
    with pytest.raises(zttp.LocalProtocolError, match="more body than the declared Content-Length"):
        conn.send_data(b"too long")


def test_oversized_body_rejected_across_writes() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(200, [(b"Content-Length", b"5")])
    conn.send_data(b"abc")
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_data(b"def")


def test_undersized_body_rejected_at_end() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(200, [(b"Content-Length", b"5")])
    conn.send_data(b"abc")
    with pytest.raises(zttp.LocalProtocolError, match="ended before the declared Content-Length"):
        conn.end_message()


def test_exact_length_body_accepted() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(200, [(b"Content-Length", b"5")])
    conn.send_data(b"ab")
    conn.send_data(b"cde")
    conn.end_message()
    assert conn.data_to_send() == b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde"


def test_trailers_rejected_on_content_length_body() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(200, [(b"Content-Length", b"3")])
    conn.send_data(b"abc")
    with pytest.raises(zttp.LocalProtocolError, match="trailers can only follow a chunked body"):
        conn.end_message([(b"X-Checksum", b"abc")])


def test_trailers_rejected_on_bodyless_message() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(204, [])
    with pytest.raises(zttp.LocalProtocolError, match="trailers can only follow a chunked body"):
        conn.end_message([(b"X-Checksum", b"abc")])


@pytest.mark.parametrize(
    ("misuse", "message"),
    [
        (lambda c: c.send_data(b"x"), "send a head first"),
        (
            lambda c: (c.send_response(200, []), c.send_response(200, [])),
            "a message is already in progress",
        ),
        (lambda c: c.end_message(), "no message is in progress to end"),
    ],
)
def test_send_misuse_raises_specific_message(misuse, message: str) -> None:  # type: ignore[no-untyped-def]
    # Distinct, actionable messages - all catchable by the one base class.
    conn = zttp.Connection(zttp.SERVER)
    with pytest.raises(zttp.ProtocolError, match=message):
        misuse(conn)


def test_send_request() -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.send_request(b"GET", b"/", b"1.1", [(b"Host", b"example.com")])
    conn.end_message()
    assert conn.data_to_send() == b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


def test_chunked_response() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(200, [(b"Transfer-Encoding", b"chunked")])
    conn.send_data(b"Wiki")
    conn.send_data(b"pedia")
    conn.end_message()
    assert conn.data_to_send() == (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    )


def test_chunked_with_trailers() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(200, [(b"Transfer-Encoding", b"chunked")])
    conn.send_data(b"data")
    conn.end_message([(b"X-Checksum", b"abc")])
    assert conn.data_to_send() == (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\nX-Checksum: abc\r\n\r\n"
    )


def test_204_response_is_bodyless() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(204, [])
    conn.end_message()
    assert conn.data_to_send() == b"HTTP/1.1 204 No Content\r\n\r\n"


def test_head_response_is_bodyless_despite_content_length() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
    list(drain(conn))
    conn.send_response(200, [(b"Content-Length", b"1234")])
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_data(b"body")
    conn.end_message()
    assert conn.data_to_send() == b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"


def test_head_response_bodyless_after_early_start_next_cycle() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
    list(drain(conn))
    conn.start_next_cycle()
    conn.send_response(200, [(b"Content-Length", b"1234")])
    conn.end_message()
    assert conn.data_to_send() == b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"


def test_error_response_keeps_its_body_after_a_head_then_malformed_request() -> None:
    # A HEAD request leaves the remembered method = HEAD, which survives
    # start_next_cycle by design. If the next pipelined request fails to parse, no
    # new Request replaces the method, so an error response the app sends must NOT
    # be framed as bodyless off the stale HEAD - that would turn remote input into a
    # LocalProtocolError in common error-handling code.
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
    list(drain(conn))
    conn.send_response(200, [])
    conn.end_message()
    conn.data_to_send()
    conn.start_next_cycle()

    conn.receive_data(b"GET / HTTP/1.1\r\nBad Header\r\n\r\n")  # malformed head
    with pytest.raises(zttp.RemoteProtocolError):
        list(drain(conn))

    # The 400 carries a body; before the fix the stale HEAD made it bodyless and
    # send_data raised LocalProtocolError.
    conn.send_response(400, [(b"Content-Length", b"11")])
    conn.send_data(b"bad request")
    conn.end_message()
    assert conn.data_to_send() == b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nbad request"


def test_head_body_parse_error_keeps_bodyless_framing() -> None:
    # A HEAD request whose (chunked) body then fails to parse must keep HEAD framing
    # for its error response: a response to HEAD is bodyless regardless of headers,
    # so the method must NOT be cleared mid-request - unlike a failure on a fresh
    # next-request head (see the test above), which does clear it.
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"HEAD / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
    assert any(isinstance(e, zttp.Request) for e in drain(conn))
    conn.receive_data(b"zz\r\n")  # invalid chunk size -> body parse error
    with pytest.raises(zttp.RemoteProtocolError):
        list(drain(conn))
    # The error response to the HEAD stays bodyless: sending a body is rejected.
    conn.send_response(400, [(b"Content-Length", b"11")])
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_data(b"bad request")
    conn.end_message()
    assert conn.data_to_send() == b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\n"


def test_status_code_formatting() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(404, [])
    conn.end_message()
    assert conn.data_to_send().startswith(b"HTTP/1.1 404 Not Found")


def test_data_to_send_clears_buffer() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(200, [])
    conn.end_message()
    assert conn.data_to_send() != b""
    assert conn.data_to_send() == b""


def test_data_before_head_is_local_protocol_error() -> None:
    conn = zttp.Connection(zttp.SERVER)
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_data(b"x")


def test_two_heads_without_ending_is_local_protocol_error() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(200, [])
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_response(200, [])


def test_status_out_of_range() -> None:
    conn = zttp.Connection(zttp.SERVER)
    with pytest.raises(ValueError):
        conn.send_response(1000, [])


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


def test_informational_then_final_response() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_informational(100)
    conn.send_response(200, [(b"Content-Length", b"2")])
    conn.send_data(b"hi")
    conn.end_message()
    assert conn.data_to_send() == (b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")


def test_informational_reason_derived_from_status() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_informational(103, [(b"Link", b"</style.css>; rel=preload")])
    assert conn.data_to_send() == b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"


def test_informational_unknown_status_falls_back() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_informational(150)
    assert conn.data_to_send() == b"HTTP/1.1 150 Informational\r\n\r\n"


def test_multiple_informational_responses() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_informational(103, [(b"Link", b"</a.css>; rel=preload")])
    conn.send_informational(100)
    conn.send_response(200, [(b"Content-Length", b"0")])
    conn.end_message()
    assert conn.data_to_send() == (
        b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n"
        b"HTTP/1.1 100 Continue\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )


@pytest.mark.parametrize("status", [99, 200, 204, 301, 500])
def test_informational_rejects_non_1xx(status: int) -> None:
    conn = zttp.Connection(zttp.SERVER)
    with pytest.raises(ValueError, match="informational status code must be in 100..199"):
        conn.send_informational(status)


def test_informational_rejects_switching_protocols() -> None:
    conn = zttp.Connection(zttp.SERVER)
    with pytest.raises(ValueError, match="101 Switching Protocols is a terminal upgrade response"):
        conn.send_informational(101)


def test_informational_rejected_mid_message() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(200, [(b"Content-Length", b"5")])
    with pytest.raises(zttp.LocalProtocolError, match="a message is already in progress"):
        conn.send_informational(100)


def test_informational_round_trips_to_reader() -> None:
    server = zttp.Connection(zttp.SERVER)
    server.send_informational(100)
    server.send_response(200, [(b"Content-Length", b"0")])
    server.end_message()
    wire = server.data_to_send()

    client = zttp.Connection(zttp.CLIENT)
    client.send_request(b"GET", b"/", b"1.1", [(b"Host", b"h")])
    client.end_message()
    client.receive_data(wire)

    interim = client.next_event()
    assert isinstance(interim, zttp.Response)
    assert interim.status_code == 100
    assert isinstance(client.next_event(), zttp.EndOfMessage)

    client.start_next_cycle()
    final = client.next_event()
    assert isinstance(final, zttp.Response)
    assert final.status_code == 200


def test_send_response_default_reason() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(404, [(b"Content-Length", b"0")])
    assert conn.data_to_send() == b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"


def test_send_response_unknown_status_class_reason() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(499, [(b"Content-Length", b"0")])
    assert conn.data_to_send() == b"HTTP/1.1 499 Client Error\r\nContent-Length: 0\r\n\r\n"


def test_send_response_headers_default_empty() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(204)
    assert conn.data_to_send() == b"HTTP/1.1 204 No Content\r\n\r\n"


def test_send_response_version_is_always_1_1() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.send_response(500)
    assert conn.data_to_send() == b"HTTP/1.1 500 Internal Server Error\r\n\r\n"


def test_send_response_version_1_1_even_for_http_1_0_request() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET / HTTP/1.0\r\nHost: h\r\n\r\n")
    assert isinstance(conn.next_event(), zttp.Request)
    conn.send_response(200, [(b"Content-Length", b"0")])
    assert conn.data_to_send() == b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
