from __future__ import annotations

from collections.abc import Iterator

import pytest

import zttp

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# An HPACK block for :method GET, :scheme http, :path /, :authority
# www.example.com (RFC 7541 C.3.1).
GET_BLOCK = bytes([0x82, 0x86, 0x84, 0x41, 0x0F]) + b"www.example.com"

# Frame flags.
END_STREAM = 0x01
END_HEADERS = 0x04


def frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    header = len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + stream_id.to_bytes(4, "big")
    return header + payload


def drain_h2(conn: zttp.Connection) -> Iterator[object]:
    """Pull events until NEED_DATA. Unlike the HTTP/1.1 drain, it does NOT stop at
    the first EndOfMessage - HTTP/2 multiplexes many streams on one connection."""
    while True:
        ev = conn.next_event()
        if ev is zttp.NEED_DATA:
            return
        yield ev


def server_with(*extra: bytes) -> zttp.Connection:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    conn.receive_data(PREFACE + frame(0x04, 0, 0, b"") + b"".join(extra))
    return conn


def test_handshake_emits_settings() -> None:
    conn = server_with()
    events = list(drain_h2(conn))
    assert len(events) == 1
    assert isinstance(events[0], zttp.Settings)
    assert events[0].params == []


def test_simple_get_request() -> None:
    conn = server_with(frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK))
    events = list(drain_h2(conn))
    settings, req, eom = events
    assert isinstance(settings, zttp.Settings)
    assert isinstance(req, zttp.Request)
    assert req.method == b"GET"
    assert req.target == b"/"
    assert req.http_version == b"2"
    assert req.stream_id == 1
    assert (b"host", b"www.example.com") in req.headers
    assert isinstance(eom, zttp.EndOfMessage)
    assert eom.stream_id == 1


def test_request_with_body() -> None:
    conn = server_with(
        frame(0x01, END_HEADERS, 1, GET_BLOCK),  # no END_STREAM
        frame(0x00, END_STREAM, 1, b"hello"),  # DATA
    )
    events = list(drain_h2(conn))
    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.stream_id == 1
    data = next(e for e in events if isinstance(e, zttp.Data))
    assert data.data == b"hello"
    assert data.stream_id == 1
    assert any(isinstance(e, zttp.EndOfMessage) for e in events)


def test_two_multiplexed_streams_carry_their_ids() -> None:
    conn = server_with(
        frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK),
        frame(0x01, END_HEADERS | END_STREAM, 3, GET_BLOCK),
    )
    requests = [e for e in drain_h2(conn) if isinstance(e, zttp.Request)]
    assert [r.stream_id for r in requests] == [1, 3]


def test_continuation_reassembly() -> None:
    conn = server_with(
        frame(0x01, END_STREAM, 1, GET_BLOCK[:3]),  # HEADERS, no END_HEADERS
        frame(0x09, END_HEADERS, 1, GET_BLOCK[3:]),  # CONTINUATION
    )
    requests = [e for e in drain_h2(conn) if isinstance(e, zttp.Request)]
    assert len(requests) == 1
    assert requests[0].method == b"GET"


def test_ping_surfaces() -> None:
    conn = server_with(frame(0x06, 0, 0, b"\x01\x02\x03\x04\x05\x06\x07\x08"))
    ping = next(e for e in drain_h2(conn) if isinstance(e, zttp.Ping))
    assert ping.ack is False
    assert ping.data == b"\x01\x02\x03\x04\x05\x06\x07\x08"


def test_malformed_first_frame_raises() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    # A PING as the first frame after the preface (must be SETTINGS).
    conn.receive_data(PREFACE + frame(0x06, 0, 0, b"\x00" * 8))
    with pytest.raises(zttp.RemoteProtocolError):
        list(drain_h2(conn))


def test_bad_preface_raises() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    conn.receive_data(b"NOT A VALID HTTP/2 PREFACE!")
    with pytest.raises(zttp.RemoteProtocolError):
        conn.next_event()


def test_partial_feed_resumes() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    data = PREFACE + frame(0x04, 0, 0, b"") + frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK)
    conn.receive_data(data[:20])
    # Not enough yet.
    assert conn.next_event() is zttp.NEED_DATA
    conn.receive_data(data[20:])
    events = list(drain_h2(conn))
    assert any(isinstance(e, zttp.Request) for e in events)


# HPACK static index 8 is exactly ":status: 200", so 0x88 is a complete head.
STATUS_200 = bytes([0x88])


def client_with(*extra: bytes) -> zttp.Connection:
    """A client sees only the server's SETTINGS (no preface to consume)."""
    conn = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    conn.receive_data(frame(0x04, 0, 0, b"") + b"".join(extra))
    return conn


def test_client_reads_a_response() -> None:
    conn = client_with(frame(0x01, END_HEADERS | END_STREAM, 1, STATUS_200))
    settings, resp, eom = list(drain_h2(conn))
    assert isinstance(settings, zttp.Settings)
    assert isinstance(resp, zttp.Response)
    assert resp.status_code == 200
    assert resp.http_version == b"2"
    assert resp.stream_id == 1
    assert isinstance(eom, zttp.EndOfMessage)


def test_client_reads_a_response_with_a_body() -> None:
    conn = client_with(
        frame(0x01, END_HEADERS, 1, STATUS_200),
        frame(0x00, END_STREAM, 1, b"hi"),  # DATA
    )
    events = list(drain_h2(conn))
    resp = next(e for e in events if isinstance(e, zttp.Response))
    data = next(e for e in events if isinstance(e, zttp.Data))
    assert resp.status_code == 200
    assert data.data == b"hi"


def test_client_sends_a_request_a_server_reads() -> None:
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    client.send_request(b"GET", b"/", b"2", [(b"host", b"example.com")])
    client.end_message()
    wire = client.data_to_send()

    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    server.receive_data(wire)
    req = next(e for e in drain_h2(server) if isinstance(e, zttp.Request))
    assert req.method == b"GET"
    assert req.target == b"/"
    assert req.http_version == b"2"
    # :authority became a synthesized host header on the read side.
    assert (b"host", b"example.com") in req.headers


def test_server_sends_a_response_a_client_reads() -> None:
    # Drive a request into the server so it knows the stream to answer on.
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    client.send_request(b"GET", b"/", b"2", [(b"host", b"x")])
    client.end_message()
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    server.receive_data(client.data_to_send())
    list(drain_h2(server))  # consume the request so h2_recv_stream is set

    server.send_response(200, [(b"content-type", b"text/plain")])
    server.send_data(b"hi")
    server.end_message()
    # Feed the server's bytes (its SETTINGS + response) back into the client.
    client.receive_data(server.data_to_send())
    events = list(drain_h2(client))
    resp = next(e for e in events if isinstance(e, zttp.Response))
    data = next(e for e in events if isinstance(e, zttp.Data))
    assert resp.status_code == 200
    assert (b"content-type", b"text/plain") in resp.headers
    assert data.data == b"hi"


def test_h2_send_side_trailers_rejected() -> None:
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    client.send_request(b"GET", b"/", b"2", [(b"host", b"x")])
    with pytest.raises(zttp.LocalProtocolError):
        client.end_message([(b"x-trailer", b"v")])


def test_h2_concurrent_responses_route_by_stream_id() -> None:
    # Two requests arrive before either is answered. Without an explicit stream_id
    # both responses would go to the last request's stream; with it they route.
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    client.send_request(b"GET", b"/a", b"2", [(b"host", b"x")])
    client.end_message()
    client.send_request(b"GET", b"/b", b"2", [(b"host", b"x")])
    client.end_message()

    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    server.receive_data(client.data_to_send())
    reqs = [e for e in drain_h2(server) if isinstance(e, zttp.Request)]
    assert len(reqs) == 2
    s1, s2 = reqs[0].stream_id, reqs[1].stream_id
    assert s1 != s2

    # Answer the FIRST request explicitly, even though the second was parsed last.
    server.send_response(201, [(b"x-which", b"a")], s1)
    server.send_data(b"AA", s1)
    server.end_message(None, s1)
    server.send_response(202, [(b"x-which", b"b")], s2)
    server.send_data(b"BB", s2)
    server.end_message(None, s2)

    client.receive_data(server.data_to_send())
    responses = {e.stream_id: e for e in drain_h2(client) if isinstance(e, zttp.Response)}
    assert responses[s1].status_code == 201
    assert responses[s2].status_code == 202


def test_h2_send_data_before_stream_selected_is_rejected() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_data(b"orphan")


def test_protocol_defaults_to_http1() -> None:
    conn = zttp.Connection(zttp.SERVER)  # no protocol arg
    conn.receive_data(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert isinstance(conn.next_event(), zttp.Request)


def test_invalid_protocol_rejected() -> None:
    with pytest.raises(ValueError):
        zttp.Connection(zttp.SERVER, protocol=99)


# -- Stream object -------------------------------------------------------------


def _data_payload_bytes(buf: bytes) -> int:
    """Total payload length across all DATA frames (type 0x00) in `buf`."""
    i, total = 0, 0
    while i < len(buf):
        length = int.from_bytes(buf[i : i + 3], "big")
        if buf[i + 3] == 0x00:
            total += length
        i += 9 + length
    return total


def test_send_request_returns_a_stream() -> None:
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    stream = client.send_request(b"GET", b"/", b"2", [(b"host", b"x")])
    assert isinstance(stream, zttp.Stream)
    assert stream.stream_id == 1


def test_stream_handle_round_trips_a_response() -> None:
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    client.send_request(b"GET", b"/", b"2", [(b"host", b"x")])
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    server.receive_data(client.data_to_send())
    req = next(e for e in drain_h2(server) if isinstance(e, zttp.Request))

    stream = server.stream(req.stream_id)
    assert stream.stream_id == req.stream_id
    stream.send_response(200, [(b"content-type", b"text/plain")])
    stream.send_data(b"hi")
    stream.end_message()

    client.receive_data(server.data_to_send())
    events = list(drain_h2(client))
    resp = next(e for e in events if isinstance(e, zttp.Response))
    data = next(e for e in events if isinstance(e, zttp.Data))
    assert resp.status_code == 200
    assert data.data == b"hi"


def test_connection_send_data_and_stream_send_data_are_equivalent() -> None:
    # The connection-level stream_id= form is a thin delegate over the Stream.
    def via_connection() -> bytes:
        s = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
        s.receive_data(server_preface_then_get())
        list(drain_h2(s))
        s.send_response(200, [(b"x", b"y")], 1)
        s.send_data(b"body", 1)
        s.end_message(None, 1)
        return s.data_to_send()

    def via_stream() -> bytes:
        s = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
        s.receive_data(server_preface_then_get())
        list(drain_h2(s))
        st = s.stream(1)
        st.send_response(200, [(b"x", b"y")])
        st.send_data(b"body")
        st.end_message()
        return s.data_to_send()

    assert via_connection() == via_stream()


def test_stream_only_on_http2() -> None:
    conn = zttp.Connection(zttp.SERVER)  # HTTP/1.1
    with pytest.raises(RuntimeError):
        conn.stream(1)


# -- Outbound flow control -----------------------------------------------------


def server_preface_then_get() -> bytes:
    return PREFACE + frame(0x04, 0, 0, b"") + frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK)


def server_with_small_window(initial: int) -> zttp.Connection:
    """A server whose peer advertised SETTINGS_INITIAL_WINDOW_SIZE=`initial`, with
    request stream 1 already opened and drained."""
    settings = (0x04).to_bytes(2, "big") + initial.to_bytes(4, "big")  # INITIAL_WINDOW_SIZE
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    conn.receive_data(PREFACE + frame(0x04, 0, 0, settings) + frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK))
    list(drain_h2(conn))
    return conn


def test_send_data_is_capped_by_the_stream_window() -> None:
    conn = server_with_small_window(5)
    stream = conn.stream(1)
    stream.send_response(200, [(b"content-type", b"text/plain")])
    stream.send_data(b"HELLO WORLD")  # 11 bytes; only 5 may leave
    stream.end_message()
    # The head plus exactly the 5 admitted body bytes; the other 6 stay parked.
    assert _data_payload_bytes(conn.data_to_send()) == 5


def test_window_update_flushes_parked_data() -> None:
    conn = server_with_small_window(5)
    stream = conn.stream(1)
    stream.send_response(200, [(b"content-type", b"text/plain")])
    stream.send_data(b"HELLO WORLD")
    stream.end_message()
    assert _data_payload_bytes(conn.data_to_send()) == 5  # drains the first 5

    # Peer grants 100 more on the stream: the parked 6 bytes now flush.
    conn.receive_data(frame(0x08, 0, 1, (100).to_bytes(4, "big")))
    list(drain_h2(conn))
    assert _data_payload_bytes(conn.data_to_send()) == 6


def test_full_body_round_trips_across_window_updates() -> None:
    conn = server_with_small_window(4)
    stream = conn.stream(1)
    stream.send_response(200, [(b"content-type", b"text/plain")])
    stream.send_data(b"abcdefghij")  # 10 bytes, window 4 at a time
    stream.end_message()

    body = bytearray()
    # Read the head + first window's worth on a fresh client.
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    client.receive_data(frame(0x04, 0, 0, b""))  # server SETTINGS stand-in
    # Feed the server output in, granting more window until the body completes.
    rounds = 0
    while len(body) < 10 and rounds < 10:
        client.receive_data(conn.data_to_send())
        for e in drain_h2(client):
            if isinstance(e, zttp.Data):
                body += e.data
        conn.receive_data(frame(0x08, 0, 1, (4).to_bytes(4, "big")))
        list(drain_h2(conn))
        rounds += 1
    assert bytes(body) == b"abcdefghij"
