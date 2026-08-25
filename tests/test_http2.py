from __future__ import annotations

from collections.abc import Iterator

import pytest
from inline_snapshot import snapshot

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


def drain_h2(conn: zttp.H2Connection) -> Iterator[object]:
    """Pull events until NEED_DATA. Unlike the HTTP/1.1 drain, it does NOT stop at
    the first EndOfMessage - HTTP/2 multiplexes many streams on one connection."""
    while True:
        ev = conn.next_event()
        if ev is zttp.NEED_DATA:
            return
        yield ev


def server_with(*extra: bytes) -> zttp.H2Connection:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    conn.receive_data(PREFACE + frame(0x04, 0, 0, b"") + b"".join(extra))
    return conn


def test_handshake_emits_settings() -> None:
    conn = server_with()
    events = list(drain_h2(conn))
    assert len(events) == 1
    assert isinstance(events[0], zttp.Settings)
    assert events[0].params == []


def _settings_flags(buf: bytes) -> list[int]:
    return [flags for ftype, flags, _, _ in _frames(buf) if ftype == 0x04]


def _own_settings(buf: bytes) -> dict[int, int]:
    # The first non-ACK SETTINGS frame is the server's own preface; decode it.
    payload = next(p for ftype, flags, _, p in _frames(buf) if ftype == 0x04 and not flags & 0x01)
    return {
        int.from_bytes(payload[j : j + 2], "big"): int.from_bytes(payload[j + 2 : j + 6], "big")
        for j in range(0, len(payload), 6)
    }


def test_receive_data_accepts_bytearray_input() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)

    conn.receive_data(bytearray(PREFACE + frame(0x04, 0, 0, b"")))

    assert isinstance(conn.next_event(), zttp.Settings)


def test_handshake_advertises_real_settings() -> None:
    # The server must advertise its enforced limits, not an empty SETTINGS, or a
    # peer uses RFC defaults and gets spurious REFUSED_STREAM resets (RFC 9113 6.5).
    conn = server_with(frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK))
    list(drain_h2(conn))
    settings = _own_settings(conn.data_to_send())
    assert settings[0x03] == 128  # MAX_CONCURRENT_STREAMS (the default cap)
    assert settings[0x06] == 64 * 1024  # MAX_HEADER_LIST_SIZE
    assert settings[0x01] == 4096  # HEADER_TABLE_SIZE
    assert settings[0x05] == 16384  # MAX_FRAME_SIZE


def test_advertised_settings_round_trip_to_a_peer() -> None:
    # A client parses the server's advertised SETTINGS as a Settings event.
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    server.initiate_connection()
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    client.receive_data(server.data_to_send())
    settings = next(e for e in drain_h2(client) if isinstance(e, zttp.Settings))
    assert (0x03, 128) in settings.params  # MAX_CONCURRENT_STREAMS


def test_server_settings_precede_the_settings_ack() -> None:
    # The server's own SETTINGS must be the first frame it sends (RFC 9113 3.4),
    # even when the client's SETTINGS is ACKed first while draining events.
    conn = server_with(frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK))
    list(drain_h2(conn))
    flags = _settings_flags(conn.data_to_send())
    assert flags[0] & 0x01 == 0  # first SETTINGS is the server's own (non-ACK)
    assert flags[1] & 0x01  # the ACK of the client's SETTINGS comes after


def test_read_only_server_still_emits_its_preface() -> None:
    conn = server_with()  # no request, server never responds
    list(drain_h2(conn))
    flags = _settings_flags(conn.data_to_send())
    assert flags and flags[0] & 0x01 == 0  # own SETTINGS emitted, not just the ACK


def test_simple_get_request() -> None:
    conn = server_with(frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK))
    events = list(drain_h2(conn))
    settings, req = events
    assert isinstance(settings, zttp.Settings)
    assert isinstance(req, zttp.Request)
    assert req.method == b"GET"
    assert req.target == b"/"
    assert req.http_version == b"2"
    assert req.stream_id == 1
    assert req.end_stream is True
    assert (b"host", b"www.example.com") in req.headers


def test_request_with_body() -> None:
    conn = server_with(
        frame(0x01, END_HEADERS, 1, GET_BLOCK),  # no END_STREAM
        frame(0x00, END_STREAM, 1, b"hello"),  # DATA
    )
    events = list(drain_h2(conn))
    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.stream_id == 1
    assert req.end_stream is False
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


def test_connection_fatal_error_emits_goaway() -> None:
    # An even-numbered request stream id is a connection PROTOCOL_ERROR; the server
    # must send a GOAWAY before closing (RFC 9113 5.4.1).
    conn = server_with(frame(0x01, END_HEADERS | END_STREAM, 2, GET_BLOCK))
    with pytest.raises(zttp.RemoteProtocolError):
        list(drain_h2(conn))
    goaways = [f for f in _frames(conn.data_to_send()) if f[0] == 0x07]
    assert len(goaways) == 1
    error_code = int.from_bytes(goaways[0][3][4:8], "big")
    assert error_code == 0x01  # PROTOCOL_ERROR


def test_goaway_is_emitted_only_once() -> None:
    conn = server_with(frame(0x01, END_HEADERS | END_STREAM, 2, GET_BLOCK))
    with pytest.raises(zttp.RemoteProtocolError):
        list(drain_h2(conn))
    conn.data_to_send()  # drains the GOAWAY
    # Re-raising the latched error must not queue another GOAWAY.
    with pytest.raises(zttp.RemoteProtocolError):
        conn.next_event()
    assert [f for f in _frames(conn.data_to_send()) if f[0] == 0x07] == []


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


def client_with(*extra: bytes) -> zttp.H2Connection:
    """A client sees only the server's SETTINGS (no preface to consume)."""
    conn = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    conn.send_request(b"GET", b"/", b"2", [(b"host", b"example.com")])
    conn.data_to_send()
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


def test_client_rejects_data_before_response_headers() -> None:
    conn = client_with(frame(0x00, END_STREAM, 1, b"body"))

    events = list(drain_h2(conn))

    assert not any(isinstance(event, (zttp.Response, zttp.Data, zttp.EndOfMessage)) for event in events)
    reset = next(event for event in events if isinstance(event, zttp.RstStream))
    assert reset.stream_id == 1
    assert reset.error_code == 0x01


def test_client_rejects_a_response_on_an_unopened_stream() -> None:
    conn = client_with(frame(0x01, END_HEADERS | END_STREAM, 3, STATUS_200))

    with pytest.raises(zttp.RemoteProtocolError):
        list(drain_h2(conn))


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
    stream = client.send_request(b"GET", b"/", b"2", [(b"host", b"example.com")])
    stream.end_message()
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
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    client.send_request(b"GET", b"/", b"2", [(b"host", b"x")])
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    server.receive_data(client.data_to_send())
    req = next(e for e in drain_h2(server) if isinstance(e, zttp.Request))

    stream = server.stream(req.stream_id)
    stream.send_response(200, [(b"content-type", b"text/plain")])
    stream.send_data(b"hi")
    stream.end_message()
    client.receive_data(server.data_to_send())
    events = list(drain_h2(client))
    resp = next(e for e in events if isinstance(e, zttp.Response))
    data = next(e for e in events if isinstance(e, zttp.Data))
    assert resp.status_code == 200
    assert (b"content-type", b"text/plain") in resp.headers
    assert data.data == b"hi"


def test_h2_send_side_trailers_rejected() -> None:
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    stream = client.send_request(b"GET", b"/", b"2", [(b"host", b"x")])
    with pytest.raises(zttp.LocalProtocolError, match="HTTP/2 send-side trailers are not supported yet"):
        stream.end_message([(b"x-trailer", b"v")])
    with pytest.raises(zttp.LocalProtocolError, match="HTTP/2 send-side trailers are not supported yet"):
        stream.end_message([(b"malformed",)])  # ty: ignore[invalid-argument-type]


def test_h2_concurrent_responses_route_by_their_stream() -> None:
    # Two requests arrive before either is answered. Each is answered through its
    # own Stream handle, so the responses route to the right stream regardless of
    # the order they were parsed in.
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    client.send_request(b"GET", b"/a", b"2", [(b"host", b"x")]).end_message()
    client.send_request(b"GET", b"/b", b"2", [(b"host", b"x")]).end_message()

    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    server.receive_data(client.data_to_send())
    reqs = [e for e in drain_h2(server) if isinstance(e, zttp.Request)]
    assert len(reqs) == 2
    s1, s2 = reqs[0].stream_id, reqs[1].stream_id
    assert s1 != s2

    # Answer the FIRST request, even though the second was parsed last.
    a, b = server.stream(s1), server.stream(s2)
    a.send_response(201, [(b"x-which", b"a")])
    a.send_data(b"AA")
    a.end_message()
    b.send_response(202, [(b"x-which", b"b")])
    b.send_data(b"BB")
    b.end_message()

    client.receive_data(server.data_to_send())
    responses = {e.stream_id: e for e in drain_h2(client) if isinstance(e, zttp.Response)}
    assert responses[s1].status_code == 201
    assert responses[s2].status_code == 202


def test_h2_send_data_on_an_unselected_stream_is_rejected() -> None:
    # Stream 0 is the connection-control stream and can never carry DATA.
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    with pytest.raises(ValueError):
        conn.stream(0)


def test_stream_id_out_of_range_is_rejected() -> None:
    # HTTP/2 stream ids are 31-bit; a larger id must raise, not crash or truncate.
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    with pytest.raises(ValueError):
        conn.stream(2**31)
    with pytest.raises(ValueError):
        conn.stream(1 << 40)
    # The largest valid id is accepted.
    assert conn.stream(2**31 - 1).stream_id == 2**31 - 1


def test_connection_construction_picks_the_protocol_subtype() -> None:
    h1 = zttp.Connection(zttp.SERVER)
    h2 = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    assert type(h1) is zttp.H1Connection
    assert type(h2) is zttp.H2Connection
    # The base is a real supertype, so protocol-agnostic code can hold either.
    assert isinstance(h1, zttp.Connection)
    assert isinstance(h2, zttp.Connection)


def test_message_scoped_send_is_absent_on_http2() -> None:
    # The H2 send surface is stream-scoped: the connection simply does not carry
    # the message-scoped methods, so misuse is a type error / AttributeError, not
    # a runtime guard that has to be remembered.
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    assert not hasattr(conn, "send_response")
    assert not hasattr(conn, "send_data")
    assert not hasattr(conn, "end_message")
    # Conversely, stream-scoped sending is absent on HTTP/1.1.
    h1 = zttp.Connection(zttp.SERVER)
    assert not hasattr(h1, "stream")


def test_protocol_defaults_to_http1() -> None:
    conn = zttp.Connection(zttp.SERVER)  # no protocol arg
    conn.receive_data(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert isinstance(conn.next_event(), zttp.Request)


def test_invalid_protocol_rejected() -> None:
    with pytest.raises(ValueError):
        zttp.Connection(zttp.SERVER, protocol=99)  # ty: ignore[no-matching-overload]


def test_connection_factory_cannot_be_subclassed() -> None:
    # Connection is a factory: it has no usable instance surface of its own, so a
    # subclass instance would be a half-built object. Constructing one is rejected.
    class Custom(zttp.Connection):
        pass

    with pytest.raises(TypeError):
        Custom(zttp.SERVER)


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


# -- Outbound flow control -----------------------------------------------------


def server_with_small_window(initial: int) -> zttp.H2Connection:
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
    client.send_request(b"GET", b"/", b"2", [(b"host", b"example.com")])
    client.data_to_send()
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


def _frames(data: bytes) -> list[tuple[int, int, int, bytes]]:
    """Parse (type, flags, stream_id, payload) tuples, skipping a leading preface."""
    if data.startswith(PREFACE):
        data = data[len(PREFACE) :]
    out: list[tuple[int, int, int, bytes]] = []
    i = 0
    while i + 9 <= len(data):
        length = int.from_bytes(data[i : i + 3], "big")
        ftype = data[i + 3]
        flags = data[i + 4]
        sid = int.from_bytes(data[i + 5 : i + 9], "big") & 0x7FFFFFFF
        out.append((ftype, flags, sid, data[i + 9 : i + 9 + length]))
        i += 9 + length
    return out


def test_h2_stream_reset_sends_rst_stream() -> None:
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    stream = client.send_request(b"GET", b"/", b"2", [(b"host", b"x")])
    stream.reset()  # defaults to CANCEL

    rst = [f for f in _frames(client.data_to_send()) if f[0] == 0x03]
    assert len(rst) == 1
    _, _, sid, payload = rst[0]
    assert sid == stream.stream_id
    assert int.from_bytes(payload, "big") == 0x08  # CANCEL


def test_h2_stream_reset_accepts_an_explicit_code() -> None:
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    stream = client.send_request(b"GET", b"/", b"2", [(b"host", b"x")])
    stream.reset(0x01)  # PROTOCOL_ERROR

    rst = [f for f in _frames(client.data_to_send()) if f[0] == 0x03]
    assert int.from_bytes(rst[0][3], "big") == 0x01


def test_h2_close_sends_goaway_with_the_highest_peer_stream() -> None:
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    client.send_request(b"GET", b"/", b"2", [(b"host", b"x")]).end_message()
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    server.receive_data(client.data_to_send())
    list(drain_h2(server))

    server.close()  # graceful: NO_ERROR, last_stream_id auto
    goaway = [f for f in _frames(server.data_to_send()) if f[0] == 0x07]
    assert len(goaway) == 1
    _, _, _, payload = goaway[0]
    last_stream_id = int.from_bytes(payload[0:4], "big")
    error_code = int.from_bytes(payload[4:8], "big")
    assert last_stream_id == 1  # the one request it processed
    assert error_code == 0  # NO_ERROR


def test_h2_close_accepts_an_explicit_code_and_last_stream_id() -> None:
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    server.close(0x0B, 0)  # ENHANCE_YOUR_CALM, last_stream_id 0

    goaway = [f for f in _frames(server.data_to_send()) if f[0] == 0x07]
    payload = goaway[0][3]
    assert int.from_bytes(payload[0:4], "big") == 0
    assert int.from_bytes(payload[4:8], "big") == 0x0B


def test_h2_close_on_an_http1_connection_is_an_error() -> None:
    conn = zttp.Connection(zttp.SERVER)
    with pytest.raises(AttributeError):
        conn.close()  # ty: ignore[unresolved-attribute]


def test_h2_response_after_stream_reset_is_ignored() -> None:
    # The reset id is closed, not a fresh stream to re-open.
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    opener = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    opener.send_request(b"GET", b"/", b"2", [(b"host", b"x")]).end_message()
    server.receive_data(opener.data_to_send())
    list(drain_h2(server))
    handle = server.stream(1)
    handle.send_response(200, [(b"x", b"y")])
    handle.send_data(b"hi")
    handle.end_message()
    response = server.data_to_send()

    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    stream = client.send_request(b"GET", b"/", b"2", [(b"host", b"x")])
    stream.reset()
    client.data_to_send()  # flush the request + RST_STREAM

    client.receive_data(response)
    events = list(drain_h2(client))
    assert not any(isinstance(e, (zttp.Response, zttp.Data)) for e in events)


def test_h2_peer_settings_is_auto_acked() -> None:
    conn = server_with()  # preface + an empty peer SETTINGS
    list(drain_h2(conn))
    ack = [f for f in _frames(conn.data_to_send()) if f[0] == 0x04 and f[1] & 0x01]
    assert len(ack) == 1  # SETTINGS frame with the ACK flag set


def test_h2_peer_ping_is_auto_acked_with_the_same_payload() -> None:
    conn = server_with()
    list(drain_h2(conn))
    conn.data_to_send()  # flush the SETTINGS ack
    conn.receive_data(frame(0x06, 0, 0, b"PINGDATA"))  # a PING request (not an ack)
    list(drain_h2(conn))
    ack = [f for f in _frames(conn.data_to_send()) if f[0] == 0x06 and f[1] & 0x01]
    assert len(ack) == 1
    assert ack[0][3] == b"PINGDATA"  # the opaque data is echoed


def test_h2_a_ping_ack_is_not_re_acked() -> None:
    conn = server_with()
    list(drain_h2(conn))
    conn.data_to_send()
    conn.receive_data(frame(0x06, 0x01, 0, b"ACKDATA0"))  # a PING with the ACK flag
    list(drain_h2(conn))
    assert [f for f in _frames(conn.data_to_send()) if f[0] == 0x06] == []


def test_h2_consumed_receive_window_is_replenished() -> None:
    conn = server_with(frame(0x01, END_HEADERS, 1, GET_BLOCK))  # open stream 1
    list(drain_h2(conn))
    conn.data_to_send()
    # Three 16 KiB DATA frames (48 KiB) cross the half-window replenish threshold.
    for _ in range(3):
        conn.receive_data(frame(0x00, 0, 1, b"x" * 16000))
    list(drain_h2(conn))
    updates = [f for f in _frames(conn.data_to_send()) if f[0] == 0x08]
    by_stream = {sid: int.from_bytes(payload, "big") for _, _, sid, payload in updates}
    assert by_stream.get(0) == 48000  # connection-level (stream 0)
    assert by_stream.get(1) == 48000  # the stream


def test_h2_a_small_body_does_not_trigger_a_window_update() -> None:
    conn = server_with(frame(0x01, END_HEADERS, 1, GET_BLOCK))
    list(drain_h2(conn))
    conn.data_to_send()
    conn.receive_data(frame(0x00, END_STREAM, 1, b"hello"))  # tiny body, below threshold
    list(drain_h2(conn))
    assert [f for f in _frames(conn.data_to_send()) if f[0] == 0x08] == []


def test_h2_padding_only_data_still_replenishes_the_window() -> None:
    # DATA frames of pure padding consume window but surface no Data event; the
    # window must still be advertised back, or the peer's send window stalls.
    conn = server_with(frame(0x01, END_HEADERS, 1, GET_BLOCK))
    list(drain_h2(conn))
    conn.data_to_send()
    PADDED = 0x08
    padding_only = bytes([255]) + b"\x00" * 255  # 256-byte frame, zero content
    for _ in range(140):  # 140 * 256 = 35840 bytes, past the 32 KiB threshold
        conn.receive_data(frame(0x00, PADDED, 1, padding_only))
    events = list(drain_h2(conn))
    assert not any(isinstance(e, zttp.Data) for e in events)  # nothing surfaced
    updates = [f for f in _frames(conn.data_to_send()) if f[0] == 0x08]
    by_stream = {sid: int.from_bytes(payload, "big") for _, _, sid, payload in updates}
    assert by_stream.get(0, 0) >= 32768  # connection window advertised
    assert by_stream.get(1, 0) >= 32768  # stream window advertised


def test_h2_head_response_with_content_length_is_not_a_stream_error() -> None:
    # A HEAD response carries content-length but no body (RFC 9110 8.6); the
    # content-length vs data-seen check must be skipped, not reset the stream.
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    client.send_request(b"HEAD", b"/", b"2", [(b"host", b"x")]).end_message()
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    server.receive_data(client.data_to_send())
    list(drain_h2(server))
    server.stream(1).send_response(200, [(b"content-length", b"1234")])
    server.stream(1).end_message()
    client.receive_data(frame(0x04, 0, 0, b""))  # server SETTINGS stand-in
    client.receive_data(server.data_to_send())
    events = [type(e).__name__ for e in drain_h2(client)]
    assert events == snapshot(["Settings", "Settings", "Response", "EndOfMessage"])


def _lit(name: bytes, value: bytes) -> bytes:
    # An HPACK literal header field, never indexed, with a literal name.
    return bytes([0x00, len(name)]) + name + bytes([len(value)]) + value


def _request_block(*extra: tuple[bytes, bytes], method: bytes = b"GET") -> bytes:
    block = _lit(b":method", method) + _lit(b":path", b"/") + _lit(b":scheme", b"http") + _lit(b":authority", b"x")
    for name, value in extra:
        block += _lit(name, value)
    return block


def test_h2_bodyless_request_with_content_length_is_reset() -> None:
    # A request declaring content-length but sending no DATA is an h2->h1 smuggling
    # vector (the downgraded h1 request advertises a body that never arrives). It
    # must be reset even though END_STREAM rode on the HEADERS frame, not DATA.
    conn = server_with(frame(0x01, END_HEADERS | END_STREAM, 1, _request_block((b"content-length", b"5"))))
    events = [type(e).__name__ for e in drain_h2(conn)]
    assert "RstStream" in events
    assert "EndOfMessage" not in events


def test_h2_content_length_mismatch_via_trailers_is_reset() -> None:
    # content-length: 5 but only 3 body bytes, with END_STREAM riding on a trailer
    # block - the mismatch must still be caught (not only on the DATA end path).
    conn = server_with(
        frame(0x01, END_HEADERS, 1, _request_block((b"content-length", b"5"), method=b"POST")),
        frame(0x00, 0, 1, b"abc"),  # 3 bytes, no END_STREAM
        frame(0x01, END_HEADERS | END_STREAM, 1, _lit(b"x-trailer", b"v")),
    )
    events = [type(e).__name__ for e in drain_h2(conn)]
    assert "RstStream" in events
    assert "EndOfMessage" not in events


def test_h2_matching_content_length_is_accepted() -> None:
    # The guard must not reject a request whose body matches its content-length.
    conn = server_with(
        frame(0x01, END_HEADERS, 1, _request_block((b"content-length", b"3"), method=b"POST")),
        frame(0x00, END_STREAM, 1, b"abc"),
    )
    events = [type(e).__name__ for e in drain_h2(conn)]
    assert "RstStream" not in events
    assert "EndOfMessage" in events


def test_initiate_connection_emits_the_preface_before_any_send() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    conn.initiate_connection()
    types = [f[0] for f in _frames(conn.data_to_send())]
    assert types == [0x04]  # the server SETTINGS frame, emitted at connection time


def test_initiate_connection_is_idempotent() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    conn.initiate_connection()
    conn.initiate_connection()
    assert len([f for f in _frames(conn.data_to_send()) if f[0] == 0x04]) == 1


def test_initiate_connection_on_http1_is_an_error() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP1)
    with pytest.raises(AttributeError):
        conn.initiate_connection()  # ty: ignore[unresolved-attribute]


def test_send_response_end_stream_rides_the_headers_frame() -> None:
    conn = server_with(frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK))
    list(drain_h2(conn))
    conn.stream(1).send_response(204, end_stream=True)
    frames = [f for f in _frames(conn.data_to_send()) if f[0] in (0x01, 0x00)]
    assert len(frames) == 1  # a single HEADERS frame, no trailing DATA
    ftype, flags, sid, _ = frames[0]
    assert ftype == 0x01 and flags & END_STREAM and sid == 1
    # The END_STREAM head closes the stream locally: it must be evicted, not left
    # half-closed counting toward MAX_CONCURRENT_STREAMS.
    assert conn.stream(1).send_window is None


def test_bodyless_responses_do_not_exhaust_concurrency() -> None:
    # Answer many bodyless requests with end_stream=True; each must free its stream
    # so the connection never refuses a later request (regression: streams used to
    # linger half-closed and count toward the concurrency cap).
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    conn.receive_data(PREFACE + frame(0x04, 0, 0, b""))
    list(drain_h2(conn))
    for sid in range(1, 600, 2):
        conn.receive_data(frame(0x01, END_HEADERS | END_STREAM, sid, GET_BLOCK))
        events = [type(e).__name__ for e in drain_h2(conn)]
        assert "Request" in events
        assert "RstStream" not in events  # never refused
        conn.stream(sid).send_response(204, end_stream=True)
        conn.data_to_send()


def test_send_response_without_end_stream_still_needs_a_data_frame() -> None:
    conn = server_with(frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK))
    list(drain_h2(conn))
    conn.stream(1).send_response(200, [(b"content-length", b"0")])
    headers = [f for f in _frames(conn.data_to_send()) if f[0] == 0x01]
    assert not (headers[0][1] & END_STREAM)  # END_STREAM rides DATA, set by end_message


def test_stream_send_informational_then_final_response() -> None:
    conn = server_with(frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK))
    list(drain_h2(conn))
    conn.stream(1).send_informational(100)
    conn.stream(1).send_response(200, [(b"content-length", b"0")])
    headers = [f for f in _frames(conn.data_to_send()) if f[0] == 0x01]
    assert len(headers) == 2  # interim HEADERS, then final HEADERS
    assert not (headers[0][1] & END_STREAM)  # an interim never ends the stream


def test_stream_send_informational_rejects_non_1xx() -> None:
    conn = server_with(frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK))
    list(drain_h2(conn))
    with pytest.raises(ValueError):
        conn.stream(1).send_informational(200)


def test_stream_send_informational_rejects_101() -> None:
    conn = server_with(frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK))
    list(drain_h2(conn))
    with pytest.raises(ValueError):
        conn.stream(1).send_informational(101)


def test_stream_send_window_and_pending_bytes_track_backpressure() -> None:
    conn = server_with_small_window(5)
    stream = conn.stream(1)
    assert stream.send_window == 5
    stream.send_response(200, [(b"content-type", b"text/plain")])
    stream.send_data(b"hello world")  # 11 bytes, window is 5
    conn.data_to_send()
    assert stream.send_window == 0
    assert stream.pending_bytes == 6  # the 6 bytes the window could not admit


def test_send_window_and_pending_bytes_are_none_for_an_unknown_stream() -> None:
    conn = server_with(frame(0x01, END_HEADERS | END_STREAM, 1, GET_BLOCK))
    list(drain_h2(conn))
    handle = conn.stream(99)
    assert handle.send_window is None
    assert handle.pending_bytes is None


def test_connection_send_window_and_has_pending_send() -> None:
    conn = server_with_small_window(5)
    assert conn.send_window == 65535  # the connection window is still the default
    assert conn.has_pending_send() is False
    stream = conn.stream(1)
    stream.send_response(200, [(b"content-type", b"text/plain")])
    stream.send_data(b"hello world")
    conn.data_to_send()
    assert conn.has_pending_send() is True


def test_h2c_seed_surfaces_the_upgraded_request() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    stream = conn.initiate_upgrade_connection(b"GET", b"/upgrade", [(b"host", b"example.com"), (b"x-k", b"v")])
    assert stream.stream_id == 1
    events = list(drain_h2(conn))
    req = next(e for e in events if isinstance(e, zttp.Request))
    assert req.method == b"GET"
    assert req.target == b"/upgrade"
    assert req.stream_id == 1
    assert (b"host", b"example.com") in req.headers
    assert (b"x-k", b"v") in req.headers
    assert req.end_stream is True
    assert not any(isinstance(e, zttp.EndOfMessage) for e in events)


def test_h2c_seed_then_respond_and_continue_with_the_preface() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    stream = conn.initiate_upgrade_connection(b"GET", b"/", [(b"host", b"x")])
    list(drain_h2(conn))
    stream.send_response(200, end_stream=True)  # answer the upgraded request on stream 1
    assert conn.data_to_send()  # a HEADERS frame went out

    # The client still sends the HTTP/2 preface after the 101, then uses stream 3.
    conn.receive_data(PREFACE + frame(0x04, 0, 0, b"") + frame(0x01, END_HEADERS | END_STREAM, 3, GET_BLOCK))
    req3 = next(e for e in drain_h2(conn) if isinstance(e, zttp.Request))
    assert req3.stream_id == 3


def test_h2c_settings_header_is_applied() -> None:
    import base64

    # The client's HTTP2-Settings header: INITIAL_WINDOW_SIZE (id 4) = 1000.
    settings = base64.urlsafe_b64encode((4).to_bytes(2, "big") + (1000).to_bytes(4, "big")).rstrip(b"=")
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    stream = conn.initiate_upgrade_connection(b"GET", b"/", [(b"host", b"x")], settings_header=settings)
    # The peer's settings governed stream 1's send window (what it will accept).
    assert stream.send_window == 1000


def test_h2c_settings_header_invalid_base64_raises() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    with pytest.raises(ValueError):
        conn.initiate_upgrade_connection(b"GET", b"/", [(b"host", b"x")], settings_header=b"not!base64!")


def test_h2c_settings_header_bad_payload_raises() -> None:
    import base64

    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    bad = base64.urlsafe_b64encode(b"\x00\x04\x00").rstrip(b"=")  # not a multiple of 6
    with pytest.raises(zttp.LocalProtocolError):
        conn.initiate_upgrade_connection(b"GET", b"/", [(b"host", b"x")], settings_header=bad)


def test_h2c_seed_with_many_large_headers_is_intact() -> None:
    # Enough header bytes to force the seed byte-store to grow mid-build; the
    # method/target and every header must survive (regression: a reallocation
    # used to dangle the slices taken before it).
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    headers = [(b"host", b"example.com")] + [(b"x-pad", b"v" * 256) for _ in range(40)]
    conn.initiate_upgrade_connection(b"GET", b"/target", headers)
    req = next(e for e in drain_h2(conn) if isinstance(e, zttp.Request))
    assert req.method == b"GET"
    assert req.target == b"/target"
    assert sum(1 for k, v in req.headers if k == b"x-pad" and v == b"v" * 256) == 40


def test_h2c_seed_rejects_a_forbidden_header() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    with pytest.raises(zttp.LocalProtocolError):
        conn.initiate_upgrade_connection(b"GET", b"/", [(b"connection", b"keep-alive")])


def test_h2c_seed_twice_is_an_error() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    conn.initiate_upgrade_connection(b"GET", b"/", [(b"host", b"x")])
    with pytest.raises(RuntimeError):
        conn.initiate_upgrade_connection(b"GET", b"/", [(b"host", b"x")])


def test_initiate_upgrade_connection_on_http1_is_an_error() -> None:
    conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP1)
    with pytest.raises(AttributeError):
        conn.initiate_upgrade_connection(  # ty: ignore[unresolved-attribute]
            b"GET", b"/", [(b"host", b"x")]
        )
