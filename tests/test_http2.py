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


def test_protocol_defaults_to_http1() -> None:
    conn = zttp.Connection(zttp.SERVER)  # no protocol arg
    conn.receive_data(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert isinstance(conn.next_event(), zttp.Request)


def test_invalid_protocol_rejected() -> None:
    with pytest.raises(ValueError):
        zttp.Connection(zttp.SERVER, protocol=99)
