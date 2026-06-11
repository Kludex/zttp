from __future__ import annotations

import pytest

import zttp
from tests.conftest import drain_all

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
GET_BLOCK = bytes([0x82, 0x86, 0x84, 0x41, 0x0F]) + b"www.example.com"


def h2_frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    header = len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + stream_id.to_bytes(4, "big")
    return header + payload


def test_limits_is_public() -> None:
    assert "Limits" in zttp.__all__
    limits: zttp.Limits = {"max_headers": 1}
    assert limits["max_headers"] == 1


def test_max_headers_override_reaches_core() -> None:
    conn = zttp.Connection(zttp.SERVER, zttp.HTTP1, limits={"max_headers": 1})
    conn.receive_data(b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n")
    with pytest.raises(zttp.RemoteProtocolError):
        drain_all(conn)


def test_max_buffer_override_caps_input() -> None:
    conn = zttp.Connection(zttp.SERVER, limits={"max_buffer": 16})
    with pytest.raises(zttp.RemoteProtocolError):
        conn.receive_data(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")


def test_strict_crlf_override_allows_bare_lf() -> None:
    conn = zttp.Connection(zttp.SERVER, limits={"strict_crlf": False})
    conn.receive_data(b"GET / HTTP/1.1\nHost: x\n\n")
    assert isinstance(conn.next_event(), zttp.Request)


def test_default_limits_parse_normally() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n")
    assert isinstance(conn.next_event(), zttp.Request)


def test_unknown_key_raises_value_error() -> None:
    with pytest.raises(ValueError):
        zttp.Connection(zttp.SERVER, limits={"nonsense": 1})


def test_negative_value_raises() -> None:
    with pytest.raises((ValueError, OverflowError)):
        zttp.Connection(zttp.SERVER, limits={"max_headers": -1})


def test_non_dict_limits_raises_type_error() -> None:
    with pytest.raises(TypeError):
        zttp.Connection(zttp.SERVER, limits=5)  # type: ignore[arg-type]


def test_h2_only_key_ignored_on_h1_connection() -> None:
    # An H2-only key on an H1 connection is ignored, not an error, so one dict
    # works regardless of protocol.
    conn = zttp.Connection(zttp.SERVER, zttp.HTTP1, limits={"max_concurrent_streams": 1})
    conn.receive_data(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert isinstance(conn.next_event(), zttp.Request)


def test_h2_max_concurrent_streams_override_refuses_extra_stream() -> None:
    conn = zttp.Connection(zttp.SERVER, zttp.HTTP2, limits={"max_concurrent_streams": 1})
    conn.receive_data(
        PREFACE + h2_frame(0x04, 0, 0, b"") + h2_frame(0x01, 0x04, 1, GET_BLOCK) + h2_frame(0x01, 0x04, 3, GET_BLOCK)
    )
    resets = []
    while True:
        ev = conn.next_event()
        if ev is zttp.NEED_DATA:
            break
        if isinstance(ev, zttp.RstStream):
            resets.append(ev)
    assert [(r.stream_id, r.error_code) for r in resets] == [(3, 7)]


def test_h2_normal_exchange_with_limits_dict() -> None:
    conn = zttp.Connection(zttp.SERVER, zttp.HTTP2, limits={"max_header_list_size": 32 * 1024})
    conn.receive_data(PREFACE + h2_frame(0x04, 0, 0, b"") + h2_frame(0x01, 0x05, 1, GET_BLOCK))
    events = []
    while True:
        ev = conn.next_event()
        if ev is zttp.NEED_DATA:
            break
        events.append(ev)
    assert any(isinstance(e, zttp.Request) for e in events)


def test_h3_limits_rejected() -> None:
    with pytest.raises(ValueError):
        zttp.Connection(zttp.SERVER, zttp.HTTP3, limits={"max_buffer": 1024})
