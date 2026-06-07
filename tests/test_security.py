from __future__ import annotations

import gc

import pytest

import zttp
from tests.conftest import drain


def _drain_until_error_or_end(conn: zttp.Connection) -> list[object]:
    return list(drain(conn))


def test_h2_synthesizing_sequence_headers_roundtrip() -> None:
    # A sequence whose __getitem__ returns fresh bytes per call was a
    # use-after-free in borrowHeaders; the held refs must keep them alive.
    class Synth:
        def __init__(self, n: int) -> None:
            self.n = n

        def __len__(self) -> int:
            return self.n

        def __getitem__(self, i: int) -> tuple[bytes, bytes]:
            if i >= self.n:  # pragma: no cover - sequence-protocol guard, not hit via __len__-bounded access
                raise IndexError
            return (b"Header-%02d" % i, b"value-%02d-%s" % (i, b"x" * 24))

    n = 40
    client = zttp.Connection(zttp.CLIENT)
    client.send_request(b"GET", b"/", b"1.1", Synth(n))
    client.end_message()
    wire = client.data_to_send()

    server = zttp.Connection(zttp.SERVER)
    server.receive_data(wire)
    req = server.next_event()
    assert isinstance(req, zttp.Request)
    got = dict(req.headers)
    for i in range(n):
        assert got[b"Header-%02d" % i] == b"value-%02d-%s" % (i, b"x" * 24)


@pytest.mark.parametrize(
    "headers",
    [
        b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n",
        b"Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n",
        b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
    ],
)
def test_h3_split_transfer_encoding_rejected(headers: bytes) -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"POST / HTTP/1.1\r\nHost: x\r\n" + headers + b"\r\n5\r\nhello\r\n0\r\n\r\n")
    with pytest.raises(zttp.RemoteProtocolError):
        _drain_until_error_or_end(conn)


def test_h4_trailer_flood_rejected() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n")
    assert isinstance(conn.next_event(), zttp.Request)
    flood = b"".join(b"X-%d: y\r\n" % i for i in range(500))
    conn.receive_data(flood)
    with pytest.raises(zttp.RemoteProtocolError):
        _drain_until_error_or_end(conn)


def test_trailer_survives_large_followup_feed() -> None:
    # H-1: store a trailer, then force a buffer realloc before EndOfMessage.
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
    assert isinstance(conn.next_event(), zttp.Request)
    conn.receive_data(b"0\r\nX-Trailer: SECRET\r\n")
    assert conn.next_event() is zttp.NEED_DATA
    conn.receive_data(b"\r\n")
    events = _drain_until_error_or_end(conn)
    eom = events[-1]
    assert isinstance(eom, zttp.EndOfMessage)
    assert eom.trailers == [(b"X-Trailer", b"SECRET")]


def test_bare_lf_request_rejected_by_default() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET / HTTP/1.1\nHost: x\n\n")
    with pytest.raises(zttp.RemoteProtocolError):
        _drain_until_error_or_end(conn)


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.send_response(b"1.1", 200, b"OK\r\nX-Evil: 1", [], True),
        lambda c: c.send_response(b"1.1", 200, b"OK", [(b"X", b"a\r\nInjected: 1")], True),
        lambda c: c.send_request(b"GET", b"/ HTTP/1.1\r\nX: y", b"1.1", []),
        lambda c: c.send_request(b"GET", b"/", b"1.1", [(b"Bad Name", b"x")]),
    ],
)
def test_send_path_injection_rejected(call) -> None:  # type: ignore[no-untyped-def]
    conn = zttp.Connection(zttp.SERVER)
    with pytest.raises(zttp.LocalProtocolError):
        call(conn)


def test_event_cycle_is_collectable() -> None:
    class Canary:
        n = 0

        def __init__(self) -> None:
            Canary.n += 1

        def __del__(self) -> None:
            Canary.n -= 1

    def make_cycle() -> None:
        c = zttp.Connection(zttp.SERVER)
        c.receive_data(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        e = c.next_event()
        can = Canary()
        e.headers.append(e)
        e.headers.append(can)
        can.back = e

    for _ in range(25):
        make_cycle()
    gc.collect()
    gc.collect()
    assert Canary.n == 0


def test_event_types_are_gc_tracked() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
    ev = conn.next_event()
    assert gc.is_tracked(ev)
