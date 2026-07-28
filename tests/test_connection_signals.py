from __future__ import annotations

import pytest

import zttp
from tests.conftest import drain


def _parse(data: bytes) -> zttp.Connection:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(data)
    list(drain(conn))
    return conn


def test_should_close_explicit() -> None:
    conn = _parse(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert conn.should_close() is True


def test_should_close_keep_alive_default_for_1_1() -> None:
    conn = _parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert conn.should_close() is False


def test_should_close_1_0_closes_by_default() -> None:
    conn = _parse(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
    assert conn.should_close() is True


def test_should_close_1_0_with_keep_alive_stays_open() -> None:
    conn = _parse(b"GET / HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
    assert conn.should_close() is False


def test_should_close_token_in_list() -> None:
    conn = _parse(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, close\r\n\r\n")
    assert conn.should_close() is True


def test_should_close_resets_after_cycle() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET /a HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    list(drain(conn))
    assert conn.should_close() is True
    conn.start_next_cycle()
    conn.receive_data(b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n")
    list(drain(conn))
    assert conn.should_close() is False


def test_client_should_close_explicit_response_close() -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.receive_data(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
    assert isinstance(conn.next_event(), zttp.Response)
    assert conn.should_close() is True


def test_client_should_close_for_close_delimited_response() -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.receive_data(b"HTTP/1.1 200 OK\r\n\r\nbody")
    assert isinstance(conn.next_event(), zttp.Response)
    assert conn.should_close() is True


def _respond(*headers: tuple[bytes, bytes]) -> zttp.Connection:
    conn = _parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert conn.should_close() is False
    conn.send_response(200, [(b"content-length", b"0"), *headers])
    conn.end_message()
    return conn


def test_should_close_for_locally_sent_response_close() -> None:
    assert _respond((b"connection", b"close")).should_close() is True


def test_should_close_for_locally_sent_response_token_in_list() -> None:
    assert _respond((b"connection", b"keep-alive, close")).should_close() is True


def test_should_close_for_locally_sent_response_is_case_insensitive() -> None:
    assert _respond((b"Connection", b"CLOSE")).should_close() is True


def test_locally_sent_response_without_close_stays_open() -> None:
    assert _respond((b"connection", b"keep-alive")).should_close() is False
    assert _respond().should_close() is False


def test_should_close_for_locally_sent_request_close() -> None:
    conn = zttp.Connection(zttp.CLIENT)
    conn.send_request(b"GET", b"/", b"1.1", [(b"Host", b"x"), (b"Connection", b"close")])
    conn.end_message()
    assert conn.should_close() is True


def test_peer_close_survives_a_response_without_close() -> None:
    conn = _parse(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    conn.send_response(200, [(b"content-length", b"0")])
    conn.end_message()
    assert conn.should_close() is True


def test_rejected_response_does_not_set_should_close() -> None:
    conn = _parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    with pytest.raises(zttp.LocalProtocolError):
        conn.send_response(204, [(b"transfer-encoding", b"chunked"), (b"connection", b"close")])
    assert conn.should_close() is False
    assert conn.data_to_send() == b""


def test_upgrade_websocket() -> None:
    conn = _parse(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
    assert conn.upgrade() == b"websocket"


def test_upgrade_none_without_connection_token() -> None:
    conn = _parse(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n")
    assert conn.upgrade() is None


def test_upgrade_none_for_plain_request() -> None:
    conn = _parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert conn.upgrade() is None


def test_upgrade_resets_after_cycle() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
    list(drain(conn))
    assert conn.upgrade() == b"websocket"
    conn.start_next_cycle()
    conn.receive_data(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    list(drain(conn))
    assert conn.upgrade() is None


def test_expect_continue_present() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nExpect: 100-continue\r\n\r\n")
    req = conn.next_event()
    assert isinstance(req, zttp.Request)
    assert req.expect_continue is True


def test_expect_continue_absent() -> None:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
    req = conn.next_event()
    assert isinstance(req, zttp.Request)
    assert req.expect_continue is False
