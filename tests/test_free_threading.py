from __future__ import annotations

import concurrent.futures
import sys
import sysconfig
import threading
from typing import cast

import pytest
from typing_extensions import Protocol

import zttp


class FreeThreadedSys(Protocol):
    def _is_gil_enabled(self) -> bool: ...


def test_free_threaded_build_keeps_gil_disabled() -> None:
    if not sysconfig.get_config_var("Py_GIL_DISABLED"):
        pytest.skip("requires a free-threaded CPython build")
    assert not cast(FreeThreadedSys, sys)._is_gil_enabled()


def test_shared_connection_serializes_calls() -> None:
    conn = zttp.Connection(zttp.SERVER)
    request = b"GET / HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    count = 300
    conn.receive_data(request * count)
    barrier = threading.Barrier(2)

    def consume() -> None:
        barrier.wait()
        for index in range(count):
            assert isinstance(conn.next_event(), zttp.Request)
            assert conn.next_event() is zttp.NEED_DATA
            if index + 1 < count:
                conn.start_next_cycle()

    def inspect() -> None:
        barrier.wait()
        for _ in range(10_000):
            assert conn.upgrade() in (None, b"websocket")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        consume_future = executor.submit(consume)
        inspect_future = executor.submit(inspect)
        consume_future.result()
        inspect_future.result()
