from __future__ import annotations

from collections.abc import Iterator

import zhttp


def drain(conn: zhttp.Connection) -> Iterator[object]:
    """Pull events until NEED_DATA, yielding each real event."""
    while True:
        ev = conn.next_event()
        if ev is zhttp.NEED_DATA:
            return
        yield ev
        if isinstance(ev, zhttp.EndOfMessage):
            return


def parse_request(data: bytes) -> list[object]:
    conn = zhttp.Connection(zhttp.SERVER)
    conn.receive_data(data)
    return list(drain(conn))
