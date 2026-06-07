from __future__ import annotations

from collections.abc import Iterator

import zttp


def drain(conn: zttp.Connection) -> Iterator[object]:
    """Pull events until NEED_DATA, yielding each real event."""
    while True:
        ev = conn.next_event()
        if ev is zttp.NEED_DATA:
            return
        yield ev
        if isinstance(ev, zttp.EndOfMessage):
            return


def parse_request(data: bytes) -> list[object]:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(data)
    return list(drain(conn))


def drain_all(conn: zttp.Connection) -> None:
    """Pull events until NEED_DATA. Used by tests asserting an error is raised
    before NEED_DATA is ever reached."""
    while conn.next_event() is not zttp.NEED_DATA:
        pass
