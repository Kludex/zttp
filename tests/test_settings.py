from __future__ import annotations

import zttp
from zttp import H2Settings


def test_h2_settings_ids_match_the_wire() -> None:
    assert H2Settings.MAX_CONCURRENT_STREAMS == 0x03
    assert H2Settings.MAX_HEADER_LIST_SIZE == 0x06
    # It is a real IntEnum: usable directly as the integer id.
    assert int(H2Settings.HEADER_TABLE_SIZE) == 1
    assert zttp.H2Settings is H2Settings


def test_h2_settings_names_a_params_id() -> None:
    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    server.initiate_connection()
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    client.receive_data(server.data_to_send())
    settings = next(e for e in _drain(client) if isinstance(e, zttp.Settings))
    values = dict(settings.params)
    assert H2Settings.MAX_CONCURRENT_STREAMS in values


def _drain(conn: zttp.Connection) -> list[object]:
    events: list[object] = []
    while True:
        ev = conn.next_event()
        if ev is zttp.NEED_DATA:
            return events
        events.append(ev)
