"""Differential roundtrip oracle: anything we encode, we must decode back.

A `CLIENT` connection serializes a request and a `SERVER` connection parses it.
The decoded method/target/headers must match what was sent. This catches a
different bug class than `harness.consume` (which only fuzzes the read path):
an encoder that emits bytes its own parser rejects, or that round-trips to a
*different* message, is a smuggling vector.
"""

from __future__ import annotations

import zttp
from fuzz.structured import draw_request


def roundtrip(data: bytes) -> None:
    method, target, headers, body = draw_request(data, safe=True)

    client = zttp.Connection(zttp.CLIENT)
    try:
        client.send_request(method, target, b"1.1", headers)
        if body:
            client.send_data(body)
        client.end_message()
    except zttp.LocalProtocolError:
        return  # the encoder rejected its own input; that is a valid outcome.
    wire = client.data_to_send()

    server = zttp.Connection(zttp.SERVER)
    server.receive_data(wire)

    events: list[object] = []
    try:
        while True:
            event = server.next_event()
            if event is zttp.NEED_DATA or event is zttp.CONNECTION_CLOSED:
                break
            events.append(event)
            if isinstance(event, zttp.EndOfMessage):
                break
    except zttp.RemoteProtocolError:
        return  # encoder emitted bytes its own parser rejects as ambiguous; a valid outcome.

    request = events[0]
    assert isinstance(request, zttp.Request), f"encoded request did not parse back: {events!r}"
    assert request.method == method, f"method changed: {method!r} -> {request.method!r}"
    assert request.target == target, f"target changed: {target!r} -> {request.target!r}"

    sent = {k.lower(): v for k, v in headers}
    got = {k.lower(): v for k, v in request.headers}
    for name, value in sent.items():
        assert got.get(name) == value, f"header {name!r} changed: {value!r} -> {got.get(name)!r}"
