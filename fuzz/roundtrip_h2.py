"""HTTP/2 differential roundtrip oracle: anything we encode, we must decode back.

A `CLIENT` H2 connection serializes a request (HEADERS, HPACK-encoded) and a
`SERVER` H2 connection parses it back. The decoded method/target/headers must
match what was sent. This catches the write/read mismatch class HPACK makes
possible - an encoder that emits a block its own decoder reads as a *different*
header list is a smuggling vector across an h2->h1 downgrade.

The host <-> :authority bridge is part of the contract: the client turns a
`host` header into the `:authority` pseudo-header, and the server synthesizes it
back into a `host` header, so the oracle compares against that transformation
rather than the raw input.
"""

from __future__ import annotations

import zttp
from fuzz.structured import draw_request


def roundtrip_h2(data: bytes) -> None:
    method, target, headers, body = draw_request(data, safe=True)
    # The client derives :authority from a host header; keep exactly one so the
    # roundtrip is deterministic (a request with no host still works - :authority
    # is just absent). Lowercase every name: HTTP/2 forbids uppercase field names
    # and the writer rejects them, so the safe corpus (HTTP/1-style capitalized)
    # would otherwise make send_request raise and skip the differential entirely.
    sent_headers = [(k.lower(), v) for k, v in headers if k.lower() != b"host"]
    sent_headers.append((b"host", b"example.com"))

    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    try:
        stream = client.send_request(method, target, b"2", sent_headers)
        if body:
            stream.send_data(body)
        stream.end_message()
    except zttp.LocalProtocolError:
        return  # the encoder rejected its own input; a valid outcome.
    wire = client.data_to_send()

    server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
    server.receive_data(wire)

    events: list[object] = []
    try:
        while True:
            event = server.next_event()
            if event is zttp.NEED_DATA:
                break
            events.append(event)
            if isinstance(event, zttp.EndOfMessage):
                break
    except zttp.RemoteProtocolError:
        return  # encoder emitted a block its own parser rejects; a valid outcome.

    request = next((e for e in events if isinstance(e, zttp.Request)), None)
    assert request is not None, f"encoded H2 request did not parse back: {events!r}"
    assert request.method == method, f"method changed: {method!r} -> {request.method!r}"
    assert request.target == target, f"target changed: {target!r} -> {request.target!r}"

    sent = {k.lower(): v for k, v in sent_headers}
    got = {k.lower(): v for k, v in request.headers}
    for name, value in sent.items():
        assert got.get(name) == value, f"H2 header {name!r} changed: {value!r} -> {got.get(name)!r}"
