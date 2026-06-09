"""Shared fuzzing logic for the zttp parser.

The contract under test: driving a `Connection` with *arbitrary* bytes must
never crash the interpreter and must only ever surface a `ProtocolError` (the
public "the peer/caller misbehaved" signal). Any other exception type - an
`AssertionError`, `SystemError`, `MemoryError`, segfault - is a parser bug.

The module exposes a single `consume(data)` entry point so the coverage-guided
runner (Atheris) and the dependency-free random runner share one code path.
"""

from __future__ import annotations

import zttp

# Exceptions the parser is allowed to raise on hostile input. Everything else
# escapes to the caller and is reported as a finding.
ALLOWED = (zttp.ProtocolError,)

ROLES = (zttp.SERVER, zttp.CLIENT)


def _drive(role: int, chunks: list[bytes]) -> None:
    """Feed `chunks` to a connection of `role`, pulling every event out.

    Mirrors how a real I/O loop drives the sans-IO core: receive, then drain to
    NEED_DATA, repeating across reads. Reaching an `EndOfMessage` starts a new
    cycle so pipelined messages keep parsing.
    """
    conn = zttp.Connection(role)
    for chunk in chunks:
        conn.receive_data(chunk)
        while True:
            event = conn.next_event()
            if event is zttp.NEED_DATA or event is zttp.CONNECTION_CLOSED:
                break
            if isinstance(event, zttp.EndOfMessage):
                conn.start_next_cycle()


def _split(data: bytes) -> list[bytes]:
    """Use the first byte as a fragmentation seed so the fuzzer also exercises
    the parser across read boundaries, not just whole-buffer feeds."""
    if not data:
        return [b""]
    seed, body = data[0], data[1:]
    step = (seed & 0x3F) + 1
    if step >= len(body) or seed & 0x40 == 0:
        return [body]
    return [body[i : i + step] for i in range(0, len(body), step)]


def consume(data: bytes) -> None:
    """Single fuzz iteration. Raises only on a real parser bug."""
    role = ROLES[data[0] & 1] if data else zttp.SERVER
    chunks = _split(data[1:] if data else data)
    try:
        _drive(role, chunks)
    except ALLOWED:
        return
