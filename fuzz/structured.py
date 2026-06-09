"""Map raw fuzzer bytes into structured HTTP requests.

Feeding pure random bytes mostly exercises the first few bytes of the parser
before it bails. A light grammar steers the fuzzer toward well-formed-ish
requests so it reaches header parsing, framing, and chunked decoding - while
still letting mutations drive the values into hostile territory.
"""

from __future__ import annotations

METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"\x00BAD")
TARGETS = (b"/", b"/a/b?c=d", b"*", b"/%2e%2e/", b"/" + b"x" * 64)
HEADER_NAMES = (b"Host", b"Content-Length", b"Transfer-Encoding", b"X-Fuzz", b"Connection", b"Expect")
HEADER_VALUES = (b"x", b"0", b"5", b"chunked", b"close", b"keep-alive", b"100-continue", b"a\r\nb")

# Headers whose values the encoder and decoder agree on byte-for-byte; the
# roundtrip oracle draws from these so a mismatch means a real corruption, not
# the known framing-strictness asymmetry between send and parse.
SAFE_NAMES = (b"Host", b"X-Fuzz", b"User-Agent", b"Accept", b"X-A", b"X-B")
SAFE_VALUES = (b"x", b"value", b"a-b-c", b"1", b"text/plain", b"")


class _Reader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def byte(self) -> int:
        if self._pos >= len(self._data):
            return 0
        value = self._data[self._pos]
        self._pos += 1
        return value

    def pick(self, choices: tuple[bytes, ...]) -> bytes:
        return choices[self.byte() % len(choices)]

    def chunk(self, length: int) -> bytes:
        out = self._data[self._pos : self._pos + length]
        self._pos += length
        return out


def draw_request(data: bytes, *, safe: bool = False) -> tuple[bytes, bytes, list[tuple[bytes, bytes]], bytes]:
    """Decode `data` into (method, target, headers, body).

    With `safe=True`, headers are drawn from names/values the encoder and parser
    treat identically, so the roundtrip oracle's equality checks stay meaningful.
    """
    reader = _Reader(data)
    method = reader.pick(METHODS)
    target = reader.pick(TARGETS)
    names, values = (SAFE_NAMES, SAFE_VALUES) if safe else (HEADER_NAMES, HEADER_VALUES)

    count = reader.byte() % 8
    headers = [(reader.pick(names), reader.pick(values)) for _ in range(count)]

    body = reader.chunk(reader.byte())
    return method, target, headers, body
