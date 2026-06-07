"""Compare zhttp against httptools and h11 on request parsing throughput.

Each parser consumes the same raw bytes and is driven to extract the same
information (method, headers, body) so the comparison reflects real work, not
just feed_data overhead.
"""

from __future__ import annotations

import time

import h11
import httptools

import zhttp

# A typical small request with a handful of headers and no body.
SIMPLE = (
    b"GET /api/v1/users/12345?include=profile HTTP/1.1\r\n"
    b"Host: api.example.com\r\n"
    b"User-Agent: Mozilla/5.0 (compatible; bench/1.0)\r\n"
    b"Accept: application/json\r\n"
    b"Accept-Encoding: gzip, deflate, br\r\n"
    b"Connection: keep-alive\r\n"
    b"Authorization: Bearer abcdef0123456789\r\n"
    b"\r\n"
)

# A POST with a JSON body.
POST = (
    b"POST /api/v1/login HTTP/1.1\r\n"
    b"Host: api.example.com\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: 53\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
    b'{"username": "alice", "password": "correcthorsebattery"}'[:53]
)


class HttptoolsProto:
    __slots__ = ("headers", "url", "body")

    def __init__(self) -> None:
        self.headers: list[tuple[bytes, bytes]] = []
        self.url = b""
        self.body = b""

    def on_url(self, url: bytes) -> None:
        self.url += url

    def on_header(self, name: bytes, value: bytes) -> None:
        self.headers.append((name, value))

    def on_body(self, body: bytes) -> None:
        self.body += body

    def on_message_complete(self) -> None:
        pass


def run_httptools(data: bytes, n: int) -> None:
    for _ in range(n):
        p = HttptoolsProto()
        parser = httptools.HttpRequestParser(p)
        parser.feed_data(data)
        parser.get_method()


def run_h11(data: bytes, n: int) -> None:
    for _ in range(n):
        conn = h11.Connection(h11.SERVER)
        conn.receive_data(data)
        while True:
            ev = conn.next_event()
            if ev is h11.NEED_DATA or isinstance(ev, h11.EndOfMessage):
                break


def run_zhttp(data: bytes, n: int) -> None:
    NEED_DATA = zhttp.NEED_DATA
    EndOfMessage = zhttp.EndOfMessage
    Connection = zhttp.Connection
    SERVER = zhttp.SERVER
    for _ in range(n):
        conn = Connection(SERVER)
        conn.receive_data(data)
        while True:
            ev = conn.next_event()
            if ev is NEED_DATA or type(ev) is EndOfMessage:
                break


def time_it(fn, data: bytes, n: int) -> float:
    fn(data, 1000)  # warmup
    best = min(timed(fn, data, n) for _ in range(5))
    return best


def timed(fn, data: bytes, n: int) -> float:
    t0 = time.perf_counter()
    fn(data, n)
    return time.perf_counter() - t0


def bench(name: str, data: bytes, n: int) -> None:
    print(f"\n== {name} ({n:,} iterations) ==")
    results = {}
    for label, fn in (("zhttp", run_zhttp), ("httptools", run_httptools), ("h11", run_h11)):
        dt = time_it(fn, data, n)
        rate = n / dt
        results[label] = rate
        print(f"  {label:>10}: {dt * 1e3:8.2f} ms  {rate:12,.0f} req/s")
    base = results["httptools"]
    print(f"  -> zhttp is {results['zhttp'] / base:.2f}x httptools, {results['zhttp'] / results['h11']:.2f}x h11")


if __name__ == "__main__":
    bench("simple GET", SIMPLE, 200_000)
    bench("POST + body", POST, 200_000)
