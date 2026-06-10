"""Compare zttp against httptools and h11 on request parsing throughput.

Each parser consumes the same raw bytes and is driven to extract the same
information (method, headers, body), verified before timing, so the comparison
reflects real work, not just feed_data overhead.

Methodology: every parser runs many short batches, interleaved round-robin so
thermal drift and scheduler placement hit all parsers equally, with the GC
disabled while a batch is timed. The headline number is the median batch, with
the spread reported so noise is visible instead of hidden.
"""

from __future__ import annotations

import argparse
import gc
import statistics
import sys
import time
from collections.abc import Callable
from importlib.metadata import version
from typing import Protocol

import h11
import httptools

import zttp

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
BODY = b'{"username": "alice", "password": "correcthorsebattery"}'
POST = (
    b"POST /api/v1/login HTTP/1.1\r\n"
    b"Host: api.example.com\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: " + str(len(BODY)).encode() + b"\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n" + BODY
)

# The real-world browser request from picohttpparser's bench.c, byte for byte.
# httparse and llhttp benchmark against the same fixture, so results on this
# workload are directly comparable to published parser benchmarks.
PICO = (
    b"GET /wp-content/uploads/2010/03/hello-kitty-darth-vader-pink.jpg HTTP/1.1\r\n"
    b"Host: www.kittyhell.com\r\n"
    b"User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; ja-JP-mac; rv:1.9.2.3) "
    b"Gecko/20100401 Firefox/3.6.3 Pathtraq/0.9\r\n"
    b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    b"Accept-Language: ja,en-us;q=0.7,en;q=0.3\r\n"
    b"Accept-Encoding: gzip,deflate\r\n"
    b"Accept-Charset: Shift_JIS,utf-8;q=0.7,*;q=0.7\r\n"
    b"Keep-Alive: 115\r\n"
    b"Connection: keep-alive\r\n"
    b"Cookie: wp_ozh_wsa_visits=2; wp_ozh_wsa_visit_lasttime=xxxxxxxxxx; "
    b"__utma=xxxxxxxxx.xxxxxxxxxx.xxxxxxxxxx.xxxxxxxxxx.xxxxxxxxxx.x; "
    b"__utmz=xxxxxxxxx.xxxxxxxxxx.x.x.utmccn=(referral)|utmcsr=reader.livedoor.com|"
    b"utmcct=/reader/|utmcmd=referral\r\n"
    b"\r\n"
)

Extracted = tuple[bytes, list[tuple[bytes, bytes]], bytes]


class Runner(Protocol):
    def __call__(self, data: bytes, n: int) -> None: ...


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


def run_zttp(data: bytes, n: int) -> None:
    NEED_DATA = zttp.NEED_DATA
    EndOfMessage = zttp.EndOfMessage
    Connection = zttp.Connection
    SERVER = zttp.SERVER
    for _ in range(n):
        conn = Connection(SERVER)
        conn.receive_data(data)
        while True:
            ev = conn.next_event()
            if ev is NEED_DATA or type(ev) is EndOfMessage:
                break


def extract_httptools(data: bytes) -> Extracted:
    p = HttptoolsProto()
    parser = httptools.HttpRequestParser(p)
    parser.feed_data(data)
    return parser.get_method(), p.headers, p.body


def extract_h11(data: bytes) -> Extracted:
    conn = h11.Connection(h11.SERVER)
    conn.receive_data(data)
    method, headers, body = b"", [], b""
    while True:
        ev = conn.next_event()
        if isinstance(ev, h11.Request):
            method, headers = ev.method, list(ev.headers)
        elif isinstance(ev, h11.Data):
            body += ev.data
        elif ev is h11.NEED_DATA or isinstance(ev, h11.EndOfMessage):
            break
    return method, headers, body


def extract_zttp(data: bytes) -> Extracted:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(data)
    method, headers, body = b"", [], b""
    while True:
        ev = conn.next_event()
        if isinstance(ev, zttp.Request):
            method, headers = ev.method, ev.headers
        elif isinstance(ev, zttp.Data):
            body += ev.data
        elif ev is zttp.NEED_DATA or isinstance(ev, zttp.EndOfMessage):
            break
    return method, headers, body


PARSERS: list[tuple[str, Runner, Callable[[bytes], Extracted]]] = [
    ("zttp", run_zttp, extract_zttp),
    ("httptools", run_httptools, extract_httptools),
    ("h11", run_h11, extract_h11),
]


def verify(data: bytes) -> None:
    def normalized(extracted: Extracted) -> tuple[bytes, list[tuple[bytes, bytes]], bytes]:
        method, headers, body = extracted
        return method, sorted((name.lower(), value) for name, value in headers), body

    reference = normalized(PARSERS[0][2](data))
    for label, _, extract in PARSERS[1:]:
        got = normalized(extract(data))
        if got != reference:
            raise AssertionError(f"{label} extracted {got!r}, zttp extracted {reference!r}")


def timed(fn: Runner, data: bytes, n: int) -> float:
    gc.collect()
    gc.disable()
    try:
        t0 = time.perf_counter()
        fn(data, n)
        return time.perf_counter() - t0
    finally:
        gc.enable()


def bench(name: str, data: bytes, batch: int, repeats: int) -> None:
    verify(data)
    total = batch * repeats
    print(f"\n== {name} ({repeats} batches of {batch:,}, {total:,} iterations per parser) ==")

    for _, fn, _ in PARSERS:
        fn(data, 2_000)  # warmup: caches, allocator, JIT-ish lazy init

    samples: dict[str, list[float]] = {label: [] for label, _, _ in PARSERS}
    for _ in range(repeats):
        for label, fn, _ in PARSERS:
            samples[label].append(timed(fn, data, batch))

    rates = {}
    for label, batches in samples.items():
        per_batch = [batch / dt for dt in batches]
        median = statistics.median(per_batch)
        spread = (max(per_batch) - min(per_batch)) / median * 100
        rates[label] = median
        print(f"  {label:>10}: {median:12,.0f} req/s  (median of {repeats}, spread {spread:4.1f}%)")

    print(f"  -> zttp is {rates['zttp'] / rates['httptools']:.2f}x httptools, {rates['zttp'] / rates['h11']:.2f}x h11")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=int, default=20_000, help="iterations per timed batch")
    parser.add_argument("--repeats", type=int, default=15, help="timed batches per parser")
    args = parser.parse_args()

    print(
        f"CPython {sys.version.split()[0]}, zttp {version('zttp')}, "
        f"httptools {version('httptools')}, h11 {version('h11')}"
    )
    bench("simple GET", SIMPLE, args.batch, args.repeats)
    bench("POST + body", POST, args.batch, args.repeats)
    bench("real-world GET (picohttpparser fixture)", PICO, args.batch, args.repeats)


if __name__ == "__main__":
    main()
