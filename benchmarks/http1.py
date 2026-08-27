"""Compare zttp against httptools and h11 on request parsing throughput.

Each parser consumes the same raw bytes and is driven to extract the same
information (request line or status, headers, body), verified before timing,
so the comparison reflects real work, not just feed_data overhead.

Methodology: every parser runs many short batches, interleaved round-robin so
thermal drift and scheduler placement hit all parsers equally, with the GC
disabled while a batch is timed. The headline number is the median batch,
reported with its p25-p75 quartiles and stdev so run-to-run noise is visible
instead of hidden.

The workloads are drawn from the parser-benchmark literature wherever one
exists (picohttpparser/llhttp/httparse fixtures, the wrk and TechEmpower
request shapes) and faithful reconstructions of modern traffic where none does
(a Chrome navigation, a k8s-ingress proxied API call). Provenance is noted on
each fixture.
"""

from __future__ import annotations

import argparse
import gc
import statistics
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import version

import h11
import httptools

import zttp

# -- request fixtures -----------------------------------------------------------

# wrk's default request (wg/wrk src/wrk.lua): GET / with only a Host header.
# The latency floor: fixed per-message overhead with almost no scanning.
WRK_GET = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

# httparse REQ_SHORT (seanmonstar/httparse benches/parse.rs), byte for byte.
HTTPARSE_SHORT = b"GET / HTTP/1.0\r\nHost: example.com\r\nCookie: session=60; user_id=1\r\n\r\n"

# The TechEmpower plaintext request (toolset/wrk/pipeline.sh), pipelined 16x
# back-to-back exactly as TFB's pipeline.lua writes it. h11's state machine
# cannot read a second request before a response is sent, so it sits out.
TFB_PLAINTEXT = (
    b"GET /plaintext HTTP/1.1\r\n"
    b"Host: tfb-server\r\n"
    b"Accept: text/plain,text/html;q=0.9,application/xhtml+xml;q=0.9,application/xml;q=0.8,*/*;q=0.7\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
) * 16

# A typical small API request with a handful of headers and no body.
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
JSON_BODY = b'{"username": "alice", "password": "correcthorsebattery"}'
POST = (
    b"POST /api/v1/login HTTP/1.1\r\n"
    b"Host: api.example.com\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: " + str(len(JSON_BODY)).encode() + b"\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n" + JSON_BODY
)

# The real-world browser request from picohttpparser's bench.c, byte for byte.
# llhttp benchmarks the same bytes; httparse's REQ differs only by a cookie
# padding suffix. Results on this workload are directly comparable to
# published parser benchmarks.
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

# llhttp's second benchmark fixture (bench/native.ts, "nodejs/http-parser"):
# a Chrome-39-shaped POST with a chunked body, from http-parser's bench.c.
CHUNKED_POST = (
    b"POST /joyent/http-parser HTTP/1.1\r\n"
    b"Host: github.com\r\n"
    b"DNT: 1\r\n"
    b"Accept-Encoding: gzip, deflate, sdch\r\n"
    b"Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
    b"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 "
    b"(KHTML, like Gecko) Chrome/39.0.2171.65 Safari/537.36\r\n"
    b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
    b"Referer: https://github.com/joyent/http-parser\r\n"
    b"Connection: keep-alive\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Cache-Control: max-age=0\r\n"
    b"\r\n"
    b"b\r\nhello world\r\n0\r\n\r\n"
)

# A modern Chrome top-level navigation over HTTP/1.1 (reconstruction: header
# set and order as Chrome 130 emits them, incl. client hints, Sec-Fetch-* and
# RFC 9218 Priority).
CHROME_GET = (
    b"GET / HTTP/1.1\r\n"
    b"Host: www.example.com\r\n"
    b"Connection: keep-alive\r\n"
    b'sec-ch-ua: "Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"\r\n'
    b"sec-ch-ua-mobile: ?0\r\n"
    b'sec-ch-ua-platform: "macOS"\r\n'
    b"Upgrade-Insecure-Requests: 1\r\n"
    b"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    b"(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n"
    b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
    b"image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
    b"Sec-Fetch-Site: none\r\n"
    b"Sec-Fetch-Mode: navigate\r\n"
    b"Sec-Fetch-User: ?1\r\n"
    b"Sec-Fetch-Dest: document\r\n"
    b"Accept-Encoding: gzip, deflate, br, zstd\r\n"
    b"Accept-Language: en-US,en;q=0.9\r\n"
    b"Cookie: _ga=GA1.2.1234567890.1700000000; _gid=GA1.2.987654321.1717000000; "
    b"session_id=a1b2c3d4e5f64758a9b0c1d2e3f40516; csrftoken=Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0De\r\n"
    b"Priority: u=0, i\r\n"
    b"\r\n"
)

# East-west API traffic as a pod sees it behind ingress-nginx (reconstruction:
# the X-Forwarded-* family ingress-nginx injects, W3C trace context, and a
# realistically long opaque bearer token).
PROXIED_GET = (
    b"GET /api/v1/users/123?include=profile HTTP/1.1\r\n"
    b"Host: api.example.com\r\n"
    b"X-Request-ID: 7f3b9c2e4d5a6f8190a1b2c3d4e5f607\r\n"
    b"X-Real-IP: 203.0.113.7\r\n"
    b"X-Forwarded-For: 203.0.113.7\r\n"
    b"X-Forwarded-Host: api.example.com\r\n"
    b"X-Forwarded-Port: 443\r\n"
    b"X-Forwarded-Proto: https\r\n"
    b"X-Forwarded-Scheme: https\r\n"
    b"X-Scheme: https\r\n"
    b"traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n"
    b"authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9."
    b"eyJzdWIiOiJ1c2VyXzEyMyIsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSIsImF1ZCI6ImFwaSIsImV4cCI6"
    b"MTcxNzI1OTIwMCwiaWF0IjoxNzE3MjU1NjAwLCJzY29wZSI6InJlYWQ6dXNlcnMifQ."
    b"sig_X9yZ2vQ8wR7tU6sP5oN4mL3kJ2hG1fE0dC9bA8z\r\n"
    b"accept: application/json\r\n"
    b"user-agent: python-httpx/0.27.0\r\n"
    b"accept-encoding: gzip, br\r\n"
    b"\r\n"
)

# A 16KB octet-stream upload, whole-buffer and again in 1448-byte pieces
# (TCP segments at a typical 1500-MTU), exercising resumable parsing.
UPLOAD_BODY = b"x" * 16384
UPLOAD = (
    b"POST /upload HTTP/1.1\r\n"
    b"Host: files.example.com\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Content-Length: " + str(len(UPLOAD_BODY)).encode() + b"\r\n"
    b"\r\n" + UPLOAD_BODY
)

# -- response fixtures (CLIENT role) ----------------------------------------------

# httparse RESP_SHORT (benches/parse.rs) plus a Content-Length: 0 line: the
# original is head-only (HTTP/1.0 reads the body until EOF, which httptools
# cannot signal), so the added header terminates the message for everyone.
HTTPARSE_RESP_SHORT = (
    b"HTTP/1.0 200 OK\r\n"
    b"Date: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
    b"Set-Cookie: session=60; user_id=1\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)

# A TechEmpower-JSON-shaped API response.
RESP_JSON_BODY = b'{"message": "Hello, World!"}'
RESP_JSON = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: uvicorn\r\n"
    b"Date: Wed, 10 Jun 2026 07:28:00 GMT\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: " + str(len(RESP_JSON_BODY)).encode() + b"\r\n"
    b"\r\n" + RESP_JSON_BODY
)


# A chunked HTML page: the streaming-response framing path.
def _chunk(data: bytes) -> bytes:
    return f"{len(data):x}".encode() + b"\r\n" + data + b"\r\n"


RESP_CHUNKED = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx/1.27.0\r\n"
    b"Date: Wed, 10 Jun 2026 07:28:00 GMT\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
    + _chunk(b"<p>" + b"a" * 1021)
    + _chunk(b"b" * 1020 + b"</p>")
    + _chunk(b"<!-- generated -->")
    + b"0\r\n\r\n"
)

# -- workloads --------------------------------------------------------------------


@dataclass(frozen=True)
class Workload:
    name: str
    raw: bytes
    kind: str = "request"  # "request" | "response"
    messages: int = 1
    fragment: int | None = None
    scale: float = 1.0  # batch-size multiplier for heavyweight inputs
    h11_ok: bool = True


WORKLOADS = [
    Workload("wrk default GET", WRK_GET),
    Workload("httparse REQ_SHORT", HTTPARSE_SHORT),
    Workload("TFB plaintext x16 pipelined", TFB_PLAINTEXT, messages=16, scale=0.25, h11_ok=False),
    Workload("small API GET", SIMPLE),
    Workload("POST + JSON body", POST),
    Workload("real-world GET (pico/llhttp)", PICO),
    Workload("chunked POST (llhttp bench)", CHUNKED_POST),
    Workload("Chrome navigation GET", CHROME_GET),
    Workload("k8s ingress proxied GET", PROXIED_GET),
    Workload("16KB upload POST", UPLOAD, scale=0.5),
    Workload("16KB upload, MTU pieces", UPLOAD, fragment=1448, scale=0.25),
    Workload("httparse RESP_SHORT", HTTPARSE_RESP_SHORT, kind="response"),
    Workload("JSON API response", RESP_JSON, kind="response"),
    Workload("chunked HTML response", RESP_CHUNKED, kind="response"),
]

# -- drivers ----------------------------------------------------------------------

Runner = Callable[[int], None]


def pieces_of(w: Workload) -> list[bytes]:
    if w.fragment is None:
        return [w.raw]
    return [w.raw[i : i + w.fragment] for i in range(0, len(w.raw), w.fragment)]


def make_zttp(w: Workload) -> Runner:
    role = zttp.SERVER if w.kind == "request" else zttp.CLIENT
    pieces, messages = pieces_of(w), w.messages
    Connection, NEED_DATA, Request, EndOfMessage = zttp.Connection, zttp.NEED_DATA, zttp.Request, zttp.EndOfMessage

    def run(n: int) -> None:
        for _ in range(n):
            conn = Connection(role)
            done = 0
            for piece in pieces:
                conn.receive_data(piece)
                while True:
                    ev = conn.next_event()
                    if ev is NEED_DATA:
                        break
                    if (type(ev) is Request and ev.end_stream) or type(ev) is EndOfMessage:
                        done += 1
                        if done < messages:
                            conn.start_next_cycle()

    return run


class HttptoolsProto:
    __slots__ = ("headers", "url", "body", "complete")

    def __init__(self) -> None:
        self.headers: list[tuple[bytes, bytes]] = []
        self.url = b""
        self.body = b""
        self.complete = 0

    def on_url(self, url: bytes) -> None:
        self.url += url

    def on_status(self, status: bytes) -> None:
        pass

    def on_header(self, name: bytes, value: bytes) -> None:
        self.headers.append((name, value))

    def on_body(self, body: bytes) -> None:
        self.body += body

    def on_message_complete(self) -> None:
        self.complete += 1


def make_httptools(w: Workload) -> Runner:
    parser_cls = httptools.HttpRequestParser if w.kind == "request" else httptools.HttpResponseParser
    pieces = pieces_of(w)
    is_request = w.kind == "request"

    def run(n: int) -> None:
        for _ in range(n):
            p = HttptoolsProto()
            parser = parser_cls(p)
            for piece in pieces:
                parser.feed_data(piece)
            if is_request:
                parser.get_method()
            else:
                parser.get_status_code()

    return run


def make_h11(w: Workload) -> Runner:
    role = h11.SERVER if w.kind == "request" else h11.CLIENT
    pieces = pieces_of(w)
    Connection, NEED_DATA, EndOfMessage = h11.Connection, h11.NEED_DATA, h11.EndOfMessage

    def run(n: int) -> None:
        for _ in range(n):
            conn = Connection(role)
            for piece in pieces:
                conn.receive_data(piece)
                while True:
                    ev = conn.next_event()
                    if ev is NEED_DATA or isinstance(ev, EndOfMessage):
                        break

    return run


PARSERS: list[tuple[str, Callable[[Workload], Runner]]] = [
    ("zttp", make_zttp),
    ("httptools", make_httptools),
    ("h11", make_h11),
]

# -- verification -------------------------------------------------------------------

# One message normalizes to (start, headers, body): start is the method for
# requests and the status code for responses; header names are lowercased
# because h11 lowercases and the others preserve wire casing.
Message = tuple[object, list[tuple[bytes, bytes]], bytes]


def extract_zttp(w: Workload) -> list[Message]:
    role = zttp.SERVER if w.kind == "request" else zttp.CLIENT
    conn = zttp.Connection(role)
    out: list[Message] = []
    start: object = None
    headers: list[tuple[bytes, bytes]] = []
    body = b""
    for piece in pieces_of(w):
        conn.receive_data(piece)
        while (ev := conn.next_event()) is not zttp.NEED_DATA:
            if isinstance(ev, zttp.Request):
                start, headers = ev.method, list(ev.headers)
                if ev.end_stream:
                    out.append((start, headers, body))
                    start, headers, body = None, [], b""
                    if len(out) < w.messages:
                        conn.start_next_cycle()
            elif isinstance(ev, zttp.Response):
                start, headers = ev.status_code, list(ev.headers)
            elif isinstance(ev, zttp.Data):
                body += ev.data
            elif isinstance(ev, zttp.EndOfMessage):
                out.append((start, headers, body))
                start, headers, body = None, [], b""
                if len(out) < w.messages:
                    conn.start_next_cycle()
    return out


def extract_httptools(w: Workload) -> list[Message]:
    out: list[Message] = []

    class Proto(HttptoolsProto):
        def on_message_complete(self) -> None:
            start = parser.get_method() if w.kind == "request" else parser.get_status_code()
            out.append((start, list(self.headers), self.body))
            self.headers, self.url, self.body = [], b"", b""

    p = Proto()
    parser_cls = httptools.HttpRequestParser if w.kind == "request" else httptools.HttpResponseParser
    parser = parser_cls(p)
    for piece in pieces_of(w):
        parser.feed_data(piece)
    return out


def extract_h11(w: Workload) -> list[Message]:
    role = h11.SERVER if w.kind == "request" else h11.CLIENT
    conn = h11.Connection(role)
    out: list[Message] = []
    start: object = None
    headers: list[tuple[bytes, bytes]] = []
    body = b""
    for piece in pieces_of(w):
        conn.receive_data(piece)
        while True:
            ev = conn.next_event()
            if ev is h11.NEED_DATA:
                break
            if isinstance(ev, h11.Request):
                start, headers = ev.method, list(ev.headers)
            elif isinstance(ev, h11.Response):
                start, headers = ev.status_code, list(ev.headers)
            elif isinstance(ev, h11.Data):
                body += bytes(ev.data)
            elif isinstance(ev, h11.EndOfMessage):
                out.append((start, headers, body))
                break
    return out


def verify(w: Workload) -> None:
    def normalized(msgs: list[Message]) -> list[Message]:
        return [(start, sorted((n.lower(), v) for n, v in headers), body) for start, headers, body in msgs]

    extractors = [("zttp", extract_zttp), ("httptools", extract_httptools)]
    if w.h11_ok:
        extractors.append(("h11", extract_h11))
    reference = normalized(extractors[0][1](w))
    if len(reference) != w.messages:
        raise AssertionError(f"{w.name}: zttp extracted {len(reference)} messages, expected {w.messages}")
    for label, extract in extractors[1:]:
        got = normalized(extract(w))
        if got != reference:
            raise AssertionError(f"{w.name}: {label} extracted {got!r}, zttp extracted {reference!r}")


# -- timing -------------------------------------------------------------------------


def timed(fn: Runner, n: int) -> float:
    gc.collect()
    gc.disable()
    try:
        t0 = time.perf_counter()
        fn(n)
        return time.perf_counter() - t0
    finally:
        gc.enable()


# The paired-ratio median and p25-p75 per workload, filled by bench() for the summary.
dispersion: dict[str, tuple[float, float, float]] = {}  # workload -> (ratio median, p25, p75)


def _quartiles(values: list[float]) -> tuple[float, float, float]:
    """Return (p25, median, p75). statistics.quantiles needs at least two points."""
    if len(values) < 2:
        v = values[0]
        return (v, v, v)
    q1, median, q3 = statistics.quantiles(values, n=4)
    return (q1, median, q3)


def bench(w: Workload, batch: int, repeats: int) -> dict[str, float]:
    verify(w)
    batch = max(1, int(batch * w.scale))
    parsers = [(label, make(w)) for label, make in PARSERS if w.h11_ok or label != "h11"]
    print(f"\n== {w.name} ({len(w.raw)}B, {repeats} batches of {batch:,}) ==")

    for _, fn in parsers:
        fn(max(1, batch // 10))  # warmup: caches, allocator, lazy init

    samples: dict[str, list[float]] = {label: [] for label, _ in parsers}
    for _ in range(repeats):
        for label, fn in parsers:
            samples[label].append(timed(fn, batch))

    per_batch = {label: [batch * w.messages / dt for dt in batches] for label, batches in samples.items()}
    rates: dict[str, float] = {}
    for label, values in per_batch.items():
        p25, median, p75 = _quartiles(values)
        stdev = statistics.stdev(values) if len(values) > 1 else 0.0
        rates[label] = median
        print(
            f"  {label:>10}: {median:12,.0f} msg/s  "
            f"(median of {repeats}, p25-p75 {p25:,.0f}-{p75:,.0f}, stdev {stdev / median * 100:4.1f}%)"
        )

    # The ratio's own dispersion: pair the interleaved zttp/httptools batches and
    # take each batch's ratio, so the headline number comes with error bars. Store the
    # paired-ratio median (not median/median) so the summary is consistent with its band.
    ratios = [z / h for z, h in zip(per_batch["zttp"], per_batch["httptools"], strict=True)]
    r25, rmed, r75 = _quartiles(ratios)
    dispersion[w.name] = (rmed, r25, r75)
    line = f"  -> zttp is {rmed:.2f}x httptools (p25-p75 {r25:.2f}-{r75:.2f})"
    if "h11" in rates:
        line += f", {rates['zttp'] / rates['h11']:.2f}x h11"
    print(line)
    return rates


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=int, default=20_000, help="iterations per timed batch")
    parser.add_argument("--repeats", type=int, default=15, help="timed batches per parser")
    parser.add_argument("--only", type=str, default=None, help="substring filter on workload names")
    args = parser.parse_args()

    print(
        f"CPython {sys.version.split()[0]}, zttp {version('zttp')}, "
        f"httptools {version('httptools')}, h11 {version('h11')}"
    )
    selected = [w for w in WORKLOADS if args.only is None or args.only.lower() in w.name.lower()]
    results = {w.name: bench(w, args.batch, args.repeats) for w in selected}

    print(f"\n{'workload':<32} {'zttp':>12} {'httptools':>12} {'ratio':>7} {'p25-p75':>13}")
    for name, rates in results.items():
        rmed, r25, r75 = dispersion[name]
        print(
            f"{name:<32} {rates['zttp']:>12,.0f} {rates['httptools']:>12,.0f} "
            f"{rmed:>6.2f}x {f'{r25:.2f}-{r75:.2f}':>13}"
        )


if __name__ == "__main__":
    main()
