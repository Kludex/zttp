"""Compare zttp's HTTP/2 read path against h2 (python-hyper) on parse throughput.

h2 is the only mainstream HTTP/2 protocol library in Python and it is pure
Python: hpack (HPACK) and hyperframe (framing) ship no C acceleration, so this
pits a Zig-core sans-IO parser against the fastest pure-Python option there is,
not against a C/Rust peer (none exists). Read the ratios with that in mind.

Both parsers decode the *same wire bytes* - a real HTTP/2 connection (preface,
SETTINGS, then HEADERS/DATA frames) built once per workload with h2's own
encoder, so the HPACK block is canonical and neither side gets a hand-tuned
input. Each parser is driven to extract the same per-stream information (method
or status, headers, body), verified equal before timing.

Methodology mirrors http1.py: many short batches interleaved round-robin so
thermal drift hits both parsers equally, GC disabled while a batch is timed, and
the median batch reported with its p25-p75 quartiles and stdev so noise is
visible. msg/s counts HTTP/2 *messages* (requests or responses), so a 16-stream
workload that decodes in one pass still counts as 16.
"""

from __future__ import annotations

import argparse
import gc
import statistics
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib.metadata import version

import h2.config
import h2.connection
import h2.events

import zttp

# -- header sets ----------------------------------------------------------------

# The same request/response shapes http1.py draws from the parser-benchmark
# literature, expressed as HTTP/2 header lists. Pseudo-headers replace the
# HTTP/1 request line; hop-by-hop headers (Connection, Keep-Alive, Transfer-
# Encoding) have no place in HTTP/2 and are dropped.

WRK_GET = [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"example.com"), (b":path", b"/")]

SIMPLE_GET = [
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"api.example.com"),
    (b":path", b"/api/v1/users/12345?include=profile"),
    (b"user-agent", b"Mozilla/5.0 (compatible; bench/1.0)"),
    (b"accept", b"application/json"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"authorization", b"Bearer abcdef0123456789"),
]

# picohttpparser/llhttp's real-world browser request, as HTTP/2 headers.
PICO_GET = [
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"www.kittyhell.com"),
    (b":path", b"/wp-content/uploads/2010/03/hello-kitty-darth-vader-pink.jpg"),
    (
        b"user-agent",
        b"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; ja-JP-mac; rv:1.9.2.3) "
        b"Gecko/20100401 Firefox/3.6.3 Pathtraq/0.9",
    ),
    (b"accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    (b"accept-language", b"ja,en-us;q=0.7,en;q=0.3"),
    (b"accept-encoding", b"gzip,deflate"),
    (b"accept-charset", b"Shift_JIS,utf-8;q=0.7,*;q=0.7"),
    (
        b"cookie",
        b"wp_ozh_wsa_visits=2; wp_ozh_wsa_visit_lasttime=xxxxxxxxxx; "
        b"__utma=xxxxxxxxx.xxxxxxxxxx.xxxxxxxxxx.xxxxxxxxxx.xxxxxxxxxx.x; "
        b"__utmz=xxxxxxxxx.xxxxxxxxxx.x.x.utmccn=(referral)|utmcsr=reader.livedoor.com|"
        b"utmcct=/reader/|utmcmd=referral",
    ),
]

# A modern Chrome top-level navigation, as Chrome actually sends it over h2:
# pseudo-headers, lowercase field names, client hints and Sec-Fetch-*.
CHROME_GET = [
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"www.example.com"),
    (b":path", b"/"),
    (b"sec-ch-ua", b'"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"'),
    (b"sec-ch-ua-mobile", b"?0"),
    (b"sec-ch-ua-platform", b'"macOS"'),
    (b"upgrade-insecure-requests", b"1"),
    (
        b"user-agent",
        b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        b"(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    ),
    (
        b"accept",
        b"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
        b"image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    ),
    (b"sec-fetch-site", b"none"),
    (b"sec-fetch-mode", b"navigate"),
    (b"sec-fetch-user", b"?1"),
    (b"sec-fetch-dest", b"document"),
    (b"accept-encoding", b"gzip, deflate, br, zstd"),
    (b"accept-language", b"en-US,en;q=0.9"),
    (
        b"cookie",
        b"_ga=GA1.2.1234567890.1700000000; _gid=GA1.2.987654321.1717000000; "
        b"session_id=a1b2c3d4e5f64758a9b0c1d2e3f40516; csrftoken=Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0De",
    ),
    (b"priority", b"u=0, i"),
]

# East-west API traffic behind ingress-nginx: the X-Forwarded-* family, W3C
# trace context, and a long opaque bearer token.
PROXIED_GET = [
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"api.example.com"),
    (b":path", b"/api/v1/users/123?include=profile"),
    (b"x-request-id", b"7f3b9c2e4d5a6f8190a1b2c3d4e5f607"),
    (b"x-real-ip", b"203.0.113.7"),
    (b"x-forwarded-for", b"203.0.113.7"),
    (b"x-forwarded-host", b"api.example.com"),
    (b"x-forwarded-port", b"443"),
    (b"x-forwarded-proto", b"https"),
    (b"x-forwarded-scheme", b"https"),
    (b"x-scheme", b"https"),
    (b"traceparent", b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    (
        b"authorization",
        b"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9."
        b"eyJzdWIiOiJ1c2VyXzEyMyIsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSIsImF1ZCI6ImFwaSIsImV4cCI6"
        b"MTcxNzI1OTIwMCwiaWF0IjoxNzE3MjU1NjAwLCJzY29wZSI6InJlYWQ6dXNlcnMifQ."
        b"sig_X9yZ2vQ8wR7tU6sP5oN4mL3kJ2hG1fE0dC9bA8z",
    ),
    (b"accept", b"application/json"),
    (b"user-agent", b"python-httpx/0.27.0"),
    (b"accept-encoding", b"gzip, br"),
]

POST_HEADERS = [
    (b":method", b"POST"),
    (b":scheme", b"https"),
    (b":authority", b"api.example.com"),
    (b":path", b"/api/v1/login"),
    (b"content-type", b"application/json"),
]
POST_BODY = b'{"username": "alice", "password": "correcthorsebattery"}'

UPLOAD_HEADERS = [
    (b":method", b"POST"),
    (b":scheme", b"https"),
    (b":authority", b"files.example.com"),
    (b":path", b"/upload"),
    (b"content-type", b"application/octet-stream"),
]
UPLOAD_BODY = b"x" * 16384

RESP_JSON_HEADERS = [
    (b":status", b"200"),
    (b"server", b"uvicorn"),
    (b"date", b"Wed, 10 Jun 2026 07:28:00 GMT"),
    (b"content-type", b"application/json"),
]
RESP_JSON_BODY = b'{"message": "Hello, World!"}'

# -- workloads --------------------------------------------------------------------


@dataclass(frozen=True)
class Stream:
    headers: list[tuple[bytes, bytes]]
    body: bytes = b""


@dataclass(frozen=True)
class Workload:
    name: str
    streams: list[Stream]
    kind: str = "request"  # "request" | "response"
    scale: float = 1.0  # batch-size multiplier for heavyweight inputs
    wire: bytes = field(default=b"", compare=False)

    @property
    def messages(self) -> int:
        return len(self.streams)


def _rep(headers: list[tuple[bytes, bytes]], n: int, body: bytes = b"") -> list[Stream]:
    return [Stream(headers, body) for _ in range(n)]


WORKLOADS = [
    Workload("wrk default GET", [Stream(WRK_GET)]),
    Workload("small API GET", [Stream(SIMPLE_GET)]),
    Workload("real-world GET (pico/llhttp)", [Stream(PICO_GET)]),
    Workload("Chrome navigation GET", [Stream(CHROME_GET)]),
    Workload("k8s ingress proxied GET", [Stream(PROXIED_GET)]),
    Workload("POST + JSON body", [Stream(POST_HEADERS, POST_BODY)]),
    Workload("16KB upload POST", [Stream(UPLOAD_HEADERS, UPLOAD_BODY)], scale=0.5),
    # The shape HTTP/2 exists for: many small requests multiplexed on one
    # connection, decoded in a single pass with a warm HPACK dynamic table.
    Workload("16 multiplexed GETs", _rep(WRK_GET, 16), scale=0.25),
    Workload("100 multiplexed GETs (h2 burst)", _rep(SIMPLE_GET, 100), scale=0.05),
    Workload("JSON API response", [Stream(RESP_JSON_HEADERS, RESP_JSON_BODY)], kind="response"),
    Workload(
        "16 multiplexed JSON responses",
        _rep(RESP_JSON_HEADERS, 16, RESP_JSON_BODY),
        kind="response",
        scale=0.25,
    ),
]

# -- wire construction ----------------------------------------------------------

# Both parsers decode the same bytes. h2 is the canonical encoder, sharing one
# HPACK dynamic table across every stream on the connection - exactly the
# compression a real peer achieves. Request wires come straight from a client.
# Response wires need a real exchange first: a server only sends HEADERS on a
# stream the client already opened, so each response is emitted in answer to a
# matching request, and only the server's output is measured.


def _encode_requests(w: Workload) -> bytes:
    enc = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding=None))
    enc.initiate_connection()
    stream_id = 1
    for s in w.streams:
        enc.send_headers(stream_id, s.headers, end_stream=not s.body)
        if s.body:
            enc.send_data(stream_id, s.body, end_stream=True)
        stream_id += 2
    return enc.data_to_send()


def _encode_responses(w: Workload) -> bytes:
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding=None))
    server = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False, header_encoding=None))
    client.initiate_connection()
    server.initiate_connection()  # the server's own SETTINGS - a client must see it first
    server.receive_data(client.data_to_send())
    stream_id = 1
    get = [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"x"), (b":path", b"/")]
    for s in w.streams:
        client.send_headers(stream_id, get, end_stream=True)
        server.receive_data(client.data_to_send())
        server.send_headers(stream_id, s.headers, end_stream=not s.body)
        if s.body:
            server.send_data(stream_id, s.body, end_stream=True)
        stream_id += 2
    return server.data_to_send()


def _encode(w: Workload) -> bytes:
    return _encode_requests(w) if w.kind == "request" else _encode_responses(w)


# -- drivers ----------------------------------------------------------------------

Runner = Callable[[int], None]


# A bare GET, sent by a response-workload's client to open the stream a response
# rides on: both parsers' read paths refuse a response on a stream they never
# opened, so the client must send before it can decode. The send is the realistic
# other half of a client round-trip and is identical for both parsers.
PRIMER_GET = [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"x"), (b":path", b"/")]


def make_zttp(w: Workload) -> Runner:
    is_request = w.kind == "request"
    role = zttp.SERVER if is_request else zttp.CLIENT
    wire, count = w.wire, w.messages
    Connection, HTTP2, NEED_DATA = zttp.Connection, zttp.HTTP2, zttp.NEED_DATA

    def run(n: int) -> None:
        for _ in range(n):
            conn = Connection(role, protocol=HTTP2)
            if not is_request:
                for _ in range(count):
                    conn.send_request(b"GET", b"/", b"2", [(b"host", b"x")]).end_message()
            conn.receive_data(wire)
            while conn.next_event() is not NEED_DATA:
                pass

    return run


def make_h2(w: Workload) -> Runner:
    is_request = w.kind == "request"
    wire, count = w.wire, w.messages
    config = h2.config.H2Configuration(client_side=not is_request, header_encoding=None)
    H2Connection = h2.connection.H2Connection

    def run(n: int) -> None:
        for _ in range(n):
            conn = H2Connection(config=config)
            conn.initiate_connection()
            if not is_request:
                for i in range(count):
                    conn.send_headers(1 + 2 * i, PRIMER_GET, end_stream=True)
            conn.clear_outbound_data_buffer()
            conn.receive_data(wire)

    return run


PARSERS: list[tuple[str, Callable[[Workload], Runner]]] = [
    ("zttp", make_zttp),
    ("h2", make_h2),
]

# -- verification -------------------------------------------------------------------

# A message normalizes to (start, headers, body): the method for requests and the
# status for responses, with pseudo-headers folded the way zttp surfaces them -
# :authority becomes a host header, the other pseudo-headers drop out - so the two
# parsers' header views are comparable.
Message = tuple[object, list[tuple[bytes, bytes]], bytes]


def _normalize(start: object, headers: list[tuple[bytes, bytes]], body: bytes) -> Message:
    regular = [(n, v) for n, v in headers if not n.startswith(b":")]
    authority = next((v for n, v in headers if n == b":authority"), None)
    if authority is not None:
        regular.append((b"host", authority))
    return (start, sorted((n.lower(), v) for n, v in regular), body)


def extract_zttp(w: Workload) -> list[Message]:
    role = zttp.SERVER if w.kind == "request" else zttp.CLIENT
    conn = zttp.Connection(role, protocol=zttp.HTTP2)
    if w.kind != "request":
        for _ in range(w.messages):
            conn.send_request(b"GET", b"/", b"2", [(b"host", b"x")]).end_message()
    conn.receive_data(w.wire)
    pending: dict[int, list[tuple[bytes, bytes]]] = {}
    starts: dict[int, object] = {}
    bodies: dict[int, bytes] = {}
    out: list[Message] = []
    while (ev := conn.next_event()) is not zttp.NEED_DATA:
        if isinstance(ev, zttp.Request):
            starts[ev.stream_id], pending[ev.stream_id], bodies[ev.stream_id] = ev.method, list(ev.headers), b""
        elif isinstance(ev, zttp.Response):
            starts[ev.stream_id], pending[ev.stream_id], bodies[ev.stream_id] = ev.status_code, list(ev.headers), b""
        elif isinstance(ev, zttp.Data):
            bodies[ev.stream_id] += ev.data
        elif isinstance(ev, zttp.EndOfMessage):
            sid = ev.stream_id
            out.append(_normalize(starts[sid], pending[sid], bodies[sid]))
    return out


def extract_h2(w: Workload) -> list[Message]:
    client_side = w.kind != "request"
    conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=client_side, header_encoding=None))
    conn.initiate_connection()
    if client_side:  # a response-workload client opens the streams before decoding
        for i in range(w.messages):
            conn.send_headers(1 + 2 * i, PRIMER_GET, end_stream=True)
    conn.clear_outbound_data_buffer()
    heads: dict[int, list[tuple[bytes, bytes]]] = {}
    starts: dict[int, object] = {}
    bodies: dict[int, bytes] = {}
    out: list[Message] = []
    for ev in conn.receive_data(w.wire):
        if isinstance(ev, h2.events.RequestReceived):
            starts[ev.stream_id] = next(v for n, v in ev.headers if n == b":method")
            heads[ev.stream_id], bodies[ev.stream_id] = list(ev.headers), b""
        elif isinstance(ev, h2.events.ResponseReceived):
            starts[ev.stream_id] = int(next(v for n, v in ev.headers if n == b":status"))
            heads[ev.stream_id], bodies[ev.stream_id] = list(ev.headers), b""
        elif isinstance(ev, h2.events.DataReceived):
            bodies[ev.stream_id] += ev.data
        elif isinstance(ev, h2.events.StreamEnded):
            sid = ev.stream_id
            out.append(_normalize(starts[sid], heads[sid], bodies[sid]))
    return out


EXTRACTORS: dict[str, Callable[[Workload], list[Message]]] = {"zttp": extract_zttp, "h2": extract_h2}


def verify(w: Workload) -> None:
    reference = sorted(extract_zttp(w))
    if len(reference) != w.messages:
        raise AssertionError(f"{w.name}: zttp extracted {len(reference)} messages, expected {w.messages}")
    got = sorted(extract_h2(w))
    if got != reference:
        raise AssertionError(f"{w.name}: h2 extracted {got!r}, zttp extracted {reference!r}")


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


# The ratio's p25-p75 per workload, filled by bench() and shown in the summary.
dispersion: dict[str, tuple[float, float]] = {}


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
    parsers = [(label, make(w)) for label, make in PARSERS]
    print(f"\n== {w.name} ({len(w.wire)}B wire, {w.messages} msg/conn, {repeats} batches of {batch:,}) ==")

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
        stdev = statistics.stdev(values)
        rates[label] = median
        print(
            f"  {label:>10}: {median:14,.0f} msg/s  "
            f"(median of {repeats}, p25-p75 {p25:,.0f}-{p75:,.0f}, stdev {stdev / median * 100:4.1f}%)"
        )

    # The ratio's own dispersion: pair the interleaved zttp/h2 batches and take
    # each batch's ratio, so the headline number comes with error bars.
    ratios = [z / h for z, h in zip(per_batch["zttp"], per_batch["h2"], strict=True)]
    r25, rmed, r75 = _quartiles(ratios)
    dispersion[w.name] = (r25, r75)
    print(f"  -> zttp is {rmed:.2f}x h2 (p25-p75 {r25:.2f}-{r75:.2f})")
    return rates


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=int, default=20_000, help="connections per timed batch")
    parser.add_argument("--repeats", type=int, default=15, help="timed batches per parser")
    parser.add_argument("--only", type=str, default=None, help="substring filter on workload names")
    args = parser.parse_args()

    print(f"CPython {sys.version.split()[0]}, zttp {version('zttp')}, h2 {version('h2')} (pure Python)")
    selected = [w for w in WORKLOADS if args.only is None or args.only.lower() in w.name.lower()]
    workloads = [Workload(w.name, w.streams, w.kind, w.scale, wire=_encode(w)) for w in selected]
    results = {w.name: bench(w, args.batch, args.repeats) for w in workloads}

    print(f"\n{'workload':<36} {'zttp':>14} {'h2':>14} {'ratio':>7} {'p25-p75':>13}")
    for name, rates in results.items():
        ratio = rates["zttp"] / rates["h2"]
        r25, r75 = dispersion[name]
        print(f"{name:<36} {rates['zttp']:>14,.0f} {rates['h2']:>14,.0f} {ratio:>6.2f}x {f'{r25:.2f}-{r75:.2f}':>13}")


if __name__ == "__main__":
    main()
