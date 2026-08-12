"""Model Uvicorn's httptools-to-ASGI request path.

Uvicorn builds the ASGI scope in ``on_message_begin``, lowercases and appends
one header tuple per ``on_header`` callback, then fills the request-line fields
in ``on_headers_complete``.  This benchmark performs that same work for
httptools and constructs the equivalent scope from zttp's Request event. Each
iteration runs through request completion as Uvicorn must before dispatch. It
also keeps the legacy eager zttp header-list path as an A/B control.

Reference implementation:
https://github.com/Kludex/uvicorn/blob/main/uvicorn/protocols/http/httptools_impl.py
"""

from __future__ import annotations

import argparse
import gc
import statistics
import time
import urllib.parse
from collections.abc import Callable

import httptools

import zttp
from benchmarks.http1 import CHROME_GET, PROXIED_GET, SIMPLE, WRK_GET

WORKLOADS = {
    "tiny": WRK_GET,
    "api": SIMPLE,
    "chrome": CHROME_GET,
    "proxied": PROXIED_GET,
}

Runner = Callable[[int], None]


def positive_int(raw: str) -> int:
    value = int(raw)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def base_scope() -> dict[str, object]:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "server": ("127.0.0.1", 8000),
        "client": ("127.0.0.1", 50000),
        "scheme": "http",
        "root_path": "",
        "headers": [],
        "state": {},
    }


class UvicornHttptoolsProtocol:
    """The request-head callbacks used by Uvicorn, without server machinery."""

    __slots__ = ("complete", "expect_100_continue", "headers", "parser", "scope", "url")

    def __init__(self) -> None:
        self.url = b""
        self.expect_100_continue = False
        self.headers: list[tuple[bytes, bytes]] = []
        self.scope: dict[str, object] = {}
        self.complete = False
        self.parser = httptools.HttpRequestParser(self)

    def on_message_begin(self) -> None:
        self.url = b""
        self.expect_100_continue = False
        self.headers = []
        self.scope = base_scope()
        self.complete = False
        self.scope["headers"] = self.headers

    def on_url(self, url: bytes) -> None:
        self.url += url

    def on_header(self, name: bytes, value: bytes) -> None:
        name = name.lower()
        if name == b"expect" and value.lower() == b"100-continue":
            self.expect_100_continue = True
        self.headers.append((name, value))

    def on_headers_complete(self) -> None:
        http_version = self.parser.get_http_version()
        self.scope["method"] = self.parser.get_method().decode("ascii")
        if http_version != "1.1":
            self.scope["http_version"] = http_version
        parsed_url = httptools.parse_url(self.url)
        raw_path = parsed_url.path
        path = raw_path.decode("ascii")
        if "%" in path:
            path = urllib.parse.unquote(path)
        self.scope["path"] = path
        self.scope["raw_path"] = raw_path
        self.scope["query_string"] = parsed_url.query or b""

    def on_message_complete(self) -> None:
        self.complete = True


def make_httptools(raw: bytes) -> Runner:
    def run(iterations: int) -> None:
        scope: dict[str, object] | None = None
        for _ in range(iterations):
            protocol = UvicornHttptoolsProtocol()
            protocol.parser.feed_data(raw)
            if not protocol.complete:
                raise AssertionError("incomplete request")
            scope = protocol.scope
        if scope is None:
            raise AssertionError("missing scope")

    return run


def scope_from_zttp(event: zttp.Request) -> dict[str, object]:
    scope = base_scope()
    scope["method"] = event.method.decode("ascii")
    http_version = event.http_version.decode("ascii")
    if http_version != "1.1":
        scope["http_version"] = http_version
    raw_path = event.path
    path = raw_path.decode("ascii")
    if "%" in path:
        path = urllib.parse.unquote(path)
    scope["path"] = path
    scope["raw_path"] = raw_path
    scope["query_string"] = event.query
    if isinstance(event.headers, zttp.HeaderBlock):
        scope["headers"] = event.headers.to_list(lowercase_names=True)
    else:
        scope["headers"] = [(name.lower(), value) for name, value in event.headers]
    return scope


def make_zttp(raw: bytes, *, packed: bool) -> Runner:
    Connection, SERVER = zttp.Connection, zttp.SERVER

    def run(iterations: int) -> None:
        scope: dict[str, object] | None = None
        for _ in range(iterations):
            conn = Connection(SERVER)
            conn.receive_data(raw)
            if packed:
                event = conn.next_event()
            else:
                event = getattr(conn, "_next_event_eager_for_benchmark")()
            scope = scope_from_zttp(event)
            if not getattr(event, "end_stream", False):
                terminal = conn.next_event()
                if not isinstance(terminal, zttp.EndOfMessage):
                    raise AssertionError("incomplete request")
        if scope is None:
            raise AssertionError("missing scope")

    return run


def verify(raw: bytes) -> None:
    protocol = UvicornHttptoolsProtocol()
    protocol.parser.feed_data(raw)
    if not protocol.complete:
        raise AssertionError("httptools did not complete the request")

    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(raw)
    request = conn.next_event()
    packed_scope = scope_from_zttp(request)
    if not getattr(request, "end_stream", False):
        terminal = conn.next_event()
        if not isinstance(terminal, zttp.EndOfMessage):
            raise AssertionError("zttp did not complete the request")
    if packed_scope != protocol.scope:
        raise AssertionError(f"zttp scope differs from Uvicorn: {packed_scope!r} != {protocol.scope!r}")


def timed(run: Runner, iterations: int) -> float:
    gc.collect()
    gc.disable()
    try:
        started = time.perf_counter()
        run(iterations)
        return time.perf_counter() - started
    finally:
        gc.enable()


def quartiles(values: list[float]) -> tuple[float, float, float]:
    if len(values) < 2:
        value = values[0]
        return value, value, value
    q1, median, q3 = statistics.quantiles(values, n=4)
    return q1, median, q3


def benchmark(name: str, raw: bytes, iterations: int, repeats: int) -> None:
    verify(raw)
    runners = {
        "httptools": make_httptools(raw),
        "zttp eager": make_zttp(raw, packed=False),
        "zttp packed": make_zttp(raw, packed=True),
    }
    for run in runners.values():
        run(max(1, iterations // 10))

    samples = {label: [] for label in runners}
    for _ in range(repeats):
        for label, run in runners.items():
            samples[label].append(iterations / timed(run, iterations))

    rates: dict[str, float] = {}
    print(f"\n== {name} ({len(raw)}B, {repeats} batches of {iterations:,}) ==")
    for label, values in samples.items():
        p25, median, p75 = quartiles(values)
        rates[label] = median
        print(f"  {label:>11}: {median:10,.0f} scope/s  (p25-p75 {p25:,.0f}-{p75:,.0f})")
    print(
        f"  -> packed/eager {rates['zttp packed'] / rates['zttp eager']:.2f}x; "
        f"packed/httptools {rates['zttp packed'] / rates['httptools']:.2f}x"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=positive_int, default=50_000)
    parser.add_argument("--repeats", type=positive_int, default=11)
    parser.add_argument("--only", choices=WORKLOADS, default=None)
    args = parser.parse_args()

    workloads = WORKLOADS.items() if args.only is None else [(args.only, WORKLOADS[args.only])]
    for name, raw in workloads:
        benchmark(name, raw, args.iterations, args.repeats)


if __name__ == "__main__":
    main()
