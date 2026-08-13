"""Model Uvicorn's httptools-to-ASGI request path.

Uvicorn builds the ASGI scope in ``on_message_begin``, lowercases and appends
one header tuple per ``on_header`` callback, then fills the request-line fields
in ``on_headers_complete``.  This benchmark performs that same work for
httptools and constructs the equivalent scope from zttp's Request event. Each
iteration runs through request completion as Uvicorn must before dispatch. It
compares zttp's split ``receive_data`` + ``next_event`` API with the combined
``receive_event`` fast path, and keeps the legacy eager header-list path as an
A/B control. Both fresh-connection and persistent keep-alive lifecycles are
available.

Reference implementation:
https://github.com/Kludex/uvicorn/blob/main/uvicorn/protocols/http/httptools_impl.py
"""

from __future__ import annotations

import argparse
import gc
import os
import platform
import statistics
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Callable
from importlib.metadata import version

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


def make_httptools(raw: bytes, *, persistent: bool) -> Runner:
    def run(iterations: int) -> None:
        scope: dict[str, object] | None = None
        protocol = UvicornHttptoolsProtocol() if persistent else None
        for _ in range(iterations):
            if protocol is None:
                protocol = UvicornHttptoolsProtocol()
            protocol.parser.feed_data(raw)
            if not protocol.complete:
                raise AssertionError("incomplete request")
            scope = protocol.scope
            if not persistent:
                protocol = None
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


def drain_request(conn: zttp.H1Connection, event: zttp.Request) -> None:
    if event.end_stream:
        return
    while True:
        terminal = conn.next_event()
        if isinstance(terminal, zttp.EndOfMessage):
            return
        if not isinstance(terminal, zttp.Data):
            raise AssertionError("incomplete request")


def make_zttp(raw: bytes, *, api: str, persistent: bool) -> Runner:
    Connection, SERVER = zttp.Connection, zttp.SERVER

    def run(iterations: int) -> None:
        scope: dict[str, object] | None = None
        conn = Connection(SERVER) if persistent else None
        for _ in range(iterations):
            if conn is None:
                conn = Connection(SERVER)
            if api == "combined":
                event = conn.receive_event(raw)
            else:
                conn.receive_data(raw)
            if api == "split":
                event = conn.next_event()
            elif api == "eager":
                event = getattr(conn, "_next_event_eager_for_benchmark")()
            if not isinstance(event, zttp.Request):
                raise AssertionError("missing request")
            scope = scope_from_zttp(event)
            drain_request(conn, event)
            if persistent:
                conn.start_next_cycle()
            else:
                conn = None
        if scope is None:
            raise AssertionError("missing scope")

    return run


def verify(raw: bytes) -> None:
    protocol = UvicornHttptoolsProtocol()
    protocol.parser.feed_data(raw)
    if not protocol.complete:
        raise AssertionError("httptools did not complete the request")

    for api in ("split", "combined"):
        conn = zttp.Connection(zttp.SERVER)
        if api == "combined":
            request = conn.receive_event(raw)
        else:
            conn.receive_data(raw)
            request = conn.next_event()
        if not isinstance(request, zttp.Request):
            raise AssertionError(f"zttp {api} API did not produce a request")
        scope = scope_from_zttp(request)
        drain_request(conn, request)
        if scope != protocol.scope:
            raise AssertionError(f"zttp {api} scope differs from Uvicorn: {scope!r} != {protocol.scope!r}")


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


def benchmark(name: str, raw: bytes, iterations: int, repeats: int, lifecycle: str) -> None:
    verify(raw)
    persistent = lifecycle == "keep-alive"
    runners = {
        "httptools": make_httptools(raw, persistent=persistent),
        "zttp eager": make_zttp(raw, api="eager", persistent=persistent),
        "zttp split": make_zttp(raw, api="split", persistent=persistent),
        "zttp combined": make_zttp(raw, api="combined", persistent=persistent),
    }
    for run in runners.values():
        run(max(1, iterations // 10))

    samples = {label: [] for label in runners}
    ordered = list(runners.items())
    for repeat in range(repeats):
        # Rotate the first runner so thermal/scheduler drift does not always
        # favour the same implementation.
        rotated = ordered[repeat % len(ordered) :] + ordered[: repeat % len(ordered)]
        for label, run in rotated:
            samples[label].append(iterations / timed(run, iterations))

    rates: dict[str, float] = {}
    print(f"\n== {name} / {lifecycle} ({len(raw)}B, {repeats} batches of {iterations:,}) ==")
    for label, values in samples.items():
        p25, median, p75 = quartiles(values)
        rates[label] = median
        print(f"  {label:>13}: {median:10,.0f} scope/s  (p25-p75 {p25:,.0f}-{p75:,.0f})")
    print(
        f"  -> combined/split {rates['zttp combined'] / rates['zttp split']:.2f}x; "
        f"combined/httptools {rates['zttp combined'] / rates['httptools']:.2f}x; "
        f"split/eager {rates['zttp split'] / rates['zttp eager']:.2f}x"
    )


def git_revision() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=os.path.dirname(__file__),
            text=True,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=positive_int, default=50_000)
    parser.add_argument("--repeats", type=positive_int, default=11)
    parser.add_argument("--only", choices=WORKLOADS, default=None)
    parser.add_argument("--lifecycle", choices=("isolated", "keep-alive", "both"), default="both")
    args = parser.parse_args()

    print(
        f"CPython {sys.version.split()[0]}, zttp {version('zttp')}, httptools {version('httptools')}, "
        f"{platform.machine()} {platform.system()}, commit {git_revision()}, "
        f"build {os.environ.get('HATCH_ZIG_BUILD_MODE', 'unknown')}"
    )
    workloads = WORKLOADS.items() if args.only is None else [(args.only, WORKLOADS[args.only])]
    lifecycles = ("isolated", "keep-alive") if args.lifecycle == "both" else (args.lifecycle,)
    for lifecycle in lifecycles:
        for name, raw in workloads:
            benchmark(name, raw, args.iterations, args.repeats, lifecycle)


if __name__ == "__main__":
    main()
