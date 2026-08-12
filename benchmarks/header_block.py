"""Measure the HTTP/1 HeaderBlock API against legacy eager header lists.

This benchmark separates the workloads that a parser-only headline conflates:
leaving headers untouched, looking up one field, iterating every field, and
converting them into the lowercase dict shape commonly built by frameworks.
"""

from __future__ import annotations

import argparse
import gc
import statistics
import time
from collections.abc import Callable

import zttp
from benchmarks.http1 import CHROME_GET, PROXIED_GET, SIMPLE, WRK_GET

WORKLOADS = {
    "tiny": WRK_GET,
    "api": SIMPLE,
    "chrome": CHROME_GET,
    "proxied": PROXIED_GET,
}


def positive_int(raw: str) -> int:
    value = int(raw)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


class FrameworkRequest:
    """Small stand-in for a framework request built from a parser event."""

    __slots__ = ("method", "target", "path", "query", "http_version", "headers")

    def __init__(self, event: zttp.Request) -> None:
        self.method = event.method
        self.target = event.target
        self.path = event.path
        self.query = event.query
        self.http_version = event.http_version
        if isinstance(event.headers, zttp.HeaderBlock):
            headers = event.headers.to_list(lowercase_names=True)
        else:
            headers = ((name.lower(), value) for name, value in event.headers)
        self.headers = dict(headers)


def consume(event: zttp.Request, operation: str) -> object:
    if operation == "no-access":
        return event
    if operation == "lookup":
        if isinstance(event.headers, zttp.HeaderBlock):
            return event.headers.get(b"host")
        for name, value in event.headers:
            if name.lower() == b"host":
                return value
        return None
    if operation == "iterate":
        return tuple(event.headers)
    if operation == "framework":
        return FrameworkRequest(event)
    raise AssertionError(operation)


def comparable(result: object) -> object:
    if isinstance(result, zttp.Request):
        return (
            result.method,
            result.target,
            result.path,
            result.query,
            result.http_version,
            tuple(result.headers),
        )
    if isinstance(result, FrameworkRequest):
        return (
            result.method,
            result.target,
            result.path,
            result.query,
            result.http_version,
            result.headers,
        )
    return result


def result_once(raw: bytes, *, lazy: bool, operation: str) -> object:
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(raw)
    event = conn.next_event() if lazy else getattr(conn, "_next_event_eager_for_benchmark")()
    return comparable(consume(event, operation))


def make_runner(raw: bytes, *, lazy: bool, operation: str) -> Callable[[int], None]:
    Connection, SERVER = zttp.Connection, zttp.SERVER

    def run(iterations: int) -> None:
        result: object = None
        for _ in range(iterations):
            conn = Connection(SERVER)
            conn.receive_data(raw)
            event = conn.next_event() if lazy else getattr(conn, "_next_event_eager_for_benchmark")()
            result = consume(event, operation)
        # Keep the last result live until the loop finishes.
        if result is None and operation != "lookup":
            raise AssertionError("missing result")

    return run


def measure(run: Callable[[int], None], iterations: int, repeats: int) -> list[float]:
    run(max(1, iterations // 10))
    samples: list[float] = []
    for _ in range(repeats):
        gc.collect()
        gc.disable()
        try:
            started = time.perf_counter_ns()
            run(iterations)
            elapsed = time.perf_counter_ns() - started
        finally:
            gc.enable()
        samples.append(elapsed / iterations)
    return samples


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=positive_int, default=100_000)
    parser.add_argument("--repeats", type=positive_int, default=11)
    parser.add_argument("--only", choices=WORKLOADS, default=None)
    args = parser.parse_args()

    workloads = WORKLOADS.items() if args.only is None else [(args.only, WORKLOADS[args.only])]
    operations = ("no-access", "lookup", "iterate", "framework")
    print(f"{'workload':<9} {'operation':<11} {'eager ns':>10} {'lazy ns':>10} {'speedup':>9}")
    for workload, raw in workloads:
        for operation in operations:
            eager_run = make_runner(raw, lazy=False, operation=operation)
            lazy_run = make_runner(raw, lazy=True, operation=operation)
            eager_result = result_once(raw, lazy=False, operation=operation)
            lazy_result = result_once(raw, lazy=True, operation=operation)
            if eager_result != lazy_result:
                raise AssertionError(f"{workload} {operation}: packed result differs from eager result")
            eager = statistics.median(measure(eager_run, args.iterations, args.repeats))
            lazy = statistics.median(measure(lazy_run, args.iterations, args.repeats))
            print(f"{workload:<9} {operation:<11} {eager:10.1f} {lazy:10.1f} {eager / lazy:8.2f}x")


if __name__ == "__main__":
    main()
