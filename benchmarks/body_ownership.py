"""Measure Uvicorn-shaped HTTP/1 request-body delivery.

The request head is delivered separately, as it normally is once an ASGI server
starts an application after parsing the head. Body pieces are immutable ``bytes``
objects like those passed by ``asyncio.Protocol.data_received``. Like Uvicorn's
httptools protocol, each parser accumulates callback/event bodies in a
``bytearray`` and materializes ``bytes`` for ASGI delivery. This keeps the
zero-copy parser improvement in a production-shaped path instead of timing a
reference handoff against a body-sized copy in isolation.
"""

from __future__ import annotations

import argparse
import gc
import statistics
import time
from collections.abc import Callable

import httptools

import zttp

Runner = Callable[[int], None]


def positive_int(raw: str) -> int:
    value = int(raw)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def pieces_of(size: int, fragment: int | None) -> list[bytes]:
    body = b"x" * size
    if fragment is None:
        return [body]
    return [body[offset : offset + fragment] for offset in range(0, size, fragment)]


def request_head(size: int) -> bytes:
    return (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: files.example.com\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: " + str(size).encode() + b"\r\n\r\n"
    )


def make_zttp(size: int, fragment: int | None) -> Runner:
    head = request_head(size)
    pieces = pieces_of(size, fragment)
    Connection, SERVER = zttp.Connection, zttp.SERVER
    Request, Data, EndOfMessage = zttp.Request, zttp.Data, zttp.EndOfMessage

    def run(iterations: int) -> None:
        seen = 0
        for _ in range(iterations):
            conn = Connection(SERVER)
            conn.receive_data(head)
            if not isinstance(conn.next_event(), Request):
                raise AssertionError("missing request")
            buffered = bytearray()
            for piece in pieces:
                conn.receive_data(piece)
                event = conn.next_event()
                if not isinstance(event, Data):
                    raise AssertionError("missing data")
                buffered += event.data
            if not isinstance(conn.next_event(), EndOfMessage):
                raise AssertionError("missing end of message")
            delivered = bytes(buffered)
            seen += len(delivered)
        if seen != iterations * size:
            raise AssertionError("body length differs")

    return run


class HttptoolsProtocol:
    __slots__ = ("body", "complete")

    def __init__(self) -> None:
        self.body = bytearray()
        self.complete = False

    def on_body(self, body: bytes) -> None:
        self.body += body

    def on_message_complete(self) -> None:
        self.complete = True


def make_httptools(size: int, fragment: int | None) -> Runner:
    head = request_head(size)
    pieces = pieces_of(size, fragment)

    def run(iterations: int) -> None:
        seen = 0
        for _ in range(iterations):
            protocol = HttptoolsProtocol()
            parser = httptools.HttpRequestParser(protocol)
            parser.feed_data(head)
            for piece in pieces:
                parser.feed_data(piece)
            if not protocol.complete:
                raise AssertionError("body differs")
            delivered = bytes(protocol.body)
            seen += len(delivered)
        if seen != iterations * size:
            raise AssertionError("body length differs")

    return run


def timed(run: Runner, iterations: int) -> float:
    gc.collect()
    gc.disable()
    try:
        started = time.perf_counter()
        run(iterations)
        return iterations / (time.perf_counter() - started)
    finally:
        gc.enable()


def benchmark(name: str, size: int, fragment: int | None, iterations: int, repeats: int) -> None:
    runners = {"zttp": make_zttp(size, fragment), "httptools": make_httptools(size, fragment)}
    samples = {label: [] for label in runners}
    for run in runners.values():
        run(max(1, iterations // 20))
    labels = tuple(runners)
    for repeat in range(repeats):
        order = labels if repeat % 2 == 0 else labels[::-1]
        for label in order:
            run = runners[label]
            samples[label].append(timed(run, iterations))

    medians = {label: statistics.median(values) for label, values in samples.items()}
    print(
        f"{name:<24} {medians['zttp']:>12,.0f} {medians['httptools']:>12,.0f} "
        f"{medians['zttp'] / medians['httptools']:>8.2f}x"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=positive_int, default=20_000)
    parser.add_argument("--repeats", type=positive_int, default=11)
    args = parser.parse_args()

    print(f"{'workload':<24} {'zttp ASGI/s':>12} {'httptools':>12} {'ratio':>9}")
    benchmark("64B body", 64, None, args.iterations, args.repeats)
    benchmark("1KiB body", 1024, None, args.iterations, args.repeats)
    benchmark("16KiB body", 16 * 1024, None, args.iterations, args.repeats)
    benchmark("16KiB in MTU reads", 16 * 1024, 1448, max(1, args.iterations // 4), args.repeats)
    benchmark("1MiB body", 1024 * 1024, None, max(1, args.iterations // 20), args.repeats)


if __name__ == "__main__":
    main()
