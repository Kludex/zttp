"""Measure HTTP/1.1 idle RSS, including native allocations, on Linux and macOS.

Each sample uses a fresh subprocess. The parent measures current resident set
size (RSS) while the worker is paused after imports, construction, and reuse.
Connection deltas exclude imports and 10,000 live warmup parsers, which occupy
free allocator pools left by imports. They include the list holding the parsers.
The five httptools callbacks validate and discard data, just like zttp events;
no sockets, responses, TLS, or application state are included. RSS includes
allocator slack, so use many connections and compare repeated runs, not a
single object's size or a process's peak RSS.
"""

import argparse
import gc
import importlib
import platform
import statistics
import subprocess
import sys
from dataclasses import dataclass
from functools import partial
from importlib.metadata import version

REQUEST = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


@dataclass(frozen=True)
class Sample:
    baseline: int
    fresh: int
    reused: int


class HttptoolsProtocol:
    __slots__ = ("complete", "parser")

    def __init__(self) -> None:
        from httptools import HttpRequestParser

        self.complete = False
        self.parser = HttpRequestParser(self)

    def on_url(self, url: bytes) -> None:
        assert url == b"/"

    def on_header(self, name: bytes, value: bytes) -> None:
        assert (name, value) == (b"Host", b"example.com")

    def on_headers_complete(self) -> None:
        pass

    def on_body(self, body: bytes) -> None:
        raise AssertionError("unexpected body")

    def on_message_complete(self) -> None:
        self.complete = True


def checkpoint() -> None:
    gc.collect()
    sys.stdout.write("ready\n")
    sys.stdout.flush()
    if sys.stdin.readline() != "continue\n":
        raise RuntimeError("memory benchmark parent disconnected")


def worker(label: str, connections: int, requests: int) -> None:
    module = importlib.import_module(label)
    constructor = partial(module.Connection, module.SERVER) if label == "zttp" else HttptoolsProtocol
    warmup = [constructor() for _ in range(10_000)]
    checkpoint()
    parsers = [constructor() for _ in range(connections)]
    checkpoint()
    for parser in parsers:
        if label == "zttp":
            for _ in range(requests):
                event = parser.receive_event(REQUEST)
                assert isinstance(event, module.Request) and event.end_stream
                assert event.method == b"GET" and event.target == b"/"
                assert len(event.headers) == 1 and event.headers[0] == (b"Host", b"example.com")
                del event
                parser.start_next_cycle()
            assert parser.next_event() is module.NEED_DATA
        else:
            for _ in range(requests):
                parser.complete = False
                parser.parser.feed_data(REQUEST)
                assert parser.complete
            if requests:
                assert parser.parser.should_keep_alive()
    checkpoint()
    del parsers, warmup


def measure(label: str, connections: int, requests: int) -> Sample:
    process = subprocess.Popen(
        [
            sys.executable,
            __file__,
            "--worker",
            label,
            "--connections",
            str(connections),
            "--requests",
            str(requests),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None and process.stdin is not None
        readings = []
        for _ in range(3):
            if process.stdout.readline() != "ready\n":
                raise RuntimeError(f"{label} memory worker failed before reporting RSS")
            readings.append(int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(process.pid)])) * 1024)
            process.stdin.write("continue\n")
            process.stdin.flush()
        if process.wait(timeout=30) != 0:
            raise RuntimeError(f"{label} memory worker exited with status {process.returncode}")
        return Sample(*readings)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        if process.stdout is not None:
            process.stdout.close()
        if process.stdin is not None:
            process.stdin.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connections", type=int, default=2000, help="simultaneously retained parsers")
    parser.add_argument("--requests", type=int, default=3000, help="requests per parser; 0 measures fresh parsers")
    parser.add_argument("--repeats", type=int, default=5, help="fresh processes per parser")
    parser.add_argument("--worker", choices=("zttp", "httptools"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.connections < 1 or args.repeats < 1 or args.requests < 0:
        parser.error("connections and repeats must be positive; requests must be nonnegative")
    if sys.platform not in ("darwin", "linux"):
        parser.error("RSS measurement requires ps on Linux or macOS")
    if args.worker is not None:
        worker(args.worker, args.connections, args.requests)
        return

    sys.stdout.write(
        f"Python {platform.python_version()}, {platform.system()} {platform.machine()}, "
        f"zttp {version('zttp')}, httptools {version('httptools')}\n"
        f"{args.connections:,} connections, {args.requests:,} requests each, "
        f"{args.repeats} fresh processes per parser\n"
        "RSS growth includes native allocations and allocator slack; httptools uses five callbacks.\n"
    )
    sys.stdout.flush()
    samples: dict[str, list[Sample]] = {"zttp": [], "httptools": []}
    for repeat in range(args.repeats):
        labels = list(samples) if repeat % 2 == 0 else list(reversed(samples))
        for label in labels:
            samples[label].append(measure(label, args.connections, args.requests))
    sys.stdout.write(f"{'parser':<12} {'fresh B/conn':>14} {'reused B/conn':>15} {'reused min-max':>22}\n")
    for label, rows in samples.items():
        fresh = [(row.fresh - row.baseline) / args.connections for row in rows]
        reused = [(row.reused - row.baseline) / args.connections for row in rows]
        sys.stdout.write(
            f"{label:<12} {statistics.median(fresh):>14,.1f} {statistics.median(reused):>15,.1f} "
            f"{min(reused):>10,.1f}-{max(reused):<10,.1f}\n"
        )


if __name__ == "__main__":
    main()
