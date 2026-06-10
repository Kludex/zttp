"""Dependency-free fuzz runner - the cron workhorse.

Atheris gives coverage guidance but isn't available on every interpreter we
ship for, so CI relies on this instead. It hammers the parser with random and
seeded inputs, runs both the read-path oracle (`harness.consume`) and the
roundtrip oracle, and on any unexpected exception writes the offending bytes to
the corpus directory and exits non-zero so the cron job fails loudly.

    uv run python -m fuzz.run --runs 200000 --seed 1
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import os
import random
import sys
import traceback
from collections.abc import Callable, Iterator
from pathlib import Path

from fuzz.harness import consume, consume_h2
from fuzz.roundtrip import roundtrip

CORPUS = Path(__file__).parent / "corpus"

# Fragments worth splicing together: framing, chunked bodies, smuggling shapes.
SEEDS = (
    b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello",
    b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
    b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-T: y\r\n\r\n",
    b"\r\n\n: \r\n\x00\xff",
)

# H2 wire fragments: preface + empty SETTINGS, then a HEADERS frame whose HPACK
# block is fully indexed (:method GET, :scheme http, :path /) with END_HEADERS.
H2_SEEDS = (
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    b"\x00\x00\x00\x04\x00\x00\x00\x00\x00",
    b"\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x86\x84",
    b"\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x00\x08",
)

ORACLES: tuple[Callable[[bytes], None], ...] = (consume, consume_h2, roundtrip)


def _mutate(rng: random.Random, sample: bytes) -> bytes:
    data = bytearray(sample)
    for _ in range(rng.randint(1, 8)):
        if not data:
            data.append(rng.randint(0, 255))
            continue
        op = rng.randint(0, 4)
        i = rng.randrange(len(data))
        if op == 0:
            data[i] = rng.randint(0, 255)
        elif op == 1:
            data.insert(i, rng.randint(0, 255))
        elif op == 2:
            del data[i]
        elif op == 3:
            data[i] = rng.choice(b"\r\n: \x00")
        else:
            data[i:i] = rng.choice(SEEDS)
    return bytes(data)


def _inputs(rng: random.Random, runs: int) -> Iterator[bytes]:
    for _ in range(runs):
        roll = rng.random()
        if roll < 0.4:
            yield _mutate(rng, rng.choice(SEEDS))
        elif roll < 0.65:
            yield _mutate(rng, b"".join(H2_SEEDS) + rng.randbytes(rng.randint(0, 32)))
        elif roll < 0.8:
            yield rng.randbytes(rng.randint(0, 256))
        else:
            yield _mutate(rng, b"".join(rng.sample(SEEDS, rng.randint(1, 3))))


def _record(data: bytes, oracle: str) -> Path:
    CORPUS.mkdir(exist_ok=True)
    digest = hashlib.sha256(data).hexdigest()[:16]
    path = CORPUS / f"crash-{oracle}-{digest}.bin"
    path.write_bytes(data)
    return path


def _replay_corpus() -> Iterator[bytes]:
    if not CORPUS.exists():
        return
    for path in sorted(CORPUS.glob("*.bin")):
        yield path.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=int(os.environ.get("FUZZ_RUNS", "200000")))
    parser.add_argument("--seed", type=int, default=int(os.environ.get("FUZZ_SEED", "0")))
    args = parser.parse_args()

    rng = random.Random(args.seed)
    findings = 0
    # Replay saved reproducers first so a regression fails fast, then fuzz. Chain
    # lazily - materializing millions of generated inputs up front would blow the
    # runner's memory before a single oracle runs.
    for data in itertools.chain(_replay_corpus(), _inputs(rng, args.runs)):
        for oracle in ORACLES:
            try:
                oracle(data)
            except Exception as error:  # the whole point is to catch anything escaping the oracle.
                findings += 1
                path = _record(data, oracle.__name__)
                print(f"FINDING via {oracle.__name__}: {type(error).__name__}: {error}")
                print(f"  saved reproducer: {path}")
                traceback.print_exc()

    if findings:
        print(f"\n{findings} finding(s) over {args.runs} runs (seed={args.seed}).")
        return 1
    print(f"clean: {args.runs} runs x {len(ORACLES)} oracles (seed={args.seed}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
