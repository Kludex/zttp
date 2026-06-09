"""Atheris coverage-guided entry point for the parser.

Run locally with a corpus directory:

    uv run --group fuzz python fuzz/fuzz_parse.py fuzz/corpus -runs=2000000

Atheris is optional: it has no wheels on every interpreter we target, so the
cron job falls back to `fuzz/run.py`. Both share `harness.consume`.
"""

from __future__ import annotations

import sys

import atheris

from fuzz.harness import consume


def _target(data: bytes) -> None:
    consume(data)


def main() -> None:
    atheris.Setup(sys.argv, _target)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
