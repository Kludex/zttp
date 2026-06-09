# Fuzzing

Continuous fuzzing for the `zttp` parser. A daily GitHub Actions cron job
(`.github/workflows/fuzz.yml`) hammers the parser; any finding fails the job and
uploads a reproducer.

## The contract under test

Driving a `Connection` with arbitrary bytes must:

- never crash the interpreter, and
- only ever raise a `ProtocolError` (or subclass) on bad input.

Any other escaping exception - `AssertionError`, `SystemError`, `MemoryError`,
a segfault - is a parser bug.

## Oracles

- `harness.consume` - read path. Splits input across read boundaries (so the
  parser is exercised mid-buffer, not just on whole feeds) and pulls every
  event out for both `SERVER` and `CLIENT` roles.
- `roundtrip.roundtrip` - encode then decode. A `CLIENT` serializes a request a
  `SERVER` parses; method, target, and headers must survive unchanged. Catches
  encoder/parser disagreements that smuggling exploits.

`structured.draw_request` maps fuzzer bytes into HTTP-shaped requests so inputs
reach header, framing, and chunked-body code instead of bailing on byte one.

## Running it

```sh
# Dependency-free runner - what CI uses. Replays the saved corpus, then fuzzes.
uv run python -m fuzz.run --runs 1000000 --seed 1

# Coverage-guided (Atheris; needs the optional group, Python < 3.13):
uv sync --group fuzz
uv run python fuzz/fuzz_parse.py fuzz/corpus -runs=2000000
```

## Corpus

`fuzz/corpus/` holds reproducers. `fuzz/run.py` replays every `crash-*.bin`
before each campaign, so a committed reproducer becomes a permanent regression
test. When the cron job finds a crash it writes the offending bytes here and
uploads them as an artifact - commit the file to lock in the regression.
