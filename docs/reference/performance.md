---
icon: lucide/gauge
---

# Performance

The point of writing a parser in Zig is to be fast. Here's where zttp stands, how
it's measured, and the caveats, because a benchmark with no methodology is just a
number.

## The numbers

Parsing the same requests through zttp and
[httptools](https://github.com/MagicStack/httptools) (the parser uvicorn uses),
with both driven to extract the **same** information (method, headers, body):

| Workload | zttp | httptools | zttp vs httptools |
| --- | ---: | ---: | ---: |
| Simple `GET` (7 headers) | ~1.11M req/s | ~1.11M req/s | **~1.0x** |
| `POST` + JSON body | ~1.27M req/s | ~1.30M req/s | **~1.0x** |

zttp matches httptools, a C parser, on both workloads, while keeping the
sans-IO pull API, and is roughly 15x faster than the pure-Python alternative.
Measured on an Apple Silicon machine with CPython 3.14, httptools 0.8.0, and
the safety-checked (`ReleaseSafe`) build; the run-to-run spread is about 5%.

!!! info "These are parser microbenchmarks"
    They measure parsing throughput in isolation, not a full server. In a real
    application the parser is one slice of the request cost; treat these as the
    ceiling the parser contributes, not end-to-end numbers.

## Run it yourself

The benchmark lives in `bench.py`:

```console
./scripts/bench
```

It feeds each parser identical bytes and verifies they extract identical data
before timing, so the comparison is apples to apples. Each parser runs many
short batches, interleaved round-robin so thermal drift and scheduler placement
hit all parsers equally, with the GC disabled while a batch is timed; the
headline is the median batch and the spread is printed alongside it.

## Why it's fast

* **A SWAR newline scan and comptime character tables.** The hot loops are
  branch-light array lookups, not per-byte conditionals.
* **One `Data` event per body span.** httptools copies the body per callback, and
  uvicorn then concatenates; zttp slices the buffer once.
* **The header list is built in Zig.** No per-header Python callback: the whole
  `list[tuple[bytes, bytes]]` is constructed in the extension.

## The honest caveat: safety has a cost

zttp ships in Zig's `ReleaseSafe` mode, which keeps bounds and overflow checks on.
The unchecked `ReleaseFast` mode is a few percent faster again, but for a parser
eating untrusted network bytes, those checks turn a would-be memory bug into a
clean trap. We chose safety. That trade is the right one for this library.

!!! tip
    If you have a workload where the last 10% matters and you trust your input,
    you can build the extension from source with `HATCH_ZIG_BUILD_MODE=ReleaseFast`.
    For almost everyone, the default is the right call.
