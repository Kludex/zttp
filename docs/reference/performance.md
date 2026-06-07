---
icon: lucide/gauge
---

# Performance

The point of writing a parser in Zig is to be fast. Here's where zttp stands, how
it's measured, and the caveats - because a benchmark with no methodology is just a
number.

## The numbers

Parsing the same requests through zttp, [httptools](https://github.com/MagicStack/httptools)
(the parser uvicorn uses), and [h11](https://github.com/python-hyper/h11), with
all three driven to extract the **same** information (method, headers, body):

| Workload | zttp | httptools | h11 | zttp vs httptools |
| --- | ---: | ---: | ---: | ---: |
| Simple `GET` (7 headers) | ~1.1M req/s | ~0.87M req/s | ~57k req/s | **~1.25x** |
| `POST` + JSON body | ~5.0M req/s | ~1.8M req/s | ~0.6M req/s | **~2.7x** |

zttp is faster than httptools on both, and roughly an order of magnitude faster
than h11. Measured on an Apple Silicon machine with CPython 3.14 and the
safety-checked (`ReleaseSafe`) build.

!!! info "These are parser microbenchmarks"
    They measure parsing throughput in isolation - not a full server. In a real
    application the parser is one slice of the request cost; treat these as the
    ceiling the parser contributes, not end-to-end numbers.

## Run it yourself

The benchmark lives in `bench.py` and compares all three parsers:

```console
uv run --group bench python bench.py
```

It feeds each parser identical bytes and verifies they extract identical data
before timing, so the comparison is apples to apples.

## Why it's fast

* **A SWAR newline scan and comptime character tables.** The hot loops are
  branch-light array lookups, not per-byte conditionals.
* **One `Data` event per body span.** httptools copies the body per callback, and
  uvicorn then concatenates; zttp slices the buffer once.
* **The header list is built in Zig.** No per-header Python callback - the whole
  `list[tuple[bytes, bytes]]` is constructed in the extension.

## The honest caveat: safety has a cost

zttp ships in Zig's `ReleaseSafe` mode, which keeps bounds and overflow checks on.
The unchecked `ReleaseFast` mode is roughly 10% faster again - but for a parser
eating untrusted network bytes, those checks turn a would-be memory bug into a
clean trap. We chose safety, and zttp still beats httptools. That trade is the
right one for this library.

!!! tip
    If you have a workload where the last 10% matters and you trust your input,
    you can build the extension from source with `HATCH_ZIG_BUILD_MODE=ReleaseFast`.
    For almost everyone, the default is the right call.
