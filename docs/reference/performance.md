---
icon: lucide/gauge
---

# Performance

The point of writing a parser in Zig is to be fast. Here's where zttp stands, how
it's measured, and the caveats, because a benchmark with no methodology is just a
number.

## The numbers

Parsing the same messages through zttp and
[httptools](https://github.com/MagicStack/httptools) (the parser uvicorn uses),
with both driven to extract the **same** information (request line or status,
headers, body), across a suite drawn from the parser-benchmark literature and
realistic modern traffic:

| Workload | zttp | httptools | zttp vs httptools |
| --- | ---: | ---: | ---: |
| wrk default `GET` | 2.05M msg/s | 2.12M msg/s | 0.97x |
| httparse `REQ_SHORT` | 1.76M msg/s | 1.76M msg/s | 1.00x |
| TFB plaintext, 16x pipelined | 129k msg/s | 160k msg/s | 0.81x |
| Small API `GET` | 1.04M msg/s | 1.07M msg/s | 0.97x |
| `POST` + JSON body | 1.19M msg/s | 1.23M msg/s | 0.96x |
| Real-world `GET` (pico/llhttp) | 821k msg/s | 828k msg/s | 0.99x |
| Chunked `POST` (llhttp bench) | 742k msg/s | 742k msg/s | 1.00x |
| Chrome navigation `GET` | 620k msg/s | 575k msg/s | **1.08x** |
| k8s ingress proxied `GET` | 621k msg/s | 631k msg/s | 0.99x |
| 16KB upload `POST` | 553k msg/s | 1.06M msg/s | **0.52x** |
| 16KB upload, MTU pieces | 264k msg/s | 215k msg/s | **1.23x** |
| httparse `RESP_SHORT` | 1.54M msg/s | 1.60M msg/s | 0.96x |
| JSON API response | 1.22M msg/s | 1.32M msg/s | 0.93x |
| Chunked HTML response | 764k msg/s | 786k msg/s | 0.97x |

The honest summary: zttp matches httptools, a C parser, on typical API and
browser traffic while keeping the sans-IO pull API, runs ahead on large modern
header blocks and on input delivered in TCP-segment-sized pieces, and is
roughly 15x the pure-Python alternative everywhere. Two workloads are tracked
as known gaps: large bodies delivered in one buffer (zttp currently copies the
body twice) and many-messages-per-buffer pipelined reads. Measured on an Apple
Silicon machine with CPython 3.14, httptools 0.8.0, and the safety-checked
(`ReleaseSafe`) build; the run-to-run spread is about 5%.

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

The workloads come from the parser-benchmark literature wherever one exists:
the picohttpparser/llhttp real-world GET, llhttp's chunked POST, httparse's
short request and response, the wrk and TechEmpower request shapes, plus
faithful reconstructions of modern traffic (a Chrome navigation, a k8s-ingress
proxied API call), large uploads delivered whole and in MTU-sized pieces, and
response parsing in the client role. `--only <substring>` runs a subset.

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
