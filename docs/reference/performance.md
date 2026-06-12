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
| wrk default `GET` | 2.42M msg/s | 2.09M msg/s | **1.16x** |
| httparse `REQ_SHORT` | 2.12M msg/s | 1.79M msg/s | **1.18x** |
| TFB plaintext, 16x pipelined | 151k msg/s | 161k msg/s | 0.94x |
| Small API `GET` | 1.24M msg/s | 1.07M msg/s | **1.16x** |
| `POST` + JSON body | 1.42M msg/s | 1.25M msg/s | **1.14x** |
| Real-world `GET` (pico/llhttp) | 947k msg/s | 831k msg/s | **1.14x** |
| Chunked `POST` (llhttp bench) | 875k msg/s | 741k msg/s | **1.18x** |
| Chrome navigation `GET` | 702k msg/s | 577k msg/s | **1.22x** |
| k8s ingress proxied `GET` | 688k msg/s | 634k msg/s | **1.08x** |
| 16KB upload `POST` | 1.11M msg/s | 1.05M msg/s | **1.06x** |
| 16KB upload, MTU pieces | 441k msg/s | 214k msg/s | **2.06x** |
| httparse `RESP_SHORT` | 1.79M msg/s | 1.60M msg/s | **1.12x** |
| JSON API response | 1.46M msg/s | 1.31M msg/s | **1.12x** |
| Chunked HTML response | 813k msg/s | 784k msg/s | **1.04x** |

The honest summary: zttp beats httptools, a C parser, on thirteen of the
fourteen workloads while keeping the sans-IO pull API, and is roughly 15x the
pure-Python alternative everywhere. The one remaining gap is the synthetic
16-messages-per-buffer pipelined read, where httptools' per-connection parser
construction amortizes in a way zttp's per-message event objects cannot.
Measured on an Apple Silicon machine with CPython 3.14, httptools 0.8.0, and
the safety-checked (`ReleaseSafe`) build; the run-to-run spread is about 5%.

!!! info "These are parser microbenchmarks"
    They measure parsing throughput in isolation, not a full server. In a real
    application the parser is one slice of the request cost; treat these as the
    ceiling the parser contributes, not end-to-end numbers.

## Run it yourself

The benchmarks live in `benchmarks/`, one file per protocol, each pitched
against the fastest Python parser for that protocol:

| File | Compares against |
| --- | --- |
| `benchmarks/http1.py` | httptools (C) and h11 (pure Python) |
| `benchmarks/http2.py` | h2 (the pure-Python `python-hyper` stack) |

```console
./scripts/bench
```

runs both. `./scripts/bench http2` runs one and forwards any extra flags
(`--batch`, `--repeats`, `--only <substring>`) to it.

The table above is the HTTP/1 suite. Each benchmark feeds its parsers identical
input and verifies they extract identical data before timing, so the comparison
is apples to apples; parsers run many short batches interleaved round-robin so
thermal drift and scheduler placement hit them equally, with the GC disabled
while a batch is timed; the headline is the median batch with the spread printed
alongside.

The HTTP/1 workloads come from the parser-benchmark literature wherever one
exists: the picohttpparser/llhttp real-world GET, llhttp's chunked POST,
httparse's short request and response, the wrk and TechEmpower request shapes,
plus faithful reconstructions of modern traffic (a Chrome navigation, a
k8s-ingress proxied API call), large uploads delivered whole and in MTU-sized
pieces, and response parsing in the client role.

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
