---
icon: lucide/gauge
---

# Performance

The point of writing a parser in Zig is to be fast. These tables show where zttp
stands and how each comparison is measured. A benchmark with no methodology is
just a number.

## HTTP/1.1

This benchmark parses the same messages with zttp and
[httptools](https://github.com/MagicStack/httptools), the C parser used by
Uvicorn. Both parsers extract the same request line or status, headers, and body.

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

zttp is faster on thirteen of the fourteen HTTP/1.1 workloads. The remaining
gap is the synthetic 16-messages-per-buffer pipelined read, where httptools
amortizes its connection parser across the whole buffer.

## HTTP/2

This benchmark compares zttp with [h2](https://python-hyper.org/projects/h2/),
the mainstream Python HTTP/2 implementation. h2 and its HPACK and framing
libraries are pure Python. There is no mainstream C or Rust HTTP/2 peer for
Python.

Both implementations decode the same bytes produced by h2's encoder. The input
contains a real connection preface, `SETTINGS`, and HPACK-compressed
`HEADERS` and `DATA` frames.

| Workload | zttp | h2 | zttp vs h2 |
| --- | ---: | ---: | ---: |
| wrk default `GET` | 711k msg/s | 18.7k msg/s | **38.06x** |
| Small API `GET` | 190k msg/s | 12.2k msg/s | **15.50x** |
| Real-world `GET` (pico/llhttp) | 50.1k msg/s | 7.58k msg/s | **6.60x** |
| Chrome navigation `GET` | 44.4k msg/s | 5.89k msg/s | **7.54x** |
| k8s ingress proxied `GET` | 45.8k msg/s | 6.30k msg/s | **7.31x** |
| `POST` + JSON body | 384k msg/s | 13.8k msg/s | **27.81x** |
| 16KB upload `POST` | 284k msg/s | 11.2k msg/s | **25.46x** |
| 16 multiplexed `GET` requests | 2.44M msg/s | 48.4k msg/s | **50.59x** |
| 100 multiplexed `GET` requests | 741k msg/s | 31.0k msg/s | **23.85x** |
| JSON API response | 327k msg/s | 9.99k msg/s | **32.52x** |
| 16 multiplexed JSON responses | 960k msg/s | 23.1k msg/s | **41.53x** |

The multiplexed rows count messages, not connections. For example, the
16-stream workload parses 16 requests from one connection buffer and credits 16
messages.

## HTTP/3

This benchmark compares complete HTTP/3 round trips with
[aioquic](https://github.com/aiortc/aioquic), the mainstream Python HTTP/3
stack. aioquic implements QUIC in Python and uses the `pylsqpack` C extension for
QPACK.

HTTP/3 has no plaintext mode. Each timed operation sends a request from an
established client, decrypts and parses it on the server, sends a response, then
decrypts and parses that response on the client. The rate includes QUIC packet
protection, QPACK, and HTTP/3 framing on both sides.

| Workload | zttp | aioquic | zttp vs aioquic |
| --- | ---: | ---: | ---: |
| Bare `GET` | 109k round trips/s | 6.02k round trips/s | **18.1x** |
| Small API `GET` | 75.4k round trips/s | 5.22k round trips/s | **14.3x** |
| `POST` + JSON body | 81.5k round trips/s | 5.64k round trips/s | **14.5x** |

## Test environment

The HTTP/2 and HTTP/3 tables were measured on Apple Silicon with CPython 3.14.3,
zttp 0.0.24.dev5, h2 4.3.0, and aioquic 1.3.0. zttp used the safety-checked
`ReleaseSafe` build. Each reported rate is the median of 15 interleaved batches.
The interquartile ratio ranges were roughly 1% to 4% of the median for HTTP/2
and 2% to 3% for HTTP/3.

The HTTP/1.1 table used the same build mode on Apple Silicon with CPython 3.14
and httptools 0.8.0. Its run-to-run spread was about 5%.

!!! info "These are protocol microbenchmarks"
    They measure protocol throughput in isolation, not a full server. In a real
    application the protocol stack is one slice of the request cost. Treat these
    rates as the ceiling the stack contributes, not end-to-end server numbers.

## Run the benchmarks

The benchmarks live in `benchmarks/`, one file per protocol.

| File | Compares against |
| --- | --- |
| `benchmarks/http1.py` | httptools (C) and h11 (pure Python) |
| `benchmarks/http2.py` | h2 (pure Python) |
| `benchmarks/http3.py` | aioquic (Python QUIC with C QPACK) |

```console
./scripts/bench
```

This runs all three suites. Run one protocol to forward options to its script:

```console
./scripts/bench http2 --repeats 5 --only multiplexed
./scripts/bench http3 --repeats 5 --only GET
```

Each suite verifies both implementations extract or exchange equivalent data
before timing. It runs short batches in an interleaved round-robin, with garbage
collection disabled during each batch. This reduces bias from thermal drift,
scheduler placement, and garbage collection. The output includes the median,
interquartile range, and standard deviation.

The HTTP/1.1 workloads draw from parser benchmark suites where possible. They
include picohttpparser and llhttp's real-world requests, httparse's short
messages, wrk and TechEmpower request shapes, modern browser and ingress traffic,
large uploads, and response parsing.

## Why it is fast

* **A SWAR newline scan and comptime character tables.** The HTTP/1.1 hot loops
  use branch-light array lookups instead of per-byte conditionals.
* **One `Data` event per body span.** httptools copies the body per callback, and
  Uvicorn then concatenates it. zttp slices the input buffer once.
* **Headers are built in Zig.** There is no per-header Python callback. zttp
  constructs the complete header block in the extension.
* **Protocol state stays native.** HTTP/2 framing, HPACK, QUIC, and QPACK run in
  the Zig core instead of crossing the Python boundary for each frame or field.

## Safety has a cost

zttp ships in Zig's `ReleaseSafe` mode, which keeps bounds and overflow checks
enabled. The unchecked `ReleaseFast` mode is a few percent faster, but a parser
consumes untrusted network bytes. The checks turn memory errors into traps, so
the safer build is the default.

!!! tip "Build without safety checks"
    If your workload needs the last few percent and you trust its input, build
    from source with `HATCH_ZIG_BUILD_MODE=ReleaseFast`. Keep `ReleaseSafe` for
    network-facing use.
