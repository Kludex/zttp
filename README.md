<p align="center">
  <img src="https://github.com/Kludex/zttp/blob/main/docs/assets/logo.png?raw=true" alt="zttp" width="400">
</p>

<p align="center">
  <em>A sans-IO HTTP parser for Python with a Zig core! ⚡</em>
</p>

<p align="center">
  <a href="https://github.com/Kludex/zttp/actions/workflows/main.yml" target="_blank">
    <img src="https://github.com/Kludex/zttp/actions/workflows/main.yml/badge.svg?event=push&branch=main" alt="Test">
  </a>
  <a href="https://pypi.org/project/zttp" target="_blank">
    <img src="https://img.shields.io/pypi/v/zttp?color=%2334D058&label=pypi%20package" alt="Package version">
  </a>
  <a href="https://pypi.org/project/zttp" target="_blank">
    <img src="https://img.shields.io/pypi/pyversions/zttp.svg?color=%2334D058" alt="Supported Python versions">
  </a>
  <a href="https://github.com/Kludex/zttp/blob/main/LICENSE" target="_blank">
    <img src="https://img.shields.io/pypi/l/zttp.svg?color=%2334D058" alt="License">
  </a>
</p>

---

**Documentation**: <a href="https://zttp.marcelotryle.com" target="_blank">https://zttp.marcelotryle.com</a>

**Source Code**: <a href="https://github.com/Kludex/zttp" target="_blank">https://github.com/Kludex/zttp</a>

---

> [!WARNING]
> **zttp** is experimental. The API and behaviour may change at any time, and it is not yet ready for production use.

zttp is a [sans-IO](https://sans-io.readthedocs.io/) HTTP parser whose engine is
written in [Zig](https://ziglang.org). It speaks **HTTP/1.1, HTTP/2, and
HTTP/3**, and it does **no I/O of its own**: you feed it bytes and pull out
events, and you ask it for bytes to send. It never touches a socket, so it works
with any I/O you like.

It's the same idea as [h11](https://github.com/python-hyper/h11), with a
hand-written Zig engine underneath instead of pure Python.

The key features are:

* **Sans-IO**: a clean, event-based API. Feed bytes with `receive_data`, pull
  `Request` / `Data` / `EndOfMessage` events with `next_event`. No callbacks, no
  sockets, no surprises.
* **HTTP/1.1, HTTP/2, and HTTP/3**: the *same* event API for all three, selected
  with one `protocol=` argument.
* **Fast**: faster than [httptools](https://github.com/MagicStack/httptools) (a C
  parser) on 13 of 14 benchmark workloads, and roughly 15x the pure-Python
  alternative.
* **Safe**: strict by default. It defends against request smuggling, rejects bare
  `LF` line endings, bounds every buffer, and ships in Zig's safety-checked build.
* **Typed**: a `py.typed` package with full type hints.
* **No dependencies**: the wheel ships the compiled engine and nothing else.

## Requirements

zttp needs **CPython 3.10+** and runs on **Linux**, **macOS**, and **Windows**.

## Installation

```console
$ pip install zttp
```

Wheels ship the Zig core already compiled, so there is nothing to build and
nothing else to configure. See
[Installation](https://zttp.marcelotryle.com/usage/install/) for building from
source.

## Example

You play the **server**: bytes come in, events come out.

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.receive_data(b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")

request = conn.next_event()  # Request(...)
request.end_stream           # True: this bodyless request is already complete
conn.next_event()   # NEED_DATA

# Build a response:
conn.send_response(200, [(b"Content-Length", b"5")])
conn.send_data(b"hello")
conn.end_message()
conn.data_to_send()  # b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello'
```

The read side yields `Request` / `Response` / `Data` / `EndOfMessage`, or the
`NEED_DATA` sentinel when more bytes are required. A `Request` with
`end_stream=True` needs no separate `EndOfMessage`. The write side serializes a
head, body data, and the end of the message, framing the body (Content-Length or
chunked) for you.

Feed `receive_data` whatever you have — a whole message, a fragment, or a single
byte — and zttp buffers and resumes. There are **no callbacks**: you *pull*
events when *you* are ready. That's what sans-IO means.

## One API, three protocols

The `protocol=` argument selects the wire format; the event API stays the same:

```python
import zttp

h1 = zttp.Connection(zttp.SERVER)                       # HTTP/1.1
h2 = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)  # HTTP/2
h3 = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3)  # HTTP/3
```

On **HTTP/2**, one connection multiplexes many requests, so the `Request` /
`Response` / `Data` / `EndOfMessage` events carry a `stream_id` and you send on
a `Stream` handle. Outbound flow control is handled for you: `send_data` emits
what the peer's window allows and parks the rest until credit arrives.

```python
stream = h2.stream(request.stream_id)
stream.send_response(200, [(b"content-type", b"text/plain")])
stream.send_data(b"Hello, HTTP/2!")
stream.end_message()
h2.data_to_send()  # the HTTP/2 frames to put on the wire
```

On **HTTP/3**, the wire is UDP, so you feed whole datagrams with
`receive_datagram` and pull the same events. The QUIC transport underneath
(packet protection, loss recovery, congestion control, stream reassembly) is
written from scratch in the Zig core. HTTP/3 uses the same stream-scoped send
surface as HTTP/2.

```python
h3.receive_datagram(datagram)
h3.next_event()  # the same Request / Data / EndOfMessage, tagged with stream_id
```

See [HTTP/2](https://zttp.marcelotryle.com/usage/http2/) and
[HTTP/3](https://zttp.marcelotryle.com/usage/http3/) for the full story, including
what each protocol changes and why. HTTP/3 support is experimental: the
convenience server constructor creates an ephemeral TLS identity for local use,
not a production server identity.

## Performance

Against [httptools](https://github.com/MagicStack/httptools) — the C parser
uvicorn uses — on the same requests, with both verified to extract identical
data:

| Workload          | zttp         | httptools    | zttp vs httptools |
| ----------------- | -----------: | -----------: | ----------------: |
| Simple GET        | ~1.24M req/s | ~1.07M req/s | **~1.16x**        |
| POST + JSON body  | ~1.42M req/s | ~1.25M req/s | **~1.14x**        |

zttp beats httptools on 13 of the benchmark suite's 14 workloads while staying
sans-IO and event-based, and is roughly 15x faster than the pure-Python
alternative. Run it yourself with `./scripts/bench`.

These are parser microbenchmarks, and single-digit-percent edges are close to
run-to-run noise — see
[Performance](https://zttp.marcelotryle.com/reference/performance/) for the full
14-workload table, the methodology, and the caveats.

### Why it is fast

- A SWAR newline scanner and comptime-built character-class tables in the Zig
  core, so the hot loops are branch-light array lookups.
- The body is emitted as a single `Data` event slicing the parse buffer, rather
  than copied per callback the way httptools does.
- The header list is built directly in Zig as `list[tuple[bytes, bytes]]`, with
  no per-header Python callback.

## Correctness & security

The core enforces the framing rules of RFC 9112 §6 against request smuggling:
the Content-Length / Transfer-Encoding conflict, duplicate-Content-Length checks,
and combining multiple `Transfer-Encoding` field-lines into one ordered list so
`chunked` must be the sole, final coding. Line endings are strict CRLF by default
(bare LF is rejected), chunk-size is strictly `1*HEXDIG`, and obsolete line
folding is rejected. Header blocks, trailers, and the receive buffer are all
bounded by conservative built-in limits so a malicious peer cannot exhaust
memory, and the outbound serializer rejects CR/LF/control bytes to prevent
response splitting. The build defaults to Zig's safety-checked `ReleaseSafe`
mode. Malformed input raises `RemoteProtocolError`; misusing the send API raises
`LocalProtocolError`.

The HTTP/2 layer applies the same posture: the per-stream state machine enforces
RFC 9113's stream lifecycle, with the exact stream-vs-connection error
classification the RFC requires.

The parser has been through two adversarial security audits (a code review and a
CVE-driven review against real HTTP-parser CVEs across Node, Go, Python, Rust, and
C servers); `zig build fuzz` runs the adversarial-input net over the core. See
[THREAT_MODEL.md](THREAT_MODEL.md) for what **zttp** defends against, the exact
limits it enforces, and what the integrator is responsible for.

## License

This project is licensed under the terms of the BSD-3-Clause license.
