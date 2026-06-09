# zttp

<p align="center">
  <img src="https://github.com/Kludex/zttp/blob/main/docs/assets/logo.png?raw=true" alt="zttp" width="400">
</p>

> [!WARNING]
> zttp is experimental. The API and behaviour may change at any time, and it is not yet ready for production use.

A [sans-IO](https://sans-io.readthedocs.io/) HTTP parser for Python, with a core
written in [Zig](https://ziglang.org). It is to [h11](https://github.com/python-hyper/h11)
what [zloop](https://github.com/Kludex/zloop) is to asyncio: the same clean,
event-based API, with a hand-written Zig engine underneath - fast enough to be
usable as the HTTP/1.1 parser in [uvicorn](https://github.com/encode/uvicorn).

## Sans-IO

zttp does no I/O. You feed it bytes and pull out events; you ask it for bytes to
send. It never touches a socket. This is the h11 model:

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.receive_data(b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")

conn.next_event()   # Request(method=b'GET', target=b'/path?q=1', http_version=b'1.1', headers=[(b'Host', b'example.com')])
conn.next_event()   # EndOfMessage(trailers=[])
conn.next_event()   # NEED_DATA

# Build a response:
conn.send_response(200, [(b"Content-Length", b"5")])
conn.send_data(b"hello")
conn.end_message()
conn.data_to_send()  # b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello'
```

The read side yields `Request` / `Response` / `Data` / `EndOfMessage`, or the
`NEED_DATA` sentinel when more bytes are required. The write side serializes a
head, body data, and the end of the message, framing the body (Content-Length or
chunked) for you.

## Performance

Against httptools and h11 on the same requests (macOS arm64, CPython 3.14,
`ReleaseFast`), all three verified to extract identical data:

| Workload          | zttp        | httptools    | h11        | zttp vs httptools |
| ----------------- | -----------: | -----------: | ---------: | -----------------: |
| Simple GET        | ~1.25M req/s | ~880k req/s  | ~57k req/s | **1.41x**          |
| POST + JSON body  | ~6.7M req/s  | ~1.84M req/s | ~616k req/s| **3.62x**          |

Run it yourself: `uv run --group bench python bench.py`.

## Why it is fast

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
bounded (`Limits`) so a malicious peer cannot exhaust memory, and the outbound
serializer rejects CR/LF/control bytes to prevent response splitting. The build
defaults to Zig's safety-checked `ReleaseSafe` mode. Malformed input raises
`RemoteProtocolError`; misusing the send API raises `LocalProtocolError`.

The parser has been through two adversarial security audits (a code review and a
CVE-driven review against real HTTP-parser CVEs across Node, Go, Python, Rust, and
C servers); `zig build fuzz` runs the adversarial-input net over the core. See
[THREAT_MODEL.md](THREAT_MODEL.md) for what zttp defends against and what the
integrator is responsible for.

## Roadmap

- **HTTP/1.1** - request and response parsing, chunked transfer-coding,
  trailers, keep-alive, the bidirectional connection state machine. *(done)*
- **Connection state policy** - h11-parity state machine guards on the read side
  (reject body bytes after a `close`, enforce request/response pairing).
- **uvicorn integration** - an `HttpToolsProtocol`-style adapter so uvicorn can
  use zttp unchanged.
- **HTTP/2** - HPACK, the frame layer, and the multiplexed connection state
  machine in the Zig core, surfaced through the same event API
  (`Connection(role, protocol=zttp.HTTP2)`); events carry a `stream_id`. Both
  read paths (server requests, client responses) and the full write side - a
  `Stream` handle per stream, with outbound flow control - are implemented. *(done)*
- **HTTP/3** - QPACK + the QUIC-side framing, same event API.

## Status

Alpha. The HTTP/1.1 parser and serializer are implemented and tested; the API
may still change.

## License

BSD-3-Clause.
