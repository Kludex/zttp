# zttp

<p align="center">
  <img src="https://github.com/Kludex/zttp/blob/main/docs/assets/logo.png?raw=true" alt="zttp" width="400">
</p>

> [!WARNING]
> **zttp** is experimental. The API and behaviour may change at any time, and it is not yet ready for production use.

A [sans-IO](https://sans-io.readthedocs.io/) HTTP/1.1, HTTP/2, and HTTP/3 parser
for Python, with a core written in [Zig](https://ziglang.org). It offers the same
clean, event-based API as [h11](https://github.com/python-hyper/h11), with a
hand-written Zig engine underneath that is fast enough to be the HTTP parser in
[uvicorn](https://github.com/encode/uvicorn). **It has no dependencies.**

## Sans-IO

**zttp** does no I/O. You feed it bytes and pull out events; you ask it for bytes to
send. It never touches a socket, so it works with any I/O you like:

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
a `Stream` handle (connection-level control events like `Settings` and `Ping`
have no stream to name). Outbound flow control is handled for you: `send_data`
emits what the peer's window allows and parks the rest until credit arrives.

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
written from scratch in the Zig core. The server read path is implemented end to
end; the TLS 1.3 handshake driver, the write side, and the client read path are
still in progress.

```python
h3.receive_datagram(datagram)
h3.next_event()  # the same Request / Data / EndOfMessage, tagged with stream_id
```

## Performance

Against httptools on the same requests (macOS arm64, CPython 3.14, httptools
0.8.0, the safety-checked `ReleaseSafe` build), both verified to extract
identical data:

| Workload          | zttp         | httptools    | zttp vs httptools |
| ----------------- | -----------: | -----------: | ----------------: |
| Simple GET        | ~1.16M req/s | ~1.2M req/s  | **~0.97x**        |
| POST + JSON body  | ~4.9M req/s  | ~2.4M req/s  | **~2.0x**         |

Run it yourself: `./scripts/bench`.

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

The HTTP/2 layer applies the same posture: the per-stream state machine enforces
RFC 9113's stream lifecycle, with the exact stream-vs-connection error
classification the RFC requires.

The parser has been through two adversarial security audits (a code review and a
CVE-driven review against real HTTP-parser CVEs across Node, Go, Python, Rust, and
C servers); `zig build fuzz` runs the adversarial-input net over the core. See
[THREAT_MODEL.md](THREAT_MODEL.md) for what **zttp** defends against and what the
integrator is responsible for.

## License

BSD-3-Clause.
