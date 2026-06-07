# zhttp

A [sans-IO](https://sans-io.readthedocs.io/) HTTP parser for Python, with a core
written in [Zig](https://ziglang.org). It is to [h11](https://github.com/python-hyper/h11)
what [zloop](https://github.com/Kludex/zloop) is to asyncio: the same clean,
event-based API, with a hand-written Zig engine underneath. The goal is to be
faster than [httptools](https://github.com/MagicStack/httptools) - and usable as
the HTTP/1.1 parser in [uvicorn](https://github.com/encode/uvicorn).

## Sans-IO

zhttp does no I/O. You feed it bytes and pull out events; you ask it for bytes to
send. It never touches a socket. This is the h11 model:

```python
import zhttp

conn = zhttp.Connection(zhttp.SERVER)
conn.receive_data(b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")

conn.next_event()   # Request(method=b'GET', target=b'/path?q=1', http_version=b'1.1', headers=[(b'Host', b'example.com')])
conn.next_event()   # EndOfMessage(trailers=[])
conn.next_event()   # NEED_DATA

# Build a response:
conn.send_response(b"1.1", 200, b"OK", [(b"Content-Length", b"5")])
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

| Workload          | zhttp        | httptools    | h11        | zhttp vs httptools |
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

## Correctness

The core enforces the framing rules of RFC 9112 §6, including the
Content-Length / Transfer-Encoding conflict and duplicate-Content-Length checks
that defend against request smuggling. Malformed input raises
`RemoteProtocolError`; misusing the send API raises `LocalProtocolError`.

## Roadmap

- **HTTP/1.1** - request and response parsing, chunked transfer-coding,
  trailers, keep-alive, the bidirectional connection state machine. *(done)*
- **Connection state policy** - h11-parity state machine guards on the read side
  (reject body bytes after a `close`, enforce request/response pairing).
- **uvicorn integration** - an `HttpToolsProtocol`-style adapter so uvicorn can
  use zhttp unchanged.
- **HTTP/2** - HPACK + frame layer in the Zig core, same event API.
- **HTTP/3** - QPACK + the QUIC-side framing, same event API.

## Status

Alpha. The HTTP/1.1 parser and serializer are implemented and tested; the API
may still change.

## License

BSD-3-Clause.
