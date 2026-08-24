---
icon: lucide/server
---

# A real server

Every example so far fed zttp bytes from a literal. That's the point of sans-IO -
the parser doesn't care where the bytes come from - but you probably want to see
it talk to an actual socket. So here is a complete HTTP/1.1 server in `asyncio`,
in one file, that you can run and `curl`.

zttp does the protocol; **you** own the I/O. The whole job is a loop: read bytes
from the socket, pull events until the parser needs more, and write the response
back.

```python title="server.py"
import asyncio

import zttp


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    conn = zttp.Connection(zttp.SERVER)
    try:
        while True:
            request = None
            body = bytearray()
            # Pull complete events; refill from the socket whenever we run dry.
            while True:
                event = conn.next_event()
                if event is zttp.NEED_DATA:
                    data = await reader.read(65536)
                    event = conn.receive_event(data)  # b"" signals EOF
                    if not data and event is zttp.NEED_DATA:
                        return
                    if event is zttp.NEED_DATA:
                        continue
                if isinstance(event, zttp.Request):
                    request = event
                    if event.end_stream:
                        break
                elif isinstance(event, zttp.Data):
                    body += event.data
                elif isinstance(event, zttp.EndOfMessage):
                    break

            assert request is not None
            reply = b"Hello, %s!\n" % (request.path.lstrip(b"/") or b"World")
            conn.send_response(200, [(b"content-type", b"text/plain"), (b"content-length", b"%d" % len(reply))])
            conn.send_data(reply)
            conn.end_message()
            writer.write(conn.data_to_send())
            await writer.drain()
            # should_close() reflects the request just parsed and the response just
            # sent (Connection: close, or HTTP/1.0 without keep-alive);
            # start_next_cycle() clears it, so ask now.
            if conn.should_close():
                return
            conn.start_next_cycle()  # reuse the connection for the next request
    except zttp.RemoteProtocolError:
        conn.send_response(400, [(b"content-length", b"0")])
        conn.end_message()
        writer.write(conn.data_to_send())
        await writer.drain()
    finally:
        writer.close()


async def main() -> None:
    server = await asyncio.start_server(handle, "127.0.0.1", 8080)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
```

Run it and hit it:

```console
$ python server.py &
$ curl http://127.0.0.1:8080/there
Hello, there!

$ curl http://127.0.0.1:8080/ http://127.0.0.1:8080/again   # two requests, one connection
Hello, World!
Hello, again!
```

That's a working keep-alive HTTP/1.1 server. No framework, no callbacks - just the
sans-IO loop. Here's each piece.

## The read loop: refill on `NEED_DATA`

The inner `while True` pulls buffered events. When `next_event()` returns
`NEED_DATA`, the parser has consumed everything you gave it and needs more. Read
from the socket, then use `receive_event` to feed the bytes and return the first
event in one extension call:

```python
event = conn.next_event()
if event is zttp.NEED_DATA:
    data = await reader.read(65536)
    event = conn.receive_event(data)
    if not data and event is zttp.NEED_DATA:
        return          # the client closed; nothing more is coming
    if event is zttp.NEED_DATA:
        continue
```

This is the whole sans-IO contract: **you** decide when to read, so backpressure
is yours. An empty read is EOF. Feed the empty bytes so the parser can finalize
a message that ends when the connection closes.

## Dispatching events

Between the head and the end, you accumulate what you need. Accumulate body bytes
into a `bytearray`, not `b""` - appending to `bytes` reallocates the whole buffer
each time (quadratic); a `bytearray` grows in place:

```python
if isinstance(event, zttp.Request):
    request = event
    if event.end_stream:
        break
elif isinstance(event, zttp.Data):
    body += event.data
elif isinstance(event, zttp.EndOfMessage):
    break
```

Bodyless requests finish on the `Request` itself. This is the common GET/HEAD
path and avoids allocating and pulling a redundant terminal event. Requests
with a framed body have `end_stream=False`; their `Data` and `EndOfMessage`
events follow normally, including any trailers.

## Writing the response

Describe the message; zttp frames it and hands you the bytes. `send_data` passes
the body through (here with a `content-length`; declare `transfer-encoding:
chunked` instead to stream a body of unknown length), and `data_to_send()` returns
the serialized bytes to put on the wire:

```python
conn.send_response(200, [(b"content-type", b"text/plain"), (b"content-length", b"%d" % len(reply))])
conn.send_data(reply)
conn.end_message()
writer.write(conn.data_to_send())
await writer.drain()
```

## Keep-alive

HTTP/1.1 reuses the connection, so the outer loop serves request after request.
zttp works out from the head whether the connection must close, so you don't scan
headers - you ask. It covers both directions: the request the peer sent, and the
response you serialized, so an application that answers with `Connection: close`
is honored without you re-reading its headers. `should_close()` is only meaningful
once the request head is parsed, and `start_next_cycle()` resets it, so check it
**after** you've answered and before you cycle:

```python
while True:
    ...
    if conn.should_close():   # Connection: close, or HTTP/1.0 without keep-alive
        return                # honor it before start_next_cycle() clears the signal
    conn.start_next_cycle()   # otherwise parse the next request on the same connection
```

## When the peer misbehaves

A parser eating bytes off the network is a security boundary, so malformed input
raises [`RemoteProtocolError`](errors.md) from `next_event()`. Catch it, send a
`400`, and close - never keep parsing a connection that already broke the protocol:

```python
except zttp.RemoteProtocolError:
    conn.send_response(400, [(b"content-length", b"0")])
    conn.end_message()
    writer.write(conn.data_to_send())
    await writer.drain()
```

!!! tip "This is HTTP/1.1"
    Event draining is shared across all protocols, but each transport has its
    own feed call. HTTP/1.1 uses `receive_event`, HTTP/2 uses `receive_data`, and
    HTTP/3 uses `receive_datagram`. On HTTP/2 and HTTP/3 you also answer on a
    [`Stream`](http2.md) (`conn.stream(request.stream_id)`) because one
    connection carries many requests at once.

## Where to go next

* [HTTP/2](http2.md): the same loop, multiplexed - streams, flow control, control events.
* [Errors](errors.md): everything zttp rejects, and why.
* [Architecture](../architecture.md): why a parser should do no I/O.
