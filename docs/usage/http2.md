---
icon: lucide/network
---

# HTTP/2

You already know the zttp API: feed bytes with `receive_data`, pull events with
`next_event`, ask for bytes with `data_to_send`. **HTTP/2 is the same API.** You
opt in with one argument, and the events you already know - `Request`,
`Response`, `Data`, `EndOfMessage` - come back, now tagged with the stream they
belong to.

```python
import zttp

conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)  # (1)!
```

1.  The only new thing: `protocol=zttp.HTTP2`. Leave it off and you get HTTP/1.1,
    exactly as before.

!!! note "Prior knowledge"
    zttp speaks HTTP/2 over a plain connection (the *prior-knowledge* mode, and
    what you get after ALPN or an upgrade negotiates `h2`). zttp does no I/O and
    no TLS - it parses and serializes the HTTP/2 framing once you have the bytes.

## Two connections, one base

A connection's *send* surface depends on its protocol, so zttp gives you the
right type for the protocol you asked for:

```python
import zttp

h1 = zttp.Connection(zttp.SERVER)                       # (1)!
h2 = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)  # (2)!

type(h1).__name__  #> 'H1Connection'
type(h2).__name__  #> 'H2Connection'

isinstance(h2, zttp.Connection)  #> True  (3)!
```

1.  An `H1Connection`: the message-scoped send API you saw in
    [Sending](sending.md) - `send_response`, `send_data`, `end_message`.

2.  An `H2Connection`: everything is **stream-scoped**, so it has no connection-level
    `send_data`. You send on a [`Stream`](#streams) instead.

3.  Both are real `Connection` subclasses, so code that only reads (`receive_data`
    / `next_event` / `data_to_send`) can take either one.

!!! tip "Your editor knows"
    Because they're distinct types, calling `h2.send_data(...)` is a **type
    error**, not a runtime surprise - your editor flags it before you run.
    HTTP/2 has no single "current message" to send on, so the method simply
    isn't there.

## The read side

Reading is what you already do. The only addition is `stream_id` on every event,
because one HTTP/2 connection multiplexes many requests at once:

```python title="server_read.py" hl_lines="10"
import zttp

server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
server.receive_data(incoming_bytes)  # (1)!

while True:
    event = server.next_event()
    if event is zttp.NEED_DATA:
        break
    if isinstance(event, zttp.Request):
        print(event.method, event.target, event.stream_id)  # (2)!
```

1.  The bytes off the wire - HTTP/2 frames, not text. Feed whole or in fragments,
    same as always.

2.  `event.stream_id` tells you which stream this `Request` arrived on. On
    HTTP/1.1 it's `0`; on HTTP/2 it's the real id, and every `Data` /
    `EndOfMessage` for that request carries the same id.

A **client** reads the mirror image - `Response` events instead of `Request` -
again tagged with the `stream_id` of the request they answer.

## Streams

In HTTP/2 you don't send "on the connection" - you send **on a stream**. A
`Stream` is a small handle with the send API scoped to one stream:

* `send_response(status, headers=None)` - a response head.
* `send_data(data)` - body bytes (flow-controlled, see [below](#flow-control)).
* `end_message(trailers=None)` - finish the message.

The connection owns the real stream state; the `Stream` is just a typed handle to
it. You get one in two ways, depending on who opens the stream.

### Client: opening a stream

The client **originates** a stream by sending a request, so `send_request`
hands you the `Stream` back:

```python title="client.py" hl_lines="4"
import zttp

client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
stream = client.send_request(b"GET", b"/", b"2", [(b"host", b"example.com")])  # (1)!

stream  #> Stream(stream_id=1)

stream.end_message()  # (2)!
print(client.data_to_send())  # the HTTP/2 frames to put on the wire
```

1.  `send_request` opens the stream and returns its `Stream`. The version arg is
    ignored (it's always `2`), and `:authority` is derived from your `host`
    header - so a request you'd build for HTTP/1.1 works unchanged.

2.  From here you talk to the **stream**, not the connection: `stream.send_data`,
    `stream.end_message`.

### Server: answering a stream

The server learns a stream's id by **reading** the request off it. Use
`conn.stream(id)` to get the handle for the stream you want to answer:

```python title="server.py" hl_lines="7 9"
import zttp

server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
server.receive_data(request_bytes)
request = next(e for e in drain(server) if isinstance(e, zttp.Request))  # (1)!

stream = server.stream(request.stream_id)  # (2)!
stream.send_response(200, [(b"content-type", b"text/plain")])
stream.send_data(b"Hello, HTTP/2!")
stream.end_message()

print(server.data_to_send())
```

1.  `drain` is just a loop over `next_event` until `NEED_DATA` - the events carry
    the `stream_id` you need.

2.  `conn.stream(id)` returns the handle for that stream. The connection already
    owns the stream state; this is your typed view onto it.

!!! tip "Many streams at once"
    Because each `Stream` names its own id, you can answer requests in **any
    order** - hold a handle per in-flight request and respond as each is ready.
    Two requests arriving before you answer either is the normal HTTP/2 case, and
    routing the responses is just `server.stream(s1)` and `server.stream(s2)`.

## Flow control

HTTP/2 has per-stream and per-connection **send windows**: the peer tells you how
many body bytes it's willing to receive, and you mustn't send past that. zttp
handles this for you - and keeps it sans-IO.

When you call `stream.send_data`, zttp emits as many bytes as the window allows
and **parks the rest**. As the peer grants more window (it sends you
`WINDOW_UPDATE` frames, which arrive as bytes you `receive_data`), zttp drains the
parked bytes automatically on the next `next_event`:

```python title="flow.py" hl_lines="6 11"
import zttp

stream = server.stream(1)
stream.send_response(200, [(b"content-type", b"text/plain")])
stream.send_data(b"a very large body ...")  # (1)!
out = server.data_to_send()                 # only what the window allowed

# ... later, the peer grants more window ...
server.receive_data(window_update_bytes)    # (2)!
for event in drain(server):
    ...                                      # a WindowUpdate flows past
more = server.data_to_send()                 # (3)!  the parked bytes, now freed
```

1.  You hand zttp the whole body. It never blocks and never drops anything - it
    sends what fits and remembers the rest.

2.  The credit arrives as ordinary inbound bytes. No special call.

3.  The bytes the window now permits are waiting for you, framed and ready.

!!! note "Buffering is not I/O"
    Parking bytes until the window opens is bookkeeping, not I/O - zttp still
    never touches a socket, never blocks, and never waits. *When* to ask for more
    window and what your event loop does meanwhile stays yours; zttp only decides
    *how many bytes may leave now*. That's the sans-IO line. See
    [Why sans-IO](../architecture/sans-io.md).

## Control events

Beyond the `Request` / `Response` / `Data` / `EndOfMessage` you already handle,
an HTTP/2 connection surfaces the protocol's own control frames as events, so you
can observe (and react to) what the peer is doing:

| Event | Meaning |
| --- | --- |
| `Settings` | The peer announced its settings. |
| `WindowUpdate` | The peer granted flow-control credit. |
| `Ping` | A keepalive / round-trip probe. |
| `RstStream` | The peer reset a single stream. |
| `Goaway` | The peer is shutting the connection down. |

They flow out of `next_event` like any other event. Most applications can ignore
them - zttp acts on the ones that matter (crediting windows, releasing parked
data) on its own - but they're there when you need visibility.

## Where to go next

<div class="grid cards" markdown>

-   :material-upload-network: **[Sending](sending.md)**

    ---

    The HTTP/1.1 write side, in full - the foundation the `Stream` API mirrors.

-   :material-alert-circle: **[Errors](errors.md)**

    ---

    `LocalProtocolError` vs `RemoteProtocolError`, on both protocols.

-   :material-book-open: **[API reference](../reference/api.md)**

    ---

    `H2Connection`, `Stream`, and the control events in full.

</div>
