---
icon: lucide/rocket
---

# First steps

zttp gives you one object: a [`Connection`](../reference/api.md#zttp.Connection).

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
```

A `Connection` holds the parse state for **one** HTTP connection. You tell it your
role when you create it:

* `zttp.SERVER`: you receive **requests** and send **responses**.
* `zttp.CLIENT`: you send **requests** and receive **responses**.

The HTTP/1.1 read side starts with `receive_event` and continues with
`next_event`.

## Feed bytes and receive an event

When bytes arrive off the wire, pass them to `receive_event`:

```python
event = conn.receive_event(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
```

It returns the first complete event, or `NEED_DATA` when the input is partial.
You can pass a whole message, a fragment, or a single byte. zttp buffers what it
has and resumes where it left off, so the network can chop your data up however
it likes.

```python
assert conn.receive_event(b"GET / HT") is zttp.NEED_DATA  # half a request line
event = conn.receive_event(b"TP/1.1\r\n\r\n")              # the completed Request
```

## Pull additional events

Call `next_event()` after `receive_event` to pull any events that followed the
first one in the same input:

```python title="echo.py"
import zttp

conn = zttp.Connection(zttp.SERVER)
event = conn.receive_event(
    b"POST /submit HTTP/1.1\r\n"
    b"Content-Length: 5\r\n"
    b"\r\n"
    b"hello"
)

while event is not zttp.NEED_DATA:
    print(type(event).__name__, getattr(event, "data", ""))
    if isinstance(event, zttp.EndOfMessage) or isinstance(event, zttp.Request) and event.end_stream:
        break
    event = conn.next_event()
```

When there isn't a complete event, either call returns the `NEED_DATA` sentinel.
That is your cue to pass more bytes to `receive_event` or stop the loop.

Run it:

```console
$ python echo.py

Request
Data b'hello'
EndOfMessage
```

## The events

A server connection yields these, in order, per request:

| Event | When | Useful fields |
| --- | --- | --- |
| `Request` | The request line + all headers are parsed | `.method`, `.target`, `.path`, `.query`, `.http_version`, `.headers`, `.expect_continue`, `.end_stream` |
| `Data` | A chunk of the body is available | `.data` |
| `EndOfMessage` | The body (and any trailers) finished | `.trailers` |
| `NEED_DATA` | No complete event yet. Feed more | *(it's a sentinel)* |

!!! tip
    `next_event()` returns `NEED_DATA` (a singleton). Compare with `is`, not
    `==`:

    ```python
    if event is zttp.NEED_DATA:
        ...
    ```

`.target` is the raw request-target; `.path` and `.query` are it split at the
first `?` (both verbatim: zttp doesn't percent-decode, that's yours to do).

A client connection is the mirror image: you get `Response` (with `.status_code`,
`.reason`, `.http_version`, `.headers`) instead of `Request`, then the same
`Data` / `EndOfMessage`.

!!! tip "Same events on HTTP/2"
    Pass `protocol=zttp.HTTP2` and the read side is unchanged: the *same*
    `Request` / `Response` / `Data` / `EndOfMessage`, plus a `.stream_id` on each
    (it's `0` on HTTP/1.1) because one connection now multiplexes many requests.
    The send side differs: HTTP/2 sends on a stream. See [HTTP/2](http2.md).

## Keep-alive

HTTP/1.1 connections are reused. After a `Request(end_stream=True)` or the
request's `EndOfMessage`, tell the connection to start the next one, unless the
peer asked to close. zttp works that out from the head it parsed, so you don't
scan headers:

```python
if conn.should_close():  # Connection: close, or HTTP/1.0 without keep-alive
    transport.close()
else:
    conn.start_next_cycle()  # parse the next request on the same connection
```

## Upgrades and 100-continue

Two more signals zttp derives from the request so you don't have to:

```python
if conn.upgrade() == b"websocket":  # Connection: upgrade + Upgrade: websocket
    ...  # hand the socket to your WebSocket stack

if request.expect_continue:  # the client sent Expect: 100-continue
    conn.send_informational(100)  # the real response still follows
```

`conn.upgrade()` returns the `Upgrade` value only when `Connection` lists the
`upgrade` token, else `None`. `request.expect_continue` is a per-request flag on
the `Request` event.

## Where to go next

You've seen the read side. Next:

* [HTTP/1.1](http1.md): the read and write sides in depth - bodies, chunked encoding, trailers, building messages.
* [A real server](real-server.md): wire it all to a socket - a complete `asyncio` server you can run.
* [Errors](errors.md): what zttp rejects, and how.
* [Security](../security.md): the threat model, and what you are responsible for.
