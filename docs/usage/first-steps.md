---
icon: lucide/rocket
---

# First steps

zttp gives you one object: a **`Connection`**.

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
```

A `Connection` holds the parse state for **one** HTTP connection. You tell it your
role when you create it:

* `zttp.SERVER` - you receive **requests** and send **responses**.
* `zttp.CLIENT` - you send **requests** and receive **responses**.

The whole read side is just two calls.

## Feed bytes in

When bytes arrive off the wire, hand them to `receive_data`:

```python
conn.receive_data(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
```

You can feed a whole message, or a fragment, or a single byte. zttp buffers what
it has and resumes where it left off - so the network can chop your data up
however it likes.

```python
conn.receive_data(b"GET / HT")   # half a request line
conn.receive_data(b"TP/1.1\r\n") # the rest of it
```

## Pull events out

Then call `next_event()` to get the next thing that happened:

```python title="echo.py" hl_lines="11"
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.receive_data(
    b"POST /submit HTTP/1.1\r\n"
    b"Content-Length: 5\r\n"
    b"\r\n"
    b"hello"
)

while True:
    event = conn.next_event()  # (1)!
    if event is zttp.NEED_DATA:  # (2)!
        break
    print(type(event).__name__, getattr(event, "data", ""))
    if isinstance(event, zttp.EndOfMessage):
        break
```

1.  Each call returns the **next complete event**, in order.

2.  When there isn't a complete event yet, you get the `NEED_DATA` sentinel -
    your cue to `receive_data` more bytes (or stop).

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
| `Request` | The request line + all headers are parsed | `.method`, `.target`, `.http_version`, `.headers` |
| `Data` | A chunk of the body is available | `.data` |
| `EndOfMessage` | The body (and any trailers) finished | `.trailers` |
| `NEED_DATA` | No complete event yet - feed more | *(it's a sentinel)* |

!!! tip
    `next_event()` returns `NEED_DATA` (a singleton) - compare with `is`, not
    `==`:

    ```python
    if event is zttp.NEED_DATA:
        ...
    ```

A client connection is the mirror image: you get `Response` (with `.status_code`,
`.reason`, `.http_version`, `.headers`) instead of `Request`, then the same
`Data` / `EndOfMessage`.

## Keep-alive

HTTP/1.1 connections are reused. After you've pulled `EndOfMessage` for one
message, tell the connection to start the next one:

```python
conn.start_next_cycle()  # ready to parse the next request on the same connection
```

## Where to go next

You've seen the read side. Next:

* [Parsing in depth](parsing.md) - bodies, chunked encoding, trailers, partial data.
* [Sending](sending.md) - the write side: build messages, get bytes to send.
* [Errors](errors.md) - what zttp rejects, and how.
