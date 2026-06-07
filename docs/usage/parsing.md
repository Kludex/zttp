---
icon: lucide/download
---

# Parsing in depth

The read side is `receive_data` + `next_event`. This page covers what happens
once bodies, chunked encoding, and partial data enter the picture.

## Bodies

A body shows up as one or more `Data` events between the head and `EndOfMessage`.
You concatenate them yourself - which means **you decide** whether to buffer the
whole body or stream it.

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.receive_data(
    b"POST / HTTP/1.1\r\n"
    b"Content-Length: 11\r\n"
    b"\r\n"
    b"hello world"
)

body = b""
while True:
    event = conn.next_event()
    if isinstance(event, zttp.Data):
        body += event.data
    elif isinstance(event, zttp.EndOfMessage):
        break
    elif event is zttp.NEED_DATA:
        break

print(body)
#> b'hello world'
```

!!! tip
    Each `Data` event's `.data` is a real `bytes` object, copied out of the parse
    buffer - so it's safe to keep. You're never handed a view that the next
    `receive_data` will overwrite.

## Partial data

This is the whole point of sans-IO: the parser doesn't care how the bytes are
split. Feed it a trickle and it resumes mid-anything - mid-header, mid-body,
mid-chunk.

```python
conn = zttp.Connection(zttp.SERVER)

conn.receive_data(b"GET / HTTP/1.1\r\nHo")
assert conn.next_event() is zttp.NEED_DATA  # (1)!

conn.receive_data(b"st: example.com\r\n\r\n")
request = conn.next_event()
print(request.headers)
#> [(b'Host', b'example.com')]
```

1.  Half a header line isn't a complete event, so you get `NEED_DATA`. No error,
    no lost state - just feed the rest.

## Chunked transfer encoding

You don't do anything special for `Transfer-Encoding: chunked`. zttp decodes the
chunks for you and emits the decoded body as `Data` events, exactly like a
fixed-length body:

```python
conn = zttp.Connection(zttp.SERVER)
conn.receive_data(
    b"POST / HTTP/1.1\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"  # (1)!
)

body = b""
while True:
    event = conn.next_event()
    if isinstance(event, zttp.Data):
        body += event.data
    elif isinstance(event, zttp.EndOfMessage):
        break
    elif event is zttp.NEED_DATA:
        break

print(body)
#> b'hello world'
```

1.  Chunk framing on the wire - `<size>\r\n<data>\r\n`, ending with a `0` chunk.
    You never see it; you get the decoded `hello world`.

## Trailers

A chunked body can carry trailer headers after the final chunk. They arrive on
the `EndOfMessage` event:

```python
conn = zttp.Connection(zttp.SERVER)
conn.receive_data(
    b"POST / HTTP/1.1\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"3\r\nabc\r\n"
    b"0\r\n"
    b"X-Checksum: 900150983cd24fb0\r\n"
    b"\r\n"
)

conn.next_event()  # Request
conn.next_event()  # Data b'abc'
end = conn.next_event()
print(end.trailers)
#> [(b'X-Checksum', b'900150983cd24fb0')]
```

## A reusable drain helper

In practice you'll want a small helper that pulls events until it needs more
data. Here's one:

```python
import zttp


def events(conn):
    """Yield every complete event currently available."""
    while True:
        event = conn.next_event()
        if event is zttp.NEED_DATA:
            return
        yield event
        if isinstance(event, zttp.EndOfMessage):
            return
```

Then a request handler reads naturally:

```python
for event in events(conn):
    match event:
        case zttp.Request(method=method, target=target):
            ...
        case zttp.Data(data=chunk):
            ...
        case zttp.EndOfMessage():
            ...
```
