---
icon: lucide/file-text
---

# HTTP/1.1

HTTP/1.1 is the default protocol: `zttp.Connection(zttp.SERVER)` with no
`protocol=` argument speaks it. This page covers both directions - reading
messages off the wire with `receive_data` + `next_event`, and writing them back
with the send API.

## Reading

The read side is `receive_data` + `next_event`. Once bodies, chunked encoding,
and partial data enter the picture, here's what happens.

### Bodies

A body shows up as one or more `Data` events between the head and `EndOfMessage`.
You concatenate them yourself, which means **you decide** whether to buffer the
whole body or stream it.

Accumulate into a `bytearray`, not `b""`. Appending to `bytes` reallocates the
whole buffer on every `Data` event (quadratic); a `bytearray` grows in place.

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.receive_data(
    b"POST / HTTP/1.1\r\n"
    b"Content-Length: 11\r\n"
    b"\r\n"
    b"hello world"
)

body = bytearray()
while True:
    event = conn.next_event()
    if isinstance(event, zttp.Data):
        body += event.data
    elif isinstance(event, zttp.EndOfMessage):
        break
    elif event is zttp.NEED_DATA:
        break

print(bytes(body))
#> b'hello world'
```

!!! tip
    Each `Data` event's `.data` is a real `bytes` object, copied out of the parse
    buffer, so it's safe to keep. You're never handed a view that the next
    `receive_data` will overwrite.

### Partial data

This is the whole point of sans-IO: the parser doesn't care how the bytes are
split. Feed it a trickle and it resumes mid-anything: mid-header, mid-body,
mid-chunk. Half a header line isn't a complete event, so you get `NEED_DATA`. No
error, no lost state. Just feed the rest.

```python
conn = zttp.Connection(zttp.SERVER)

conn.receive_data(b"GET / HTTP/1.1\r\nHo")
assert conn.next_event() is zttp.NEED_DATA

conn.receive_data(b"st: example.com\r\n\r\n")
request = conn.next_event()
print(request.headers)
#> [(b'Host', b'example.com')]
```

### Chunked transfer encoding

You don't do anything special for `Transfer-Encoding: chunked`. zttp decodes the
chunks for you and emits the decoded body as `Data` events, exactly like a
fixed-length body. The chunk framing on the wire is `<size>\r\n<data>\r\n`,
ending with a `0` chunk; you never see it, you get the decoded `hello world`:

```python
conn = zttp.Connection(zttp.SERVER)
conn.receive_data(
    b"POST / HTTP/1.1\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
)

body = bytearray()
while True:
    event = conn.next_event()
    if isinstance(event, zttp.Data):
        body += event.data
    elif isinstance(event, zttp.EndOfMessage):
        break
    elif event is zttp.NEED_DATA:
        break

print(bytes(body))
#> b'hello world'
```

### Trailers

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

### A reusable drain helper

In practice you'll want a small helper that pulls events until it needs more
data. Here's one, used by the examples that follow:

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

### Bodyless responses (client)

Some responses have **no body no matter what their headers say**: the response to
a `HEAD` request, and any `1xx` / `204` / `304`. A `HEAD` response, for instance,
carries the `Content-Length` the `GET` *would* have had, but sends no bytes.

You don't track this. Because you sent the request through the same connection, it
remembers the method and frames the response correctly on its own. The connection
saw the `HEAD`, so it yields `EndOfMessage` straight after the head instead of
waiting for 1234 body bytes that never come (using the `events` helper above):

```python
import zttp

conn = zttp.Connection(zttp.CLIENT)
conn.send_request(b"HEAD", b"/", b"1.1", [(b"Host", b"example.com")])
conn.data_to_send()
conn.receive_data(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")

print([type(e).__name__ for e in events(conn)])
#> ['Response', 'EndOfMessage']
```

## Sending

The read side turns bytes into events. The **write side** does the reverse: you
describe a message, and zttp gives you the bytes to put on the wire. It frames the
body for you (Content-Length or chunked) and refuses to serialize anything that
would corrupt the wire.

There are four building blocks, plus one call to collect the output:

* `send_request(method, target, version, headers)`: a request head.
* `send_response(status, headers=None)`: a response head.
* `send_data(data)`: a run of body bytes.
* `end_message(trailers=None)`: finish the message.
* `data_to_send()`: take and clear the bytes produced so far.

These same four building blocks carry over to HTTP/2: there, you call them on a
[`Stream`](http2.md) instead of the connection, because one connection carries
many at once.

### A response

As a **server**, you answer a request. The head is just the status code plus the
headers as a list of `(name, value)` byte pairs - the reason phrase is derived
from the status and the version is `1.1`, so you pass neither. With a
`Content-Length` the body bytes pass straight through. `end_message` marks the
message complete, and `data_to_send` hands you the serialized bytes and clears
the buffer, ready for the next message:

```python title="respond.py"
import zttp

conn = zttp.Connection(zttp.SERVER)

conn.send_response(
    200,
    [(b"Content-Type", b"text/plain"), (b"Content-Length", b"5")],
)
conn.send_data(b"hello")
conn.end_message()

print(conn.data_to_send())
#> b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello'
```

### A request

As a **client**, you build a request the same way:

```python
import zttp

conn = zttp.Connection(zttp.CLIENT)
conn.send_request(b"GET", b"/", b"1.1", [(b"Host", b"example.com")])
conn.end_message()

print(conn.data_to_send())
#> b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
```

### Chunked output

Declare `Transfer-Encoding: chunked` in the head, and every `send_data` is
chunk-framed for you, so you can stream a body of unknown length. Trailers go on
`end_message`; they're only emitted for a chunked body:

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.send_response(200, [(b"Transfer-Encoding", b"chunked")])
conn.send_data(b"Wiki")
conn.send_data(b"pedia")
conn.end_message([(b"X-Checksum", b"abc")])

print(conn.data_to_send())
#> b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Checksum: abc\r\n\r\n'
```

Other transfer codings may precede `chunked`, either in one field-line or across
several. zttp treats them as one ordered list, requires `chunked` exactly once
and last, preserves the field-lines you supplied, and adds the final chunk framing:

```python
import gzip

import zttp

already_gzipped = gzip.compress(b"hello")
conn = zttp.Connection(zttp.SERVER)
conn.send_response(200, [(b"Transfer-Encoding", b"gzip, chunked")])
conn.send_data(already_gzipped)
conn.end_message()
wire_bytes = conn.data_to_send()  # write each produced byte to the socket
```

!!! warning "zttp does not apply the preceding coding"
    `gzip` describes bytes your application already compressed. zttp does **not**
    gzip `send_data`; it only adds the chunk framing it implements. Declaring
    `gzip, chunked` around uncompressed bytes lies to the peer. A coding without
    final `chunked`, `chunked, gzip`, duplicate `chunked`, and
    `Transfer-Encoding` together with `Content-Length` are all rejected.

### Bodyless responses

Some responses have no body no matter what (a `204`, a `304`, the reply to a
`HEAD`). You don't flag this: zttp derives it from the response status and the
request method it parsed, so the framing stays correct on its own:

```python
conn.send_response(204)
conn.end_message()
print(conn.data_to_send())
#> b'HTTP/1.1 204 No Content\r\n\r\n'
```

A `HEAD` response is the subtle case: it carries the `Content-Length` the `GET`
would have, but no bytes. Because the connection remembers the request was a
`HEAD`, `send_data` is refused and no body is framed, so you don't track it.

### It holds you to the Content-Length

When you declare a `Content-Length`, zttp counts the body bytes you send against
it. Sending more than you promised, or ending the message with bytes still owed,
is refused: either would put a malformed message on the wire:

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.send_response(200, [(b"Content-Length", b"5")])
conn.send_data(b"too long")
#> zttp.LocalProtocolError: sent more body than the declared Content-Length
```

For a body of unknown length, use `Transfer-Encoding: chunked` instead: then
`send_data` frames each run for you and there's nothing to count.

### It won't let you split the response

zttp validates everything it serializes. A `\r\n` smuggled into a header value,
reason phrase, or target (the classic response-splitting trick) is refused:

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.send_response(200, [(b"X-Evil", b"a\r\nInjected: yes")])
#> zttp.LocalProtocolError: invalid field: a header/method/target/version/reason was malformed or contained CR/LF/control bytes
```

!!! info "Local vs Remote"
    Misusing the send API raises `LocalProtocolError`: *you* did something wrong.
    Malformed bytes from the peer raise `RemoteProtocolError`. See
    [Errors](errors.md).

## Where to go next

* [HTTP/2](http2.md): the same four building blocks, multiplexed across streams.
* [Errors](errors.md): what zttp rejects, and why.
* [Architecture](../architecture.md): how the sans-IO core fits together.
