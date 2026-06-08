---
icon: lucide/upload
---

# Sending

The read side turns bytes into events. The **write side** does the reverse: you
describe a message, and zttp gives you the bytes to put on the wire. It frames the
body for you (Content-Length or chunked) and refuses to serialize anything that
would corrupt the wire.

There are four building blocks, plus one call to collect the output:

* `send_request(method, target, version, headers)` - a request head.
* `send_response(version, status, reason, headers)` - a response head.
* `send_data(data)` - a run of body bytes.
* `end_message(trailers=None)` - finish the message.
* `data_to_send()` - take and clear the bytes produced so far.

## A response

As a **server**, you answer a request:

```python title="respond.py" hl_lines="5 9 10"
import zttp

conn = zttp.Connection(zttp.SERVER)

conn.send_response(  # (1)!
    b"1.1", 200, b"OK",
    [(b"Content-Type", b"text/plain"), (b"Content-Length", b"5")],
)
conn.send_data(b"hello")  # (2)!
conn.end_message()  # (3)!

print(conn.data_to_send())  # (4)!
#> b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello'
```

1.  The head: version, status code, reason phrase, and the headers as a list of
    `(name, value)` byte pairs.

2.  Body bytes. With a `Content-Length` they pass straight through.

3.  Marks the message complete.

4.  Hands you the serialized bytes and clears the buffer, ready for the next
    message.

## A request

As a **client**, you build a request the same way:

```python
import zttp

conn = zttp.Connection(zttp.CLIENT)
conn.send_request(b"GET", b"/", b"1.1", [(b"Host", b"example.com")])
conn.end_message()

print(conn.data_to_send())
#> b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
```

## Chunked output

Declare `Transfer-Encoding: chunked` in the head, and every `send_data` is
chunk-framed for you - so you can stream a body of unknown length:

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.send_response(b"1.1", 200, b"OK", [(b"Transfer-Encoding", b"chunked")])
conn.send_data(b"Wiki")
conn.send_data(b"pedia")
conn.end_message([(b"X-Checksum", b"abc")])  # (1)!

print(conn.data_to_send())
#> b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Checksum: abc\r\n\r\n'
```

1.  Trailers go on `end_message`. They're only emitted for a chunked body.

## Bodyless responses

Some responses have no body no matter what (a `204`, a `304`, the reply to a
`HEAD`). You don't flag this - zttp derives it from the response status and the
request method it parsed, so the framing stays correct on its own:

```python
conn.send_response(b"1.1", 204, b"No Content", [])
conn.end_message()
print(conn.data_to_send())
#> b'HTTP/1.1 204 No Content\r\n\r\n'
```

A `HEAD` response is the subtle case: it carries the `Content-Length` the `GET`
would have, but no bytes. Because the connection remembers the request was a
`HEAD`, `send_data` is refused and no body is framed - you don't track it.

## It holds you to the Content-Length

When you declare a `Content-Length`, zttp counts the body bytes you send against
it. Sending more than you promised, or ending the message with bytes still owed,
is refused - either would put a malformed message on the wire:

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.send_response(b"1.1", 200, b"OK", [(b"Content-Length", b"5")])
conn.send_data(b"too long")
#> zttp.LocalProtocolError: invalid send for current connection state
```

For a body of unknown length, use `Transfer-Encoding: chunked` instead - then
`send_data` frames each run for you and there's nothing to count.

## It won't let you split the response

zttp validates everything it serializes. A `\r\n` smuggled into a header value,
reason phrase, or target - the classic response-splitting trick - is refused:

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.send_response(b"1.1", 200, b"OK", [(b"X-Evil", b"a\r\nInjected: yes")])
#> zttp.LocalProtocolError: invalid field: a header/method/target/version/reason was malformed or contained CR/LF/control bytes
```

!!! info "Local vs Remote"
    Misusing the send API raises `LocalProtocolError` - *you* did something wrong.
    Malformed bytes from the peer raise `RemoteProtocolError`. See
    [Errors](errors.md).
