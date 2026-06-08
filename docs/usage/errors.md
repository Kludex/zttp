---
icon: lucide/shield-alert
---

# Errors

zttp is **strict by default**. A parser that ingests bytes straight off the
network is a security boundary, so when something is wrong, zttp raises rather
than guesses. There are two kinds of wrong, and two exceptions for them.

## The exception hierarchy

```text
ProtocolError
├── RemoteProtocolError   the peer sent something malformed
└── LocalProtocolError    you used the API incorrectly
```

You can catch the base `ProtocolError` for both, or be specific.

```python
import zttp

try:
    conn.next_event()
except zttp.RemoteProtocolError:
    ...  # the client sent garbage - reply 400 and close
```

## `RemoteProtocolError`: the peer is wrong

Raised from `next_event()` when the bytes you fed can't be parsed. For example, a
header with no colon:

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.receive_data(b"GET / HTTP/1.1\r\nNot a valid header\r\n\r\n")
conn.next_event()
#> zttp.RemoteProtocolError: malformed header field
```

What zttp rejects (a partial list):

* A malformed request/status line or header field.
* **Request smuggling**: `Content-Length` together with `Transfer-Encoding`,
  conflicting duplicate `Content-Length`, or a `chunked` coding that isn't the
  final one (even split across multiple `Transfer-Encoding` lines).
* A bare `LF` line ending (zttp wants `CRLF` - see the tip below).
* A malformed chunk size or chunk framing.
* A message that blows past a configured size limit.

!!! info "Strict CRLF"
    A bare `LF` (without the preceding `CR`) is a known smuggling vector when a
    strict front-end and a lenient back-end disagree on where a line ends. zttp
    rejects it by default, matching h11's stance.

## `LocalProtocolError`: you are wrong

Raised from the **send** side when you call it in a way that can't produce a valid
message - sending a body before a head, two heads in a row, or a field with
control characters in it:

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.send_data(b"x")  # no head was sent first
#> zttp.LocalProtocolError: invalid send for current connection state
```

```python
conn = zttp.Connection(zttp.SERVER)
conn.send_response(b"1.1", 200, b"OK", [(b"X", b"a\r\nInjected: 1")])
#> zttp.LocalProtocolError: invalid field: a header/method/target/version/reason was malformed or contained CR/LF/control bytes
```

## A robust server loop

Put together, handling a connection looks like this:

```python
import zttp


def handle(conn, raw_bytes):
    conn.receive_data(raw_bytes)
    try:
        while True:
            event = conn.next_event()
            if event is zttp.NEED_DATA:
                return  # wait for more bytes
            ...  # dispatch on the event
            if isinstance(event, zttp.EndOfMessage):
                conn.start_next_cycle()
    except zttp.RemoteProtocolError:
        # the peer misbehaved: send a 400 and close the connection
        conn.send_response(b"1.1", 400, b"Bad Request", [(b"Content-Length", b"0")])
        conn.end_message()
        ...
```
