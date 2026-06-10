---
icon: lucide/unplug
---

# Why sans-IO

zttp does no I/O. That's not a limitation; it's the design. This page explains
what that means and why it's the right shape for a parser.

## The problem with a parser that does I/O

Most parsers are tangled up with how the bytes arrive. They read from a socket, or
they call you back (`on_header(name, value)`, `on_body(chunk)`), and now your
application logic lives inside the parser's callbacks. You don't control the flow
anymore; the parser does. Want to use it with threads instead of asyncio? With a
test that feeds canned bytes? With a new async library? You're rewriting glue.

## The sans-IO idea

[Sans-IO](https://sans-io.readthedocs.io/) flips it around. The parser is a pure
state machine over bytes:

* You give it bytes whenever you have them: `receive_data(data)`.
* You ask it what happened, when you're ready: `next_event()`.

It never reads a socket, never calls you back, never blocks. **You** own the I/O
and the control flow; zttp owns only the protocol.

```python
conn = zttp.Connection(zttp.SERVER)
conn.receive_data(raw)        # bytes from wherever: socket, file, test
event = conn.next_event()     # pull, when you want it
```

## What you get for free

=== "Use any I/O"

    The same `Connection` works under asyncio, threads, `anyio`, a green-thread
    library, or no I/O at all. zttp doesn't know or care where the bytes came
    from.

=== "Trivial to test"

    A test is just bytes in, events out. No sockets, no event loop, no mocking.

    ```python
    conn = zttp.Connection(zttp.SERVER)
    conn.receive_data(b"GET / HTTP/1.1\r\n\r\n")
    assert conn.next_event().method == b"GET"
    ```

=== "Backpressure is yours"

    Because you pull events, you decide when to read more. The parser never runs
    ahead of you or buffers without bound (every buffer is capped).

## How it differs from httptools

[httptools](https://github.com/MagicStack/httptools) (what uvicorn uses today) is
a callback parser: you give it a protocol object with `on_url`, `on_header`,
`on_body`, ... and it calls them as it parses. It's fast, but the control flow is
inverted into your callbacks, and the body gets copied per callback.

zttp keeps the performance of a native engine, since it's written in Zig (see
[Performance](../reference/performance.md)), but gives you the cleaner pull API,
and emits each body span as a single `Data` event instead of a stream of
callbacks.

| | httptools | zttp |
| --- | --- | --- |
| API | callbacks (`on_header`, `on_body`) | pull (`next_event`) |
| Control flow | inverted into your callbacks | yours |
| Body | copied per callback | one `Data` event per span |
| I/O coupling | none (also sans-IO at the core) | none |

!!! tip
    If you know [h11](https://github.com/python-hyper/h11), you already know
    zttp's shape: it's the same `Connection` / `receive_data` / `next_event`
    model, with a Zig engine instead of pure Python.
