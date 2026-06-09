---
icon: lucide/zap
---

# zttp

<p align="center">
    <img src="assets/logo.png" alt="zttp" width="400">
</p>

<p align="center">
    <em>A sans-IO HTTP parser for Python with a Zig core! ⚡</em>
</p>

---

**Source Code**: <a href="https://github.com/Kludex/zttp" target="_blank">https://github.com/Kludex/zttp</a>

---

zttp is a [sans-IO](https://sans-io.readthedocs.io/) HTTP/1.1 parser whose engine
is written in [Zig](https://ziglang.org). It does **no I/O of its own**: you feed
it bytes and pull out events, and you ask it for bytes to send. It never touches a
socket - so it works with any I/O you like (asyncio, threads, a green-thread
library, a test harness), and it's a joy to test.

It's the same idea as [h11](https://github.com/python-hyper/h11), with a
hand-written Zig engine underneath instead of pure Python.

The key features are:

* **Sans-IO**: a clean, event-based API. Feed bytes with `receive_data`, pull
  `Request` / `Data` / `EndOfMessage` events with `next_event`. No callbacks, no
  sockets, no surprises.
* **Fast**: a hand-written Zig engine with branch-light scanning and minimal
  allocation - see [Performance](reference/performance.md) for the numbers.
* **Safe**: strict by default. It defends against request smuggling, rejects bare
  `LF` line endings, bounds every buffer, and ships in Zig's safety-checked build.
* **Typed**: a `py.typed` package with full type hints. Your editor knows every
  event field.
* **Tested**: a high-level test suite at **100% coverage**, plus the Zig core's
  own tests and an adversarial-input fuzz harness.

!!! warning "Experimental"
    zttp is experimental. The API and behaviour may change at any time, and it is
    not yet ready for production use.

## Installation

```console
uv add zttp
```

!!! note "Requirements"
    zttp needs **CPython 3.10+** and runs on **Linux**, **macOS**, and **Windows**.

## Example

Let's parse an HTTP request. You play the **server**: bytes come in, events come
out.

```python title="parse.py" hl_lines="3 5 13"
import zttp

conn = zttp.Connection(zttp.SERVER)  # (1)!

conn.receive_data(  # (2)!
    b"GET /hello?name=you HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)

event = conn.next_event()  # (3)!
print(event.method, event.target)
#> b'GET' b'/hello?name=you'

print(conn.next_event())
#> EndOfMessage(trailers=[])
```

1.  A `Connection` is the one object you need. Tell it your role - `SERVER` (you
    receive requests) or `CLIENT` (you receive responses).

2.  Feed it whatever bytes you have. A whole request, half a request, one byte -
    it doesn't matter. zttp buffers and resumes.

3.  Pull events out one at a time. Each call returns the next complete event, or
    the `NEED_DATA` sentinel when it needs more bytes.

Run it:

```console
$ python parse.py

b'GET' b'/hello?name=you'
EndOfMessage(trailers=[])
```

That's it. The buffering, the header parsing, the body framing - all Zig. 🎉

!!! tip
    Notice there were **no callbacks**. You don't register `on_header` /
    `on_body` functions and lose control of the flow. You *pull* events when
    *you* are ready. That's what sans-IO means - read
    [Why sans-IO](architecture/sans-io.md) for the why.

## Where to go next

<div class="grid cards" markdown>

-   :material-rocket-launch: **[First steps](usage/first-steps.md)**

    ---

    The 30-second tour of the read side: feed bytes, pull events.

-   :material-upload-network: **[Sending](usage/sending.md)**

    ---

    The write side: build requests and responses, get bytes to send.

-   :material-sitemap: **[Why sans-IO](architecture/sans-io.md)**

    ---

    What sans-IO is, and why a parser should do no I/O.

-   :material-speedometer: **[Performance](reference/performance.md)**

    ---

    The benchmarks, the methodology, and the honest caveats.

</div>
