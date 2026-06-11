---
icon: lucide/radio
---

# HTTP/3

HTTP/3 is the same zttp API again: opt in with one argument, pull the same
events. The difference is the wire. HTTP/3 runs over **QUIC** on UDP, so instead
of feeding a byte stream you feed whole datagrams:

```python
import zttp

conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3)
```

As with HTTP/2, the `protocol` argument picks the subtype, so construction
returns an `H3Connection` and the surface you get matches the wire you chose.

!!! warning "Scope"
    The HTTP/3 **server read path** is implemented end to end: a client Initial
    datagram is decrypted, its stream bytes are reassembled, and the request
    comes out as events. The TLS 1.3 handshake driver (only the Initial key
    space is wired today), the write side, and the client read path are still
    in progress, and the QPACK dynamic table is intentionally disabled.

## Datagrams in, events out

TCP hands you an ordered byte stream, so HTTP/1.1 and HTTP/2 take
`receive_data(bytes)`. QUIC is packet-oriented and the transport must see
datagram boundaries, so HTTP/3 takes `receive_datagram` instead. Pass one UDP
payload per call, exactly as it came off the socket; the QUIC layer underneath
decrypts the packets, tracks acks, and reassembles the stream bytes for you. The
event side is unchanged:

```python title="server_read.py"
import zttp

conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3)
conn.receive_datagram(udp_payload)

while (event := conn.next_event()) is not zttp.NEED_DATA:
    if isinstance(event, zttp.Request):
        print(event.method, event.path, event.stream_id)
```

You get the same `Request` / `Data` / `EndOfMessage` events, now tagged with the
QUIC `stream_id`. An HTTP/3 request collapses its pseudo-headers into the same
shape the other protocols use, and `http_version` is `b"3"`.

## The transport is inside

For HTTP/1.1 and HTTP/2, the kernel's TCP gives zttp an ordered, reliable byte
stream and the core only parses it. For HTTP/3, the core also *is* the
transport: packet protection, loss recovery, congestion control, flow control,
and stream reassembly all live in the Zig core, written from scratch on
`std.crypto`. The sans-IO line holds: the core never touches a socket; your I/O
layer moves the datagrams.

Read [Architecture](../architecture.md) for the layering and the QUIC-as-transport
tour, including the security posture (amplification limits, AEAD packet
protection, and the QPACK bomb defenses).

## Where to go next

<div class="grid cards" markdown>

-   :material-transit-connection-variant: **[HTTP/2](http2.md)**

    ---

    The same multiplexed event model over TCP, with the full write side.

-   :material-sitemap: **[Architecture](../architecture.md)**

    ---

    How the from-scratch QUIC transport is built, layer by layer.

</div>
