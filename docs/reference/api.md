---
icon: lucide/book-open
---

# API reference

The whole public surface of zttp. It's small on purpose. Everything here is
importable straight from `zttp` (e.g. `from zttp import Connection`).

## Connection

`zttp.Connection` is a factory. Constructing one returns the subtype for the
protocol you picked - an `H1Connection` (the default), an `H2Connection`, or an
`H3Connection` - so the surface you get matches the wire. `Connection` itself
isn't a usable instance type and can't be subclassed; only `next_event()` is
common to all three, because the read/write *byte* surface is transport-specific.
HTTP/1.1 provides `receive_event` and `receive_data`, HTTP/2 reads
`receive_data`, and HTTP/3 reads `receive_datagram`.

::: zttp.Connection

::: zttp.H1Connection

::: zttp.H2Connection

::: zttp.H3Connection

A `Stream` is the per-stream send handle on HTTP/2 and HTTP/3 connections; see
[HTTP/2](../usage/http2.md) and [HTTP/3](../usage/http3.md).

::: zttp.Stream

## Roles and protocols

A `Connection`'s role and protocol are fixed at construction:

- `zttp.SERVER`: you receive requests, send responses.
- `zttp.CLIENT`: you send requests, receive responses.
- `zttp.HTTP1` *(default)*: one message at a time; you send on the connection.
- `zttp.HTTP2`: multiplexed streams; you send on a `Stream`.
- `zttp.HTTP3`: the same streams over QUIC; you feed UDP datagrams with
  `receive_datagram` (see [HTTP/3](../usage/http3.md)).

For HTTP/3, a server's TLS identity is passed as
[`credentials=TlsCredentials(...)`](#zttp.TlsCredentials) and a resumption
secret as [`resumption=SessionResumption(...)`](#zttp.SessionResumption) -
typed value
objects, so the same-typed `bytes` pairs can't be transposed (omit `credentials`
and the server uses an ephemeral local identity). zttp supplies the QUIC
transport defaults internally; the remaining constructor fields
(`transport_params`, `connection_id`, `random`, `ephemeral_seed`, ...) are
advanced overrides for deterministic tests and interoperability work.

### HTTP/3 value objects

Passed to the HTTP/3 constructor; both are keyword-only frozen dataclasses so the
same-typed `bytes` fields can't be swapped.

::: zttp.TlsCredentials

::: zttp.SessionResumption

## Events

[`next_event`](#zttp.Connection.next_event) returns one of these. On HTTP/2 and
HTTP/3 each also carries a `.stream_id`.

::: zttp.Request

::: zttp.Response

::: zttp.Data

::: zttp.EndOfMessage

### HTTP/2 control events

An HTTP/2 connection also surfaces the protocol's control frames. zttp acts on
the ones that matter on its own; they're here when you want visibility.

::: zttp.Settings

::: zttp.WindowUpdate

::: zttp.Ping

::: zttp.RstStream

::: zttp.GoAway

The integer ids in a `Settings` event's `params` have names (RFC 9113 6.5.2):

::: zttp.H2Settings

### HTTP/3 results

Returned by an [`H3Connection`](#zttp.H3Connection)'s introspection methods.

::: zttp.SessionTicket

::: zttp.CloseInfo

### Sentinels

`next_event()` returns one of these instead of an event when there is nothing to
report. Both are singletons - compare with `is`, not `==`.

| Value | Meaning |
| --- | --- |
| `zttp.NEED_DATA` | No complete event yet; feed more bytes. |
| `zttp.CONNECTION_CLOSED` | The peer closed the connection. |

::: zttp.NeedData

::: zttp.ConnectionClosed

### The event union

`Event` is the union of everything [`next_event`](#zttp.Connection.next_event)
can return, for annotating your own handlers:

```python
import zttp


def handle(event: zttp.Event) -> None:
    match event:
        case zttp.Request(method=method):
            ...
        case zttp.Data(data=chunk):
            ...
```

A connection only ever yields the events its protocol has: HTTP/1.1 never
produces a `stream_id`-bearing control event, and only HTTP/2 produces `Ping` or
`WindowUpdate`. The union is the widest of the three.

## Demultiplexing a shared UDP socket

An HTTP/3 server usually has one UDP socket and many connections on it, so it
must decide which `H3Connection` a datagram belongs to **before** feeding it to
one. `parse_datagram_header` reads the routable prefix without decrypting
anything or touching connection state.

There are four cases, and a server has to handle all of them:

```python
import time

import zttp

connections: dict[bytes, zttp.H3Connection] = {}  # keyed by local connection id


def now_us() -> int:
    """QUIC timestamps are monotonic microseconds."""
    return time.monotonic_ns() // 1000


def lookup_by_prefix(datagram: bytes) -> zttp.H3Connection | None:
    """Match a short header's destination id, whose length is not on the wire."""
    for connection_id, conn in connections.items():
        if datagram[1:].startswith(connection_id):
            return conn
    return None


def route(datagram: bytes, peer_address: bytes) -> None:
    try:
        header = zttp.parse_datagram_header(datagram)
    except zttp.RemoteProtocolError:
        return  # not a QUIC datagram we can route: drop it

    if header.is_long_header:
        conn = connections.get(header.destination_connection_id)
        if conn is None:
            if not header.is_initial:
                # Handshake or 0-RTT for a connection we do not have. We hold no
                # keys for it and it must not start one: drop it.
                return
            # A new connection. The client chose this destination id, so key the
            # connection on it until it issues ids of its own.
            conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3)
            connections[header.destination_connection_id] = conn
    else:
        # A short (1-RTT) header does not encode the destination id's length on
        # the wire, so match its prefix against the ids you already track.
        conn = lookup_by_prefix(datagram)
        if conn is None:
            return  # unknown connection: drop, or send a stateless reset

    conn.receive_datagram(datagram, now_us(), peer_address)
```

!!! warning "Only an Initial may create a connection"
    Routing an unknown *non*-Initial long-header packet into a fresh connection
    lets any peer allocate state with one spoofed datagram. Drop it - the keys to
    decrypt it do not exist. Same for an unmatched short header, though there you
    may instead send a stateless reset (RFC 9000 10.3), so a peer holding a dead
    connection learns to give up rather than retrying into silence.

See [HTTP/3](../usage/http3.md#serving-many-connections-on-one-socket) for how
this sits inside the read and timer loop.

::: zttp.parse_datagram_header

::: zttp.DatagramHeader

## Exceptions

::: zttp.ProtocolError

::: zttp.RemoteProtocolError

::: zttp.LocalProtocolError
