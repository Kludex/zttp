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
`receive_data`, and HTTP/3 reads `receive_datagram`. Each receive method accepts
any contiguous buffer, including `bytes`, `bytearray`, and `memoryview`.

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

```python
import time

import zttp

endpoint = zttp.QuicEndpoint(retry=True, token_secret=b"replace-with-at-least-32-secret-bytes")
outbound: list[zttp.OutboundDatagram] = []


def receive(datagram: bytes, peer_address: bytes) -> zttp.H3Connection | None:
    now = time.monotonic_ns() // 1000
    connection = endpoint.receive_datagram(datagram, peer_address, now)
    outbound.extend(endpoint.data_to_send())
    return connection
```

`QuicEndpoint` maps destination connection IDs to `H3Connection` instances. It
retains state only after the QUIC core authenticates an Initial packet. Unknown
short, Handshake, and 0-RTT packets are dropped. Unsupported versions receive a
Version Negotiation packet. The endpoint returns the routed connection so you can
drain its HTTP events with `next_event()`.

Retry remains stateless. The endpoint sends a Retry before allocating a
connection, authenticates the token with HMAC-SHA256, binds it to `peer_address`,
and retains the connection only when the client returns a valid token. Use the
same `token_secret` in every worker that can receive packets for the same UDP
address. `issue_token()` sends a compatible `NEW_TOKEN` so a later connection can
validate its address without Retry.

Use `issue_connection_id()` on the endpoint for connection ID rotation. It keeps
routing synchronized with active and retired IDs in the QUIC core.

The endpoint does not own `udp_socket`, call `sendto`, read the clock, or schedule
a timer. Call `next_timeout()` and `handle_timeout(now)` from your event loop.

`data_to_send()` drains connections changed by `receive_datagram()`, endpoint timer
handling, or endpoint control methods. If your application queues output on a
connection after an earlier drain, pass that connection to
`data_to_send(connection)`.

::: zttp.QuicEndpoint

::: zttp.ConnectionIDFactory

::: zttp.OutboundDatagram

`parse_datagram_header` remains available when you need the lower-level routing
prefix directly.

::: zttp.parse_datagram_header

::: zttp.DatagramHeader

## Exceptions

::: zttp.ProtocolError

::: zttp.RemoteProtocolError

::: zttp.LocalProtocolError
