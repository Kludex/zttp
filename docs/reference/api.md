---
icon: lucide/book-open
---

# API reference

The whole public surface of zttp. It's small on purpose. Everything here is
importable straight from `zttp` (e.g. `from zttp import Connection`).

## Connection

`zttp.Connection` is the base: the read side, shared by every protocol.
Constructing one returns the subclass for the protocol you picked: an
`H1Connection` (the default), an `H2Connection`, or an `H3Connection`, so the
send surface you get matches the protocol.

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

::: zttp.Goaway

### Sentinels

| Value | Meaning |
| --- | --- |
| `zttp.NEED_DATA` | No complete event yet; feed more bytes. Compare with `is`. |
| `zttp.CONNECTION_CLOSED` | The peer closed the connection. Compare with `is`. |

## Exceptions

::: zttp.ProtocolError

::: zttp.RemoteProtocolError

::: zttp.LocalProtocolError
