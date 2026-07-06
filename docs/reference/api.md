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
common to all three, because the read/write *byte* surface is transport-specific
(HTTP/1.1 and HTTP/2 read `receive_data`; HTTP/3 reads `receive_datagram`).

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
[`credentials=TlsCredentials(...)`][zttp.TlsCredentials] and a resumption secret
as [`resumption=SessionResumption(...)`][zttp.SessionResumption] - typed value
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

::: zttp.Goaway

The integer ids in a `Settings` event's `params` have names (RFC 9113 6.5.2):

::: zttp.H2Settings

### HTTP/3 results

Returned by an [`H3Connection`](#zttp.H3Connection)'s introspection methods.

::: zttp.SessionTicket

::: zttp.CloseInfo

### Sentinels

| Value | Meaning |
| --- | --- |
| `zttp.NEED_DATA` | No complete event yet; feed more bytes. Compare with `is`. |
| `zttp.CONNECTION_CLOSED` | The peer closed the connection. Compare with `is`. |

## Exceptions

::: zttp.ProtocolError

::: zttp.RemoteProtocolError

::: zttp.LocalProtocolError
