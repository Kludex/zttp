---
icon: lucide/book-open
---

# API reference

The whole public surface of zttp. It's small on purpose. Everything here is
importable straight from `zttp` (e.g. `from zttp import Connection`).

## Connection

::: zttp.Connection

## Roles

A `Connection`'s role is fixed at construction:

- `zttp.SERVER` - you receive requests, send responses.
- `zttp.CLIENT` - you send requests, receive responses.

## Events

[`next_event`](#zttp.Connection.next_event) returns one of these.

::: zttp.Request

::: zttp.Response

::: zttp.Data

::: zttp.EndOfMessage

### Sentinels

| Value | Meaning |
| --- | --- |
| `zttp.NEED_DATA` | No complete event yet - feed more bytes. Compare with `is`. |
| `zttp.CONNECTION_CLOSED` | The peer closed the connection. Compare with `is`. |

## Exceptions

::: zttp.ProtocolError

::: zttp.RemoteProtocolError

::: zttp.LocalProtocolError
