---
icon: lucide/book-open
---

# API reference

The whole public surface of zttp. It's small on purpose.

## `Connection`

```python
zttp.Connection(role)
```

The one object you create. `role` is `zttp.SERVER` or `zttp.CLIENT`.

### Read side

| Method | Description |
| --- | --- |
| `receive_data(data: bytes) -> None` | Append received bytes. An empty `bytes` signals end of input (the peer closed). |
| `next_event() -> Event` | Return the next event, or the `NEED_DATA` sentinel if more bytes are needed. A parse error poisons the connection: every later call re-raises it. |
| `start_next_cycle() -> None` | Reset to read the next message on a kept-alive connection (call after `EndOfMessage`). |
| `expect_bodyless() -> None` | Declare that the next response has no body regardless of its headers - responses to `HEAD`, and `1xx` / `204` / `304`. Client role; call before parsing that response's head. |

### Write side

| Method | Description |
| --- | --- |
| `send_request(method, target, version, headers) -> None` | Serialize a request head. |
| `send_response(version, status, reason, headers, bodyless=False) -> None` | Serialize a response head. |
| `send_data(data: bytes) -> None` | Serialize body bytes (chunk-framed if the head declared chunked). |
| `end_message(trailers=None) -> None` | Finish the outgoing message. |
| `data_to_send() -> bytes` | Return and clear the pending outgoing bytes. |

All `headers` / `trailers` are sequences of `(name, value)` byte pairs.

## Roles

| Constant | Meaning |
| --- | --- |
| `zttp.SERVER` | You receive requests, send responses. |
| `zttp.CLIENT` | You send requests, receive responses. |

## Events

`next_event()` returns one of these.

### `Request`

The start of a request (server role).

| Field | Type |
| --- | --- |
| `method` | `bytes` |
| `target` | `bytes` |
| `http_version` | `bytes` |
| `headers` | `list[tuple[bytes, bytes]]` |

### `Response`

The start of a response (client role).

| Field | Type |
| --- | --- |
| `status_code` | `int` |
| `reason` | `bytes` |
| `http_version` | `bytes` |
| `headers` | `list[tuple[bytes, bytes]]` |

### `Data`

A run of body bytes.

| Field | Type |
| --- | --- |
| `data` | `bytes` |

### `EndOfMessage`

The body has ended.

| Field | Type |
| --- | --- |
| `trailers` | `list[tuple[bytes, bytes]]` |

### Sentinels

| Value | Meaning |
| --- | --- |
| `zttp.NEED_DATA` | No complete event yet - feed more bytes. Compare with `is`. |
| `zttp.ConnectionClosed` | The peer closed the connection. |

## Exceptions

```text
zttp.ProtocolError
├── zttp.RemoteProtocolError   the peer sent something malformed
└── zttp.LocalProtocolError    you used the API incorrectly
```

See [Errors](../usage/errors.md) for when each is raised.
