"""Value objects returned by HTTP/3 introspection methods.

`H3Connection.session_tickets()` and `H3Connection.close_info()` return these frozen
dataclasses. Read them by field name (`info.error_code`, `ticket.psk`) - they are not
tuples, so there is no positional access to get wrong.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "CloseInfo",
    "SessionTicket",
]


@dataclass(frozen=True)
class SessionTicket:
    """A TLS session ticket received from the peer (RFC 8446 4.6.1)."""

    lifetime: int
    age_add: int
    nonce: bytes
    ticket: bytes
    extensions: bytes
    max_early_data_size: int | None
    psk: bytes | None


@dataclass(frozen=True)
class CloseInfo:
    """A QUIC CONNECTION_CLOSE received from the peer (RFC 9000 19.19)."""

    error_code: int
    reason: bytes
    is_application: bool
