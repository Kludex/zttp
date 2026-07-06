"""Typed value objects for the HTTP/3 constructor.

The HTTP/3 handshake needs two pairs of same-typed `bytes` - a certificate and its
private key, and a resumption ticket identity and its PSK. Passed as bare keyword
arguments they can be silently transposed. These frozen value objects name each
half, so `Connection(SERVER, HTTP3, credentials=TlsCredentials(...))` makes a swap
a type error rather than a handshake failure. They are keyword-only, so even
positional construction cannot transpose the two same-typed fields.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "SessionResumption",
    "TlsCredentials",
]


@dataclass(frozen=True, kw_only=True)
class TlsCredentials:
    """An HTTP/3 server's TLS identity: the certificate and its private key."""

    certificate: bytes
    private_key: bytes


@dataclass(frozen=True, kw_only=True)
class SessionResumption:
    """A TLS-PSK resumption secret: the ticket identity and its pre-shared key."""

    identity: bytes
    psk: bytes
