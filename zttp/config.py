"""Typed configuration for the HTTP/3 constructor.

The HTTP/3 handshake needs two pairs of same-typed `bytes` - a certificate and its
private key, and a resumption ticket identity and its PSK. The credential dictionary
names each field, while the frozen resumption value keeps its two fields together.
The Zig extension validates both values when you construct a connection.
"""

from __future__ import annotations

from dataclasses import dataclass

from typing_extensions import NotRequired, TypedDict

__all__ = [
    "SessionResumption",
    "TlsCredentials",
]


class TlsCredentials(TypedDict):
    """An HTTP/3 server's ordered certificate chain and leaf private key."""

    private_key: bytes
    certificate: NotRequired[bytes]
    certificates: NotRequired[tuple[bytes, ...]]


@dataclass(frozen=True, kw_only=True)
class SessionResumption:
    """A TLS-PSK resumption secret: the ticket identity and its pre-shared key."""

    identity: bytes
    psk: bytes
