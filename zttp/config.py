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
    """An HTTP/3 server's ordered certificate chain and leaf private key."""

    private_key: bytes
    certificate: bytes | None = None
    certificates: tuple[bytes, ...] | None = None

    def __post_init__(self) -> None:
        if self.certificate is not None and self.certificates is not None:
            raise ValueError("pass either certificate or certificates, not both")
        if isinstance(self.certificates, (bytes, bytearray, memoryview)):
            raise ValueError("certificates must be a sequence of certificate bytes")
        if self.certificates is not None:
            object.__setattr__(self, "certificates", tuple(self.certificates))
        chain = self.certificate_chain
        if not chain:
            raise ValueError("the certificate chain must not be empty")
        if any(not isinstance(item, bytes) or not item for item in chain):
            raise ValueError("every certificate must be non-empty bytes")

    @property
    def certificate_chain(self) -> tuple[bytes, ...]:
        """The leaf certificate followed by its intermediates."""
        if self.certificates is not None:
            return self.certificates
        if self.certificate is not None:
            return (self.certificate,)
        return ()


@dataclass(frozen=True, kw_only=True)
class SessionResumption:
    """A TLS-PSK resumption secret: the ticket identity and its pre-shared key."""

    identity: bytes
    psk: bytes
