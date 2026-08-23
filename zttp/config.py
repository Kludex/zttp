"""Typed configuration for the HTTP/3 constructor.

The HTTP/3 handshake needs two pairs of same-typed `bytes` - a certificate and its
private key, and a resumption ticket identity and its PSK. Passed as bare keyword
arguments they can be silently transposed. These frozen value objects name each
half, so `Connection(SERVER, HTTP3, credentials=TlsCredentials(...))` makes a swap
a type error rather than a handshake failure. They are keyword-only, so even
positional construction cannot transpose the two same-typed fields.
"""

from __future__ import annotations

from dataclasses import dataclass

from typing_extensions import TypedDict

__all__ = [
    "QuicTransportParameters",
    "SessionResumption",
    "TlsCredentials",
]


class QuicTransportParameters(TypedDict, total=False):
    """QUIC flow-control, stream, timeout, payload, and migration settings."""

    max_idle_timeout: int
    stateless_reset_token: bytes
    max_udp_payload_size: int
    initial_max_data: int
    initial_max_stream_data_bidi_local: int
    initial_max_stream_data_bidi_remote: int
    initial_max_stream_data_uni: int
    initial_max_streams_bidi: int
    initial_max_streams_uni: int
    ack_delay_exponent: int
    max_ack_delay: int
    disable_active_migration: bool
    active_connection_id_limit: int


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
