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


class TlsCredentials(TypedDict):
    """An HTTP/3 server's certificate chain and signing key or raw P-256 scalar."""

    private_key: NotRequired[bytes]
    private_key_scalar: NotRequired[bytes]
    certificate: NotRequired[bytes]
    certificates: NotRequired[tuple[bytes, ...]]


@dataclass(frozen=True, kw_only=True)
class SessionResumption:
    """A TLS-PSK resumption secret: the ticket identity and its pre-shared key."""

    identity: bytes
    psk: bytes
