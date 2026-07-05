"""Typed construction helpers for HTTP/3 connections.

The raw `Connection(role, HTTP3, ...)` constructor takes a dozen order-independent
`bytes` keyword arguments. Because every value is `bytes`, the type checker cannot
tell a certificate from a private key, or one PSK from another. These value objects
name the pieces, and the `h3_server` / `h3_client` factories assemble them into a
connection - so a swap is a type error, not a silent handshake failure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from zttp._zttp import CLIENT, HTTP3, SERVER, Connection

if TYPE_CHECKING:
    from zttp._zttp import H3Connection

__all__ = [
    "SessionResumption",
    "TlsCredentials",
    "h3_client",
    "h3_server",
]


@dataclass(frozen=True)
class TlsCredentials:
    """An HTTP/3 server's TLS identity: the certificate and its private key."""

    certificate: bytes
    private_key: bytes


@dataclass(frozen=True)
class SessionResumption:
    """A TLS-PSK resumption secret: the ticket identity and its pre-shared key."""

    identity: bytes
    psk: bytes


def h3_server(
    credentials: TlsCredentials | None = None,
    *,
    transport_params: bytes | None = None,
    alpn: bytes | None = None,
    resumption: SessionResumption | None = None,
    random: bytes | None = None,
    ephemeral_seed: bytes | None = None,
) -> H3Connection:
    """Create an HTTP/3 server connection.

    Args:
        credentials: The server's TLS identity. Defaults to an ephemeral local
            identity (development only - not a production server identity).
        transport_params: Encoded QUIC transport parameters. Defaults to zttp's.
        alpn: The ALPN token. Defaults to ``b"h3"``.
        resumption: A PSK to accept for session resumption.
        random: Deterministic randomness (testing).
        ephemeral_seed: Deterministic key-share seed (testing).
    """
    return Connection(
        SERVER,
        HTTP3,
        certificate=credentials.certificate if credentials is not None else None,
        private_key=credentials.private_key if credentials is not None else None,
        transport_params=transport_params,
        alpn=alpn,
        resumption_identity=resumption.identity if resumption is not None else None,
        resumption_psk=resumption.psk if resumption is not None else None,
        random=random,
        ephemeral_seed=ephemeral_seed,
    )


def h3_client(
    *,
    server_name: bytes | None = None,
    alpn: bytes | None = None,
    transport_params: bytes | None = None,
    connection_id: bytes | None = None,
    resumption: SessionResumption | None = None,
    early_data: bool = False,
    obfuscated_ticket_age: int = 0,
    remembered_transport_params: bytes | None = None,
    validation_token: bytes | None = None,
    random: bytes | None = None,
    ephemeral_seed: bytes | None = None,
) -> H3Connection:
    """Create an HTTP/3 client connection.

    Args:
        server_name: The TLS SNI / :authority host.
        alpn: The ALPN token. Defaults to ``b"h3"``.
        transport_params: Encoded QUIC transport parameters. Defaults to zttp's.
        connection_id: The initial destination connection ID.
        resumption: A PSK from a prior session to offer for resumption / 0-RTT.
        early_data: Offer 0-RTT early data (only meaningful with ``resumption``).
        obfuscated_ticket_age: The obfuscated ticket age for 0-RTT anti-replay.
        remembered_transport_params: Transport parameters remembered from the
            resumed session, required to send 0-RTT.
        validation_token: A NEW_TOKEN address-validation token from a prior connection.
        random: Deterministic randomness (testing).
        ephemeral_seed: Deterministic key-share seed (testing).

    Raises:
        ValueError: if a 0-RTT parameter (``early_data``, ``obfuscated_ticket_age``,
            ``remembered_transport_params``) is given without ``resumption``.
    """
    if resumption is None:
        if early_data or obfuscated_ticket_age or remembered_transport_params is not None:
            raise ValueError(
                "early_data, obfuscated_ticket_age and remembered_transport_params require `resumption`"
            )
        return Connection(
            CLIENT,
            HTTP3,
            server_name=server_name,
            alpn=alpn,
            transport_params=transport_params,
            connection_id=connection_id,
            validation_token=validation_token,
            random=random,
            ephemeral_seed=ephemeral_seed,
        )
    return Connection(
        CLIENT,
        HTTP3,
        server_name=server_name,
        alpn=alpn,
        transport_params=transport_params,
        connection_id=connection_id,
        resumption_identity=resumption.identity,
        resumption_psk=resumption.psk,
        early_data=early_data,
        obfuscated_ticket_age=obfuscated_ticket_age,
        remembered_transport_params=remembered_transport_params,
        validation_token=validation_token,
        random=random,
        ephemeral_seed=ephemeral_seed,
    )
