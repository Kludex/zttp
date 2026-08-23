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
    "QuicTransportParameters",
    "SessionResumption",
    "TlsCredentials",
]


_QUIC_VARINT_MAX = (1 << 62) - 1


def _encode_varint(value: int) -> bytes:
    if value < 1 << 6:
        return bytes((value,))
    if value < 1 << 14:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 1 << 30:
        return (value | 0x80000000).to_bytes(4, "big")
    return (value | 0xC000000000000000).to_bytes(8, "big")


def _encode_integer_parameter(identifier: int, value: int) -> bytes:
    encoded = _encode_varint(value)
    return _encode_varint(identifier) + _encode_varint(len(encoded)) + encoded


def _validate_integer(name: str, value: int | None, minimum: int, maximum: int) -> None:
    if value is not None and (type(value) is not int or value < minimum or value > maximum):
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")


@dataclass(frozen=True, kw_only=True)
class QuicTransportParameters:
    """QUIC flow-control, stream, timeout, payload, and migration settings."""

    max_idle_timeout: int | None = None
    stateless_reset_token: bytes | None = None
    max_udp_payload_size: int | None = None
    initial_max_data: int | None = None
    initial_max_stream_data_bidi_local: int | None = None
    initial_max_stream_data_bidi_remote: int | None = None
    initial_max_stream_data_uni: int | None = None
    initial_max_streams_bidi: int | None = None
    initial_max_streams_uni: int | None = None
    ack_delay_exponent: int | None = None
    max_ack_delay: int | None = None
    disable_active_migration: bool = False
    active_connection_id_limit: int | None = None

    def __post_init__(self) -> None:
        _validate_integer("max_idle_timeout", self.max_idle_timeout, 0, 1 << 32)
        _validate_integer("max_udp_payload_size", self.max_udp_payload_size, 1200, 65527)
        _validate_integer("initial_max_data", self.initial_max_data, 0, _QUIC_VARINT_MAX)
        _validate_integer(
            "initial_max_stream_data_bidi_local", self.initial_max_stream_data_bidi_local, 0, _QUIC_VARINT_MAX
        )
        _validate_integer(
            "initial_max_stream_data_bidi_remote", self.initial_max_stream_data_bidi_remote, 0, _QUIC_VARINT_MAX
        )
        _validate_integer("initial_max_stream_data_uni", self.initial_max_stream_data_uni, 0, _QUIC_VARINT_MAX)
        _validate_integer("initial_max_streams_bidi", self.initial_max_streams_bidi, 0, 1 << 60)
        _validate_integer("initial_max_streams_uni", self.initial_max_streams_uni, 0, 1 << 60)
        _validate_integer("ack_delay_exponent", self.ack_delay_exponent, 0, 20)
        _validate_integer("max_ack_delay", self.max_ack_delay, 0, (1 << 14) - 1)
        _validate_integer("active_connection_id_limit", self.active_connection_id_limit, 2, _QUIC_VARINT_MAX)
        if self.stateless_reset_token is not None and (
            not isinstance(self.stateless_reset_token, bytes) or len(self.stateless_reset_token) != 16
        ):
            raise ValueError("stateless_reset_token must be exactly 16 bytes")
        if type(self.disable_active_migration) is not bool:
            raise ValueError("disable_active_migration must be a bool")

    @property
    def encoded(self) -> bytes:
        """The canonical RFC 9000 transport-parameter encoding."""
        parameters: list[bytes] = []
        integer_parameters = (
            (0x01, self.max_idle_timeout),
            (0x03, self.max_udp_payload_size),
            (0x04, self.initial_max_data),
            (0x05, self.initial_max_stream_data_bidi_local),
            (0x06, self.initial_max_stream_data_bidi_remote),
            (0x07, self.initial_max_stream_data_uni),
            (0x08, self.initial_max_streams_bidi),
            (0x09, self.initial_max_streams_uni),
            (0x0A, self.ack_delay_exponent),
            (0x0B, self.max_ack_delay),
            (0x0E, self.active_connection_id_limit),
        )
        for identifier, value in integer_parameters:
            if value is not None:
                parameters.append(_encode_integer_parameter(identifier, value))
        if self.stateless_reset_token is not None:
            parameters.insert(1, b"\x02\x10" + self.stateless_reset_token)
        if self.disable_active_migration:
            parameters.append(b"\x0c\x00")
        return b"".join(parameters)


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
