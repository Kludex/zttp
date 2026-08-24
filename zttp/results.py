"""Value objects returned by HTTP/3 introspection methods.

HTTP/3 introspection methods return these frozen dataclasses. Read them by field
name (`info.error_code`, `ticket.psk`, `connection_id.sequence_number`) - they are not
tuples, so there is no positional access to get wrong.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "CloseInfo",
    "DatagramHeader",
    "LocalConnectionId",
    "OutboundDatagram",
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


@dataclass(frozen=True)
class LocalConnectionId:
    """An active destination connection ID routed to one HTTP/3 connection."""

    sequence_number: int
    connection_id: bytes


@dataclass(frozen=True, slots=True)
class OutboundDatagram:
    """One QUIC datagram and its opaque destination address key."""

    data: bytes
    peer_address: bytes | None


@dataclass(frozen=True)
class DatagramHeader:
    """The routable prefix of a received QUIC datagram (RFC 9000 17).

    Returned by [`parse_datagram_header`][zttp.parse_datagram_header] to demultiplex a
    shared UDP socket onto per-connection state. A long header carries the connection
    ids and their lengths on the wire; a short (1-RTT) header does not encode the
    destination id's length, so `destination_connection_id` is empty for one and the
    receiver must match it against connection ids it already tracks. `token` contains
    the address-validation token from a QUIC v1 Initial and is empty for other packets.
    """

    destination_connection_id: bytes
    source_connection_id: bytes
    version: int
    is_long_header: bool
    is_initial: bool
    token: bytes
