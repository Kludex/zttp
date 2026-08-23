from __future__ import annotations

import hmac
from dataclasses import dataclass


@dataclass(frozen=True)
class RetryContext:
    original_destination_connection_id: bytes
    retry_source_connection_id: bytes


class RetryTokenCodec:
    def __init__(self, secret: bytes, ttl: int) -> None:
        if len(secret) < 32:
            raise ValueError("retry_secret must contain at least 32 bytes")
        if ttl <= 0:
            raise ValueError("retry_token_ttl must be positive")
        self._secret = bytes(secret)
        self._ttl = ttl

    def create(self, peer_address: bytes, original_dcid: bytes, retry_scid: bytes, now: int) -> bytes:
        if len(peer_address) > 256:
            raise ValueError("peer_address must be at most 256 bytes")
        payload = b"".join(
            (
                b"\x01",
                now.to_bytes(8, "big"),
                len(peer_address).to_bytes(2, "big"),
                peer_address,
                bytes((len(original_dcid),)),
                original_dcid,
                bytes((len(retry_scid),)),
                retry_scid,
            )
        )
        return payload + hmac.digest(self._secret, payload, "sha256")

    def validate(self, peer_address: bytes, token: bytes, now: int) -> RetryContext | None:
        if len(token) < 53:
            return None
        payload = token[:-32]
        if not hmac.compare_digest(token[-32:], hmac.digest(self._secret, payload, "sha256")):
            return None
        if payload[0] != 1:  # pragma: no cover - authenticated tokens are emitted by create()
            return None
        issued_at = int.from_bytes(payload[1:9], "big")
        if now < issued_at or now - issued_at > self._ttl:
            return None
        address_length = int.from_bytes(payload[9:11], "big")
        offset = 11
        address_end = offset + address_length
        if address_end >= len(payload):  # pragma: no cover - authenticated tokens are emitted by create()
            return None
        if payload[offset:address_end] != peer_address:
            return None
        offset = address_end
        original_length = payload[offset]
        offset += 1
        original_end = offset + original_length
        if original_length < 8 or original_end >= len(payload):  # pragma: no cover - authenticated token shape
            return None
        original_dcid = payload[offset:original_end]
        offset = original_end
        retry_length = payload[offset]
        offset += 1
        retry_end = offset + retry_length
        if (
            retry_length == 0 or retry_length > 20 or retry_end != len(payload)
        ):  # pragma: no cover - authenticated token shape
            return None
        return RetryContext(original_dcid, payload[offset:retry_end])
