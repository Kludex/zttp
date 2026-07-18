"""HTTP/3 server-certificate verification (the client authenticating the server).

Drives a full handshake so the client's server-flight verification actually runs,
using real self-signed X.509 identities minted by zttp.generate_self_signed.
"""

from __future__ import annotations

import pytest

import zttp

NOW = 1700000000  # 2023-11-14, inside every window below
FAR = 2000000000  # 2033
PAST_START, PAST_END = 1600000000, 1650000000  # a window that closed in 2022

SERVER_TP = b"\x04\x04\x80\x10\x00\x00\x08\x01\x08\x09\x01\x08\x06\x04\x80\x04\x00\x00\x07\x04\x80\x04\x00\x00"
CLIENT_TP = (
    b"\x04\x04\x80\x01\x00\x00\x05\x04\x80\x04\x00\x00\x06\x04\x80\x04\x00\x00"
    b"\x07\x04\x80\x04\x00\x00\x08\x01\x10\x09\x01\x10"
)
SERVER_SEED = b"\x11" * 32


def server_cert(
    dns: bytes = b"localhost", *, seed: bytes = SERVER_SEED, not_before: int = PAST_START, not_after: int = FAR
) -> bytes:
    return zttp.generate_self_signed(dns, seed, not_before, not_after)


def make_pair(
    *, cert: bytes, seed: bytes = SERVER_SEED, now: int = NOW, **client_kwargs: object
) -> tuple[zttp.H3Connection, zttp.H3Connection]:
    server = zttp.Connection(
        zttp.SERVER,
        protocol=zttp.HTTP3,
        credentials=zttp.TlsCredentials(certificate=cert, private_key=seed),
        now_sec=now,
        random=b"\xab" * 32,
        ephemeral_seed=b"\x33" * 32,
        transport_params=SERVER_TP,
    )
    client = zttp.Connection(
        zttp.CLIENT,
        protocol=zttp.HTTP3,
        now_sec=now,
        random=b"\x44" * 32,
        ephemeral_seed=b"\x55" * 32,
        connection_id=b"\x11\x22\x33\x44",
        alpn=b"h3",
        transport_params=CLIENT_TP,
        **client_kwargs,
    )
    return client, server


def handshake(client: zttp.H3Connection, server: zttp.H3Connection, now: int = NOW) -> None:
    # ClientHello -> server, then the server flight -> client, where the client
    # verifies the certificate chain.
    for dgram in client.data_to_send():
        server.receive_datagram(dgram, now)
    for dgram in server.data_to_send():
        client.receive_datagram(dgram, now)


def test_generate_self_signed_round_trips_as_a_pinned_identity() -> None:
    cert = server_cert(b"example.test")
    assert isinstance(cert, bytes) and cert[0] == 0x30  # a DER SEQUENCE
    client, server = make_pair(cert=cert, server_name=b"example.test", trust=cert)
    handshake(client, server)  # no error: the pinned cert authenticates the server


def test_client_rejects_an_untrusted_certificate() -> None:
    cert = server_cert()
    other = zttp.generate_self_signed(b"localhost", b"\x22" * 32, PAST_START, FAR)
    client, server = make_pair(cert=cert, server_name=b"localhost", trust=other)
    with pytest.raises(zttp.RemoteProtocolError):
        handshake(client, server)


def test_client_rejects_a_certificate_for_the_wrong_host() -> None:
    cert = server_cert(b"localhost")
    client, server = make_pair(cert=cert, server_name=b"attacker.example", trust=cert)
    with pytest.raises(zttp.RemoteProtocolError):
        handshake(client, server)


def test_client_rejects_an_expired_certificate() -> None:
    cert = server_cert(b"localhost", not_before=PAST_START, not_after=PAST_END)  # long expired
    client, server = make_pair(cert=cert, server_name=b"localhost", trust=cert)
    with pytest.raises(zttp.RemoteProtocolError):
        handshake(client, server)


def test_verify_false_accepts_any_certificate() -> None:
    cert = server_cert(b"whoever")
    client, server = make_pair(cert=cert, server_name=b"unrelated.host", verify=False)
    handshake(client, server)  # verification disabled: no error despite the mismatch


def test_matching_san_wildcard_is_accepted() -> None:
    cert = server_cert(b"*.example.test")
    client, server = make_pair(cert=cert, server_name=b"api.example.test", trust=cert)
    handshake(client, server)


# -- constructor policy (no handshake needed) ---------------------------------


def test_verifying_client_requires_trust() -> None:
    with pytest.raises(ValueError, match="sans-IO"):
        zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, server_name=b"example.test")


def test_trust_and_verify_false_conflict() -> None:
    with pytest.raises(ValueError):
        zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, server_name=b"x", trust=server_cert(), verify=False)


@pytest.mark.parametrize(
    "bad",
    [
        b"not a cert",
        b"",
        bytes([0x30, 0x03, 0x02, 0x01, 0x01]),  # valid DER, wrong shape
        bytes([0x30, 0x82, 0xFF, 0xFF]),  # length past the buffer
        bytes([0x30, 0x80]),  # indefinite length (not DER)
    ],
)
def test_malformed_trust_is_rejected_not_crashed(bad: bytes) -> None:
    with pytest.raises(ValueError):
        zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, server_name=b"x", trust=bad)


def test_trust_and_verify_are_client_only() -> None:
    for kw in ({"trust": server_cert()}, {"verify": False}):
        with pytest.raises(ValueError, match="only valid for HTTP/3 clients"):
            zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3, **kw)  # type: ignore[arg-type]
