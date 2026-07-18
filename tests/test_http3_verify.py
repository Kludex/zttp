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


# A real 2048-bit RSA self-signed root (OpenSSL). Certificate verification is
# ECDSA + RSA (PKCS#1 v1.5 / PSS), so an RSA CA is a usable trust anchor - the DER
# parses through the binding without error. (The chain-verification math itself is
# covered end to end by the Zig tests, which drive real RSA fixtures.)
RSA_ROOT_DER = bytes.fromhex(
    "30820311308201f9a003020102021446201ad42ef894e101f97948bbb9080643f3b56d300d06092a8648"
    "86f70d01010b050030183116301406035504030c0d7a7474702052534120526f6f74301e170d32363037"
    "31383131333134305a170d3336303731353131333134305a30183116301406035504030c0d7a74747020"
    "52534120526f6f7430820122300d06092a864886f70d01010105000382010f003082010a0282010100b0"
    "a78a6bde412ab773f447b7a0fb16d69f53d62e29d3313e9010e6541cdd1f426b17b4c1870c77497cde8f9"
    "65f9545ca69baaf2c481d13da0380a292f9123c42e3321919243e0749e85f4495b119fc57278082 31e41"
    "e5f6e56888603cc52d0989c7456e2b57796ceb9f3b3c7ab2627972e4e5811a44b84fe1a2041caa3647756"
    "f459aa704b18399afa05ea414ac62a5f1ad299d84d906669b5edae488fc8aeeea3e3f186286dfd7beadd5"
    "e89eb4a708e26badced8ae10b0de3f641afab5b3c3b598844776c5ee608231dc51dd888c272c033e3308a"
    "d2e2ea366593569321c37623a77e7c34eb74b53e148bfb201273ad946e3074ba9df347151eea5f4077d7d"
    "b0203010001a3533051301d0603551d0e041604142487baccc2bd48dc5c60ce2538e8915b205c4534301f"
    "0603551d230418301680142487baccc2bd48dc5c60ce2538e8915b205c4534300f0603551d130101ff04"
    "0530030101ff300d06092a864886f70d01010b05000382010100875c7d06e4193c10b63b95adf9ebe6ed"
    "e2d0f20738aed10dea48e05258d07c514c10757ff0fd1d765fa46fe87491e2f2e848d5642995e50799 3d8"
    "618b96005b580bccb7c0cdc43af6155e0192d521984a23b81a597e2f0fe7414cbed3da532d549057c327c"
    "7af18c695e22a8c60d92e35e8d577fac73751204d755f31bc90e5dfedc88de1795157d7e728369bea8350"
    "a9b7621526dc2994725f67cb1fc1cc02002befba88b9b075e511435d7336dfa86062cb22a35067531dc4d"
    "3e328015078004def1944b401e022c3173736c0c622a4f2547626f3ffd0448042137c184bb712b945f6c8"
    "171f78af7ff98fd06438c5f172a821d4c7f063daa5b60d3dfcc9fc8".replace(" ", "")
)


def test_an_rsa_certificate_is_a_usable_trust_anchor() -> None:
    # Constructs without error: the RSA anchor parses through the binding.
    client = zttp.Connection(
        zttp.CLIENT, protocol=zttp.HTTP3, server_name=b"example.test", trust=RSA_ROOT_DER, now_sec=1800000000
    )
    assert isinstance(client, zttp.H3Connection)
