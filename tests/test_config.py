from __future__ import annotations

import dataclasses

import pytest
from typing_extensions import TypedDict

import zttp


class CredentialsCase(TypedDict):
    credentials: object
    exception: type[Exception]
    match: str


def test_tls_credentials_is_a_typed_dictionary() -> None:
    credentials = zttp.TlsCredentials(certificate=b"CERT", private_key=b"KEY")
    scalar_credentials = zttp.TlsCredentials(certificate=b"CERT", private_key_scalar=b"SCALAR")

    assert credentials == {"certificate": b"CERT", "private_key": b"KEY"}
    assert scalar_credentials == {"certificate": b"CERT", "private_key_scalar": b"SCALAR"}


def test_session_resumption_is_frozen() -> None:
    resumption = zttp.SessionResumption(identity=b"id", psk=b"\x00" * 32)

    with pytest.raises(dataclasses.FrozenInstanceError):
        resumption.psk = b"other"  # ty: ignore[invalid-assignment]


def test_session_resumption_needs_both_halves() -> None:
    with pytest.raises(TypeError):
        zttp.SessionResumption(identity=b"id")  # ty: ignore[missing-argument]


def test_quic_transport_parameters_is_a_typed_dictionary() -> None:
    parameters: zttp.QuicTransportParameters = {
        "initial_max_data": 64,
        "disable_active_migration": True,
    }
    assert parameters == {"initial_max_data": 64, "disable_active_migration": True}


@pytest.mark.parametrize(
    "case",
    [
        CredentialsCase(
            credentials=object(),
            exception=TypeError,
            match="credentials must be a TlsCredentials dictionary",
        ),
        CredentialsCase(
            credentials={"certificate": b"leaf"},
            exception=TypeError,
            match="credentials must include private_key or private_key_scalar",
        ),
        CredentialsCase(
            credentials={"private_key": b"\x42" * 32},
            exception=ValueError,
            match="credentials must include certificate or certificates",
        ),
        CredentialsCase(
            credentials={
                "certificate": b"leaf",
                "certificates": (b"intermediate",),
                "private_key": b"\x42" * 32,
            },
            exception=ValueError,
            match="pass either certificate or certificates, not both",
        ),
        CredentialsCase(
            credentials={
                "certificate": b"leaf",
                "private_key": b"\x42" * 32,
                "private_key_scalar": b"\x43" * 32,
            },
            exception=ValueError,
            match="pass either private_key or private_key_scalar, not both",
        ),
        CredentialsCase(
            credentials={"certificate": b"leaf", "private_key": b"\x42" * 32, "unknown": b"value"},
            exception=ValueError,
            match="credentials contains an unknown field",
        ),
        CredentialsCase(
            credentials={"certificate": b"leaf", "private_key_scalar": b"short"},
            exception=ValueError,
            match="private_key_scalar must be exactly 32 bytes",
        ),
        CredentialsCase(
            credentials={"certificate": b"leaf", "private_key_scalar": b"\x00" * 32},
            exception=ValueError,
            match="private_key_scalar is not a valid P-256 scalar",
        ),
        CredentialsCase(
            credentials={"certificate": b"", "private_key": b"\x42" * 32},
            exception=ValueError,
            match="every certificate must be non-empty bytes",
        ),
        CredentialsCase(
            credentials={"certificates": (), "private_key": b"\x42" * 32},
            exception=ValueError,
            match="the certificate chain must not be empty",
        ),
        CredentialsCase(
            credentials={"certificates": (b"",), "private_key": b"\x42" * 32},
            exception=ValueError,
            match="every certificate must be non-empty bytes",
        ),
        CredentialsCase(
            credentials={"certificates": b"single-certificate", "private_key": b"\x42" * 32},
            exception=TypeError,
            match="bytes",
        ),
        CredentialsCase(
            credentials={"certificates": ("not-bytes",), "private_key": b"\x42" * 32},
            exception=TypeError,
            match="bytes",
        ),
    ],
)
def test_h3_constructor_validates_tls_credentials(case: CredentialsCase) -> None:
    with pytest.raises(case["exception"], match=case["match"]):
        zttp.Connection(
            zttp.SERVER,
            zttp.HTTP3,
            credentials=case["credentials"],  # ty: ignore[invalid-argument-type]
        )


def test_h3_constructor_takes_value_objects() -> None:
    client = zttp.Connection(
        zttp.CLIENT,
        zttp.HTTP3,
        server_name=b"example.com",
        resumption=zttp.SessionResumption(identity=b"ticket", psk=b"\x00" * 32),
    )
    assert isinstance(client, zttp.H3Connection)


def test_h3_constructor_rejects_the_old_raw_kwargs() -> None:
    for bad in (
        {"certificate": b"c", "private_key": b"k"},
        {"resumption_identity": b"i", "resumption_psk": b"\x00" * 32},
    ):
        with pytest.raises(TypeError):
            zttp.Connection(zttp.SERVER, zttp.HTTP3, **bad)  # ty: ignore[no-matching-overload]


def test_session_resumption_is_keyword_only() -> None:
    with pytest.raises(TypeError):
        zttp.SessionResumption(b"id", b"psk")  # ty: ignore[missing-argument, too-many-positional-arguments]
