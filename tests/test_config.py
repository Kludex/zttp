from __future__ import annotations

import dataclasses

import pytest

import zttp


def test_tls_credentials_is_a_typed_dictionary() -> None:
    credentials = zttp.TlsCredentials(certificate=b"CERT", private_key=b"KEY")

    assert credentials == {"certificate": b"CERT", "private_key": b"KEY"}


def test_session_resumption_is_frozen() -> None:
    resumption = zttp.SessionResumption(identity=b"id", psk=b"\x00" * 32)

    with pytest.raises(dataclasses.FrozenInstanceError):
        resumption.psk = b"other"  # type: ignore[misc]


def test_session_resumption_needs_both_halves() -> None:
    with pytest.raises(TypeError):
        zttp.SessionResumption(identity=b"id")  # type: ignore[call-arg]


def test_quic_transport_parameters_is_a_typed_dictionary() -> None:
    parameters: zttp.QuicTransportParameters = {
        "initial_max_data": 64,
        "disable_active_migration": True,
    }
    assert parameters == {"initial_max_data": 64, "disable_active_migration": True}


@pytest.mark.parametrize(
    ("credentials", "exception"),
    [
        (object(), TypeError),
        ({"certificate": b"leaf"}, TypeError),
        ({"private_key": b"\x42" * 32}, ValueError),
        ({"certificate": b"leaf", "certificates": (b"intermediate",), "private_key": b"\x42" * 32}, ValueError),
        ({"certificate": b"leaf", "private_key": b"\x42" * 32, "unknown": b"value"}, ValueError),
        ({"certificate": b"", "private_key": b"\x42" * 32}, ValueError),
        ({"certificates": (), "private_key": b"\x42" * 32}, ValueError),
        ({"certificates": (b"",), "private_key": b"\x42" * 32}, ValueError),
        ({"certificates": b"single-certificate", "private_key": b"\x42" * 32}, TypeError),
        ({"certificates": ("not-bytes",), "private_key": b"\x42" * 32}, TypeError),
    ],
)
def test_h3_constructor_validates_tls_credentials(credentials: object, exception: type[Exception]) -> None:
    with pytest.raises(exception):
        zttp.Connection(
            zttp.SERVER,
            zttp.HTTP3,
            credentials=credentials,  # type: ignore[arg-type]
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
            zttp.Connection(zttp.SERVER, zttp.HTTP3, **bad)  # type: ignore[call-overload]


def test_session_resumption_is_keyword_only() -> None:
    with pytest.raises(TypeError):
        zttp.SessionResumption(b"id", b"psk")  # type: ignore[misc]
