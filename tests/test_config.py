from __future__ import annotations

import dataclasses

import pytest

import zttp


def test_value_objects_are_frozen() -> None:
    creds = zttp.TlsCredentials(certificate=b"CERT", private_key=b"KEY")
    resumption = zttp.SessionResumption(identity=b"id", psk=b"\x00" * 32)
    with pytest.raises(dataclasses.FrozenInstanceError):
        creds.certificate = b"other"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        resumption.psk = b"other"  # type: ignore[misc]


def test_credentials_and_resumption_need_both_halves() -> None:
    # Naming both fields is the whole point: neither can be built half-formed, so a
    # certificate/key (or identity/psk) swap has nowhere to hide.
    with pytest.raises(TypeError):
        zttp.TlsCredentials(certificate=b"CERT")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        zttp.SessionResumption(identity=b"id")  # type: ignore[call-arg]


def test_h3_constructor_takes_value_objects() -> None:
    client = zttp.Connection(
        zttp.CLIENT,
        zttp.HTTP3,
        server_name=b"example.com",
        resumption=zttp.SessionResumption(identity=b"ticket", psk=b"\x00" * 32),
        verify=False,
    )
    assert isinstance(client, zttp.H3Connection)


def test_h3_constructor_rejects_the_old_raw_kwargs() -> None:
    for bad in (
        {"certificate": b"c", "private_key": b"k"},
        {"resumption_identity": b"i", "resumption_psk": b"\x00" * 32},
    ):
        with pytest.raises(TypeError):
            zttp.Connection(zttp.SERVER, zttp.HTTP3, **bad)  # type: ignore[call-overload]


def test_value_objects_are_keyword_only() -> None:
    # Positional construction is where a same-typed swap could still hide, so the
    # fields are keyword-only: TlsCredentials(key, cert) is a TypeError, not a silent
    # transposition.
    with pytest.raises(TypeError):
        zttp.TlsCredentials(b"cert", b"key")  # type: ignore[misc]
    with pytest.raises(TypeError):
        zttp.SessionResumption(b"id", b"psk")  # type: ignore[misc]
    # Keyword construction is unaffected.
    assert zttp.TlsCredentials(certificate=b"c", private_key=b"k").private_key == b"k"
