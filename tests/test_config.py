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


def test_quic_transport_parameters_use_canonical_varints() -> None:
    parameters = zttp.QuicTransportParameters(
        max_idle_timeout=63,
        stateless_reset_token=b"r" * 16,
        max_udp_payload_size=1200,
        initial_max_data=64,
        initial_max_stream_data_bidi_local=16383,
        initial_max_stream_data_bidi_remote=16384,
        initial_max_stream_data_uni=1 << 30,
        initial_max_streams_bidi=4,
        initial_max_streams_uni=5,
        ack_delay_exponent=3,
        max_ack_delay=25,
        disable_active_migration=True,
        active_connection_id_limit=2,
    )

    assert parameters.encoded == (
        b"\x01\x01\x3f"
        b"\x02\x10" + b"r" * 16 + b"\x03\x02\x44\xb0"
        b"\x04\x02\x40\x40"
        b"\x05\x02\x7f\xff"
        b"\x06\x04\x80\x00\x40\x00"
        b"\x07\x08\xc0\x00\x00\x00\x40\x00\x00\x00"
        b"\x08\x01\x04"
        b"\x09\x01\x05"
        b"\x0a\x01\x03"
        b"\x0b\x01\x19"
        b"\x0e\x01\x02"
        b"\x0c\x00"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_idle_timeout", -1),
        ("max_udp_payload_size", 1199),
        ("initial_max_data", 1 << 62),
        ("initial_max_stream_data_bidi_local", -1),
        ("initial_max_stream_data_bidi_remote", True),
        ("initial_max_stream_data_uni", -1),
        ("initial_max_streams_bidi", (1 << 60) + 1),
        ("initial_max_streams_uni", -1),
        ("ack_delay_exponent", 21),
        ("max_ack_delay", 1 << 14),
        ("active_connection_id_limit", 1),
        ("stateless_reset_token", b"short"),
        ("stateless_reset_token", "not-bytes"),
        ("disable_active_migration", 1),
    ],
)
def test_quic_transport_parameters_validate_ranges(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        zttp.QuicTransportParameters(**{field: value})  # type: ignore[arg-type]


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
