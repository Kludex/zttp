from __future__ import annotations

import dataclasses
from typing import Any

import pytest

import zttp
from zttp import config


def test_value_objects_are_frozen() -> None:
    creds = zttp.TlsCredentials(certificate=b"CERT", private_key=b"KEY")
    resumption = zttp.SessionResumption(identity=b"id", psk=b"psk")
    with pytest.raises(dataclasses.FrozenInstanceError):
        creds.certificate = b"other"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        resumption.psk = b"other"  # type: ignore[misc]


def _capture(monkeypatch: pytest.MonkeyPatch) -> list[tuple[tuple[Any, ...], dict[str, Any]]]:
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def fake(*args: Any, **kwargs: Any) -> str:
        calls.append((args, kwargs))
        return "connection"

    monkeypatch.setattr(config, "Connection", fake)
    return calls


def test_h3_server_maps_credentials_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _capture(monkeypatch)
    config.h3_server(
        zttp.TlsCredentials(certificate=b"CERT", private_key=b"KEY"),
        alpn=b"h3",
        resumption=zttp.SessionResumption(identity=b"id", psk=b"psk"),
    )
    (args, kwargs) = calls[0]
    assert args == (zttp.SERVER, zttp.HTTP3)
    # The point of the value object: cert and key land in the right slots.
    assert kwargs["certificate"] == b"CERT"
    assert kwargs["private_key"] == b"KEY"
    assert kwargs["alpn"] == b"h3"
    assert kwargs["resumption_identity"] == b"id"
    assert kwargs["resumption_psk"] == b"psk"


def test_h3_server_defaults_to_ephemeral_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _capture(monkeypatch)
    config.h3_server()
    (_, kwargs) = calls[0]
    assert kwargs["certificate"] is None
    assert kwargs["private_key"] is None


def test_h3_client_maps_resumption_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _capture(monkeypatch)
    config.h3_client(
        server_name=b"example.com",
        resumption=zttp.SessionResumption(identity=b"id", psk=b"psk"),
        early_data=True,
        obfuscated_ticket_age=42,
    )
    (args, kwargs) = calls[0]
    assert args == (zttp.CLIENT, zttp.HTTP3)
    assert kwargs["server_name"] == b"example.com"
    assert kwargs["resumption_identity"] == b"id"
    assert kwargs["resumption_psk"] == b"psk"
    assert kwargs["early_data"] is True
    assert kwargs["obfuscated_ticket_age"] == 42


def test_h3_client_without_resumption_omits_zero_rtt(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _capture(monkeypatch)
    config.h3_client(server_name=b"example.com")
    (_, kwargs) = calls[0]
    assert "obfuscated_ticket_age" not in kwargs
    assert "early_data" not in kwargs
    assert "resumption_identity" not in kwargs


def test_h3_client_zero_rtt_without_resumption_is_rejected() -> None:
    with pytest.raises(ValueError, match="require `resumption`"):
        zttp.h3_client(server_name=b"example.com", early_data=True)
    with pytest.raises(ValueError, match="require `resumption`"):
        zttp.h3_client(server_name=b"example.com", obfuscated_ticket_age=1)


def test_factories_build_real_h3_connections() -> None:
    assert isinstance(zttp.h3_server(), zttp.H3Connection)
    assert isinstance(zttp.h3_client(server_name=b"example.com"), zttp.H3Connection)
