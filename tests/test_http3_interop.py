from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.http3_interop


def run_interop_smoke(backend: str) -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "interop_aioquic.py"
    spec = importlib.util.spec_from_file_location(f"zttp_interop_{backend}", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    old_backend = os.environ.get("ZTTP_INTEROP_BACKEND")
    os.environ["ZTTP_INTEROP_BACKEND"] = backend
    try:
        spec.loader.exec_module(module)
        module.main()
    finally:
        if old_backend is None:
            os.environ.pop("ZTTP_INTEROP_BACKEND", None)
        else:
            os.environ["ZTTP_INTEROP_BACKEND"] = old_backend


def test_aioquic_interop_smoke() -> None:
    pytest.importorskip("aioquic")

    run_interop_smoke("aioquic")


def test_qh3_interop_smoke() -> None:
    pytest.importorskip("cryptography")
    pytest.importorskip("qh3")

    run_interop_smoke("qh3")
