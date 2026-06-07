from __future__ import annotations

import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

ROOT = Path(__file__).parent

# cibuildwheel builds every macOS wheel on the arm64 runner and asks for a
# specific arch through ARCHFLAGS; translate it into a Zig cross-compile target
# so the produced `.so` matches the wheel tag delocate enforces.
_MACOS_ZIG_TARGET = {"arm64": "aarch64-macos", "x86_64": "x86_64-macos"}


def _zig_target_args() -> list[str]:
    archflags = os.environ.get("ARCHFLAGS", "")
    arches = archflags.split()[1::2]  # "-arch x86_64 -arch arm64" -> ["x86_64", "arm64"]
    if len(arches) != 1 or sys.platform != "darwin":
        return []
    target = _MACOS_ZIG_TARGET.get(arches[0])
    return [f"-Dtarget={target}"] if target else []


def _zig_command() -> list[str]:
    """Resolve how to invoke Zig: a `zig` on PATH, else the `ziglang` pip package.

    The pip fallback (`python -m ziglang`) works identically on the host and inside
    cibuildwheel's manylinux containers, where a host-installed `zig` isn't visible.
    """
    if shutil.which("zig"):
        return ["zig"]
    try:
        import ziglang  # noqa: F401
    except ImportError:
        raise RuntimeError(
            "Zig toolchain not found: install Zig and put it on PATH, or `pip install ziglang`."
        ) from None
    return [sys.executable, "-m", "ziglang"]


class ZigBuildHook(BuildHookInterface):
    """Compile the Zig extension against the building interpreter during the wheel build.

    This makes `uv build` / `pip wheel` / cibuildwheel produce a correct, platform-tagged
    wheel with no out-of-band step: the `.so` is built here, against `sys.executable`, and
    `build.zig` installs it into the `zttp/` package as `_zttp<EXT_SUFFIX>`.
    """

    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name != "wheel":
            return

        include = sysconfig.get_path("platinclude")
        ext_suffix = sysconfig.get_config_var("EXT_SUFFIX")
        if not include or not ext_suffix:
            raise RuntimeError("could not resolve platinclude / EXT_SUFFIX from the building interpreter")

        # ReleaseSafe by default: the parser ingests untrusted bytes, so keeping
        # Zig's bounds/overflow checks on trades a little speed for turning any
        # reachable UB into a trapped panic instead of memory corruption.
        mode = os.environ.get("ZTTP_BUILD_MODE", "ReleaseSafe")
        env = {**os.environ, "ZTTP_PYTHON_INCLUDE": include, "ZTTP_EXT_SUFFIX": ext_suffix}
        subprocess.run(
            [*_zig_command(), "build", f"-Doptimize={mode}", *_zig_target_args()],
            cwd=ROOT,
            env=env,
            check=True,
        )

        artifact = f"zttp/_zttp{ext_suffix}"
        if not (ROOT / artifact).exists():
            raise RuntimeError(f"zig build did not produce {artifact}")

        # Tag the wheel for this interpreter + platform rather than py3-none-any.
        build_data["pure_python"] = False
        build_data["infer_tag"] = True
        build_data["artifacts"].append(artifact)

    def clean(self, versions: list[str]) -> None:
        for path in ROOT.glob("zttp/_zttp*.so"):
            path.unlink()
        for path in ROOT.glob("zttp/_zttp*.pyd"):
            path.unlink()
        print(f"removed compiled extensions; building Zig core via {sys.executable}", file=sys.stderr)
