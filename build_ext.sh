#!/usr/bin/env bash
# Build the zttp Zig extension against the interpreter that will import it.
# Usage: ./build_ext.sh [path-to-python]   (defaults to the project venv python)
set -euo pipefail

PY="${1:-$(pwd)/.venv/bin/python}"
cd "$(dirname "$0")"

read -r INCLUDE SUFFIX < <("$PY" -c \
  'import sysconfig as s; print(s.get_path("platinclude"), s.get_config_var("EXT_SUFFIX"))')

export ZTTP_PYTHON_INCLUDE="$INCLUDE"
export ZTTP_EXT_SUFFIX="$SUFFIX"

# ReleaseSafe by default: this parser ingests untrusted bytes, so keeping
# bounds/overflow checks on turns a would-be UB/crash into a trapped panic.
MODE="${ZTTP_BUILD_MODE:-ReleaseSafe}"
zig build "-Doptimize=$MODE" "$@" 2>/dev/null || zig build "-Doptimize=$MODE"
echo "built zttp/_zttp$SUFFIX against $("$PY" --version) ($INCLUDE)"
