#!/usr/bin/env bash
# Build the zhttp Zig extension against the interpreter that will import it.
# Usage: ./build_ext.sh [path-to-python]   (defaults to the project venv python)
set -euo pipefail

PY="${1:-$(pwd)/.venv/bin/python}"
cd "$(dirname "$0")"

read -r INCLUDE SUFFIX < <("$PY" -c \
  'import sysconfig as s; print(s.get_path("platinclude"), s.get_config_var("EXT_SUFFIX"))')

export ZHTTP_PYTHON_INCLUDE="$INCLUDE"
export ZHTTP_EXT_SUFFIX="$SUFFIX"

# ReleaseSafe by default: this parser ingests untrusted bytes, so keeping
# bounds/overflow checks on turns a would-be UB/crash into a trapped panic.
MODE="${ZHTTP_BUILD_MODE:-ReleaseSafe}"
zig build "-Doptimize=$MODE" "$@" 2>/dev/null || zig build "-Doptimize=$MODE"
echo "built zhttp/_zhttp$SUFFIX against $("$PY" --version) ($INCLUDE)"
