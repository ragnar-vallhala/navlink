#!/usr/bin/env sh
# Build and launch the vtest orchestrator (vtest/) over this repo's suites.
#
#   scripts/vtest.sh           interactive TUI
#   scripts/vtest.sh <args>    passed straight through to the binary
#
# Rebuilds only when the source is newer than the binary.
set -eu
cd "$(dirname "$0")/.."
BIN=build/vtest

if [ ! -f vtest/vtest.c ]; then
  echo "vtest/ is empty — run: git submodule update --init" >&2
  exit 2
fi
if [ ! -x "$BIN" ] || [ vtest/vtest.c -nt "$BIN" ]; then
  mkdir -p build
  ${CC:-cc} -std=c11 -O2 -Wall -Wextra vtest/vtest.c -o "$BIN"
fi
exec "$BIN" "$@"
