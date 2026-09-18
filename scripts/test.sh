#!/usr/bin/env sh
# Run the NavLink test suite.
#
#   scripts/test.sh            everything, via ctest
#   scripts/test.sh -R <regex> passed through to ctest, e.g. -R test_codec
#
# Configures the build dir on first use. The codec is generated as a build step
# and the Python tests take it from a ctest fixture, so a clean tree needs no
# special ordering.
set -eu
cd "$(dirname "$0")/.."

[ -f build/CMakeCache.txt ] || cmake -S . -B build >/dev/null
cmake --build build -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" >/dev/null
exec ctest --test-dir build --output-on-failure "$@"
