#!/usr/bin/env sh
# Run the NavLink test suite.
#
#   scripts/test.sh            the full 7-step pipeline (tests/run_tests.py):
#                              regenerate, Python codec tests, compile + run the
#                              C test, C<->Python parity, and both loopbacks
#   scripts/test.sh <name>     one standalone test, e.g. test_xfer_loopback.py
#
# No third-party dependencies -- python3 and a C compiler, nothing else. That is
# a deliberate property of this repo: it is the wire contract three codebases
# generate from, so its tests must run anywhere without a package install.
set -eu
cd "$(dirname "$0")/.."

if [ $# -gt 0 ]; then
  exec python3 "tests/$1"
fi
exec python3 tests/run_tests.py
