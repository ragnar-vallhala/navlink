#!/usr/bin/env sh
# Copyright (C) 2026 NAVRobotec Pvt Ltd
# Author: Ragnar Vallhala
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
