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

# Run vtest over this repo's suites (vtest.conf), from anywhere in the tree.
#
#   scripts/vtest.sh           interactive TUI
#   scripts/vtest.sh --run     everything, batch
#   scripts/vtest.sh --list    the catalog
#
# vtest is a system tool shared by every repo on the machine, not something this
# tree builds or pins: vayu and navigator pull navlink in as a submodule, and a
# nested vtest pin would ride along into every one of their checkouts. Install
# it once and every repo uses the same binary. VTEST=path forces a specific one.
set -eu
cd "$(dirname "$0")/.."

VTEST="${VTEST:-vtest}"
if ! command -v "$VTEST" >/dev/null 2>&1; then
  echo "vtest not installed. Install it once:" >&2
  echo "  git clone https://github.com/ragnar-vallhala/vtest.git ~/src/vtest" >&2
  echo "  cmake -S ~/src/vtest -B ~/src/vtest/build" >&2
  echo "  cmake --build ~/src/vtest/build" >&2
  echo "  cmake --install ~/src/vtest/build --prefix ~/.local" >&2
  exit 2
fi
exec "$VTEST" "$@"
