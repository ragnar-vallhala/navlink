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
