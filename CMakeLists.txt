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

# NavLink — the dialect, the generated codec, and the test suite.
#
# Two ways in:
#
#   Top level   builds the test suite, registered with ctest so one orchestrator
#               can drive this repo the same way it drives the C repos that
#               consume it:
#                 cmake -S . -B build && ctest --test-dir build
#
#   Subproject  (add_subdirectory, which is what `nav` does for a library
#               dependency) defines only the `navlink` static library: the C
#               codec generated from dialect.json at build time, plus its
#               header directory. No tests, no enable_testing(), no options
#               forced on the parent. The codec needs only <stdint.h>,
#               <stddef.h> and memcpy, so it builds for a freestanding /
#               arm-none-eabi consumer. Python is needed at build time to
#               run generate.py, never on the target.
cmake_minimum_required(VERSION 3.16)
project(navlink C)

# PROJECT_IS_TOP_LEVEL needs CMake 3.21; this is the 3.16-compatible equivalent.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(NAVLINK_TOP_LEVEL ON)
else()
  set(NAVLINK_TOP_LEVEL OFF)
endif()

# No-op when the parent already found it (nav passes -DPython3_EXECUTABLE).
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# "prod" omits messages flagged "test": true; "test" is for hwtest firmware.
set(NAVLINK_PROFILE "prod" CACHE STRING "Codec profile: prod or test")
set_property(CACHE NAVLINK_PROFILE PROPERTY STRINGS prod test)

set(GEN ${CMAKE_CURRENT_BINARY_DIR}/generated)
set(GEN_C ${GEN}/c)

# The generated sources are not tracked: dialect.json is the only source of
# truth, so regenerate whenever it (or the generator) changes.
# Top level also needs the Python codec and the parity source for the tests; a
# consumer only needs the C codec.
if(NAVLINK_TOP_LEVEL)
  set(NAVLINK_GEN_LANG all)
else()
  set(NAVLINK_GEN_LANG c)
endif()
add_custom_command(
  OUTPUT ${GEN_C}/navlink_msgs.h ${GEN_C}/navlink_msgs.c ${GEN_C}/navlink_parity.c
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/generate.py
          --lang ${NAVLINK_GEN_LANG} --profile ${NAVLINK_PROFILE} --out ${GEN}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/dialect.json
          ${CMAKE_CURRENT_SOURCE_DIR}/generate.py
  COMMENT "navlink: generating the codec from dialect.json"
  VERBATIM)
add_custom_target(navlink_codec DEPENDS ${GEN_C}/navlink_msgs.c)

# The library a consumer links. navlink_parity.c is deliberately not in it: it
# is a host-only test helper (printf of every message's bytes for the C<->Python
# parity check) and would drag stdio into a firmware image. The target name
# equals nav.toml [project].name, as nav requires.
add_library(navlink STATIC ${GEN_C}/navlink_msgs.c)
target_include_directories(navlink PUBLIC $<BUILD_INTERFACE:${GEN_C}>)
set_target_properties(navlink PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)

if(NOT NAVLINK_TOP_LEVEL)
  return()
endif()

option(NAVLINK_SANITIZE "Build the C test with ASan + UBSan" OFF)

enable_testing()

# --- the C side: compiled against the generated codec, as a consumer would ---
add_executable(test_c tests/test_c.c ${GEN_C}/navlink_msgs.c ${GEN_C}/navlink_parity.c)
target_include_directories(test_c PRIVATE ${GEN_C})
# -UNDEBUG: every check in test_c.c is an assert(), so a build type that defines
# NDEBUG would compile the entire test away into a no-op that still passes.
target_compile_options(test_c PRIVATE -std=c11 -Wall -Wextra -Werror -UNDEBUG)
# The generated codec does the pointer arithmetic that packs and unpacks every
# message, so it is the part worth running under a sanitizer.
if(NAVLINK_SANITIZE)
  target_compile_options(test_c PRIVATE -fsanitize=address,undefined
                                        -fno-omit-frame-pointer)
  target_link_options(test_c PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME test_c COMMAND test_c)

# --- the Python side ---
# Each test reads generated/, so generation is a ctest fixture rather than
# something each test re-does or each runner has to know to sequence.
add_test(NAME generate
         COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/generate.py)
set_tests_properties(generate PROPERTIES FIXTURES_SETUP navlink_gen)

set(PY_TESTS test_codec test_xfer_loopback test_fs_nav_loopback)
foreach(t ${PY_TESTS})
  add_test(NAME ${t}
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/${t}.py)
  set_tests_properties(${t} PROPERTIES FIXTURES_REQUIRED navlink_gen)
endforeach()

# The full 7-step run: regeneration, the C compile, and the C<->Python parity
# checks over CRC_EXTRA and wire size that no single test above covers.
add_test(NAME pipeline
         COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.py)

# A target per test name so an orchestrator's "build just this case" resolves.
# The Python tests have nothing to compile; their build is the generation.
foreach(t ${PY_TESTS} generate pipeline)
  add_custom_target(${t}_build DEPENDS navlink_codec)
endforeach()
