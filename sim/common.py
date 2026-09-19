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

"""Shared bootstrap for the NavLink simulator: locate (and if needed generate)
the Python codec, and import it once."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                       # navlink/
GEN_PY = os.path.join(ROOT, "generated", "python")


def load_nl():
    """Import the generated navlink_msgs module, regenerating it if absent."""
    if not os.path.exists(os.path.join(GEN_PY, "navlink_msgs.py")):
        subprocess.run([sys.executable, os.path.join(ROOT, "generate.py")], check=True)
    if GEN_PY not in sys.path:
        sys.path.insert(0, GEN_PY)
    import navlink_msgs
    return navlink_msgs
