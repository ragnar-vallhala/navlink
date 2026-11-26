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

"""The parameter catalog (params.json): load, validate, emit.

One catalog, three consumers. The firmware compiles the C table, the GCS reads the
resolved JSON (which also carries the display text), and the Python tools import
the module. All three come from the same params.json, so they cannot drift.

The flight controller stays the enforcer: the range here is the safety envelope
the firmware checks every PARAM_SET against, and the GCS uses it only to keep a
user from typing a value that would be refused.

Wire and table facts (spec 12.2):
  - id is at most 16 characters, [A-Z][A-Z0-9_]*, unique. PARAM_VALUE.index is the
    position in params.json, so the order is part of the contract: append only.
  - v1 types are 32 bits or less: U8 I8 U16 I16 U32 I32 F32.
  - min, max and default are stored as 4 raw bytes: the value in its own type,
    little-endian, zero-padded to 4 bytes (I8 -1 is FF 00 00 00; F32 is IEEE-754).
  - the range is a closed interval: a value equal to min or max is allowed.
  - the table CRC (CRC-32, as zlib) covers id, type, flags, group, min, max and
    default of every entry in order, except an entry whose default is "@table_crc"
    (the entry that reports the CRC cannot be part of it). The default is in it so
    that a firmware that changes a default is told apart by the GCS, whose
    "reset to default" would otherwise write the old value.
"""
from __future__ import annotations

import json
import math
import os
import re
import struct
import zlib

ID_MAX = 16
COUNT_MAX = 0xFFFF  # PARAM_VALUE.index / count are u16

# type name -> (PARAM_VALUE.type enum value, struct format, int min, int max)
TYPES = {
    "U8":  (1, "B", 0, 0xFF),
    "I8":  (2, "b", -0x80, 0x7F),
    "U16": (3, "H", 0, 0xFFFF),
    "I16": (4, "h", -0x8000, 0x7FFF),
    "U32": (5, "I", 0, 0xFFFFFFFF),
    "I32": (6, "i", -0x80000000, 0x7FFFFFFF),
    "F32": (9, "f", None, None),
}

# flags byte of a table entry
FLAGS = {
    "READ_ONLY":         0x01,  # the GCS cannot write it
    "LOCKED_WHEN_ARMED": 0x02,  # a write while armed is DENIED
    "REBOOT_REQUIRED":   0x04,  # takes effect after a reboot
    "PERSISTED":         0x08,  # saved by CMD_PARAM_COMMIT
}

TABLE_CRC_DEFAULT = "@table_crc"
ID_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def load_params(dialect_path):
    """The catalog next to the dialect, or None when there is none."""
    path = os.path.join(os.path.dirname(os.path.abspath(dialect_path)), "params.json")
    if not os.path.exists(path):
        return None
    with open(path) as fh:
        return json.load(fh)


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _num_ok(tname, v):
    """True if v is a finite number of the right kind for the type."""
    if isinstance(v, bool):
        return False
    if tname == "F32":
        if not isinstance(v, (int, float)) or not math.isfinite(v):
            return False
        # the value must survive the trip to a 32-bit float without turning into inf
        try:
            struct.pack("<f", v)
        except OverflowError:
            return False
        return True
    _, _, lo, hi = TYPES[tname]
    return _is_int(v) and lo <= v <= hi


def validate_params(pc):
    """Every rule that makes a catalog safe to generate from. Returns error strings."""
    errs = []
    groups = pc.get("groups", {})
    params = pc.get("params", [])
    if not isinstance(params, list) or not params:
        return ["params: the catalog has no entries"]
    if len(params) > COUNT_MAX:
        errs.append(f"params: {len(params)} entries, the u16 index allows {COUNT_MAX}")

    gids = {}
    for k, g in groups.items():
        if not (k.isdigit() and 1 <= int(k) <= 255):
            errs.append(f"group {k!r}: the id must be a number 1..255 (0 means ungrouped)")
            continue
        if not isinstance(g, dict) or not g.get("name") or not g.get("doc"):
            errs.append(f"group {k}: needs a name and a doc")
        gids[int(k)] = g

    seen = {}
    members = {}
    for i, p in enumerate(params):
        pid = p.get("id")
        where = f"param {pid!r}" if isinstance(pid, str) else f"param #{i}"
        if not isinstance(pid, str) or not ID_RE.match(pid):
            errs.append(f"{where}: id must match [A-Z][A-Z0-9_]*")
            continue
        if len(pid) > ID_MAX:
            errs.append(f"{where}: id is {len(pid)} characters, the wire carries {ID_MAX}")
        if pid in seen:
            errs.append(f"{where}: duplicate id (also entry #{seen[pid]})")
        seen[pid] = i

        t = p.get("type")
        if t not in TYPES:
            errs.append(f"{where}: type {t!r} is not one of {', '.join(TYPES)}")
            continue

        unknown_flags = [f for f in p.get("flags", []) if f not in FLAGS]
        if unknown_flags:
            errs.append(f"{where}: unknown flag(s) {unknown_flags}")
        flags = set(p.get("flags", []))

        g = p.get("group", 0)
        if not _is_int(g) or not (0 <= g <= 255):
            errs.append(f"{where}: group must be 0..255")
        elif g and g not in gids:
            errs.append(f"{where}: group {g} is not declared in groups")
        elif g:
            members.setdefault(g, []).append((pid, flags))

        for key in ("doc", "range_why"):
            if not isinstance(p.get(key), str) or not p[key].strip():
                errs.append(f"{where}: {key} is required (what it is / why this range)")

        dflt = p.get("default")
        lo, hi = p.get("min"), p.get("max")
        if dflt == TABLE_CRC_DEFAULT:
            if t != "U32" or "READ_ONLY" not in flags:
                errs.append(f"{where}: the {TABLE_CRC_DEFAULT} entry must be a READ_ONLY U32")
            if not (_num_ok(t, lo) and _num_ok(t, hi)) or lo != 0 or hi != 0xFFFFFFFF:
                errs.append(f"{where}: the {TABLE_CRC_DEFAULT} entry spans 0..4294967295")
            continue
        bad = False
        for name, v in (("min", lo), ("max", hi), ("default", dflt)):
            if not _num_ok(t, v):
                errs.append(f"{where}: {name} {v!r} is not a finite {t} value")
                bad = True
        if bad:
            continue
        if lo > hi:
            errs.append(f"{where}: min {lo} is above max {hi}")
        elif not (lo <= dflt <= hi):
            errs.append(f"{where}: default {dflt} is outside [{lo}, {hi}]")

    for g, ms in members.items():
        ro = [pid for pid, f in ms if "READ_ONLY" in f]
        if ro:
            errs.append(f"group {g}: read-only member(s) {ro}: a group is committed together, "
                        f"so every member must be writable")
        locked = {("LOCKED_WHEN_ARMED" in f) for _, f in ms}
        if len(locked) > 1:
            errs.append(f"group {g}: members mix LOCKED_WHEN_ARMED and not; a group commits as "
                        f"one unit, so it is locked as one unit")
    for g in gids:
        if g not in members:
            errs.append(f"group {g}: declared but has no member")
    return errs


def _fmt_for(t):
    return TYPES[t][1]


def raw4(t, v):
    """The value as 4 bytes: its own type, little-endian, zero-padded."""
    return struct.pack("<" + _fmt_for(t), v).ljust(4, b"\0")


def raw_u32(t, v):
    return struct.unpack("<I", raw4(t, v))[0]


def flags_byte(p):
    b = 0
    for f in p.get("flags", []):
        b |= FLAGS[f]
    return b


def table_crc(pc):
    """CRC-32 of id, type, flags, group, min, max, default of every entry (module doc)."""
    crc = 0
    for p in pc["params"]:
        if p["default"] == TABLE_CRC_DEFAULT:
            continue
        blob = p["id"].encode("ascii").ljust(ID_MAX, b"\0")
        blob += bytes([TYPES[p["type"]][0], flags_byte(p), p.get("group", 0)])
        blob += raw4(p["type"], p["min"]) + raw4(p["type"], p["max"])
        blob += raw4(p["type"], p["default"])
        crc = zlib.crc32(blob, crc)
    return crc & 0xFFFFFFFF


def resolved(pc):
    """The catalog with the table CRC filled in and the raw words added."""
    crc = table_crc(pc)
    out = {"catalog": pc.get("catalog", 1), "table_crc": crc, "groups": pc.get("groups", {}),
           "params": []}
    for i, p in enumerate(pc["params"]):
        q = dict(p)
        q["index"] = i
        q["group"] = p.get("group", 0)
        q["flags"] = list(p.get("flags", []))
        if p["default"] == TABLE_CRC_DEFAULT:
            q["default"] = crc
        q["type_id"] = TYPES[p["type"]][0]
        q["flags_byte"] = flags_byte(p)
        out["params"].append(q)
    return out


def gen_c(pc):
    """(header text, source text) for the firmware table."""
    r = resolved(pc)
    n = len(r["params"])
    h = []
    p = h.append
    p("/* GENERATED from params.json by catalog.py - DO NOT EDIT */")
    p("#ifndef NAVLINK_PARAMS_H")
    p("#define NAVLINK_PARAMS_H")
    p("#include <stdint.h>")
    p("")
    p("#ifdef __cplusplus")
    p('extern "C" {')
    p("#endif")
    p("")
    p("/* flags byte of a table entry */")
    for name, bit in FLAGS.items():
        p(f"#define NAVLINK_PARAM_F_{name} 0x{bit:02X}u")
    p("")
    p("/* The value of min, max and default: 4 raw bytes, the value in its own type, as a")
    p("   little-endian word (I8 -1 is 0x000000FF, F32 is the IEEE-754 bit pattern). */")
    p("typedef struct {")
    p("    char     id[16];      /* NUL-padded; all 16 bytes are used by a 16-character id */")
    p("    uint8_t  type;        /* PARAM_VALUE.type (navlink_param_type) */")
    p("    uint8_t  flags;       /* NAVLINK_PARAM_F_* */")
    p("    uint8_t  group;       /* 0 = ungrouped; else the catalog group (staged, committed together) */")
    p("    uint8_t  _pad;")
    p("    uint32_t min_raw;")
    p("    uint32_t max_raw;")
    p("    uint32_t def_raw;")
    p("} navlink_param_def_t;")
    p("")
    p(f"#define NAVLINK_PARAM_COUNT {n}u")
    p(f"#define NAVLINK_PARAMS_TABLE_CRC 0x{r['table_crc']:08X}u  /* the value of SYS_PTBL_CRC */")
    p("extern const navlink_param_def_t navlink_param_table[NAVLINK_PARAM_COUNT];")
    p("")
    p("/* Stable index of each parameter (PARAM_VALUE.index). */")
    for q in r["params"]:
        p(f"#define NAVLINK_PARAM_IDX_{q['id']} {q['index']}u")
    p("")
    p("#ifdef __cplusplus")
    p("}")
    p("#endif")
    p("#endif /* NAVLINK_PARAMS_H */")
    p("")

    c = []
    p = c.append
    p("/* GENERATED from params.json by catalog.py - DO NOT EDIT */")
    p('#include "navlink_params.h"')
    p("")
    p("const navlink_param_def_t navlink_param_table[NAVLINK_PARAM_COUNT] = {")
    for q in r["params"]:
        t = q["type"]
        ident = '"' + q["id"] + '"'
        p(f"    {{ {ident}, {q['type_id']}u, 0x{q['flags_byte']:02X}u, {q['group']}u, 0u, "
          f"0x{raw_u32(t, q['min']):08X}u, 0x{raw_u32(t, q['max']):08X}u, "
          f"0x{raw_u32(t, q['default']):08X}u }},  /* {q['index']} {t} */")
    p("};")
    p("")
    return "\n".join(h), "\n".join(c)


def gen_py(pc):
    r = resolved(pc)
    out = ["# GENERATED from params.json by catalog.py - DO NOT EDIT",
           '"""The parameter catalog (see catalog.py)."""',
           f"TABLE_CRC = 0x{r['table_crc']:08X}",
           f"COUNT = {len(r['params'])}",
           "GROUPS = " + repr({int(k): v for k, v in r["groups"].items()}),
           "PARAMS = " + repr(r["params"]),
           "BY_ID = {p['id']: p for p in PARAMS}",
           ""]
    return "\n".join(out)


def gen_json(pc):
    return json.dumps(resolved(pc), indent=2, sort_keys=False) + "\n"
