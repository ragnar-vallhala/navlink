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
"""Parameter catalog (params.json): validator failures, raw words, CRC, wire fields."""
import copy
import json
import math
import os
import struct
import sys
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "generated", "python"))

import catalog  # noqa: E402

if not os.path.exists(os.path.join(ROOT, "generated", "python", "navlink_msgs.py")):
    os.system(f"{sys.executable} {os.path.join(ROOT, 'generate.py')} >/dev/null")
import navlink_msgs as nl  # noqa: E402

with open(os.path.join(ROOT, "params.json")) as fh:
    REAL = json.load(fh)


def entry(**kw):
    e = {"id": "T_X", "type": "F32", "min": 0.0, "max": 1.0, "default": 0.5,
         "flags": [], "group": 0, "doc": "d", "range_why": "w"}
    e.update(kw)
    return e


def cat(*entries, groups=None):
    return {"catalog": 1, "groups": groups or {}, "params": list(entries)}


def errs(*entries, groups=None):
    return catalog.validate_params(cat(*entries, groups=groups))


class TestShippedCatalog(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(catalog.validate_params(REAL), [])

    def test_every_entry_justifies_its_range(self):
        for p in REAL["params"]:
            self.assertTrue(p["range_why"].strip(), p["id"])

    def test_crc_entry_is_first_and_holds_the_table_crc(self):
        r = catalog.resolved(REAL)
        self.assertEqual(r["params"][0]["id"], "SYS_PTBL_CRC")
        self.assertEqual(r["params"][0]["default"], r["table_crc"])

    def test_crc_ignores_docs_and_units(self):
        a = catalog.table_crc(REAL)
        b = copy.deepcopy(REAL)
        b["params"][1]["doc"] = "changed"
        b["params"][1]["unit"] = "x"
        b["params"][1]["range_why"] = "changed"
        self.assertEqual(catalog.table_crc(b), a)

    def test_crc_covers_the_default(self):
        # a firmware that changes a default must not keep the same CRC
        a = catalog.table_crc(REAL)
        b = copy.deepcopy(REAL)
        e = b["params"][1]
        e["default"] = e["max"]
        self.assertNotEqual(catalog.table_crc(b), a)

    def test_crc_changes_with_range_type_flags_group_and_order(self):
        base = catalog.table_crc(REAL)
        for mutate in (
            lambda c: c["params"][1].__setitem__("max", 0.5),
            lambda c: c["params"][1].__setitem__("min", 0.0001) or c["params"][1].__setitem__("default", 0.5),
            lambda c: c["params"][1].__setitem__("flags", []),
            lambda c: c["params"][1].__setitem__("group", 2),
            lambda c: c["params"].reverse(),
        ):
            c = copy.deepcopy(REAL)
            mutate(c)
            self.assertNotEqual(catalog.table_crc(c), base)

    def test_crc_matches_a_hand_computation(self):
        c = cat(entry(id="A", type="U8", min=0, max=9, default=1, flags=["PERSISTED"]))
        blob = (b"A".ljust(16, b"\0") + bytes([1, 0x08, 0]) + b"\x00\0\0\0"
                + b"\x09\0\0\0" + b"\x01\0\0\0")
        self.assertEqual(catalog.table_crc(c), zlib.crc32(blob) & 0xFFFFFFFF)

    def test_c_table_text_matches_python(self):
        h, c = catalog.gen_c(REAL)
        r = catalog.resolved(REAL)
        self.assertIn(f"NAVLINK_PARAM_COUNT {len(r['params'])}u", h)
        self.assertIn(f"0x{r['table_crc']:08X}u", h)
        self.assertEqual(c.count("{ \""), len(r["params"]))


class TestRangesAreNotLoopOff(unittest.TestCase):
    def test_kp_minimum_cannot_turn_the_loop_off(self):
        for p in REAL["params"]:
            if p["id"].endswith("_KP"):
                self.assertGreaterEqual(p["min"], 0.25 * p["default"] * 0.999999, p["id"])
                self.assertGreater(p["min"], 0, p["id"])

    def test_gyro_lpf_is_below_16_hz_cutoff_time_constant(self):
        for p in REAL["params"]:
            if p["id"].startswith("GLPF_"):
                self.assertLessEqual(p["max"], 0.01, p["id"])


class TestRawWords(unittest.TestCase):
    def test_small_ints_are_zero_padded_not_sign_extended(self):
        self.assertEqual(catalog.raw4("I8", -1), b"\xff\0\0\0")
        self.assertEqual(catalog.raw_u32("I8", -1), 0xFF)
        self.assertEqual(catalog.raw_u32("U16", 0x1234), 0x1234)
        self.assertEqual(catalog.raw_u32("I16", -2), 0xFFFE)

    def test_f32_is_the_ieee_pattern(self):
        self.assertEqual(catalog.raw_u32("F32", 1.0), 0x3F800000)
        self.assertEqual(catalog.raw_u32("F32", -0.0), 0x80000000)

    def test_i32_min(self):
        self.assertEqual(catalog.raw_u32("I32", -2**31), 0x80000000)


class TestValidatorRejects(unittest.TestCase):
    def has(self, e, text):
        self.assertTrue(any(text in x for x in e), e)

    def test_ok(self):
        self.assertEqual(errs(entry()), [])

    def test_empty(self):
        self.has(catalog.validate_params(cat()), "no entries")

    def test_duplicate_id(self):
        self.has(errs(entry(), entry()), "duplicate")

    def test_id_too_long(self):
        self.has(errs(entry(id="A" * 17)), "17 characters")

    def test_id_exactly_16_ok(self):
        self.assertEqual(errs(entry(id="A" * 16)), [])

    def test_id_charset(self):
        for bad in ("lower", "1ABC", "A-B", "", "A B"):
            self.has(errs(entry(id=bad)), "id must match")

    def test_bad_type(self):
        self.has(errs(entry(type="F64")), "type")

    def test_min_above_max(self):
        self.has(errs(entry(min=2.0, max=1.0)), "above max")

    def test_default_outside(self):
        self.has(errs(entry(default=1.5)), "outside")
        self.has(errs(entry(default=-0.1)), "outside")

    def test_bounds_inclusive(self):
        self.assertEqual(errs(entry(default=0.0)), [])
        self.assertEqual(errs(entry(default=1.0)), [])

    def test_non_finite(self):
        for bad in (math.nan, math.inf, -math.inf):
            self.has(errs(entry(min=bad)), "finite")
            self.has(errs(entry(max=bad)), "finite")
            self.has(errs(entry(default=bad)), "finite")

    def test_f32_overflow(self):
        self.has(errs(entry(max=1e300, default=1.0)), "finite")

    def test_int_out_of_type(self):
        self.has(errs(entry(type="U8", min=0, max=256, default=1)), "U8")
        self.has(errs(entry(type="I8", min=-129, max=0, default=0)), "I8")

    def test_int_type_takes_no_float(self):
        self.has(errs(entry(type="U8", min=0, max=1, default=0.5)), "U8")

    def test_bool_is_not_a_number(self):
        self.has(errs(entry(type="U8", min=0, max=1, default=True)), "U8")

    def test_needs_doc_and_range_why(self):
        self.has(errs(entry(range_why="")), "range_why")
        self.has(errs(entry(doc=" ")), "doc")

    def test_unknown_flag(self):
        self.has(errs(entry(flags=["NOPE"])), "unknown flag")

    def test_undeclared_group(self):
        self.has(errs(entry(group=3)), "not declared")

    def test_group_id_range(self):
        g = {"0": {"name": "x", "doc": "d"}}
        self.has(errs(entry(), groups=g), "1..255")

    def test_group_without_member(self):
        g = {"1": {"name": "x", "doc": "d"}}
        self.has(errs(entry(), groups=g), "no member")

    def test_group_straddling_locked(self):
        g = {"1": {"name": "x", "doc": "d"}}
        e = errs(entry(id="A", group=1, flags=["LOCKED_WHEN_ARMED"]),
                 entry(id="B", group=1, flags=[]), groups=g)
        self.has(e, "mix LOCKED_WHEN_ARMED")

    def test_group_with_read_only_member(self):
        g = {"1": {"name": "x", "doc": "d"}}
        self.has(errs(entry(id="A", group=1, flags=["READ_ONLY"]), groups=g), "read-only")

    def test_crc_entry_shape(self):
        self.has(errs(entry(type="U32", min=0, max=5, default="@table_crc", flags=["READ_ONLY"])),
                 "spans")
        self.has(errs(entry(type="U32", min=0, max=0xFFFFFFFF, default="@table_crc")), "READ_ONLY")

    def test_too_many_entries(self):
        many = [entry(id=f"P{i}") for i in range(catalog.COUNT_MAX + 1)]
        self.has(catalog.validate_params(cat(*many)), "u16")


V = list(struct.pack("<f", 1.0)) + [0] * 4


class TestWire(unittest.TestCase):
    def test_capability_bit(self):
        self.assertEqual(int(nl.Capability.PARAMS), 8)

    def test_param_value_flags_are_an_extension(self):
        a = nl.ParamValue(param_id="X", value=V, type=9, index=0, count=1, generation=0)
        b = nl.ParamValue(param_id="X", value=V, type=9, index=0, count=1, generation=0, flags=3)
        self.assertEqual(nl.ParamValue.unpack(b.pack()).flags, 3)
        # a parser that predates the field still reads the base fields
        self.assertEqual(nl.ParamValue.unpack(a.pack()).flags, 0)

    def test_param_set_acks_and_defers(self):
        out = []
        h = nl.Handlers(send=out.append, sysid=1, compid=1,
                        on_param_set=lambda f, m: nl.CommandResult.DENIED)
        nl.Parser(h).push(nl.encode(nl.ParamSet(target_sys=0, target_comp=0, param_id="X", type=9, value=V, req_seq=7)))
        got = []
        nl.Parser(nl.Handlers(on_command_ack=lambda f, m: got.append(m))).push(out[0])
        self.assertEqual((got[0].command, got[0].req_seq, got[0].result),
                         (nl.ParamSet.MSGID, 7, nl.CommandResult.DENIED))

    def test_param_set_without_req_seq_still_sets(self):
        got = []
        h = nl.Handlers(send=lambda b: None, on_param_set=lambda f, m: got.append(m))
        # an old GCS never sends req_seq: the frame is shorter, the field reads 0
        nl.Parser(h).push(nl.encode(nl.ParamSet(target_sys=0, target_comp=0, param_id="X", type=9, value=V)))
        self.assertEqual(got[0].req_seq, 0)

    def test_param_commit_roundtrip(self):
        m = nl.CmdParamCommit(req_seq=3, op=1, group=4)
        r = nl.CmdParamCommit.unpack(m.pack())
        self.assertEqual((r.req_seq, r.op, r.group), (3, 1, 4))

    def test_param_commit_is_acked(self):
        out = []
        h = nl.Handlers(send=out.append, on_cmd_param_commit=lambda f, m: None)
        nl.Parser(h).push(nl.encode(nl.CmdParamCommit(req_seq=9, op=0, group=0)))
        self.assertEqual(len(out), 1)

    def test_notch_autoband_is_acked(self):
        out = []
        h = nl.Handlers(send=out.append, on_cmd_notch_autoband=lambda f, m: None)
        nl.Parser(h).push(nl.encode(nl.CmdNotchAutoband(req_seq=9)))
        self.assertEqual(len(out), 1)


if __name__ == "__main__":
    unittest.main()
