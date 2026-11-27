#!/usr/bin/env python3
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


"""Python side of the secured-frame tests: the independent codec in
sec/navlink_sec.py must produce the same bytes as the C code (the golden frame
in tests/test_sec.c) and refuse the same things."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sec"))
import navlink_sec as s  # noqa: E402

GOLD_KS = "e39d895c3b4c260f29a2a8669b62e32f34c42f0ab83d07db569fbfd0b4f3b4a0"
GOLD_FRAME = ("56020d020501010201008233895a406a47cbe3b3bd40a6000000000000b761956991c4ee47"
              "3ec698a19a5f819e")
GOLD_KEY_ID = 385178778

k = bytes(range(32))
nonce = bytes(range(16))
uid = bytes(range(12))


def expect_error(fn, what):
    try:
        fn()
    except s.SecError as e:
        assert str(e) == what, (str(e), what)
        return
    raise AssertionError("no error, wanted " + what)


def test_golden():
    ks = s.derive(k, s.DIR_GCS_TO_FC, nonce, 7, 3, uid)
    assert ks.hex() == GOLD_KS
    assert s.key_id(k) == GOLD_KEY_ID
    tx = s.Tx(ks, s.DIR_GCS_TO_FC)
    f = tx.seal(5, 1, 1, 0x102, b"hello navlink")
    assert f.hex() == GOLD_FRAME
    hdr, pt = s.Rx(ks, s.DIR_GCS_TO_FC).open(bytes.fromhex(GOLD_FRAME))
    assert pt == b"hello navlink" and hdr["msgid"] == 0x102 and hdr["seq"] == 5


def test_failures():
    ks = s.derive(k, s.DIR_GCS_TO_FC, nonce, 7, 3, uid)
    tx = s.Tx(ks, s.DIR_GCS_TO_FC)
    f = tx.seal(5, 1, 1, 0x102, b"hello navlink")
    for bit in range(len(f) * 8):
        g = bytearray(f)
        g[bit // 8] ^= 1 << (bit % 8)
        rx = s.Rx(ks, s.DIR_GCS_TO_FC)
        try:
            rx.open(bytes(g))
        except s.SecError:
            assert not rx.have
            continue
        raise AssertionError("bit %d accepted" % bit)
    rx = s.Rx(ks, s.DIR_GCS_TO_FC)
    rx.open(f)
    expect_error(lambda: rx.open(f), "counter")
    expect_error(lambda: s.Rx(ks, s.DIR_FC_TO_GCS).open(f), "tag")
    expect_error(lambda: s.Rx(bytes(32), s.DIR_GCS_TO_FC).open(f), "tag")
    g = bytearray(f)
    g[3] = 0
    expect_error(lambda: s.Rx(ks, s.DIR_GCS_TO_FC).open(bytes(g)), "format")
    expect_error(lambda: s.Rx(ks, s.DIR_GCS_TO_FC).open(f[:-1]), "size")
    # reorder
    tx = s.Tx(ks, s.DIR_GCS_TO_FC)
    fr = [tx.seal(i, 1, 1, 7, b"x") for i in range(3)]
    rx = s.Rx(ks, s.DIR_GCS_TO_FC)
    rx.open(fr[2])
    rx.open(fr[1])                                       # inside the window: taken once
    expect_error(lambda: rx.open(fr[1]), "counter")      # a replay
    expect_error(lambda: rx.open(fr[2]), "counter")
    rx.open(fr[0])
    expect_error(lambda: rx.open(fr[0]), "counter")
    # the window ends REPLAY_WINDOW below the highest counter
    W = s.REPLAY_WINDOW
    tx = s.Tx(ks, s.DIR_GCS_TO_FC)
    fw = [tx.seal(i & 0xFF, 1, 1, 7, b"x") for i in range(W + 2)]
    rx = s.Rx(ks, s.DIR_GCS_TO_FC)
    rx.open(fw[W + 1])
    rx.open(fw[2])                                       # W - 1 below: taken
    expect_error(lambda: rx.open(fw[1]), "counter")      # W below: outside
    expect_error(lambda: rx.open(fw[0]), "counter")
    # a jump of 64+ forgets the map
    tx = s.Tx(ks, s.DIR_GCS_TO_FC)
    fj = [tx.seal(i & 0xFF, 1, 1, 7, b"x") for i in range(70)]
    rx = s.Rx(ks, s.DIR_GCS_TO_FC)
    rx.open(fj[3])
    rx.open(fj[69])
    expect_error(lambda: rx.open(fj[3]), "counter")
    rx.open(fj[68])
    expect_error(lambda: rx.open(fj[68]), "counter")
    # a forged frame inside the window does not mark its counter as seen
    tx = s.Tx(ks, s.DIR_GCS_TO_FC)
    f3 = [tx.seal(i, 1, 1, 7, b"x") for i in range(3)]
    rx = s.Rx(ks, s.DIR_GCS_TO_FC)
    rx.open(f3[2])
    bad = bytearray(f3[1])
    bad[-1] ^= 1
    expect_error(lambda: rx.open(bytes(bad)), "tag")
    rx.open(f3[1])
    # counter max closes, never wraps
    tx.counter = s.COUNTER_MAX - 1
    tx.seal(0, 1, 1, 7, b"x")
    expect_error(lambda: tx.seal(0, 1, 1, 7, b"x"), "closed")


def test_keys_differ():
    a = s.derive(k, 1, nonce, 7, 1, uid)
    assert a != s.derive(k, 1, nonce, 7, 2, uid)   # same HELLO, next handshake
    assert a != s.derive(k, 1, nonce, 8, 1, uid)   # next boot
    assert a != s.derive(k, 0, nonce, 7, 1, uid)   # other direction


def test_full_frame():
    ks = s.derive(k, 0, nonce, 1, 1, uid)
    f = s.Tx(ks, 0).seal(9, 1, 1, 0xABCDEF, bytes([0x5A]) * 255)
    assert len(f) == 287
    hdr, pt = s.Rx(ks, 0).open(f)
    assert hdr["msgid"] == 0xABCDEF and len(pt) == 255


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
    print("test_sec.py: ok")
