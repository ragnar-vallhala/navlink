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


"""Python side of the handshake tests: sec/navlink_sess.py must reproduce the
C golden reply and first frame, and refuse what the C code refuses."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sec"))
import navlink_sec as sec  # noqa: E402
import navlink_sess as hs  # noqa: E402

k = bytes(range(32))
uid = bytes(range(12))
PL = bytes([1, 2, 3, 4])
GOLD_REPLY = ("000102030405060708090a0b0c0d0e0f0700000001000000000102030405060708090a0b"
              "e9184bceca2b9c815b9651ca328d2774")
GOLD_FRAME = "56020402010101070000a55eda0400000000000082f8de702737e1001ef44bfc0c07d2a5"


def nonce(v):
    return bytes([v]) * 16


def err(fn, what, cls=hs.HsError):
    try:
        fn()
    except cls as e:
        assert str(e) == what, (str(e), what)
        return
    raise AssertionError("no error, wanted " + what)


def connect(fc, g, t, v):
    r = fc.hello(t, g.hello(nonce(v)))
    g.take_reply(r)
    f = g.seal(1, 1, 1, 7, PL)
    assert fc.open(t + 0.01, f)[1] == PL


def test_golden():
    fc, g = hs.Fc(k, uid, 7), hs.Gcs(k)
    r = fc.hello(0, g.hello(bytes(range(16))))
    assert r.hex() == GOLD_REPLY
    g.take_reply(r)
    assert g.seal(1, 1, 1, 7, PL).hex() == GOLD_FRAME


def test_hello_during_live():
    fc, g = hs.Fc(k, uid, 7), hs.Gcs(k)
    connect(fc, g, 0, 1)
    fc.hello(2.0, nonce(0x66))
    for i in range(5):
        assert fc.open(2.1 + i, g.seal(1, 1, 1, 7, PL))[1] == PL
        assert g.open(fc.seal(1, 1, 1, 7, PL))[1] == PL
    try:
        fc.open(2.2, b"\x55" * 40)
        raise AssertionError("garbage accepted")
    except sec.SecError:
        pass
    assert fc.pending and fc.live
    fc.tick(2.0 + hs.PENDING_S)
    assert fc.pending is None and fc.live
    assert fc.open(8.0, g.seal(1, 1, 1, 7, PL))[1] == PL


def test_promotion():
    fc, g1, g2 = hs.Fc(k, uid, 7), hs.Gcs(k), hs.Gcs(k)
    connect(fc, g1, 0, 1)
    f1 = g1.seal(1, 1, 1, 7, PL)
    g2.take_reply(fc.hello(3.0, g2.hello(nonce(2))))
    assert fc.open(3.1, f1)[1] == PL
    assert fc.open(3.2, g2.seal(1, 1, 1, 7, PL))[1] == PL
    try:
        fc.open(3.3, g1.seal(1, 1, 1, 7, PL))
        raise AssertionError("old session accepted")
    except sec.SecError:
        pass
    assert g2.open(fc.seal(1, 1, 1, 7, PL))[1] == PL


def test_rate_repeat_ring():
    fc = hs.Fc(k, uid, 7)
    fc.hello(5.0, nonce(1))
    err(lambda: fc.hello(5.999, nonce(2)), "rate")
    fc.hello(6.0, nonce(2))
    err(lambda: fc.hello(8.0, nonce(1)), "repeat")
    t = 8.0
    for v in range(3, 3 + hs.NONCE_RING):
        t += 1.0
        fc.hello(t, nonce(v))
    fc.hello(t + 1.0, nonce(1))  # it has left the ring


def test_reply_checks():
    fc, g = hs.Fc(k, uid, 7), hs.Gcs(k)
    r = fc.hello(0, g.hello(nonce(1)))
    for bit in range(len(r) * 8):
        bad = bytearray(r)
        bad[bit // 8] ^= 1 << (bit % 8)
        err(lambda: g.take_reply(bytes(bad)), "reply")
    err(lambda: g.take_reply(r[:-1]), "reply")
    g.take_reply(r)
    err(lambda: g.take_reply(r), "reply")        # one reply per HELLO
    g.hello(nonce(2))
    err(lambda: g.take_reply(r), "reply")        # reply to an older HELLO
    err(lambda: hs.Gcs(k).take_reply(r), "reply")  # never sent one
    g3 = hs.Gcs(bytes([1]) + k[1:])
    g3.hello(nonce(1))
    err(lambda: g3.take_reply(r), "reply")      # wrong K


def test_keys_and_exhaustion():
    a, b = hs.Fc(k, uid, 7), hs.Fc(k, uid, 8)
    ra, rb = a.hello(0, nonce(5)), b.hello(0, nonce(5))
    assert ra != rb
    err(lambda: hs.Fc(k, uid, 0), "closed")
    err(lambda: hs.Fc(k, uid, 0xFFFFFFFF), "closed")
    fc = hs.Fc(k, uid, 0xFFFFFFFE)
    fc.hs = 0xFFFFFFFE
    fc.hello(0, nonce(1))
    err(lambda: fc.hello(2.0, nonce(2)), "closed")
    err(lambda: fc.hello(9.0, nonce(3)), "closed")


def test_full_frame():
    fc, g = hs.Fc(k, uid, 7), hs.Gcs(k)
    connect(fc, g, 0, 1)
    f = fc.seal(1, 1, 1, 0xABCDEF, b"\x42" * 255)
    assert len(f) == 287 and g.open(f)[1] == b"\x42" * 255


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
    print("test_sess.py: ok")
