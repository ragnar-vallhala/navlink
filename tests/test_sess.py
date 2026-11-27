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


NOW = 0.0


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
    f = g.seal(t, 1, 1, 1, 7, PL)
    assert fc.open(t + 0.01, f)[1] == PL


def test_golden():
    fc, g = hs.Fc(k, uid, 7), hs.Gcs(k)
    r = fc.hello(0, g.hello(bytes(range(16))))
    assert r.hex() == GOLD_REPLY
    g.take_reply(r)
    assert g.seal(0.0, 1, 1, 1, 7, PL).hex() == GOLD_FRAME


def test_hello_during_live():
    fc, g = hs.Fc(k, uid, 7), hs.Gcs(k)
    connect(fc, g, 0, 1)
    fc.hello(2.0, nonce(0x66))
    for i in range(5):
        assert fc.open(2.1 + i, g.seal(NOW, 1, 1, 1, 7, PL))[1] == PL
        assert g.open(fc.seal(1, 1, 1, 7, PL))[1] == PL
    try:
        fc.open(2.2, b"\x55" * 40)
        raise AssertionError("garbage accepted")
    except sec.SecError:
        pass
    assert fc.pending and fc.live
    fc.tick(2.0 + hs.PENDING_S)
    assert not fc.pending and fc.live
    assert fc.open(8.0, g.seal(NOW, 1, 1, 1, 7, PL))[1] == PL


def test_promotion():
    fc, g1, g2 = hs.Fc(k, uid, 7), hs.Gcs(k), hs.Gcs(k)
    connect(fc, g1, 0, 1)
    f1 = g1.seal(NOW, 1, 1, 1, 7, PL)
    g2.take_reply(fc.hello(3.0, g2.hello(nonce(2))))
    assert fc.open(3.1, f1)[1] == PL
    assert fc.open(3.2, g2.seal(NOW, 1, 1, 1, 7, PL))[1] == PL
    try:
        fc.open(3.3, g1.seal(NOW, 1, 1, 1, 7, PL))
        raise AssertionError("old session accepted")
    except sec.SecError:
        pass
    assert g2.open(fc.seal(1, 1, 1, 7, PL))[1] == PL


def test_rate_repeat_ring():
    fc = hs.Fc(k, uid, 7)
    for v in range(1, 1 + hs.HELLO_BURST):               # a burst is taken
        fc.hello(5.0, nonce(v))
    err(lambda: fc.hello(5.0, nonce(9)), "rate")
    err(lambda: fc.hello(5.999, nonce(9)), "rate")
    fc.hello(6.0, nonce(9))                              # one per second refills
    err(lambda: fc.hello(7.0, nonce(9)), "repeat")       # and a repeat costs nothing
    fc.hello(7.0, nonce(10))
    t = 7.0
    for v in range(11, 11 + hs.NONCE_RING):
        t += 1.0
        fc.hello(t, nonce(v))
    fc.hello(t + 1.0, nonce(1))                          # it has left the ring


def test_flood_does_not_starve_connect():
    """Todo 71 (4): a keyless sender's HELLOs, one inside the real HELLO's second and
    some before the real first frame, do not stop the connect."""
    fc, g = hs.Fc(k, uid, 7), hs.Gcs(k)
    for i in range(4):
        fc.hello(float(i), nonce(0x40 + i))
    g.take_reply(fc.hello(3.5, g.hello(nonce(1))))
    fc.hello(3.6, nonce(0x60))
    fc.hello(3.601, nonce(0x61))
    err(lambda: fc.hello(3.602, nonce(0x62)), "rate")
    assert fc.open(3.7, g.seal(NOW, 1, 1, 1, 7, PL))[1] == PL and fc.live


def test_peer_slots():
    fc = hs.Fc(k, uid, 7)
    fc.hello(0.0, nonce(1), peer=77)
    err(lambda: fc.hello(0.5, nonce(2), peer=77), "rate")   # its own 1/s
    fc.hello(1.0, nonce(2), peer=77)
    assert len(fc.pending) == 1                             # replaced its own slot
    for p in (1, 2, 3):
        fc.hello(1.0, nonce(10 + p), peer=p)
    assert len(fc.pending) == hs.PENDING_SLOTS
    fc.hello(2.0, nonce(50), peer=99)                       # evicts the oldest
    assert sorted(p.peer for p in fc.pending) == [1, 2, 3, 99]
    fc.tick(2.0 + hs.PENDING_S)
    assert not fc.pending


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


def test_lost_first_frame_and_recovery():
    fc, g = hs.Fc(k, uid, 7), hs.Gcs(k)
    assert not g.needs_hello(100.0)
    g.take_reply(fc.hello(0.0, g.hello(nonce(1))))
    g.seal(0.0, 1, 1, 1, 7, PL)                         # lost
    f2 = g.seal(1.0, 1, 1, 1, 7, PL)
    assert fc.open(1.1, f2)[1] == PL and fc.live and not fc.pending
    assert g.open(fc.seal(1, 1, 1, 7, PL))[1] == PL
    assert not g.needs_hello(60.0)
    # every GCS frame lost for more than 5 s
    g.take_reply(fc.hello(10.0, g.hello(nonce(2))))
    lost = [g.seal(10.0 + i, 1, 1, 1, 7, PL) for i in range(6)]
    try:
        fc.open(16.0, lost[-1])
        raise AssertionError("expired pending accepted")
    except sec.SecError:
        pass
    assert not fc.pending and fc.live
    try:
        g.open(fc.seal(1, 1, 1, 7, PL))
        raise AssertionError("old keys readable")
    except sec.SecError:
        pass
    assert not g.needs_hello(10.0 + hs.GCS_RESYNC_S - 0.001)
    assert g.needs_hello(10.0 + hs.GCS_RESYNC_S)
    g.take_reply(fc.hello(16.5, g.hello(nonce(3))))
    assert fc.open(16.6, g.seal(16.5, 1, 1, 1, 7, PL))[1] == PL
    assert g.open(fc.seal(1, 1, 1, 7, PL))[1] == PL
    assert not g.needs_hello(90.0)


def test_uid_reported_and_checked():
    uid2 = uid[:11] + bytes([uid[11] ^ 0x80])
    fc, other, g = hs.Fc(k, uid, 7), hs.Fc(k, uid2, 9), hs.Gcs(k)
    h = g.hello(nonce(1), uid)
    r_other, r_ours = other.hello(0.0, h), fc.hello(0.0, h)
    try:
        g.take_reply(r_other)
        raise AssertionError("other vehicle taken")
    except hs.HsError as e:
        assert str(e) == "uid" and e.info["uid"] == uid2 and e.info["boot"] == 9
    assert g.next is None and g.nonce is not None
    info = g.take_reply(r_ours)
    assert info == {"uid": uid, "boot": 7, "hs": 1} and g.next
    g.hello(nonce(1))
    assert g.take_reply(r_other)["uid"] == uid2


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
