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


"""The Python parser's secured-frame hook, the same cases as tests/test_parser_sec.c:
only IFLAG_ENCRYPTED is routed, no hook = rejected as before, the tag replaces the
CRC, a rejection rescans, and accept_unsecured gates unsecured frames only."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "generated", "python"))
sys.path.insert(0, os.path.join(ROOT, "sec"))
import navlink_msgs as nl  # noqa: E402
import navlink_sec as s  # noqa: E402

KEY = bytes(range(1, 33))
GCS_TO_FC = 1


def hello(first):
    return nl.HsHello(gcs_nonce=bytes([first]) + bytes(15))


def secured(tx, first):
    m = hello(first)
    return tx.seal(1, 1, 1, m.MSGID, m.pack())


class Rig:
    def __init__(self, hook=True, accept=None):
        self.seen, self.flags, self.opens = [], [], 0
        self.rx = s.Rx(KEY, GCS_TO_FC)
        self.accept = accept
        h = nl.Handlers(on_hs_hello=self._on)
        if hook:
            h.secure_open = self._open
        if accept is not None:
            h.accept_unsecured = lambda f: self.accept
        self.p = nl.Parser(h)

    def _on(self, f, m):
        self.seen.append(m.gcs_nonce[0])
        self.flags.append(f.incompat_flags)

    def _open(self, frame):
        self.opens += 1
        try:
            return self.rx.open(frame)[1]
        except s.SecError:
            return None


class SecureParser(unittest.TestCase):
    def test_no_hook_rejects_encrypted(self):
        r = Rig(hook=False)
        r.p.push(secured(s.Tx(KEY, GCS_TO_FC), 9))
        self.assertEqual(r.seen, [])
        r.p.push(nl.encode(hello(5)))
        self.assertEqual(r.seen, [5])

    def test_routed_and_bytewise(self):
        tx = s.Tx(KEY, GCS_TO_FC)
        r = Rig()
        r.p.push(secured(tx, 0x42))
        self.assertEqual((r.seen, r.flags), ([0x42], [nl.IFLAG_ENCRYPTED]))
        f = secured(tx, 0x43)
        for b in f[:-1]:
            r.p.push(bytes([b]))
        self.assertEqual((r.seen, r.opens), ([0x42], 1))
        r.p.push(f[-1:])
        self.assertEqual(r.seen, [0x42, 0x43])

    def test_other_bits_never_routed(self):
        f = bytearray(secured(s.Tx(KEY, GCS_TO_FC), 1))
        for bad in (0x01, 0x03, 0x06, 0x12, 0x82, 0x10, 0x80):
            g = bytearray(f)
            g[3] = bad
            r = Rig()
            r.p.push(bytes(g))
            self.assertEqual((r.seen, r.opens), ([], 0), hex(bad))

    def test_bad_bit_rejected_at_header(self):
        plain = nl.encode(hello(0x33))
        for bad in (0x12, 0x03, 0x82):
            hdr = bytes([0x56, 0x02, 16, bad, 0, 0, 0, 6, 0, 0])
            r = Rig()
            r.p.push(hdr + plain)       # 38 bytes, short of a 48-byte claim
            self.assertEqual((r.seen, r.opens), ([0x33], 0), hex(bad))

    def test_reject_rescans_and_bad_length(self):
        plain = nl.encode(hello(0x55))
        hdr = bytes([0x56, 0x02, 16, nl.IFLAG_ENCRYPTED, 0, 0, 0, 6, 0, 0])
        span = (hdr + plain).ljust(48, b"\0")
        r = Rig()
        r.p.push(span)
        self.assertEqual((r.seen, r.opens), ([0x55], 1))
        # a hook returning the wrong plaintext length drops the frame
        r = Rig()
        r.p.h.secure_open = lambda frame: b"abc"
        r.p.push(secured(s.Tx(KEY, GCS_TO_FC), 1))
        self.assertEqual(r.seen, [])

    def test_max_frame(self):
        hdr = bytes([0x56, 0x02, 255, nl.IFLAG_ENCRYPTED, 0, 0, 0, 6, 0, 0])
        frame = hdr + bytes(255 + 22)
        self.assertEqual(len(frame), nl.MAX_FRAME)
        r = Rig()
        r.p.h.secure_open = lambda f: bytes([0x77]) + bytes(254)
        r.p.push(frame)
        self.assertEqual(r.seen, [0x77])
        r = Rig()
        r.p.h.secure_open = lambda f: bytes(255)
        r.p.push(frame[:-1])
        self.assertEqual(r.seen, [])

    def test_unknown_msgid_authentic_consumed(self):
        tx = s.Tx(KEY, GCS_TO_FC)
        r = Rig()
        r.p.push(tx.seal(1, 1, 1, 0xFFFF00, b"\x01\x02\x03\x04"))
        self.assertEqual((r.seen, r.opens), ([], 1))

    def test_accept_unsecured(self):
        r = Rig(accept=False)
        r.p.push(nl.encode(hello(7)))
        self.assertEqual(r.seen, [])
        r.accept = True
        r.p.push(nl.encode(hello(7)))
        self.assertEqual(r.seen, [7])
        r.accept = False
        r.p.push(secured(s.Tx(KEY, GCS_TO_FC), 8))   # not subject to it
        self.assertEqual(r.seen, [7, 8])

    def test_real_aead_failures(self):
        tx = s.Tx(KEY, GCS_TO_FC)
        r = Rig()
        f = secured(tx, 0x10)
        r.p.push(f)
        r.p.push(f)                                  # replay
        self.assertEqual(r.seen, [0x10])
        g = secured(tx, 0x11)
        for pos in (len(g) - 1, 10, 4):              # tag, ciphertext, header (AAD)
            t = bytearray(g)
            t[pos] ^= 1
            r.p.push(bytes(t))
        self.assertEqual(r.seen, [0x10])
        r.p.push(g)                                  # the untouched one still opens
        self.assertEqual(r.seen, [0x10, 0x11])


if __name__ == "__main__":
    unittest.main()
