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


"""Python side of the handshake (navlink-v2-spec.md section 11.9), written
against hashlib and the Tx/Rx of navlink_sec.py, not against the C code."""
import hashlib
import struct

import navlink_sec as sec

HELLO_LEN = 16
REPLY_LEN = 52
PENDING_S = 5.0
GCS_RESYNC_S = 3.0
HELLO_MIN_GAP_S = 1.0       # the HELLO budget refills one per this long
HELLO_BURST = 4             # HELLOs accepted back to back
PENDING_SLOTS = 4           # unconfirmed sessions kept at once
NONCE_RING = 8


class HsError(Exception):
    pass


def reply_mac(k, nonce, boot, hs, uid):
    msg = b"navlink-hs-reply" + nonce + struct.pack("<II", boot, hs) + uid
    return hashlib.blake2b(msg, digest_size=16, key=k).digest()


def make_reply(k, nonce, boot, hs, uid):
    return nonce + struct.pack("<II", boot, hs) + uid + reply_mac(k, nonce, boot, hs, uid)


def _session(k, fc_side, nonce, boot, hs, uid):
    to_fc = sec.derive(k, sec.DIR_GCS_TO_FC, nonce, boot, hs, uid)
    to_gcs = sec.derive(k, sec.DIR_FC_TO_GCS, nonce, boot, hs, uid)
    if fc_side:
        return sec.Tx(to_gcs, sec.DIR_FC_TO_GCS), sec.Rx(to_fc, sec.DIR_GCS_TO_FC)
    return sec.Tx(to_fc, sec.DIR_GCS_TO_FC), sec.Rx(to_gcs, sec.DIR_FC_TO_GCS)


class Gcs:
    def __init__(self, k):
        self.k, self.nonce, self.expect_uid = k, None, None
        self.live, self.next = None, None
        self.switched_at, self.fc_verified = None, False

    def hello(self, nonce, expect_uid=None):
        assert len(nonce) == 16
        self.nonce, self.expect_uid = nonce, expect_uid
        return nonce

    def take_reply(self, reply):
        """Returns {uid, boot, hs}. With an expected uid, another vehicle's
        authentic reply raises HsError('uid') carrying the info, and is not taken."""
        if len(reply) != REPLY_LEN or self.nonce is None:
            raise HsError("reply")
        boot, hs = struct.unpack("<II", reply[16:24])
        uid = reply[24:36]
        if reply[:16] != self.nonce or reply_mac(self.k, self.nonce, boot, hs, uid) != reply[36:]:
            raise HsError("reply")
        info = {"uid": uid, "boot": boot, "hs": hs}
        if self.expect_uid is not None and uid != self.expect_uid:
            e = HsError("uid")
            e.info = info
            raise e
        self.nonce = None
        self.next = _session(self.k, False, reply[:16], boot, hs, uid)
        return info

    def seal(self, now, seq, sysid, compid, msgid, payload):
        if self.next:
            self.live, self.next = self.next, None
            self.switched_at, self.fc_verified = now, False
        if not self.live:
            raise HsError("nosession")
        return self.live[0].seal(seq, sysid, compid, msgid, payload)

    def open(self, frame):
        if not self.live:
            raise HsError("nosession")
        r = self.live[1].open(frame)
        self.fc_verified = True
        return r

    def needs_hello(self, now):
        return (self.switched_at is not None and not self.fc_verified
                and now - self.switched_at >= GCS_RESYNC_S)


class _Pending:
    __slots__ = ("session", "since", "peer")

    def __init__(self, session, now, peer):
        self.session, self.since, self.peer = session, now, peer


class Fc:
    def __init__(self, k, uid, boot):
        if boot in (0, 0xFFFFFFFF):
            raise HsError("closed")
        self.k, self.uid, self.boot, self.hs = k, uid, boot, 0
        self.live = None
        self.slots = [None] * PENDING_SLOTS     # unconfirmed sessions, one per HELLO
        self.budget = HELLO_BURST * HELLO_MIN_GAP_S
        self.budget_at = None
        self.ring = []
        self.closed = False

    @property
    def pending(self):
        """The unconfirmed sessions (a list, empty when there are none)."""
        return [p for p in self.slots if p is not None]

    def tick(self, now):
        self.slots = [None if p is not None and now - p.since >= PENDING_S else p
                      for p in self.slots]

    def _budget(self, now):
        cap = HELLO_BURST * HELLO_MIN_GAP_S
        if self.budget_at is not None:
            self.budget = min(cap, self.budget + (now - self.budget_at))
        self.budget_at = now
        return self.budget

    def hello(self, now, nonce, peer=0):
        """peer: the transport's id of the sender (non-zero), or 0 for unknown. A
        known peer holds one slot and may send one HELLO per second; the budget itself is
        shared by all senders."""
        if self.closed or self.hs == 0xFFFFFFFF:
            self.closed = True
            raise HsError("closed")
        self.tick(now)
        slot = None
        if peer:
            for i, p in enumerate(self.slots):
                if p is not None and p.peer == peer:
                    if now - p.since < HELLO_MIN_GAP_S:
                        raise HsError("rate")
                    slot = i
        if self._budget(now) < HELLO_MIN_GAP_S:
            raise HsError("rate")
        if nonce in self.ring:
            raise HsError("repeat")
        if slot is None:                          # a free slot, else the oldest
            oldest = None
            for i, p in enumerate(self.slots):
                if p is None:
                    slot = i
                    break
                if slot is None or now - p.since > oldest:
                    slot, oldest = i, now - p.since
        self.budget -= HELLO_MIN_GAP_S
        self.hs += 1
        self.ring = (self.ring + [nonce])[-NONCE_RING:]
        self.slots[slot] = _Pending(
            _session(self.k, True, nonce, self.boot, self.hs, self.uid), now, peer)
        return make_reply(self.k, nonce, self.boot, self.hs, self.uid)

    def open(self, now, frame):
        self.tick(now)
        err = None
        if self.live:
            try:
                return self.live[1].open(frame)
            except sec.SecError as e:
                err = e
        for i, p in enumerate(self.slots):
            if p is None:
                continue
            try:
                r = p.session[1].open(frame)
            except sec.SecError as e:
                err = err or e
            else:
                self.live, self.slots[i] = p.session, None
                return r
        raise err or HsError("nosession")

    def seal(self, seq, sysid, compid, msgid, payload):
        if not self.live:
            raise HsError("nosession")
        return self.live[0].seal(seq, sysid, compid, msgid, payload)
