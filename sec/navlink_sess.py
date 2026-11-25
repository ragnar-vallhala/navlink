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
HELLO_MIN_GAP_S = 1.0
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
        self.k, self.nonce, self.live, self.next = k, None, None, None

    def hello(self, nonce):
        assert len(nonce) == 16
        self.nonce = nonce
        return nonce

    def take_reply(self, reply):
        if len(reply) != REPLY_LEN or self.nonce is None:
            raise HsError("reply")
        boot, hs = struct.unpack("<II", reply[16:24])
        uid = reply[24:36]
        if reply[:16] != self.nonce or reply_mac(self.k, self.nonce, boot, hs, uid) != reply[36:]:
            raise HsError("reply")
        self.nonce = None
        self.next = _session(self.k, False, reply[:16], boot, hs, uid)

    def seal(self, seq, sysid, compid, msgid, payload):
        if self.next:
            self.live, self.next = self.next, None
        if not self.live:
            raise HsError("nosession")
        return self.live[0].seal(seq, sysid, compid, msgid, payload)

    def open(self, frame):
        if not self.live:
            raise HsError("nosession")
        return self.live[1].open(frame)


class Fc:
    def __init__(self, k, uid, boot):
        if boot in (0, 0xFFFFFFFF):
            raise HsError("closed")
        self.k, self.uid, self.boot, self.hs = k, uid, boot, 0
        self.live = self.pending = None
        self.pending_t = 0.0
        self.last_hello = None
        self.ring = []
        self.closed = False

    def tick(self, now):
        if self.pending and now - self.pending_t >= PENDING_S:
            self.pending = None

    def hello(self, now, nonce):
        if self.closed or self.hs == 0xFFFFFFFF:
            self.closed = True
            raise HsError("closed")
        if self.last_hello is not None and now - self.last_hello < HELLO_MIN_GAP_S:
            raise HsError("rate")
        if nonce in self.ring:
            raise HsError("repeat")
        self.hs += 1
        self.last_hello = now
        self.ring = (self.ring + [nonce])[-NONCE_RING:]
        self.pending = _session(self.k, True, nonce, self.boot, self.hs, self.uid)
        self.pending_t = now
        return make_reply(self.k, nonce, self.boot, self.hs, self.uid)

    def open(self, now, frame):
        self.tick(now)
        err = None
        if self.live:
            try:
                return self.live[1].open(frame)
            except sec.SecError as e:
                err = e
        if self.pending:
            try:
                r = self.pending[1].open(frame)
            except sec.SecError as e:
                err = err or e
            else:
                self.live, self.pending = self.pending, None
                return r
        raise err or HsError("nosession")

    def seal(self, seq, sysid, compid, msgid, payload):
        if not self.live:
            raise HsError("nosession")
        return self.live[0].seal(seq, sysid, compid, msgid, payload)
