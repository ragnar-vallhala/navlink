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


"""Python codec for the secured frame (navlink-v2-spec.md section 11).

Written independently of the C code and of Monocypher: the cipher is the
`cryptography` package's ChaCha20-Poly1305 (RFC 8439) and the hash is
hashlib.blake2b. tests/test_sec.py checks that its bytes equal the C bytes."""
import hashlib
import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

TAG_LEN = 16
HEADER_LEN = 10
TRAILER_LEN = 22
COUNTER_MAX = (1 << 48) - 1
IFLAG_ENCRYPTED = 0x02
DIR_FC_TO_GCS = 0
DIR_GCS_TO_FC = 1


class SecError(Exception):
    pass


def derive(k, direction, gcs_nonce, fc_boot_ctr, fc_hs_ctr, uid):
    msg = (b"navlink-session" + bytes([direction]) + gcs_nonce +
           struct.pack("<II", fc_boot_ctr, fc_hs_ctr) + uid)
    return hashlib.blake2b(msg, digest_size=32, key=k).digest()


def key_id(k):
    return struct.unpack("<I", hashlib.blake2b(b"navlink-key-id", digest_size=32,
                                               key=k).digest()[:4])[0]


def _nonce(counter, seq, sysid, compid):
    return counter.to_bytes(6, "little") + bytes([seq, sysid, compid, 0, 0, 0])


def _header(payload_len, seq, sysid, compid, msgid):
    return bytes([0x56, 0x02, payload_len, IFLAG_ENCRYPTED, seq, sysid, compid,
                  msgid & 0xFF, (msgid >> 8) & 0xFF, (msgid >> 16) & 0xFF])


class Tx:
    def __init__(self, key, direction):
        self.key, self.dir, self.counter = key, direction, 0

    def seal(self, seq, sysid, compid, msgid, payload):
        if self.counter >= COUNTER_MAX:
            raise SecError("closed")
        hdr = _header(len(payload), seq, sysid, compid, msgid)
        aad = hdr[1:10] + bytes([TAG_LEN, self.dir])
        ct = ChaCha20Poly1305(self.key).encrypt(
            _nonce(self.counter, seq, sysid, compid), payload, aad)
        # library returns ciphertext || tag
        frame = hdr + ct[:-TAG_LEN] + self.counter.to_bytes(6, "little") + ct[-TAG_LEN:]
        self.counter += 1
        return frame


class Rx:
    def __init__(self, key, direction):
        self.key, self.dir, self.last, self.have = key, direction, 0, False

    def open(self, frame):
        if len(frame) < HEADER_LEN + TRAILER_LEN:
            raise SecError("size")
        if frame[0] != 0x56 or frame[1] != 0x02 or frame[3] != IFLAG_ENCRYPTED:
            raise SecError("format")
        plen = frame[2]
        if len(frame) != HEADER_LEN + plen + TRAILER_LEN:
            raise SecError("size")
        ct = frame[HEADER_LEN:HEADER_LEN + plen]
        counter = int.from_bytes(frame[HEADER_LEN + plen:HEADER_LEN + plen + 6], "little")
        tag = frame[-TAG_LEN:]
        if self.have and counter <= self.last:
            raise SecError("counter")
        aad = frame[1:10] + bytes([TAG_LEN, self.dir])
        try:
            pt = ChaCha20Poly1305(self.key).decrypt(
                _nonce(counter, frame[4], frame[5], frame[6]), ct + tag, aad)
        except Exception:
            raise SecError("tag")
        self.last, self.have = counter, True
        return {"seq": frame[4], "sysid": frame[5], "compid": frame[6],
                "msgid": frame[7] | frame[8] << 8 | frame[9] << 16}, pt
