/* Copyright (C) 2026 NAVRobotec Pvt Ltd
 * Author: Ragnar Vallhala
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* navlink_sess: the handshake and the live/pending session slots of
 * navlink-v2-spec.md section 11.9, on top of navlink_sec.
 *
 * Pure: no clock, no heap, no I/O, no randomness. The caller supplies the time
 * (now_ms, any 32-bit millisecond counter; only differences are used) and, on
 * the ground-station side, the 16 random bytes of the HELLO. On the vehicle the
 * caller supplies fc_boot_ctr: it MUST have incremented the persisted counter and
 * read the new value back BEFORE calling navlink_fc_init (spec 11.9); this layer
 * cannot do that for it. A failure here changes nothing but a return value
 * (spec 11.10).
 *
 * Vehicle: one live session, one pending session. navlink_fc_hello() fills the
 * pending slot and never touches the live one. navlink_fc_open() promotes the
 * pending session, and drops the old live one, only when a frame verifies under
 * the pending keys. A pending session not confirmed within
 * NAVLINK_SESS_PENDING_MS is discarded. */
#ifndef NAVLINK_SESS_H
#define NAVLINK_SESS_H

#include "navlink_sec.h"

#define NAVLINK_HS_HELLO_LEN 16
#define NAVLINK_HS_REPLY_LEN 52 /* nonce 16, boot 4, hs 4, uid 12, mac 16 */
#define NAVLINK_HS_MAC_LEN 16

#define NAVLINK_SESS_PENDING_MS 5000u
#define NAVLINK_SESS_HELLO_MIN_GAP_MS 1000u
#define NAVLINK_SESS_NONCE_RING 8

#define NAVLINK_SESS_ERR_RATE (-10)    /* HELLO inside the 1/s limit: dropped */
#define NAVLINK_SESS_ERR_REPEAT (-11)  /* gcs_nonce seen recently: dropped */
#define NAVLINK_SESS_ERR_NOSESSION (-12)
#define NAVLINK_SESS_ERR_REPLY (-13)   /* reply does not authenticate */

/* Both directions of one session, seen from one side. */
typedef struct {
  navlink_sec_tx_t tx;
  navlink_sec_rx_t rx;
  uint8_t valid;
} navlink_session_t;

typedef struct {
  uint8_t k[NAVLINK_SEC_KEY_LEN];
  uint8_t uid[12];
  uint32_t boot_ctr;
  uint32_t hs_ctr; /* RAM; +1 per accepted HELLO */
  uint8_t closed;
  navlink_session_t live;
  navlink_session_t pending;
  uint32_t pending_since_ms;
  uint32_t last_hello_ms;
  uint8_t have_hello;
  uint8_t nonces[NAVLINK_SESS_NONCE_RING][16];
  uint8_t nonce_count;
  uint8_t nonce_next;
} navlink_fc_t;

typedef struct {
  uint8_t k[NAVLINK_SEC_KEY_LEN];
  uint8_t nonce[16];
  uint8_t waiting; /* a HELLO is out and no reply has been taken */
  navlink_session_t live;
  navlink_session_t next; /* derived, becomes live on the first frame we send */
} navlink_gcs_t;

/* ---- vehicle ---- */

/* boot_ctr must be a value just persisted and read back; 0 and 0xFFFFFFFF are
 * refused (what an unwritten or wrapped counter reads as). */
int navlink_fc_init(navlink_fc_t *fc, const uint8_t k[32], const uint8_t uid[12],
                    uint32_t boot_ctr);
void navlink_fc_wipe(navlink_fc_t *fc);

/* Handle a HELLO. On success writes NAVLINK_HS_REPLY_LEN bytes to reply, fills
 * the pending slot (replacing an earlier pending one) and returns the length.
 * Refused, with nothing changed: closed, inside the rate limit, repeated nonce,
 * hs_ctr exhausted. */
int navlink_fc_hello(navlink_fc_t *fc, uint32_t now_ms,
                     const uint8_t gcs_nonce[16], uint8_t *reply);

/* Open a frame from the ground station: live first, then pending (promoting it
 * on success). Returns the payload length or a negative code. */
int navlink_fc_open(navlink_fc_t *fc, uint32_t now_ms, const uint8_t *frame,
                    size_t len, navlink_sec_hdr_t *hdr, uint8_t *payload_out);

/* Seal a frame to the ground station under the live session. */
int navlink_fc_seal(navlink_fc_t *fc, uint8_t *out, size_t cap, uint8_t iflags,
                    const navlink_sec_hdr_t *hdr, const uint8_t *payload);

/* Drop an unconfirmed pending session that has timed out. */
void navlink_fc_tick(navlink_fc_t *fc, uint32_t now_ms);

/* ---- ground station ---- */

int navlink_gcs_init(navlink_gcs_t *g, const uint8_t k[32]);
void navlink_gcs_wipe(navlink_gcs_t *g);

/* Remember the 16 fresh random bytes the caller drew and write them to hello
 * (NAVLINK_HS_HELLO_LEN bytes) for sending. */
int navlink_gcs_hello(navlink_gcs_t *g, const uint8_t gcs_nonce[16],
                      uint8_t *hello);

/* Take the vehicle's reply. It must echo our nonce and carry the right mac;
 * otherwise nothing changes. On success the new session is held as `next`. A
 * second copy of the same reply is refused. */
int navlink_gcs_reply(navlink_gcs_t *g, const uint8_t *reply, size_t len);

/* Seal under the newest session; the first call after a reply makes the new
 * session live (this first frame is what promotes it on the vehicle). */
int navlink_gcs_seal(navlink_gcs_t *g, uint8_t *out, size_t cap, uint8_t iflags,
                     const navlink_sec_hdr_t *hdr, const uint8_t *payload);

int navlink_gcs_open(navlink_gcs_t *g, const uint8_t *frame, size_t len,
                     navlink_sec_hdr_t *hdr, uint8_t *payload_out);

#endif /* NAVLINK_SESS_H */
