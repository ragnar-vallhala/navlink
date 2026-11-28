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
 * Vehicle: one live session, NAVLINK_SESS_PENDING_SLOTS pending sessions.
 * navlink_fc_hello() fills a pending slot and never touches the live one.
 * navlink_fc_open() promotes a pending session, and drops the old live one, only
 * when a frame verifies under that session's keys. A pending session not
 * confirmed within NAVLINK_SESS_PENDING_MS is discarded. */
#ifndef NAVLINK_SESS_H
#define NAVLINK_SESS_H

#include "navlink_sec.h"

#define NAVLINK_HS_HELLO_LEN 16
#define NAVLINK_HS_REPLY_LEN 52 /* nonce 16, boot 4, hs 4, uid 12, mac 16 */
#define NAVLINK_HS_MAC_LEN 16

#define NAVLINK_SESS_PENDING_MS 5000u
#define NAVLINK_SESS_HELLO_MIN_GAP_MS 1000u
#define NAVLINK_SESS_NONCE_RING 8
/* Unconfirmed sessions kept at once, so a keyless sender's HELLO cannot replace the
 * real ground station's before its first secured frame arrives. */
#define NAVLINK_SESS_PENDING_SLOTS 4
/* HELLOs accepted back to back; the budget refills at one per
 * NAVLINK_SESS_HELLO_MIN_GAP_MS. A sender at the plain 1/s rate (the old fixed
 * gap) can no longer starve a real HELLO that lands in the same second. */
#define NAVLINK_SESS_HELLO_BURST 4u
/* A reserve for the peer whose session is live (the sender that last proved it
 * holds the key, given with navlink_fc_hello_peer): its HELLOs are charged to this
 * separate budget, so a flood from other senders cannot spend it. Same refill. */
#define NAVLINK_SESS_RESERVE_BURST 2u
/* Ground station: no vehicle frame has verified this long after switching to new
 * keys means the switch did not take (see navlink_gcs_needs_hello). */
#define NAVLINK_SESS_GCS_RESYNC_MS 3000u

#define NAVLINK_SESS_ERR_RATE (-10)    /* HELLO inside the 1/s limit: dropped */
#define NAVLINK_SESS_ERR_REPEAT (-11)  /* gcs_nonce seen recently: dropped */
#define NAVLINK_SESS_ERR_NOSESSION (-12)
#define NAVLINK_SESS_ERR_REPLY (-13)   /* reply does not authenticate */
#define NAVLINK_SESS_ERR_UID (-14)     /* authentic reply, but not the expected vehicle */

/* Both directions of one session, seen from one side. */
typedef struct {
  navlink_sec_tx_t tx;
  navlink_sec_rx_t rx;
  uint8_t valid;
} navlink_session_t;

/* One unconfirmed session. `peer` is the transport's id of the sender (0 = unknown). */
typedef struct {
  navlink_session_t s;
  uint32_t since_ms;
  uint32_t peer;
  uint8_t has_addr; /* sysid/compid below were given with the HELLO */
  uint8_t sysid, compid;
} navlink_pending_t;

typedef struct {
  uint8_t k[NAVLINK_SEC_KEY_LEN];
  uint8_t uid[12];
  uint32_t boot_ctr;
  uint32_t hs_ctr; /* RAM; +1 per accepted HELLO */
  uint8_t closed;
  navlink_session_t live;
  navlink_pending_t pending[NAVLINK_SESS_PENDING_SLOTS];
  uint32_t budget_ms; /* HELLO budget, in ms of refill (1 HELLO = HELLO_MIN_GAP_MS) */
  uint32_t budget_at_ms;
  uint8_t budget_init;
  uint32_t live_peer;     /* peer of the live session, 0 = none or unknown */
  uint32_t reserve_ms;    /* that peer's own HELLO budget */
  uint32_t reserve_at_ms;
  uint8_t nonces[NAVLINK_SESS_NONCE_RING][16];
  uint8_t nonce_count;
  uint8_t nonce_next;
} navlink_fc_t;

/* What an authentic reply said about the vehicle. */
typedef struct {
  uint8_t uid[12];
  uint32_t fc_boot_ctr;
  uint32_t fc_hs_ctr;
} navlink_hs_info_t;

typedef struct {
  uint8_t k[NAVLINK_SEC_KEY_LEN];
  uint8_t nonce[16];
  uint8_t expect_uid[12];
  uint8_t have_expect;
  uint8_t waiting; /* a HELLO is out and no reply has been taken */
  uint8_t switched;     /* the newest session went live and no vehicle frame has */
  uint8_t fc_verified;  /* verified under it yet */
  uint32_t switched_ms;
  navlink_session_t live;
  navlink_session_t next; /* derived, becomes live on the first frame we send */
} navlink_gcs_t;

/* ---- vehicle ---- */

/* boot_ctr must be a value just persisted and read back; 0 and 0xFFFFFFFF are
 * refused (what an unwritten or wrapped counter reads as). */
int navlink_fc_init(navlink_fc_t *fc, const uint8_t k[32], const uint8_t uid[12],
                    uint32_t boot_ctr);
void navlink_fc_wipe(navlink_fc_t *fc);

/* Handle a HELLO. On success writes NAVLINK_HS_REPLY_LEN bytes to reply, fills a
 * pending slot and returns the length. A HELLO takes a free slot, else replaces
 * the oldest pending one, so up to NAVLINK_SESS_PENDING_SLOTS HELLOs can wait for
 * their first frame at once. Refused, with nothing changed: closed, no HELLO
 * budget left (NAVLINK_SESS_HELLO_BURST, refilling 1 per second), repeated nonce,
 * hs_ctr exhausted. */
int navlink_fc_hello(navlink_fc_t *fc, uint32_t now_ms,
                     const uint8_t gcs_nonce[16], uint8_t *reply);

/* Same, for a transport that can tell senders apart (a UDP source address, hashed
 * to a non-zero id): a peer holds at most ONE pending slot (its next HELLO
 * replaces its own) and may send one HELLO per second. The HELLO budget is still
 * ONE budget for all other senders: a flooder that keeps changing its id (a
 * rotating source port) can spend it and delay a HELLO from a new address (ERR_RATE
 * until it refills). The peer whose session is live has a reserve of its own
 * (NAVLINK_SESS_RESERVE_BURST) that those senders cannot spend; a flooder that
 * spoofs that peer's id can.
 * peer 0 is "unknown" and behaves as navlink_fc_hello(). */
int navlink_fc_hello_peer(navlink_fc_t *fc, uint32_t now_ms, uint32_t peer,
                          const uint8_t gcs_nonce[16], uint8_t *reply);

/* Same, and also records the (sysid, compid) of the HELLO frame's header. In
 * navlink_fc_open() a pending session recorded this way is tried only for frames
 * from the same (sysid, compid), so a keyless sender holding every slot costs
 * the real ground station's frames no extra AEAD attempts. Use it only when the
 * ground station sends its secured frames with the same (sysid, compid) as its
 * HELLO; a pending session recorded this way never opens a frame from another
 * address. navlink_fc_hello() and navlink_fc_hello_peer() record none and are
 * tried for every frame, as before. */
int navlink_fc_hello_from(navlink_fc_t *fc, uint32_t now_ms, uint32_t peer,
                          uint8_t sysid, uint8_t compid,
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
 * (NAVLINK_HS_HELLO_LEN bytes) for sending.
 *
 * expect_uid is the UID of the vehicle the caller means to reach (12 bytes), or
 * NULL. The mac only proves the replier holds K; vehicles that share K on one
 * link would otherwise answer for each other. The caller MUST pass the UID it
 * means to reach, or else compare info->uid from navlink_gcs_reply itself. */
int navlink_gcs_hello(navlink_gcs_t *g, const uint8_t gcs_nonce[16],
                      const uint8_t *expect_uid, uint8_t *hello);

/* Take the vehicle's reply. It must echo our nonce and carry the right mac;
 * otherwise nothing changes. On success the new session is held as `next` and
 * info (required) is filled with the authenticated UID and counters. A second
 * copy of the same reply is refused. If an expected UID was given to
 * navlink_gcs_hello and this reply is from another vehicle, info is still filled
 * (so the caller can report it) but the reply is NOT taken: NAVLINK_SESS_ERR_UID,
 * and the ground station keeps waiting for the right one. */
int navlink_gcs_reply(navlink_gcs_t *g, const uint8_t *reply, size_t len,
                      navlink_hs_info_t *info);

/* Seal under the newest session; the first call after a reply makes the new
 * session live (this first frame is what promotes it on the vehicle) and drops
 * the old keys.
 *
 * LIVENESS. The vehicle discards an unconfirmed pending session after
 * NAVLINK_SESS_PENDING_MS and keeps the OLD live one, but this side has already
 * dropped the old keys. If the first frame, and every frame in the next 5 s, is
 * lost, neither side can read the other until a new HELLO. So the ground station
 * MUST poll navlink_gcs_needs_hello() and, when it returns 1, send a new HELLO. A
 * frame lost but followed by another within 5 s is fine: any frame that verifies
 * promotes. */
int navlink_gcs_seal(navlink_gcs_t *g, uint32_t now_ms, uint8_t *out, size_t cap,
                     uint8_t iflags, const navlink_sec_hdr_t *hdr,
                     const uint8_t *payload);

/* 1 if the session went live NAVLINK_SESS_GCS_RESYNC_MS or more ago and no vehicle
 * frame has verified under it: the switch did not take, send a new HELLO. */
int navlink_gcs_needs_hello(const navlink_gcs_t *g, uint32_t now_ms);

int navlink_gcs_open(navlink_gcs_t *g, const uint8_t *frame, size_t len,
                     navlink_sec_hdr_t *hdr, uint8_t *payload_out);

#endif /* NAVLINK_SESS_H */
