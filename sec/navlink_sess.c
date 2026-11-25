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

/* navlink_sess.c: see navlink_sess.h. */
#include "navlink_sess.h"
#include "monocypher.h"
#include <string.h>

static void put_le32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

/* mac over 'navlink-hs-reply' || gcs_nonce || boot || hs || uid */
static void reply_mac(uint8_t mac[NAVLINK_HS_MAC_LEN], const uint8_t k[32],
                      const uint8_t nonce[16], uint32_t boot, uint32_t hs,
                      const uint8_t uid[12]) {
  static const char label[] = "navlink-hs-reply";
  uint8_t msg[16 + 16 + 4 + 4 + 12];
  size_t n = 0;
  memcpy(msg + n, label, 16);
  n += 16;
  memcpy(msg + n, nonce, 16);
  n += 16;
  put_le32(msg + n, boot);
  n += 4;
  put_le32(msg + n, hs);
  n += 4;
  memcpy(msg + n, uid, 12);
  n += 12;
  crypto_blake2b_keyed(mac, NAVLINK_HS_MAC_LEN, k, 32, msg, n);
  crypto_wipe(msg, sizeof msg);
}

/* Build both directions of a session. fc_side: rx = GCS->FC, tx = FC->GCS. */
static void make_session(navlink_session_t *s, int fc_side, const uint8_t k[32],
                         const uint8_t nonce[16], uint32_t boot, uint32_t hs,
                         const uint8_t uid[12]) {
  uint8_t k_to_fc[32], k_to_gcs[32];
  navlink_sec_derive(k_to_fc, k, NAVLINK_SEC_DIR_GCS_TO_FC, nonce, boot, hs, uid);
  navlink_sec_derive(k_to_gcs, k, NAVLINK_SEC_DIR_FC_TO_GCS, nonce, boot, hs,
                     uid);
  if (fc_side) {
    navlink_sec_tx_init(&s->tx, k_to_gcs, NAVLINK_SEC_DIR_FC_TO_GCS);
    navlink_sec_rx_init(&s->rx, k_to_fc, NAVLINK_SEC_DIR_GCS_TO_FC);
  } else {
    navlink_sec_tx_init(&s->tx, k_to_fc, NAVLINK_SEC_DIR_GCS_TO_FC);
    navlink_sec_rx_init(&s->rx, k_to_gcs, NAVLINK_SEC_DIR_FC_TO_GCS);
  }
  s->valid = 1;
  crypto_wipe(k_to_fc, 32);
  crypto_wipe(k_to_gcs, 32);
}

static void drop(navlink_session_t *s) {
  crypto_wipe(s, sizeof *s);
}

/* ---- vehicle ---- */

int navlink_fc_init(navlink_fc_t *fc, const uint8_t k[32], const uint8_t uid[12],
                    uint32_t boot_ctr) {
  if (fc == NULL || k == NULL || uid == NULL)
    return NAVLINK_SEC_ERR_ARG;
  if (boot_ctr == 0u || boot_ctr == 0xFFFFFFFFu)
    return NAVLINK_SEC_ERR_CLOSED;
  memset(fc, 0, sizeof *fc);
  memcpy(fc->k, k, 32);
  memcpy(fc->uid, uid, 12);
  fc->boot_ctr = boot_ctr;
  return 0;
}

void navlink_fc_wipe(navlink_fc_t *fc) {
  if (fc != NULL)
    crypto_wipe(fc, sizeof *fc);
}

void navlink_fc_tick(navlink_fc_t *fc, uint32_t now_ms) {
  if (fc != NULL && fc->pending.valid &&
      (uint32_t)(now_ms - fc->pending_since_ms) >= NAVLINK_SESS_PENDING_MS)
    drop(&fc->pending);
}

int navlink_fc_hello(navlink_fc_t *fc, uint32_t now_ms,
                     const uint8_t gcs_nonce[16], uint8_t *reply) {
  if (fc == NULL || gcs_nonce == NULL || reply == NULL)
    return NAVLINK_SEC_ERR_ARG;
  if (fc->closed || fc->hs_ctr == 0xFFFFFFFFu) {
    fc->closed = 1;
    return NAVLINK_SEC_ERR_CLOSED;
  }
  if (fc->have_hello &&
      (uint32_t)(now_ms - fc->last_hello_ms) < NAVLINK_SESS_HELLO_MIN_GAP_MS)
    return NAVLINK_SESS_ERR_RATE;
  for (unsigned i = 0; i < fc->nonce_count; ++i)
    if (memcmp(fc->nonces[i], gcs_nonce, 16) == 0)
      return NAVLINK_SESS_ERR_REPEAT;

  fc->hs_ctr++;
  fc->last_hello_ms = now_ms;
  fc->have_hello = 1;
  memcpy(fc->nonces[fc->nonce_next], gcs_nonce, 16);
  fc->nonce_next = (uint8_t)((fc->nonce_next + 1u) % NAVLINK_SESS_NONCE_RING);
  if (fc->nonce_count < NAVLINK_SESS_NONCE_RING)
    fc->nonce_count++;

  make_session(&fc->pending, 1, fc->k, gcs_nonce, fc->boot_ctr, fc->hs_ctr,
               fc->uid);
  fc->pending_since_ms = now_ms;

  memcpy(reply, gcs_nonce, 16);
  put_le32(reply + 16, fc->boot_ctr);
  put_le32(reply + 20, fc->hs_ctr);
  memcpy(reply + 24, fc->uid, 12);
  reply_mac(reply + 36, fc->k, gcs_nonce, fc->boot_ctr, fc->hs_ctr, fc->uid);
  return NAVLINK_HS_REPLY_LEN;
}

int navlink_fc_open(navlink_fc_t *fc, uint32_t now_ms, const uint8_t *frame,
                    size_t len, navlink_sec_hdr_t *hdr, uint8_t *payload_out) {
  if (fc == NULL)
    return NAVLINK_SEC_ERR_ARG;
  navlink_fc_tick(fc, now_ms);
  int r = NAVLINK_SESS_ERR_NOSESSION;
  if (fc->live.valid) {
    r = navlink_sec_open(&fc->live.rx, frame, len, hdr, payload_out);
    if (r >= 0)
      return r;
  }
  if (fc->pending.valid) {
    const int p = navlink_sec_open(&fc->pending.rx, frame, len, hdr, payload_out);
    if (p >= 0) {
      /* proof the sender holds K: the pending session takes over */
      drop(&fc->live);
      fc->live = fc->pending;
      drop(&fc->pending);
      return p;
    }
    if (r == NAVLINK_SESS_ERR_NOSESSION)
      r = p;
  }
  return r;
}

int navlink_fc_seal(navlink_fc_t *fc, uint8_t *out, size_t cap, uint8_t iflags,
                    const navlink_sec_hdr_t *hdr, const uint8_t *payload) {
  if (fc == NULL)
    return NAVLINK_SEC_ERR_ARG;
  if (!fc->live.valid)
    return NAVLINK_SESS_ERR_NOSESSION;
  return navlink_sec_seal(&fc->live.tx, out, cap, iflags, hdr, payload);
}

/* ---- ground station ---- */

int navlink_gcs_init(navlink_gcs_t *g, const uint8_t k[32]) {
  if (g == NULL || k == NULL)
    return NAVLINK_SEC_ERR_ARG;
  memset(g, 0, sizeof *g);
  memcpy(g->k, k, 32);
  return 0;
}

void navlink_gcs_wipe(navlink_gcs_t *g) {
  if (g != NULL)
    crypto_wipe(g, sizeof *g);
}

int navlink_gcs_hello(navlink_gcs_t *g, const uint8_t gcs_nonce[16],
                      const uint8_t *expect_uid, uint8_t *hello) {
  if (g == NULL || gcs_nonce == NULL || hello == NULL)
    return NAVLINK_SEC_ERR_ARG;
  if (expect_uid != NULL) {
    memcpy(g->expect_uid, expect_uid, 12);
    g->have_expect = 1;
  } else {
    g->have_expect = 0;
  }
  memcpy(g->nonce, gcs_nonce, 16);
  g->waiting = 1;
  memcpy(hello, gcs_nonce, 16);
  return NAVLINK_HS_HELLO_LEN;
}

int navlink_gcs_reply(navlink_gcs_t *g, const uint8_t *reply, size_t len,
                      navlink_hs_info_t *info) {
  if (g == NULL || reply == NULL || info == NULL)
    return NAVLINK_SEC_ERR_ARG;
  if (len != NAVLINK_HS_REPLY_LEN)
    return NAVLINK_SEC_ERR_SIZE;
  if (!g->waiting)
    return NAVLINK_SESS_ERR_REPLY;
  uint8_t mac[NAVLINK_HS_MAC_LEN];
  const uint32_t boot = get_le32(reply + 16);
  const uint32_t hs = get_le32(reply + 20);
  /* The mac is computed over OUR nonce, not the echoed one: a reply made for
   * another HELLO cannot verify, whatever it echoes. */
  reply_mac(mac, g->k, g->nonce, boot, hs, reply + 24);
  const int ok = crypto_verify16(mac, reply + 36) == 0 &&
                 memcmp(reply, g->nonce, 16) == 0;
  crypto_wipe(mac, sizeof mac);
  if (!ok)
    return NAVLINK_SESS_ERR_REPLY;
  memcpy(info->uid, reply + 24, 12);
  info->fc_boot_ctr = boot;
  info->fc_hs_ctr = hs;
  if (g->have_expect && memcmp(g->expect_uid, info->uid, 12) != 0)
    return NAVLINK_SESS_ERR_UID; /* authentic, but another vehicle: keep waiting */
  g->waiting = 0; /* one reply per HELLO */
  make_session(&g->next, 0, g->k, g->nonce, boot, hs, reply + 24);
  return 0;
}

int navlink_gcs_seal(navlink_gcs_t *g, uint32_t now_ms, uint8_t *out, size_t cap,
                     uint8_t iflags, const navlink_sec_hdr_t *hdr,
                     const uint8_t *payload) {
  if (g == NULL)
    return NAVLINK_SEC_ERR_ARG;
  if (g->next.valid) {
    drop(&g->live);
    g->live = g->next;
    drop(&g->next);
    g->switched = 1;
    g->fc_verified = 0;
    g->switched_ms = now_ms;
  }
  if (!g->live.valid)
    return NAVLINK_SESS_ERR_NOSESSION;
  return navlink_sec_seal(&g->live.tx, out, cap, iflags, hdr, payload);
}

int navlink_gcs_open(navlink_gcs_t *g, const uint8_t *frame, size_t len,
                     navlink_sec_hdr_t *hdr, uint8_t *payload_out) {
  if (g == NULL)
    return NAVLINK_SEC_ERR_ARG;
  if (!g->live.valid)
    return NAVLINK_SESS_ERR_NOSESSION;
  const int r = navlink_sec_open(&g->live.rx, frame, len, hdr, payload_out);
  if (r >= 0)
    g->fc_verified = 1;
  return r;
}

int navlink_gcs_needs_hello(const navlink_gcs_t *g, uint32_t now_ms) {
  return g != NULL && g->switched && !g->fc_verified &&
         (uint32_t)(now_ms - g->switched_ms) >= NAVLINK_SESS_GCS_RESYNC_MS;
}
