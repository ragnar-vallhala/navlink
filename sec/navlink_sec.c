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

/* navlink_sec.c: see navlink_sec.h. The cipher and the hash are Monocypher's
 * (vendor/monocypher); nothing here is a primitive. */
#include "navlink_sec.h"
#include "monocypher.h"
#include <string.h>

#define AAD_LEN (9 + 2) /* header bytes 1..9, tag_len, dir */

static void put_le32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static void put_le48(uint8_t *p, uint64_t v) {
  for (int i = 0; i < 6; ++i)
    p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t get_le48(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 6; ++i)
    v |= (uint64_t)p[i] << (8 * i);
  return v;
}

void navlink_sec_derive(uint8_t out_key[NAVLINK_SEC_KEY_LEN],
                        const uint8_t k[NAVLINK_SEC_KEY_LEN], uint8_t dir,
                        const uint8_t gcs_nonce[16], uint32_t fc_boot_ctr,
                        uint32_t fc_hs_ctr, const uint8_t uid[12]) {
  static const char label[] = "navlink-session";
  uint8_t msg[15 + 1 + 16 + 4 + 4 + 12];
  size_t n = 0;
  memcpy(msg + n, label, 15);
  n += 15;
  msg[n++] = dir;
  memcpy(msg + n, gcs_nonce, 16);
  n += 16;
  put_le32(msg + n, fc_boot_ctr);
  n += 4;
  put_le32(msg + n, fc_hs_ctr);
  n += 4;
  memcpy(msg + n, uid, 12);
  n += 12;
  crypto_blake2b_keyed(out_key, NAVLINK_SEC_KEY_LEN, k, NAVLINK_SEC_KEY_LEN,
                       msg, n);
  crypto_wipe(msg, sizeof msg);
}

uint32_t navlink_sec_key_id(const uint8_t k[NAVLINK_SEC_KEY_LEN]) {
  static const char label[] = "navlink-key-id";
  uint8_t h[NAVLINK_SEC_KEY_LEN];
  crypto_blake2b_keyed(h, sizeof h, k, NAVLINK_SEC_KEY_LEN,
                       (const uint8_t *)label, 14);
  const uint32_t id = (uint32_t)h[0] | ((uint32_t)h[1] << 8) |
                      ((uint32_t)h[2] << 16) | ((uint32_t)h[3] << 24);
  crypto_wipe(h, sizeof h);
  return id;
}

int navlink_sec_tx_init(navlink_sec_tx_t *tx, const uint8_t key[32],
                        uint8_t dir) {
  if (tx == NULL || key == NULL || dir > NAVLINK_SEC_DIR_GCS_TO_FC)
    return NAVLINK_SEC_ERR_ARG;
  memcpy(tx->key, key, NAVLINK_SEC_KEY_LEN);
  tx->counter = 0;
  tx->dir = dir;
  tx->closed = 0;
  return 0;
}

_Static_assert(NAVLINK_SEC_REPLAY_WINDOW <= 64, "the window is a 64-bit map");

int navlink_sec_rx_init(navlink_sec_rx_t *rx, const uint8_t key[32],
                        uint8_t dir) {
  if (rx == NULL || key == NULL || dir > NAVLINK_SEC_DIR_GCS_TO_FC)
    return NAVLINK_SEC_ERR_ARG;
  memcpy(rx->key, key, NAVLINK_SEC_KEY_LEN);
  rx->last = 0;
  rx->seen = 0;
  rx->have = 0;
  rx->dir = dir;
  return 0;
}

void navlink_sec_tx_wipe(navlink_sec_tx_t *tx) {
  if (tx != NULL)
    crypto_wipe(tx, sizeof *tx);
}

void navlink_sec_rx_wipe(navlink_sec_rx_t *rx) {
  if (rx != NULL)
    crypto_wipe(rx, sizeof *rx);
}

int navlink_sec_equal16(const uint8_t a[16], const uint8_t b[16]) {
  return crypto_verify16(a, b) == 0;
}

/* nonce = counter(6) || seq || sysid || compid || 0 0 0  (spec 11.4) */
static void make_nonce(uint8_t nonce[12], uint64_t counter, uint8_t seq,
                       uint8_t sysid, uint8_t compid) {
  put_le48(nonce, counter);
  nonce[6] = seq;
  nonce[7] = sysid;
  nonce[8] = compid;
  nonce[9] = 0;
  nonce[10] = 0;
  nonce[11] = 0;
}

/* AAD = header[1..9] || tag_len || dir  (spec 11.2) */
static void make_aad(uint8_t aad[AAD_LEN], const uint8_t *header, uint8_t dir) {
  memcpy(aad, header + 1, 9);
  aad[9] = NAVLINK_SEC_TAG_LEN;
  aad[10] = dir;
}

int navlink_sec_seal(navlink_sec_tx_t *tx, uint8_t *out, size_t cap,
                     uint8_t iflags, const navlink_sec_hdr_t *hdr,
                     const uint8_t *payload) {
  if (tx == NULL || out == NULL || hdr == NULL ||
      (hdr->payload_len != 0 && payload == NULL))
    return NAVLINK_SEC_ERR_ARG;
  if (iflags != NAVLINK_SEC_IFLAG_ENCRYPTED)
    return NAVLINK_SEC_ERR_UNSUPPORTED;
  if (hdr->msgid > 0xFFFFFFu)
    return NAVLINK_SEC_ERR_ARG;
  if (tx->closed || tx->counter >= NAVLINK_SEC_COUNTER_MAX) {
    tx->closed = 1; /* never wrap: the session is over */
    return NAVLINK_SEC_ERR_CLOSED;
  }
  const size_t plen = hdr->payload_len;
  const size_t total = NAVLINK_SEC_HEADER_LEN + plen + NAVLINK_SEC_TRAILER_LEN;
  if (cap < total)
    return NAVLINK_SEC_ERR_SIZE;

  out[0] = NAVLINK_SEC_SYNC;
  out[1] = NAVLINK_SEC_VERSION;
  out[2] = hdr->payload_len;
  out[3] = iflags;
  out[4] = hdr->seq;
  out[5] = hdr->sysid;
  out[6] = hdr->compid;
  out[7] = (uint8_t)hdr->msgid;
  out[8] = (uint8_t)(hdr->msgid >> 8);
  out[9] = (uint8_t)(hdr->msgid >> 16);

  uint8_t nonce[12];
  uint8_t aad[AAD_LEN];
  make_nonce(nonce, tx->counter, hdr->seq, hdr->sysid, hdr->compid);
  make_aad(aad, out, tx->dir);

  crypto_aead_ctx ctx;
  crypto_aead_init_ietf(&ctx, tx->key, nonce);
  uint8_t *ct = out + NAVLINK_SEC_HEADER_LEN;
  uint8_t *trailer = ct + plen;
  put_le48(trailer, tx->counter);
  crypto_aead_write(&ctx, ct, trailer + NAVLINK_SEC_COUNTER_LEN, aad, AAD_LEN,
                    payload, plen);
  crypto_wipe(&ctx, sizeof ctx);
  tx->counter++;
  return (int)total;
}

int navlink_sec_open(navlink_sec_rx_t *rx, const uint8_t *frame, size_t len,
                     navlink_sec_hdr_t *hdr, uint8_t *payload_out) {
  if (rx == NULL || frame == NULL || hdr == NULL || payload_out == NULL)
    return NAVLINK_SEC_ERR_ARG;
  if (len < NAVLINK_SEC_HEADER_LEN + NAVLINK_SEC_TRAILER_LEN)
    return NAVLINK_SEC_ERR_SIZE;
  if (frame[0] != NAVLINK_SEC_SYNC || frame[1] != NAVLINK_SEC_VERSION ||
      frame[3] != NAVLINK_SEC_IFLAG_ENCRYPTED)
    return NAVLINK_SEC_ERR_FORMAT;
  const size_t plen = frame[2];
  if (len != NAVLINK_SEC_HEADER_LEN + plen + NAVLINK_SEC_TRAILER_LEN)
    return NAVLINK_SEC_ERR_SIZE;

  const uint8_t *ct = frame + NAVLINK_SEC_HEADER_LEN;
  const uint8_t *trailer = ct + plen;
  const uint64_t counter = get_le48(trailer);
  /* Cheap rejection first; it never changes state. A counter above the highest
   * seen is new; one inside the window is taken once; the rest are replays. */
  if (rx->have && counter <= rx->last) {
    const uint64_t d = rx->last - counter;
    if (d >= NAVLINK_SEC_REPLAY_WINDOW || ((rx->seen >> d) & 1u))
      return NAVLINK_SEC_ERR_COUNTER;
  }

  uint8_t nonce[12];
  uint8_t aad[AAD_LEN];
  make_nonce(nonce, counter, frame[4], frame[5], frame[6]);
  make_aad(aad, frame, rx->dir);

  uint8_t plain[255];
  crypto_aead_ctx ctx;
  crypto_aead_init_ietf(&ctx, rx->key, nonce);
  const int bad = crypto_aead_read(&ctx, plain, trailer + NAVLINK_SEC_COUNTER_LEN,
                                   aad, AAD_LEN, ct, plen);
  crypto_wipe(&ctx, sizeof ctx);
  if (bad != 0) {
    crypto_wipe(plain, sizeof plain);
    return NAVLINK_SEC_ERR_TAG;
  }
  /* Authentic: only now does the receive state move. */
  if (!rx->have) {
    rx->seen = 1u;
    rx->last = counter;
  } else if (counter > rx->last) {
    const uint64_t shift = counter - rx->last;
    rx->seen = (shift >= 64u) ? 0u : (rx->seen << shift);
    rx->seen |= 1u;
    rx->last = counter;
  } else {
    rx->seen |= (uint64_t)1u << (rx->last - counter);
  }
  rx->have = 1;
  hdr->seq = frame[4];
  hdr->sysid = frame[5];
  hdr->compid = frame[6];
  hdr->msgid = (uint32_t)frame[7] | ((uint32_t)frame[8] << 8) |
               ((uint32_t)frame[9] << 16);
  hdr->payload_len = frame[2];
  memcpy(payload_out, plain, plen);
  crypto_wipe(plain, sizeof plain);
  return (int)plen;
}
