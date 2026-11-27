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

/* navlink_sec: the secured frame of navlink-v2-spec.md section 11, as pure code.
 *
 * What is here: the per-direction session key derivation (11.9), sealing and
 * opening one IFLAG_ENCRYPTED frame (11.2, 11.4, 11.5, 11.6), the key id (11.7).
 * What is NOT here: the handshake exchange, its messages and the pending/live
 * session slots (11.9), the key store (11.7), strict mode (11.8). Those need
 * the dialect change and a transport; this layer needs neither. IFLAG_SIGNED is
 * not implemented (the policy is encrypt everywhere); asking for it is an error.
 *
 * No I/O, no clock, no heap, no randomness, bounded work per frame. A failure
 * changes nothing but the return value (spec 11.10): in particular a frame that
 * does not verify never moves the receive counter.
 *
 * One tx state per direction of a session and ONE counter at the sender for
 * every component that sends in that direction (11.9): share the navlink_sec_tx_t
 * and serialise its use (an atomic or a lock around seal), do not copy it. */
#ifndef NAVLINK_SEC_H
#define NAVLINK_SEC_H

#include <stddef.h>
#include <stdint.h>

#define NAVLINK_SEC_KEY_LEN 32
#define NAVLINK_SEC_TAG_LEN 16
#define NAVLINK_SEC_COUNTER_LEN 6
#define NAVLINK_SEC_TRAILER_LEN (NAVLINK_SEC_COUNTER_LEN + NAVLINK_SEC_TAG_LEN)
#define NAVLINK_SEC_HEADER_LEN 10
/* 10 header + 255 payload + 22 trailer */
#define NAVLINK_SEC_MAX_FRAME 287
#define NAVLINK_SEC_COUNTER_MAX ((uint64_t)0xFFFFFFFFFFFFULL) /* 2^48 - 1 */

#define NAVLINK_SEC_SYNC 0x56
#define NAVLINK_SEC_VERSION 0x02
#define NAVLINK_SEC_IFLAG_SIGNED 0x01
#define NAVLINK_SEC_IFLAG_ENCRYPTED 0x02

/* Direction byte (AAD) and key label. 0 = FC to GCS, 1 = GCS to FC. */
#define NAVLINK_SEC_DIR_FC_TO_GCS 0
#define NAVLINK_SEC_DIR_GCS_TO_FC 1

/* Return codes. Zero or positive is success (a length); negative is failure. */
#define NAVLINK_SEC_ERR_ARG (-1)       /* null pointer, bad direction */
#define NAVLINK_SEC_ERR_UNSUPPORTED (-2) /* IFLAG_SIGNED or an unknown flag */
#define NAVLINK_SEC_ERR_SIZE (-3)      /* output too small, length mismatch */
#define NAVLINK_SEC_ERR_CLOSED (-4)    /* tx counter exhausted: session over */
#define NAVLINK_SEC_ERR_FORMAT (-5)    /* sync, version or flags are wrong */
#define NAVLINK_SEC_ERR_COUNTER (-6)   /* a replay: counter already seen, or older than the window */
#define NAVLINK_SEC_ERR_TAG (-7)       /* authentication failed */

/* The sending side of one direction of one session. */
typedef struct {
  uint8_t key[NAVLINK_SEC_KEY_LEN];
  uint64_t counter; /* the counter the NEXT frame will carry */
  uint8_t dir;
  uint8_t closed; /* set once the counter would reach NAVLINK_SEC_COUNTER_MAX */
} navlink_sec_tx_t;

/* Reorder window (spec 11.5): a frame with a counter up to this many below the
 * highest accepted one is still taken, once, if it has not been seen. UDP and
 * radio links reorder; with 0 the rule is the strict "greater than the last".
 * At most 64. */
#ifndef NAVLINK_SEC_REPLAY_WINDOW
#define NAVLINK_SEC_REPLAY_WINDOW 16u
#endif

/* The receiving side of one direction of one session. */
typedef struct {
  uint8_t key[NAVLINK_SEC_KEY_LEN];
  uint64_t last; /* highest counter accepted; meaningful only if have != 0 */
  uint64_t seen; /* bit i set: counter last - i was accepted (bit 0 is `last`) */
  uint8_t dir;
  uint8_t have;
} navlink_sec_rx_t;

/* The fields of a frame header that the caller supplies and gets back. */
typedef struct {
  uint8_t seq;
  uint8_t sysid;
  uint8_t compid;
  uint32_t msgid; /* 24 bits */
  uint8_t payload_len;
} navlink_sec_hdr_t;

/* Session key for one direction (spec 11.9):
 *   BLAKE2b-256 keyed with K over
 *   "navlink-session" || dir || gcs_nonce[16] || fc_boot_ctr(LE32)
 *                     || fc_hs_ctr(LE32) || uid[12]. */
void navlink_sec_derive(uint8_t out_key[NAVLINK_SEC_KEY_LEN],
                        const uint8_t k[NAVLINK_SEC_KEY_LEN], uint8_t dir,
                        const uint8_t gcs_nonce[16], uint32_t fc_boot_ctr,
                        uint32_t fc_hs_ctr, const uint8_t uid[12]);

/* The non-secret key id (spec 11.7): the first four bytes (LE) of BLAKE2b-256
 * keyed with K over "navlink-key-id". */
uint32_t navlink_sec_key_id(const uint8_t k[NAVLINK_SEC_KEY_LEN]);

/* Start a direction with a derived key; counters begin at 0 / nothing seen. */
int navlink_sec_tx_init(navlink_sec_tx_t *tx, const uint8_t key[32],
                        uint8_t dir);
int navlink_sec_rx_init(navlink_sec_rx_t *rx, const uint8_t key[32],
                        uint8_t dir);
/* Wipe the key material. */
void navlink_sec_tx_wipe(navlink_sec_tx_t *tx);
void navlink_sec_rx_wipe(navlink_sec_rx_t *rx);

/* Seal one frame into out (cap >= 10 + payload_len + 22). The payload is the
 * already zero-truncated message payload (spec 5.6). iflags must be
 * NAVLINK_SEC_IFLAG_ENCRYPTED. Returns the frame length, or a negative code.
 * The counter advances only on success. */
int navlink_sec_seal(navlink_sec_tx_t *tx, uint8_t *out, size_t cap,
                     uint8_t iflags, const navlink_sec_hdr_t *hdr,
                     const uint8_t *payload);

/* Open one frame of exactly len bytes. On success returns the payload length,
 * writes the payload to payload_out (cap >= 255) and the header fields to hdr;
 * the receive counter advances to the frame's counter. On any failure nothing
 * is written to payload_out and the receive counter does not move. */
int navlink_sec_open(navlink_sec_rx_t *rx, const uint8_t *frame, size_t len,
                     navlink_sec_hdr_t *hdr, uint8_t *payload_out);

/* Constant-time compare for callers that hold secrets. */
int navlink_sec_equal16(const uint8_t a[16], const uint8_t b[16]);

#endif /* NAVLINK_SEC_H */
