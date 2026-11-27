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

/* The parser's secured-frame hook (navlink_handlers_t.secure_open and
 * .accept_unsecured): routing, rejection, rescan, bounds, and an end-to-end run
 * through real AEAD. Only IFLAG_ENCRYPTED is routed; with no hook an encrypted
 * frame is rejected exactly as before. */
#include "navlink_msgs.h"
#include "navlink_sec.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int g_bad;
#define CHECK(c)                                                               \
  do {                                                                         \
    if (!(c)) {                                                                \
      printf("FAIL line %d: %s\n", __LINE__, #c);                              \
      g_bad = 1;                                                               \
    }                                                                          \
  } while (0)

static int g_hello;      /* on_hs_hello calls */
static uint8_t g_nonce0; /* first byte of the last nonce seen */
static uint8_t g_flags;  /* incompat_flags seen by the handler */
static int g_open_calls;
static size_t g_open_len;
static int g_open_ret;    /* -2 = real AEAD, else this value (n >= 0: a fake) */
static int g_accept_ret;  /* what accept_unsecured returns */
static int g_accept_calls;
static navlink_sec_rx_t g_rx;

static void on_hello(void *ctx, const navlink_frame_hdr_t *hdr,
                     const navlink_hs_hello_t *msg) {
  (void)ctx;
  g_hello++;
  g_nonce0 = msg->gcs_nonce[0];
  g_flags = hdr->incompat_flags;
}

static int open_hook(void *ctx, const uint8_t *frame, size_t len,
                     uint8_t *out) {
  (void)ctx;
  g_open_calls++;
  g_open_len = len;
  if (g_open_ret == -2) {
    navlink_sec_hdr_t h;
    int r = navlink_sec_open(&g_rx, frame, len, &h, out);
    return r < 0 ? r : (int)h.payload_len;
  }
  if (g_open_ret >= 0) { /* a fake: the plaintext is the first byte repeated */
    memset(out, 0x41, 255);
    out[0] = 0x77;
  }
  return g_open_ret;
}

static int accept_hook(void *ctx, const navlink_frame_hdr_t *hdr) {
  (void)ctx;
  (void)hdr;
  g_accept_calls++;
  return g_accept_ret;
}

static navlink_handlers_t H;
static navlink_parser_t P;

static void reset(int with_hook) {
  memset(&H, 0, sizeof H);
  H.on_hs_hello = on_hello;
  if (with_hook)
    H.secure_open = open_hook;
  navlink_parser_init(&P);
  g_hello = g_open_calls = g_accept_calls = 0;
  g_open_len = 0;
  g_flags = 0;
  g_accept_ret = 1;
}

static const uint8_t KEY[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                                30, 31, 32};

/* A secured HS_HELLO frame under a fresh tx counter. */
static size_t secured(navlink_sec_tx_t *tx, uint8_t first, uint8_t *out) {
  navlink_hs_hello_wire_t w;
  memset(&w, 0, sizeof w);
  w.gcs_nonce[0] = first;
  uint8_t pl[16];
  size_t n = navlink_hs_hello_pack(pl, &w);
  navlink_sec_hdr_t h = {.seq = 1, .sysid = 1, .compid = 1,
                         .msgid = NAVLINK_MSGID_HS_HELLO, .payload_len = (uint8_t)n};
  int r = navlink_sec_seal(tx, out, NAVLINK_MAX_FRAME, NAVLINK_SEC_IFLAG_ENCRYPTED,
                           &h, pl);
  CHECK(r > 0);
  return (size_t)r;
}

static size_t plain(uint8_t first, uint8_t *out) {
  navlink_hs_hello_t m;
  memset(&m, 0, sizeof m);
  m.gcs_nonce[0] = first;
  return navlink_hs_hello_encode(out, &m, 1, 1, 1);
}

static void sec_reset(navlink_sec_tx_t *tx) {
  CHECK(navlink_sec_tx_init(tx, KEY, NAVLINK_SEC_DIR_GCS_TO_FC) == 0);
  CHECK(navlink_sec_rx_init(&g_rx, KEY, NAVLINK_SEC_DIR_GCS_TO_FC) == 0);
}

static void test_no_hook(void) {
  navlink_sec_tx_t tx;
  uint8_t f[NAVLINK_MAX_FRAME], g[NAVLINK_MAX_FRAME];
  sec_reset(&tx);
  size_t n = secured(&tx, 9, f);
  reset(0);
  navlink_parser_push(&P, &H, f, n);
  CHECK(g_hello == 0 && g_open_calls == 0); /* rejected, as before */
  /* and an unsecured frame behind it still parses */
  size_t m = plain(5, g);
  navlink_parser_push(&P, &H, g, m);
  CHECK(g_hello == 1 && g_nonce0 == 5 && g_flags == 0);
}

static void test_routed(void) {
  navlink_sec_tx_t tx;
  uint8_t f[NAVLINK_MAX_FRAME];
  sec_reset(&tx);
  size_t n = secured(&tx, 0x42, f);
  CHECK(n == 10 + 16 + 22);
  reset(1);
  g_open_ret = -2;
  navlink_parser_push(&P, &H, f, n);
  CHECK(g_hello == 1 && g_nonce0 == 0x42);
  CHECK(g_flags == NAVLINK_IFLAG_ENCRYPTED);
  CHECK(g_open_calls == 1 && g_open_len == n); /* the whole frame, once */
  /* a frame fed one byte at a time dispatches only at the last byte */
  sec_reset(&tx);
  n = secured(&tx, 0x43, f);
  reset(1);
  g_open_ret = -2;
  for (size_t i = 0; i + 1 < n; i++)
    navlink_parser_push(&P, &H, f + i, 1);
  CHECK(g_hello == 0 && g_open_calls == 0);
  navlink_parser_push(&P, &H, f + n - 1, 1);
  CHECK(g_hello == 1 && g_nonce0 == 0x43);
}

static void test_other_bits(void) {
  navlink_sec_tx_t tx;
  uint8_t f[NAVLINK_MAX_FRAME];
  const uint8_t bad[] = {0x01, 0x03, 0x06, 0x12, 0x82, 0x10, 0x80};
  sec_reset(&tx);
  size_t n = secured(&tx, 1, f);
  for (unsigned i = 0; i < sizeof bad; i++) {
    uint8_t g[NAVLINK_MAX_FRAME];
    memcpy(g, f, n);
    g[3] = bad[i];
    reset(1);
    g_open_ret = 0;
    navlink_parser_push(&P, &H, g, n);
    CHECK(g_hello == 0 && g_open_calls == 0); /* never routed */
  }
}

/* A header with a bad bit claiming a long frame must be rejected AT the header, so
 * a real frame right behind it parses at once instead of being swallowed while
 * the parser waits for a trailer that is not coming. */
static void test_bad_bit_rejected_at_header(void) {
  uint8_t buf[64], g[NAVLINK_MAX_FRAME];
  size_t m = plain(0x33, g);
  const uint8_t bad[] = {0x12, 0x03, 0x82};
  for (unsigned i = 0; i < sizeof bad; i++) {
    memset(buf, 0, sizeof buf);
    buf[0] = 0x56;
    buf[1] = 0x02;
    buf[2] = 16;
    buf[3] = bad[i];
    buf[7] = 6;
    memcpy(buf + 10, g, m); /* 10 + 28 = 38 bytes, short of a 48-byte claim */
    reset(1);
    g_open_ret = -1;
    navlink_parser_push(&P, &H, buf, 10 + m);
    CHECK(g_hello == 1 && g_nonce0 == 0x33 && g_open_calls == 0);
  }
}

static void test_reject_and_rescan(void) {
  navlink_sec_tx_t tx;
  uint8_t f[NAVLINK_MAX_FRAME], g[NAVLINK_MAX_FRAME], both[2 * NAVLINK_MAX_FRAME];
  sec_reset(&tx);
  size_t n = secured(&tx, 1, f);
  /* hook rejects: nothing dispatched */
  reset(1);
  g_open_ret = -1;
  navlink_parser_push(&P, &H, f, n);
  CHECK(g_open_calls == 1 && g_hello == 0);
  /* a plaintext length that is not the header's payload_len is dropped too */
  reset(1);
  g_open_ret = 3;
  navlink_parser_push(&P, &H, f, n);
  CHECK(g_hello == 0);
  /* a forged encrypted header swallows 40 bytes that hold a real frame: the
   * real one is still found after the rejection */
  size_t m = plain(0x55, g);
  memset(both, 0, sizeof both);
  both[0] = 0x56;
  both[1] = 0x02;
  both[2] = 0x10; /* claims 16 bytes: 10+16+22 = 48 */
  both[3] = NAVLINK_IFLAG_ENCRYPTED;
  both[7] = 6; /* msgid 6 */
  memcpy(both + 10, g, m); /* the real frame sits inside the claimed span */
  reset(1);
  g_open_ret = -1;
  navlink_parser_push(&P, &H, both, 48);
  CHECK(g_hello == 1 && g_nonce0 == 0x55 && g_flags == 0);
}

static void test_bounds(void) {
  /* payload_len 255: 10 + 255 + 22 = 287 = NAVLINK_MAX_FRAME, the parser buffer. */
  uint8_t f[NAVLINK_MAX_FRAME];
  memset(f, 0xA5, sizeof f);
  f[0] = 0x56;
  f[1] = 0x02;
  f[2] = 255;
  f[3] = NAVLINK_IFLAG_ENCRYPTED;
  f[7] = 6;
  f[8] = 0;
  f[9] = 0;
  reset(1);
  g_open_ret = 255;
  navlink_parser_push(&P, &H, f, sizeof f);
  CHECK(g_open_calls == 1 && g_open_len == 287u);
  CHECK(g_hello == 1 && g_nonce0 == 0x77);
  /* one byte short: nothing yet */
  reset(1);
  g_open_ret = 255;
  navlink_parser_push(&P, &H, f, sizeof f - 1);
  CHECK(g_open_calls == 0 && g_hello == 0);
}

static void test_unknown_msgid_consumed(void) {
  navlink_sec_tx_t tx;
  uint8_t f[NAVLINK_MAX_FRAME];
  sec_reset(&tx);
  navlink_sec_hdr_t h = {.seq = 1, .sysid = 1, .compid = 1, .msgid = 0xFFFF00,
                         .payload_len = 4};
  uint8_t pl[4] = {1, 2, 3, 4};
  int r = navlink_sec_seal(&tx, f, sizeof f, NAVLINK_SEC_IFLAG_ENCRYPTED, &h, pl);
  CHECK(r > 0);
  reset(1);
  g_open_ret = -2;
  navlink_parser_push(&P, &H, f, (size_t)r);
  CHECK(g_open_calls == 1 && g_hello == 0); /* authentic, unknown: no dispatch */
}

static void test_accept_unsecured(void) {
  navlink_sec_tx_t tx;
  uint8_t f[NAVLINK_MAX_FRAME], g[NAVLINK_MAX_FRAME];
  size_t m = plain(7, g);
  reset(1);
  H.accept_unsecured = accept_hook;
  g_accept_ret = 0;
  navlink_parser_push(&P, &H, g, m);
  CHECK(g_accept_calls == 1 && g_hello == 0); /* CRC-valid, refused by policy */
  g_accept_ret = 1;
  navlink_parser_push(&P, &H, g, m);
  CHECK(g_accept_calls == 2 && g_hello == 1);
  /* a secured frame is not subject to it */
  sec_reset(&tx);
  size_t n = secured(&tx, 8, f);
  g_accept_ret = 0;
  g_open_ret = -2;
  navlink_parser_push(&P, &H, f, n);
  CHECK(g_accept_calls == 2 && g_hello == 2 && g_nonce0 == 8);
  /* a CRC failure never reaches the policy */
  g[m - 1] ^= 1;
  navlink_parser_push(&P, &H, g, m);
  CHECK(g_accept_calls == 2);
}

static int g_text, g_hb;
static void on_hb(void *ctx, const navlink_frame_hdr_t *hdr,
                  const navlink_heartbeat_t *msg) {
  (void)ctx;
  (void)hdr;
  (void)msg;
  g_hb++;
}
static void on_text(void *ctx, const navlink_frame_hdr_t *hdr,
                    const navlink_statustext_t *msg) {
  (void)ctx;
  (void)hdr;
  (void)msg;
  g_text++;
}

/* Spec 11.8: with secure_open set and no accept_unsecured, the parser is strict by
 * default: only HEARTBEAT, CAPABILITIES and the handshake pass unsecured. */
static void test_strict_by_default(void) {
  uint8_t t[NAVLINK_MAX_FRAME], hb[NAVLINK_MAX_FRAME], hs[NAVLINK_MAX_FRAME];
  navlink_statustext_t st;
  memset(&st, 0, sizeof st);
  memcpy(st.text, "x", 1);
  size_t tn = navlink_statustext_encode(t, &st, 0, 1, 1);
  navlink_heartbeat_t h0;
  memset(&h0, 0, sizeof h0);
  size_t hn = navlink_heartbeat_encode(hb, &h0, 0, 1, 1);
  size_t m = plain(7, hs); /* an unsecured HS_HELLO */

  reset(1);
  H.on_statustext = on_text;
  H.on_heartbeat = on_hb;
  g_text = g_hb = 0;
  navlink_parser_push(&P, &H, t, tn);
  CHECK(g_text == 0); /* keyed, no policy hook: a plaintext STATUSTEXT is dropped */
  navlink_parser_push(&P, &H, hs, m);
  CHECK(g_hello == 1); /* the handshake still passes */
  navlink_parser_push(&P, &H, hb, hn);
  CHECK(g_hb == 1); /* so does a HEARTBEAT */
  /* An explicit accept-all hook opts out. */
  H.accept_unsecured = accept_hook;
  g_accept_ret = 1;
  navlink_parser_push(&P, &H, t, tn);
  CHECK(g_text == 1);
  /* No secure_open: nothing is keyed, so nothing is refused (unchanged). */
  reset(0);
  H.on_statustext = on_text;
  navlink_parser_push(&P, &H, t, tn);
  CHECK(g_text == 2);
}

static void test_real_aead(void) {
  navlink_sec_tx_t tx;
  uint8_t f[NAVLINK_MAX_FRAME], t[NAVLINK_MAX_FRAME];
  sec_reset(&tx);
  size_t n = secured(&tx, 0x10, f);
  reset(1);
  g_open_ret = -2;
  navlink_parser_push(&P, &H, f, n);
  CHECK(g_hello == 1);
  navlink_parser_push(&P, &H, f, n); /* replay */
  CHECK(g_hello == 1);
  memcpy(t, f, n); /* flipped tag byte */
  t[n - 1] ^= 1;
  sec_reset(&tx);
  n = secured(&tx, 0x11, f);
  memcpy(t, f, n);
  t[n - 1] ^= 1;
  navlink_parser_push(&P, &H, t, n);
  CHECK(g_hello == 1);
  memcpy(t, f, n); /* flipped ciphertext byte */
  t[10] ^= 1;
  navlink_parser_push(&P, &H, t, n);
  CHECK(g_hello == 1);
  memcpy(t, f, n); /* header tampered: seq is AAD */
  t[4] ^= 1;
  navlink_parser_push(&P, &H, t, n);
  CHECK(g_hello == 1);
  navlink_parser_push(&P, &H, f, n); /* the untouched one still opens after the failures */
  CHECK(g_hello == 2 && g_nonce0 == 0x11);
}

int main(void) {
  test_no_hook();
  test_routed();
  test_other_bits();
  test_bad_bit_rejected_at_header();
  test_reject_and_rescan();
  test_bounds();
  test_unknown_msgid_consumed();
  test_accept_unsecured();
  test_strict_by_default();
  test_real_aead();
  puts(g_bad ? "parser_sec: FAIL" : "parser_sec: ok");
  return g_bad;
}
