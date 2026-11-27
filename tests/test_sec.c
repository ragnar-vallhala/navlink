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

/* Tests for sec/navlink_sec.c and the vendored Monocypher: RFC 8439 vectors,
 * a golden frame that tests/test_sec.py reproduces independently, and the
 * failure cases of spec section 11. */
#include "monocypher.h"
#include "navlink_sec.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int unhex(const char *h, uint8_t *out) {
  int n = 0;
  for (; h[0] && h[1]; h += 2, n++) {
    unsigned v;
    sscanf(h, "%2x", &v);
    out[n] = (uint8_t)v;
  }
  return n;
}

static void key_seq(uint8_t k[32]) {
  for (int i = 0; i < 32; i++)
    k[i] = (uint8_t)i;
}

/* RFC 8439 section 2.8.2 */
static void test_rfc8439(void) {
  uint8_t key[32], nonce[12], aad[12], tag_exp[16], ct_exp[114], ct[114],
      tag[16], back[114];
  for (int i = 0; i < 32; i++)
    key[i] = (uint8_t)(0x80 + i);
  unhex("070000004041424344454647", nonce);
  unhex("50515253c0c1c2c3c4c5c6c7", aad);
  unhex("1ae10b594f09e26a7e902ecbd0600691", tag_exp);
  unhex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e"
        "8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c"
        "9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d265"
        "86cec64b6116",
        ct_exp);
  const char *pt =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one "
      "tip for the future, sunscreen would be it.";
  assert(strlen(pt) == 114);
  crypto_aead_ctx c;
  crypto_aead_init_ietf(&c, key, nonce);
  crypto_aead_write(&c, ct, tag, aad, 12, (const uint8_t *)pt, 114);
  assert(memcmp(ct, ct_exp, 114) == 0);
  assert(memcmp(tag, tag_exp, 16) == 0);
  crypto_aead_init_ietf(&c, key, nonce);
  assert(crypto_aead_read(&c, back, tag, aad, 12, ct, 114) == 0);
  assert(memcmp(back, pt, 114) == 0);
  tag[0] ^= 1;
  crypto_aead_init_ietf(&c, key, nonce);
  assert(crypto_aead_read(&c, back, tag, aad, 12, ct, 114) != 0);
}

/* RFC 7693 appendix A: BLAKE2b-512("abc") */
static void test_blake2b(void) {
  uint8_t exp[64], h[64];
  unhex("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        exp);
  crypto_blake2b(h, 64, (const uint8_t *)"abc", 3);
  assert(memcmp(h, exp, 64) == 0);
}

static const char *GOLD_KS =
    "e39d895c3b4c260f29a2a8669b62e32f34c42f0ab83d07db569fbfd0b4f3b4a0";
static const char *GOLD_FRAME =
    "56020d020501010201008233895a406a47cbe3b3bd40a6000000000000b761956991c4ee47"
    "3ec698a19a5f819e";
#define GOLD_KEY_ID 385178778u

static void setup(navlink_sec_tx_t *tx, navlink_sec_rx_t *rx, uint8_t dir) {
  uint8_t ks[32], k[32], n[16], uid[12];
  key_seq(k);
  for (int i = 0; i < 16; i++)
    n[i] = (uint8_t)i;
  for (int i = 0; i < 12; i++)
    uid[i] = (uint8_t)i;
  navlink_sec_derive(ks, k, dir, n, 7, 3, uid);
  assert(navlink_sec_tx_init(tx, ks, dir) == 0);
  assert(navlink_sec_rx_init(rx, ks, dir) == 0);
}

static const navlink_sec_hdr_t H = {5, 1, 1, 0x000102, 13};
static const uint8_t PL[] = "hello navlink"; /* 13 bytes; the NUL is not sent */

static void test_golden(void) {
  uint8_t ks[32], exp[32], k[32], n[16], uid[12], f[300], want[300];
  key_seq(k);
  for (int i = 0; i < 16; i++)
    n[i] = (uint8_t)i;
  for (int i = 0; i < 12; i++)
    uid[i] = (uint8_t)i;
  navlink_sec_derive(ks, k, NAVLINK_SEC_DIR_GCS_TO_FC, n, 7, 3, uid);
  unhex(GOLD_KS, exp);
  assert(memcmp(ks, exp, 32) == 0);
  assert(navlink_sec_key_id(k) == GOLD_KEY_ID);
  navlink_sec_tx_t tx;
  navlink_sec_rx_t rx;
  setup(&tx, &rx, NAVLINK_SEC_DIR_GCS_TO_FC);
  int n1 = navlink_sec_seal(&tx, f, sizeof f, NAVLINK_SEC_IFLAG_ENCRYPTED, &H, PL);
  assert(n1 == 45);
  assert(unhex(GOLD_FRAME, want) == 45);
  assert(memcmp(f, want, 45) == 0);
  navlink_sec_hdr_t h;
  uint8_t out[255];
  assert(navlink_sec_open(&rx, f, 45, &h, out) == 13);
  assert(memcmp(out, PL, 13) == 0 && h.msgid == 0x102 && h.seq == 5);
}

static void test_failures(void) {
  navlink_sec_tx_t tx;
  navlink_sec_rx_t rx;
  navlink_sec_hdr_t h;
  uint8_t f[300], g[300], out[255];
  setup(&tx, &rx, NAVLINK_SEC_DIR_GCS_TO_FC);
  int n = navlink_sec_seal(&tx, f, sizeof f, NAVLINK_SEC_IFLAG_ENCRYPTED, &H, PL);

  /* every single-bit flip anywhere in the frame is rejected, and a rejected
   * frame leaves the receive state alone */
  for (int b = 0; b < n * 8; b++) {
    memcpy(g, f, (size_t)n);
    g[b / 8] ^= (uint8_t)(1u << (b % 8));
    memset(out, 0xAA, sizeof out);
    assert(navlink_sec_open(&rx, g, (size_t)n, &h, out) < 0);
    assert(out[0] == 0xAA && !rx.have);
  }
  /* the untouched frame still opens, once */
  assert(navlink_sec_open(&rx, f, (size_t)n, &h, out) == 13);
  assert(navlink_sec_open(&rx, f, (size_t)n, &h, out) == NAVLINK_SEC_ERR_COUNTER);

  /* wrong key */
  navlink_sec_rx_t bad;
  uint8_t k2[32] = {1};
  navlink_sec_rx_init(&bad, k2, NAVLINK_SEC_DIR_GCS_TO_FC);
  assert(navlink_sec_open(&bad, f, (size_t)n, &h, out) == NAVLINK_SEC_ERR_TAG);

  /* a frame sent one way does not open the other way (direction in the AAD) */
  navlink_sec_rx_t other;
  navlink_sec_rx_init(&other, rx.key, NAVLINK_SEC_DIR_FC_TO_GCS);
  assert(navlink_sec_open(&other, f, (size_t)n, &h, out) == NAVLINK_SEC_ERR_TAG);

  /* The FC->GCS (telemetry) direction has a reorder window; the GCS->FC (command)
   * direction is strict (checked below).
   * reorder: 0,1,2 sent; 2 then 1 then 0 arrive. Inside the window each is
   * taken ONCE; a second copy is a replay. */
  setup(&tx, &rx, NAVLINK_SEC_DIR_FC_TO_GCS);
  uint8_t fr[3][300];
  int ln[3];
  for (int i = 0; i < 3; i++)
    ln[i] = navlink_sec_seal(&tx, fr[i], 300, NAVLINK_SEC_IFLAG_ENCRYPTED, &H, PL);
  assert(navlink_sec_open(&rx, fr[2], (size_t)ln[2], &h, out) == 13);
  assert(navlink_sec_open(&rx, fr[1], (size_t)ln[1], &h, out) == 13);
  assert(navlink_sec_open(&rx, fr[1], (size_t)ln[1], &h, out) ==
         NAVLINK_SEC_ERR_COUNTER); /* replay of one just taken */
  assert(navlink_sec_open(&rx, fr[2], (size_t)ln[2], &h, out) ==
         NAVLINK_SEC_ERR_COUNTER); /* and of the highest */
  assert(navlink_sec_open(&rx, fr[0], (size_t)ln[0], &h, out) == 13);
  assert(navlink_sec_open(&rx, fr[0], (size_t)ln[0], &h, out) ==
         NAVLINK_SEC_ERR_COUNTER);

  /* the window ends: with W frames sent, the oldest is outside it once the
   * newest is taken, and the one just inside is taken */
  {
    enum { W = NAVLINK_SEC_REPLAY_WINDOW };
    static uint8_t wf[W + 2][300];
    int wl[W + 2];
    setup(&tx, &rx, NAVLINK_SEC_DIR_FC_TO_GCS);
    for (int i = 0; i < W + 2; i++)
      wl[i] = navlink_sec_seal(&tx, wf[i], 300, NAVLINK_SEC_IFLAG_ENCRYPTED, &H, PL);
    assert(navlink_sec_open(&rx, wf[W + 1], (size_t)wl[W + 1], &h, out) == 13);
    /* counter W+1 is the highest: W+1-W = 1 is exactly W - 1 below -> taken */
    assert(navlink_sec_open(&rx, wf[2], (size_t)wl[2], &h, out) == 13);
    assert(navlink_sec_open(&rx, wf[1], (size_t)wl[1], &h, out) ==
           NAVLINK_SEC_ERR_COUNTER); /* W below: outside */
    assert(navlink_sec_open(&rx, wf[0], (size_t)wl[0], &h, out) ==
           NAVLINK_SEC_ERR_COUNTER);
  }
  /* a jump of 64 or more forgets the map: the old frames are outside anyway */
  {
    static uint8_t jf[70][300];
    int jl[70];
    setup(&tx, &rx, NAVLINK_SEC_DIR_FC_TO_GCS);
    for (int i = 0; i < 70; i++)
      jl[i] = navlink_sec_seal(&tx, jf[i], 300, NAVLINK_SEC_IFLAG_ENCRYPTED, &H, PL);
    assert(navlink_sec_open(&rx, jf[3], (size_t)jl[3], &h, out) == 13);
    assert(navlink_sec_open(&rx, jf[69], (size_t)jl[69], &h, out) == 13);
    assert(navlink_sec_open(&rx, jf[3], (size_t)jl[3], &h, out) ==
           NAVLINK_SEC_ERR_COUNTER);
    assert(navlink_sec_open(&rx, jf[68], (size_t)jl[68], &h, out) == 13);
    assert(navlink_sec_open(&rx, jf[68], (size_t)jl[68], &h, out) ==
           NAVLINK_SEC_ERR_COUNTER);
  }
  /* a forged frame inside the window does not mark its counter as seen */
  setup(&tx, &rx, NAVLINK_SEC_DIR_FC_TO_GCS);
  for (int i = 0; i < 3; i++)
    ln[i] = navlink_sec_seal(&tx, fr[i], 300, NAVLINK_SEC_IFLAG_ENCRYPTED, &H, PL);
  assert(navlink_sec_open(&rx, fr[2], (size_t)ln[2], &h, out) == 13);
  uint8_t forged[300];
  memcpy(forged, fr[1], (size_t)ln[1]);
  forged[ln[1] - 1] ^= 1;
  assert(navlink_sec_open(&rx, forged, (size_t)ln[1], &h, out) == NAVLINK_SEC_ERR_TAG);
  assert(navlink_sec_open(&rx, fr[1], (size_t)ln[1], &h, out) == 13); /* the real one */

  /* a jump of 17..63 keeps the map: the frame W-1 below the new top is taken once */
  {
    enum { W = NAVLINK_SEC_REPLAY_WINDOW };
    static uint8_t qf[40][300];
    int ql[40];
    setup(&tx, &rx, NAVLINK_SEC_DIR_FC_TO_GCS);
    for (int i = 0; i < 40; i++)
      ql[i] = navlink_sec_seal(&tx, qf[i], 300, NAVLINK_SEC_IFLAG_ENCRYPTED, &H, PL);
    assert(navlink_sec_open(&rx, qf[2], (size_t)ql[2], &h, out) == 13);
    assert(navlink_sec_open(&rx, qf[30], (size_t)ql[30], &h, out) == 13); /* jump of 28 */
    assert(navlink_sec_open(&rx, qf[30 - (W - 1)], (size_t)ql[30 - (W - 1)], &h, out) == 13);
    assert(navlink_sec_open(&rx, qf[30 - (W - 1)], (size_t)ql[30 - (W - 1)], &h, out) ==
           NAVLINK_SEC_ERR_COUNTER);
    assert(navlink_sec_open(&rx, qf[30 - W], (size_t)ql[30 - W], &h, out) ==
           NAVLINK_SEC_ERR_COUNTER);
  }
  /* GCS->FC (commands) is strict: a held-back frame is refused once a later one
   * is taken, so a command cannot be reordered past another */
  {
    uint8_t cf[3][300];
    int cl[3];
    setup(&tx, &rx, NAVLINK_SEC_DIR_GCS_TO_FC);
    assert(rx.window == NAVLINK_SEC_REPLAY_WINDOW_CMD);
    for (int i = 0; i < 3; i++)
      cl[i] = navlink_sec_seal(&tx, cf[i], 300, NAVLINK_SEC_IFLAG_ENCRYPTED, &H, PL);
    assert(navlink_sec_open(&rx, cf[0], (size_t)cl[0], &h, out) == 13);
    assert(navlink_sec_open(&rx, cf[2], (size_t)cl[2], &h, out) == 13);
    assert(navlink_sec_open(&rx, cf[1], (size_t)cl[1], &h, out) ==
           NAVLINK_SEC_ERR_COUNTER);
  }

  /* a forged huge counter with a bad tag does not move the receiver, so the
   * next real frame still opens */
  setup(&tx, &rx, NAVLINK_SEC_DIR_GCS_TO_FC);
  n = navlink_sec_seal(&tx, f, sizeof f, NAVLINK_SEC_IFLAG_ENCRYPTED, &H, PL);
  memcpy(g, f, (size_t)n);
  memset(g + n - 22, 0xFF, 6);
  assert(navlink_sec_open(&rx, g, (size_t)n, &h, out) == NAVLINK_SEC_ERR_TAG);
  assert(navlink_sec_open(&rx, f, (size_t)n, &h, out) == 13);

  /* downgrade: the flags byte stripped to unsigned/clear is not accepted */
  memcpy(g, f, (size_t)n);
  g[3] = 0;
  assert(navlink_sec_open(&rx, g, (size_t)n, &h, out) == NAVLINK_SEC_ERR_FORMAT);
  /* SIGNED is not implemented: sealing it is refused */
  assert(navlink_sec_seal(&tx, g, sizeof g, NAVLINK_SEC_IFLAG_SIGNED, &H, PL) ==
         NAVLINK_SEC_ERR_UNSUPPORTED);
  /* truncated and over-long frames */
  assert(navlink_sec_open(&rx, f, (size_t)n - 1, &h, out) == NAVLINK_SEC_ERR_SIZE);
  assert(navlink_sec_open(&rx, f, 5, &h, out) == NAVLINK_SEC_ERR_SIZE);
  /* output too small */
  assert(navlink_sec_seal(&tx, g, 20, NAVLINK_SEC_IFLAG_ENCRYPTED, &H, PL) ==
         NAVLINK_SEC_ERR_SIZE);
}

static void test_counter_max_and_full_frame(void) {
  navlink_sec_tx_t tx;
  navlink_sec_rx_t rx;
  navlink_sec_hdr_t h;
  uint8_t f[300], out[255], pl[255];
  memset(pl, 0x5A, sizeof pl);
  setup(&tx, &rx, NAVLINK_SEC_DIR_FC_TO_GCS);
  navlink_sec_hdr_t big = {9, 1, 1, 0xABCDEF, 255};
  int n = navlink_sec_seal(&tx, f, sizeof f, NAVLINK_SEC_IFLAG_ENCRYPTED, &big, pl);
  assert(n == NAVLINK_SEC_MAX_FRAME);
  assert(navlink_sec_open(&rx, f, (size_t)n, &h, out) == 255);
  assert(h.msgid == 0xABCDEF && memcmp(out, pl, 255) == 0);
  /* zero-length payload */
  navlink_sec_hdr_t z = {1, 1, 1, 7, 0};
  n = navlink_sec_seal(&tx, f, sizeof f, NAVLINK_SEC_IFLAG_ENCRYPTED, &z, NULL);
  assert(n == 32 && navlink_sec_open(&rx, f, (size_t)n, &h, out) == 0);

  /* the last counter is used, then the session is closed, never wrapped */
  tx.counter = NAVLINK_SEC_COUNTER_MAX - 1;
  assert(navlink_sec_seal(&tx, f, sizeof f, NAVLINK_SEC_IFLAG_ENCRYPTED, &H, PL) > 0);
  assert(navlink_sec_seal(&tx, f, sizeof f, NAVLINK_SEC_IFLAG_ENCRYPTED, &H, PL) ==
         NAVLINK_SEC_ERR_CLOSED);
  assert(tx.closed);
}

static void test_same_hello_new_keys(void) {
  uint8_t k[32], n[16], uid[12], a[32], b[32], c[32], d[32];
  key_seq(k);
  memset(n, 7, 16);
  memset(uid, 3, 12);
  /* the same HELLO twice in one boot: the FC's handshake counter has moved */
  navlink_sec_derive(a, k, 1, n, 7, 1, uid);
  navlink_sec_derive(b, k, 1, n, 7, 2, uid);
  assert(memcmp(a, b, 32) != 0);
  /* a new boot, same HELLO and handshake counter */
  navlink_sec_derive(c, k, 1, n, 8, 1, uid);
  assert(memcmp(a, c, 32) != 0);
  /* the two directions never share a key */
  navlink_sec_derive(d, k, 0, n, 7, 1, uid);
  assert(memcmp(a, d, 32) != 0);
  /* a different vehicle */
  uid[0] ^= 1;
  navlink_sec_derive(d, k, 1, n, 7, 1, uid);
  assert(memcmp(a, d, 32) != 0);
}

int main(void) {
  test_rfc8439();
  test_blake2b();
  test_golden();
  test_failures();
  test_counter_max_and_full_frame();
  test_same_hello_new_keys();
  puts("test_sec: ok");
  return 0;
}
