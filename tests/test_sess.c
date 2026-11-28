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

/* Tests for sec/navlink_sess.c: the handshake and the live/pending slots. */
#include "navlink_msgs.h"
#include "navlink_sess.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* The handshake messages in the dialect and the session code must agree. */
_Static_assert(NAVLINK_WIRE_SIZE_HS_HELLO == NAVLINK_HS_HELLO_LEN, "hello size");
_Static_assert(NAVLINK_WIRE_SIZE_HS_REPLY == NAVLINK_HS_REPLY_LEN, "reply size");
_Static_assert(NAVLINK_MAX_FRAME == NAVLINK_SEC_MAX_FRAME, "max secured frame");
_Static_assert(NAVLINK_MSGID_HS_HELLO == 6u && NAVLINK_MSGID_HS_REPLY == 7u,
               "handshake ids");

static const uint8_t K[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                              16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                              29, 30, 31};
static const uint8_t UID[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
static const navlink_sec_hdr_t H = {1, 1, 1, 7, 4};
static const uint8_t PL[4] = {1, 2, 3, 4};
#define E NAVLINK_SEC_IFLAG_ENCRYPTED

static navlink_hs_info_t INFO;
static uint32_t NOW;

static void nonce(uint8_t n[16], uint8_t v) { memset(n, v, 16); }

/* One full connect: GCS HELLO, FC reply, GCS first frame, FC verifies it. */
static void connect_pair(navlink_fc_t *fc, navlink_gcs_t *g, uint32_t t,
                         uint8_t nv) {
  uint8_t n[16], hello[16], reply[52], f[300], out[255];
  navlink_sec_hdr_t h;
  nonce(n, nv);
  assert(navlink_gcs_hello(g, n, NULL, hello) == 16);
  assert(navlink_fc_hello(fc, t, hello, reply) == 52);
  assert(navlink_gcs_reply(g, reply, 52, &INFO) == 0);
  int l = navlink_gcs_seal(g, NOW, f, sizeof f, E, &H, PL);
  assert(l > 0);
  assert(navlink_fc_open(fc, t + 10, f, (size_t)l, &h, out) == 4);
}

static void test_golden(void) {
  navlink_fc_t fc;
  navlink_gcs_t g;
  uint8_t hello[16], reply[52], n[16];
  for (int i = 0; i < 16; i++)
    n[i] = (uint8_t)i;
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  assert(navlink_gcs_init(&g, K) == 0);
  navlink_gcs_hello(&g, n, NULL, hello);
  assert(navlink_fc_hello(&fc, 0, hello, reply) == 52);
  /* fc_hs_ctr is 1 for the first HELLO of a boot; the frame test uses 7 and 3 */
  assert(reply[16] == 7 && reply[20] == 1);
  assert(navlink_gcs_reply(&g, reply, 52, &INFO) == 0);
  /* the golden reply, reproduced by tests/test_sess.py */
  static const char *GOLD =
      "000102030405060708090a0b0c0d0e0f07000000010000000001020304050607"
      "08090a0b";
  char hex[160];
  for (int i = 0; i < 36; i++)
    sprintf(hex + 2 * i, "%02x", reply[i]);
  assert(strncmp(hex, GOLD, 72) == 0);
  static const char *GOLD_MAC = "e9184bceca2b9c815b9651ca328d2774";
  for (int i = 36; i < 52; i++)
    sprintf(hex + 2 * (i - 36), "%02x", reply[i]);
  assert(strncmp(hex, GOLD_MAC, 32) == 0);
  /* the generated codec reads the same bytes as the same fields */
  navlink_hs_reply_wire_t w;
  navlink_hs_reply_unpack(&w, reply, 52);
  assert(w.fc_boot_ctr == 7u && w.fc_hs_ctr == 1u);
  assert(memcmp(w.gcs_nonce, n, 16) == 0 && memcmp(w.uid, UID, 12) == 0);
  assert(memcmp(w.mac, reply + 36, 16) == 0);
  /* the first ground-station frame under these keys, reproduced by
   * tests/test_sess.py from hashlib and the cryptography package */
  static const char *GOLD_FRAME =
      "56020402010101070000a55eda0400000000000082f8de702737e1001ef44bfc0c07d2a5";
  uint8_t f[300];
  int l = navlink_gcs_seal(&g, NOW, f, sizeof f, E, &H, PL);
  assert(l == 36);
  for (int i = 0; i < l; i++)
    sprintf(hex + 2 * i, "%02x", f[i]);
  assert(strcmp(hex, GOLD_FRAME) == 0);
}

static void test_basic_roundtrip(void) {
  navlink_fc_t fc;
  navlink_gcs_t g;
  uint8_t f[300], out[255];
  navlink_sec_hdr_t h;
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  assert(navlink_gcs_init(&g, K) == 0);
  /* nothing live yet: sealing refuses, opening refuses */
  assert(navlink_fc_seal(&fc, f, sizeof f, E, &H, PL) == NAVLINK_SESS_ERR_NOSESSION);
  connect_pair(&fc, &g, 0, 1);
  /* both directions work, in order */
  int l = navlink_fc_seal(&fc, f, sizeof f, E, &H, PL);
  assert(l > 0 && navlink_gcs_open(&g, f, (size_t)l, &h, out) == 4);
  l = navlink_gcs_seal(&g, NOW, f, sizeof f, E, &H, PL);
  assert(l > 0 && navlink_fc_open(&fc, 20, f, (size_t)l, &h, out) == 4);
  /* a GCS frame is not accepted as an FC frame and the reverse */
  l = navlink_gcs_seal(&g, NOW, f, sizeof f, E, &H, PL);
  assert(navlink_gcs_open(&g, f, (size_t)l, &h, out) < 0);
}

static void test_hello_during_live_session(void) {
  navlink_fc_t fc;
  navlink_gcs_t g;
  uint8_t f[300], out[255], hello[16], reply[52], n[16];
  navlink_sec_hdr_t h;
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  assert(navlink_gcs_init(&g, K) == 0);
  connect_pair(&fc, &g, 0, 1);
  /* an attacker, no key, HELLOs; the live session keeps working both ways */
  nonce(n, 0x66);
  assert(navlink_fc_hello(&fc, 2000, n, reply) == 52);
  for (int i = 0; i < 5; i++) {
    int l = navlink_gcs_seal(&g, NOW, f, sizeof f, E, &H, PL);
    assert(navlink_fc_open(&fc, 2100 + i, f, (size_t)l, &h, out) == 4);
    l = navlink_fc_seal(&fc, f, sizeof f, E, &H, PL);
    assert(navlink_gcs_open(&g, f, (size_t)l, &h, out) == 4);
  }
  /* garbage and a frame forged without K do not promote the pending session */
  memset(f, 0x55, 40);
  assert(navlink_fc_open(&fc, 2200, f, 40, &h, out) < 0);
  assert(fc.pending[0].s.valid);
  /* it expires after 5 s, live untouched */
  navlink_fc_tick(&fc, 2000 + NAVLINK_SESS_PENDING_MS);
  assert(!fc.pending[0].s.valid && fc.live.valid);
  int l = navlink_gcs_seal(&g, NOW, f, sizeof f, E, &H, PL);
  assert(navlink_fc_open(&fc, 8000, f, (size_t)l, &h, out) == 4);
  (void)hello;
}

static void test_promotion_and_old_session(void) {
  navlink_fc_t fc;
  navlink_gcs_t g1, g2;
  uint8_t f1[300], f2[300], out[255], hello[16], reply[52], n[16];
  navlink_sec_hdr_t h;
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  assert(navlink_gcs_init(&g1, K) == 0);
  assert(navlink_gcs_init(&g2, K) == 0);
  connect_pair(&fc, &g1, 0, 1);
  int l1 = navlink_gcs_seal(&g1, NOW, f1, sizeof f1, E, &H, PL);
  /* the real GCS reconnects (restart): HELLO, reply, first frame */
  nonce(n, 2);
  navlink_gcs_hello(&g2, n, NULL, hello);
  assert(navlink_fc_hello(&fc, 3000, hello, reply) == 52);
  assert(navlink_gcs_reply(&g2, reply, 52, &INFO) == 0);
  /* before the first frame, the old session still works */
  assert(navlink_fc_open(&fc, 3100, f1, (size_t)l1, &h, out) == 4);
  int l2 = navlink_gcs_seal(&g2, NOW, f2, sizeof f2, E, &H, PL);
  assert(navlink_fc_open(&fc, 3200, f2, (size_t)l2, &h, out) == 4);
  /* promoted: the old session's next frame no longer verifies */
  l1 = navlink_gcs_seal(&g1, NOW, f1, sizeof f1, E, &H, PL);
  assert(navlink_fc_open(&fc, 3300, f1, (size_t)l1, &h, out) < 0);
  /* and the FC now talks under the new keys, which g2 reads */
  int l = navlink_fc_seal(&fc, f2, sizeof f2, E, &H, PL);
  assert(navlink_gcs_open(&g2, f2, (size_t)l, &h, out) == 4);
  assert(navlink_gcs_open(&g1, f2, (size_t)l, &h, out) < 0);
}

static void test_rate_and_repeat(void) {
  navlink_fc_t fc;
  uint8_t reply[52], n[16];
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  /* a burst of NAVLINK_SESS_HELLO_BURST HELLOs is taken, the next one is not */
  for (uint8_t i = 1; i <= NAVLINK_SESS_HELLO_BURST; i++) {
    nonce(n, i);
    assert(navlink_fc_hello(&fc, 5000, n, reply) == 52);
  }
  nonce(n, 9);
  const uint32_t hs = fc.hs_ctr;
  assert(navlink_fc_hello(&fc, 5000, n, reply) == NAVLINK_SESS_ERR_RATE);
  assert(navlink_fc_hello(&fc, 5999, n, reply) == NAVLINK_SESS_ERR_RATE);
  assert(fc.hs_ctr == hs); /* refused, nothing changed */
  /* the budget refills one HELLO per second */
  assert(navlink_fc_hello(&fc, 6000, n, reply) == 52);
  /* the same nonce again, after the refill: dropped, and no budget is spent */
  assert(navlink_fc_hello(&fc, 7000, n, reply) == NAVLINK_SESS_ERR_REPEAT);
  nonce(n, 10);
  assert(navlink_fc_hello(&fc, 7000, n, reply) == 52);
  nonce(n, 11);
  assert(navlink_fc_hello(&fc, 7500, n, reply) == NAVLINK_SESS_ERR_RATE);
  /* a counter that wraps the 32-bit clock still measures the gap */
  navlink_fc_t f2;
  assert(navlink_fc_init(&f2, K, UID, 7) == 0);
  for (uint8_t i = 1; i <= NAVLINK_SESS_HELLO_BURST; i++) {
    nonce(n, 20 + i);
    assert(navlink_fc_hello(&f2, 0xFFFFFF00u, n, reply) == 52);
  }
  nonce(n, 30);
  assert(navlink_fc_hello(&f2, 0xFFFFFF10u, n, reply) == NAVLINK_SESS_ERR_RATE);
  assert(navlink_fc_hello(&f2, 0xFFFFFF00u + 1000u, n, reply) == 52);
}

/* A keyless sender sending a HELLO per second, one landing between the
 * real HELLO and the real first frame, must not stop the connect. With one pending
 * slot and a fixed 1 s gap the real HELLO was refused or its slot was replaced. */
static void test_flood_does_not_starve_connect(void) {
  navlink_fc_t fc;
  navlink_gcs_t g;
  uint8_t atk[16], hello[16], reply[52], f[300], out[255], n[16];
  navlink_sec_hdr_t h;
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  assert(navlink_gcs_init(&g, K) == 0);
  for (uint32_t t = 0; t < 4000; t += 1000) {
    nonce(atk, (uint8_t)(0x40 + t / 1000));
    assert(navlink_fc_hello(&fc, t, atk, reply) == 52);
  }
  nonce(n, 1);
  assert(navlink_gcs_hello(&g, n, NULL, hello) == 16);
  assert(navlink_fc_hello(&fc, 3500, hello, reply) == 52); /* inside the second */
  assert(navlink_gcs_reply(&g, reply, 52, &INFO) == 0);
  /* more attacker HELLOs before the real first frame lands: they take other
   * slots, the real session is still pending, and the budget runs out for them */
  nonce(atk, 0x60);
  assert(navlink_fc_hello(&fc, 3600, atk, reply) == 52);
  nonce(atk, 0x61);
  assert(navlink_fc_hello(&fc, 3601, atk, reply) == 52);
  nonce(atk, 0x62);
  assert(navlink_fc_hello(&fc, 3602, atk, reply) == NAVLINK_SESS_ERR_RATE);
  int l = navlink_gcs_seal(&g, NOW, f, sizeof f, E, &H, PL);
  assert(l > 0);
  assert(navlink_fc_open(&fc, 3700, f, (size_t)l, &h, out) == 4);
  assert(fc.live.valid);
}

/* The budget is shared: a flooder that rotates its peer id spends it, and the
 * real HELLO is then refused until it refills. This documents the limit. */
static void test_rotating_peer_flood_spends_shared_budget(void) {
  navlink_fc_t fc;
  uint8_t n[16], reply[52];
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  int ok = 0;
  for (uint32_t p = 100; p < 120; p++) { /* 20 HELLOs in 20 ms, a new id each */
    nonce(n, (uint8_t)p);
    ok += navlink_fc_hello_peer(&fc, p - 100u, p, n, reply) == 52;
  }
  assert(ok == (int)NAVLINK_SESS_HELLO_BURST); /* only the burst got through */
  nonce(n, 0xEE);
  assert(navlink_fc_hello_peer(&fc, 30, 5, n, reply) == NAVLINK_SESS_ERR_RATE);
  assert(navlink_fc_hello_peer(&fc, 1030, 5, n, reply) == 52); /* a second later */
}

/* A pending session recorded with (sysid, compid) opens only frames from that
 * address; one recorded without keeps trying every frame. */
static void test_hello_from_address_filter(void) {
  navlink_fc_t fc;
  navlink_gcs_t g;
  uint8_t n[16], hello[16], reply[52], f[300], out[255];
  navlink_sec_hdr_t h;
  const navlink_sec_hdr_t other = {1, 9, 9, 7, 4}; /* same key, another address */
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  assert(navlink_gcs_init(&g, K) == 0);
  nonce(n, 1);
  assert(navlink_gcs_hello(&g, n, NULL, hello) == 16);
  assert(navlink_fc_hello_from(&fc, 0, 0, 1, 1, hello, reply) == 52);
  assert(navlink_gcs_reply(&g, reply, 52, &INFO) == 0);
  int l = navlink_gcs_seal(&g, NOW, f, sizeof f, E, &other, PL);
  assert(l > 0);
  /* the key is right but the address is not the recorded one: not tried */
  assert(navlink_fc_open(&fc, 100, f, (size_t)l, &h, out) ==
         NAVLINK_SESS_ERR_NOSESSION);
  l = navlink_gcs_seal(&g, NOW, f, sizeof f, E, &H, PL);
  assert(l > 0);
  assert(navlink_fc_open(&fc, 200, f, (size_t)l, &h, out) == 4); /* recorded address */

  /* without an address the old behaviour: any address that verifies is taken */
  assert(navlink_fc_init(&fc, K, UID, 8) == 0);
  nonce(n, 2);
  assert(navlink_gcs_hello(&g, n, NULL, hello) == 16);
  assert(navlink_fc_hello(&fc, 0, hello, reply) == 52);
  assert(navlink_gcs_reply(&g, reply, 52, &INFO) == 0);
  l = navlink_gcs_seal(&g, NOW, f, sizeof f, E, &other, PL);
  assert(navlink_fc_open(&fc, 100, f, (size_t)l, &h, out) == 4);
}

/* The peer whose session is live has a reserve a rotating-id flood cannot spend. */
static void test_live_peer_reserve(void) {
  navlink_fc_t fc;
  navlink_gcs_t g;
  uint8_t n[16], hello[16], reply[52], f[300], out[255];
  navlink_sec_hdr_t h;
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  assert(navlink_gcs_init(&g, K) == 0);
  nonce(n, 1);
  assert(navlink_gcs_hello(&g, n, NULL, hello) == 16);
  assert(navlink_fc_hello_peer(&fc, 0, 500, hello, reply) == 52);
  assert(navlink_gcs_reply(&g, reply, 52, &INFO) == 0);
  int l = navlink_gcs_seal(&g, NOW, f, sizeof f, E, &H, PL);
  assert(l > 0);
  assert(navlink_fc_open(&fc, 100, f, (size_t)l, &h, out) == 4); /* peer 500 is live */
  /* a flood of fresh ids spends the shared budget */
  uint32_t t = 200;
  int ok = 0;
  for (uint32_t p = 1000; p < 1030; p++) {
    nonce(n, (uint8_t)p);
    ok += navlink_fc_hello_peer(&fc, t, p, n, reply) == 52;
  }
  assert(ok >= 1 && ok <= (int)NAVLINK_SESS_HELLO_BURST);
  nonce(n, 0xE0);
  assert(navlink_fc_hello_peer(&fc, t, 2000, n, reply) == NAVLINK_SESS_ERR_RATE);
  /* the live peer still gets in while the shared budget is empty; its own 1/s
   * limit applies, and the flood did not touch its reserve */
  nonce(n, 0xE1);
  assert(navlink_fc_hello_peer(&fc, t, 500, n, reply) == 52);
  nonce(n, 0xE2);
  assert(navlink_fc_hello_peer(&fc, t + 500, 500, n, reply) == NAVLINK_SESS_ERR_RATE);
  nonce(n, 0xE3);
  assert(navlink_fc_hello_peer(&fc, t + 1000, 500, n, reply) == 52);
}

/* With a peer id, one sender holds one slot and has its own 1/s limit. */
static void test_peer_slots(void) {
  navlink_fc_t fc;
  uint8_t n[16], reply[52];
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  nonce(n, 1);
  assert(navlink_fc_hello_peer(&fc, 0, 77, n, reply) == 52);
  nonce(n, 2);
  assert(navlink_fc_hello_peer(&fc, 500, 77, n, reply) == NAVLINK_SESS_ERR_RATE);
  assert(navlink_fc_hello_peer(&fc, 1000, 77, n, reply) == 52);
  int used = 0;
  for (int i = 0; i < NAVLINK_SESS_PENDING_SLOTS; i++)
    used += fc.pending[i].s.valid;
  assert(used == 1); /* the second HELLO replaced the first, same peer */
  /* other peers fill the rest; one more evicts the oldest, never a newer one */
  for (uint32_t p = 1; p <= 3; p++) {
    nonce(n, (uint8_t)(10 + p));
    assert(navlink_fc_hello_peer(&fc, 1000, p, n, reply) == 52);
  }
  used = 0;
  for (int i = 0; i < NAVLINK_SESS_PENDING_SLOTS; i++)
    used += fc.pending[i].s.valid;
  assert(used == NAVLINK_SESS_PENDING_SLOTS);
  nonce(n, 50);
  assert(navlink_fc_hello_peer(&fc, 2000, 99, n, reply) == 52);
  int p77 = 0;
  for (int i = 0; i < NAVLINK_SESS_PENDING_SLOTS; i++)
    p77 += fc.pending[i].s.valid && fc.pending[i].peer == 77;
  assert(p77 == 0); /* all four were the same age; the first slot (77) went */
  /* a pending session expires on its own */
  navlink_fc_tick(&fc, 2000 + NAVLINK_SESS_PENDING_MS);
  for (int i = 0; i < NAVLINK_SESS_PENDING_SLOTS; i++)
    assert(!fc.pending[i].s.valid);
}

static void test_ring_forgets_old(void) {
  navlink_fc_t fc;
  uint8_t reply[52], n[16];
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  uint32_t t = 0;
  for (uint8_t i = 1; i <= NAVLINK_SESS_NONCE_RING + 2; i++) {
    nonce(n, i);
    t += 1000;
    assert(navlink_fc_hello(&fc, t, n, reply) == 52);
  }
  /* the most recent are remembered; the oldest has left the ring */
  nonce(n, NAVLINK_SESS_NONCE_RING + 2);
  t += 1000;
  assert(navlink_fc_hello(&fc, t, n, reply) == NAVLINK_SESS_ERR_REPEAT);
  nonce(n, 1);
  t += 1000;
  assert(navlink_fc_hello(&fc, t, n, reply) == 52);
}

static void test_same_hello_different_keys(void) {
  navlink_fc_t fc, fc2;
  uint8_t r1[52], r2[52], n[16];
  nonce(n, 5);
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  assert(navlink_fc_hello(&fc, 0, n, r1) == 52);
  uint8_t key1[32];
  memcpy(key1, fc.pending[0].s.rx.key, 32);
  /* a second boot with the same HELLO: different boot counter, different key */
  assert(navlink_fc_init(&fc2, K, UID, 8) == 0);
  assert(navlink_fc_hello(&fc2, 0, n, r2) == 52);
  assert(memcmp(key1, fc2.pending[0].s.rx.key, 32) != 0);
  assert(memcmp(r1 + 16, r2 + 16, 4) != 0);
  /* in one boot: the ring drops the repeat, so the key cannot be reused; if the
   * ring had forgotten it, hs_ctr alone would still change the key (test_sec) */
  assert(navlink_fc_hello(&fc, 2000, n, r2) == NAVLINK_SESS_ERR_REPEAT);
}

static void test_reply_checks(void) {
  navlink_fc_t fc;
  navlink_gcs_t g, g2;
  uint8_t n[16], hello[16], reply[52], bad[52], f[300];
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  assert(navlink_gcs_init(&g, K) == 0);
  nonce(n, 1);
  navlink_gcs_hello(&g, n, NULL, hello);
  assert(navlink_fc_hello(&fc, 0, hello, reply) == 52);
  /* every bit of the reply matters */
  for (int b = 0; b < 52 * 8; b++) {
    memcpy(bad, reply, 52);
    bad[b / 8] ^= (uint8_t)(1u << (b % 8));
    assert(navlink_gcs_reply(&g, bad, 52, &INFO) == NAVLINK_SESS_ERR_REPLY);
    assert(!g.next.valid && g.waiting);
  }
  assert(navlink_gcs_reply(&g, reply, 51, &INFO) == NAVLINK_SEC_ERR_SIZE);
  /* the genuine reply is taken once; a second copy is refused */
  assert(navlink_gcs_reply(&g, reply, 52, &INFO) == 0);
  assert(navlink_gcs_reply(&g, reply, 52, &INFO) == NAVLINK_SESS_ERR_REPLY);
  /* a reply made for an earlier HELLO is refused by a GCS that sent a new one */
  nonce(n, 2);
  navlink_gcs_hello(&g, n, NULL, hello);
  assert(navlink_gcs_reply(&g, reply, 52, &INFO) == NAVLINK_SESS_ERR_REPLY);
  /* a GCS that never sent a HELLO takes no reply */
  assert(navlink_gcs_init(&g2, K) == 0);
  assert(navlink_gcs_reply(&g2, reply, 52, &INFO) == NAVLINK_SESS_ERR_REPLY);
  /* wrong K on the GCS side */
  uint8_t k2[32];
  memcpy(k2, K, 32);
  k2[0] ^= 1;
  navlink_gcs_t g3;
  assert(navlink_gcs_init(&g3, k2) == 0);
  nonce(n, 1);
  navlink_gcs_hello(&g3, n, NULL, hello);
  assert(navlink_gcs_reply(&g3, reply, 52, &INFO) == NAVLINK_SESS_ERR_REPLY);
  (void)f;
}

static void test_wrong_key_gcs_frame(void) {
  navlink_fc_t fc;
  navlink_gcs_t g;
  uint8_t k2[32], hello[16], reply[52], n[16], f[300], out[255];
  navlink_sec_hdr_t h;
  memcpy(k2, K, 32);
  k2[5] ^= 0x40;
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  assert(navlink_gcs_init(&g, k2) == 0);
  nonce(n, 3);
  navlink_gcs_hello(&g, n, NULL, hello);
  assert(navlink_fc_hello(&fc, 0, hello, reply) == 52);
  /* the GCS with the wrong key rejects the reply, so it has no session; even a
   * session built by force from its own key does not promote */
  assert(navlink_gcs_reply(&g, reply, 52, &INFO) == NAVLINK_SESS_ERR_REPLY);
  assert(navlink_gcs_seal(&g, NOW, f, sizeof f, E, &H, PL) == NAVLINK_SESS_ERR_NOSESSION);
  assert(navlink_fc_open(&fc, 10, reply, 52, &h, out) < 0);
  assert(fc.pending[0].s.valid && !fc.live.valid);
}

static void test_exhaustion(void) {
  navlink_fc_t fc;
  uint8_t reply[52], n[16];
  assert(navlink_fc_init(&fc, K, UID, 0) != 0);
  assert(navlink_fc_init(&fc, K, UID, 0xFFFFFFFFu) != 0);
  assert(navlink_fc_init(&fc, K, UID, 0xFFFFFFFEu) == 0);
  fc.hs_ctr = 0xFFFFFFFEu;
  nonce(n, 1);
  assert(navlink_fc_hello(&fc, 0, n, reply) == 52); /* uses 0xFFFFFFFF */
  nonce(n, 2);
  assert(navlink_fc_hello(&fc, 2000, n, reply) == NAVLINK_SEC_ERR_CLOSED);
  assert(fc.closed);
  nonce(n, 3);
  assert(navlink_fc_hello(&fc, 9000, n, reply) == NAVLINK_SEC_ERR_CLOSED);
}

static void test_max_frame_through_session(void) {
  navlink_fc_t fc;
  navlink_gcs_t g;
  uint8_t f[300], out[255], pl[255];
  navlink_sec_hdr_t h, big = {1, 1, 1, 0xABCDEF, 255};
  memset(pl, 0x42, sizeof pl);
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  assert(navlink_gcs_init(&g, K) == 0);
  connect_pair(&fc, &g, 0, 1);
  int l = navlink_fc_seal(&fc, f, sizeof f, E, &big, pl);
  assert(l == NAVLINK_SEC_MAX_FRAME);
  assert(navlink_gcs_open(&g, f, (size_t)l, &h, out) == 255);
}

static void test_lost_first_frame_and_recovery(void) {
  navlink_fc_t fc;
  navlink_gcs_t g;
  navlink_hs_info_t info;
  uint8_t f1[300], f2[300], f3[300], out[255], hello[16], reply[52], n[16];
  navlink_sec_hdr_t h;
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  assert(navlink_gcs_init(&g, K) == 0);
  assert(!navlink_gcs_needs_hello(&g, 100000));

  /* first GCS frame lost, the second arrives inside the pending window */
  nonce(n, 1);
  navlink_gcs_hello(&g, n, NULL, hello);
  assert(navlink_fc_hello(&fc, 0, hello, reply) == 52);
  assert(navlink_gcs_reply(&g, reply, 52, &info) == 0);
  assert(navlink_gcs_seal(&g, 0, f1, sizeof f1, E, &H, PL) > 0); /* lost */
  int l2 = navlink_gcs_seal(&g, 1000, f2, sizeof f2, E, &H, PL);
  assert(navlink_fc_open(&fc, 1100, f2, (size_t)l2, &h, out) == 4);
  assert(fc.live.valid && !fc.pending[0].s.valid);
  int l = navlink_fc_seal(&fc, f3, sizeof f3, E, &H, PL);
  assert(navlink_gcs_open(&g, f3, (size_t)l, &h, out) == 4);
  assert(!navlink_gcs_needs_hello(&g, 60000)); /* a vehicle frame verified */

  /* every GCS frame lost for more than 5 s: the vehicle drops the pending
   * session and keeps the old keys, which the GCS no longer has */
  nonce(n, 2);
  navlink_gcs_hello(&g, n, NULL, hello);
  assert(navlink_fc_hello(&fc, 10000, hello, reply) == 52);
  assert(navlink_gcs_reply(&g, reply, 52, &info) == 0);
  for (uint32_t t = 10000; t <= 15000; t += 1000)
    assert(navlink_gcs_seal(&g, t, f1, sizeof f1, E, &H, PL) > 0); /* all lost */
  assert(navlink_fc_open(&fc, 16000, f1, 36, &h, out) < 0);
  assert(!fc.pending[0].s.valid && fc.live.valid);
  l = navlink_fc_seal(&fc, f3, sizeof f3, E, &H, PL); /* old keys: unreadable */
  assert(navlink_gcs_open(&g, f3, (size_t)l, &h, out) < 0);
  assert(!navlink_gcs_needs_hello(&g, 10000 + NAVLINK_SESS_GCS_RESYNC_MS - 1));
  assert(navlink_gcs_needs_hello(&g, 10000 + NAVLINK_SESS_GCS_RESYNC_MS));
  /* the re-HELLO recovers it */
  nonce(n, 3);
  navlink_gcs_hello(&g, n, NULL, hello);
  assert(navlink_fc_hello(&fc, 16500, hello, reply) == 52);
  assert(navlink_gcs_reply(&g, reply, 52, &info) == 0);
  l2 = navlink_gcs_seal(&g, 16500, f2, sizeof f2, E, &H, PL);
  assert(navlink_fc_open(&fc, 16600, f2, (size_t)l2, &h, out) == 4);
  l = navlink_fc_seal(&fc, f3, sizeof f3, E, &H, PL);
  assert(navlink_gcs_open(&g, f3, (size_t)l, &h, out) == 4);
  assert(!navlink_gcs_needs_hello(&g, 90000));
}

static void test_uid_is_reported_and_checked(void) {
  navlink_fc_t fc, other;
  navlink_gcs_t g;
  navlink_hs_info_t info;
  uint8_t uid2[12], hello[16], r_other[52], r_ours[52], n[16];
  memcpy(uid2, UID, 12);
  uid2[11] ^= 0x80;
  assert(navlink_fc_init(&fc, K, UID, 7) == 0);
  assert(navlink_fc_init(&other, K, uid2, 9) == 0); /* same K, another vehicle */
  assert(navlink_gcs_init(&g, K) == 0);
  nonce(n, 1);
  /* a ground station that named the vehicle it wants: the other one's authentic
   * reply is reported and refused, and it keeps waiting for the right one */
  navlink_gcs_hello(&g, n, UID, hello);
  assert(navlink_fc_hello(&other, 0, hello, r_other) == 52);
  assert(navlink_fc_hello(&fc, 0, hello, r_ours) == 52);
  memset(&info, 0, sizeof info);
  assert(navlink_gcs_reply(&g, r_other, 52, &info) == NAVLINK_SESS_ERR_UID);
  assert(memcmp(info.uid, uid2, 12) == 0 && info.fc_boot_ctr == 9u);
  assert(!g.next.valid && g.waiting);
  assert(navlink_gcs_reply(&g, r_ours, 52, &info) == 0);
  assert(memcmp(info.uid, UID, 12) == 0 && info.fc_boot_ctr == 7u &&
         info.fc_hs_ctr == 1u);
  assert(g.next.valid && !g.waiting);
  /* without a named vehicle the reply is taken, and the uid is there to compare */
  navlink_gcs_hello(&g, n, NULL, hello);
  assert(navlink_gcs_reply(&g, r_other, 52, &info) == 0);
  assert(memcmp(info.uid, uid2, 12) == 0);
}

int main(void) {
  test_golden();
  test_basic_roundtrip();
  test_hello_during_live_session();
  test_promotion_and_old_session();
  test_rate_and_repeat();
  test_flood_does_not_starve_connect();
  test_rotating_peer_flood_spends_shared_budget();
  test_hello_from_address_filter();
  test_live_peer_reserve();
  test_peer_slots();
  test_ring_forgets_old();
  test_same_hello_different_keys();
  test_reply_checks();
  test_wrong_key_gcs_frame();
  test_exhaustion();
  test_max_frame_through_session();
  test_lost_first_frame_and_recovery();
  test_uid_is_reported_and_checked();
  puts("test_sess: ok");
  return 0;
}
