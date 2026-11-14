/*
 * Copyright (C) 2026 NAVRobotec Pvt Ltd
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

/* NavLink v2 C codec tests + cross-language parity emitter.
 *
 * Asserts round-trips locally, then prints a machine-parseable report that
 * run_tests.py checks against the Python codec:
 *   TABLE <msgid> <crc_extra> <wire_size>      (one per message)
 *   BYTES <NAME> <hex>                          (packed payload for fixed values)
 * Exits non-zero on any local assertion failure. */
#include "navlink_msgs.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void navlink_emit_parity(void); /* generated/c/navlink_parity.c */

static void count_heartbeat(void *ctx, const navlink_frame_hdr_t *hdr,
                            const navlink_heartbeat_t *msg) {
  (void)hdr;
  (void)msg;
  ++*(int *)ctx;
}

static void note_crc_error(void *ctx, uint32_t msgid) {
  (void)msgid;
  ++((int *)ctx)[1];
}
static void note_unknown(void *ctx, uint32_t msgid, const uint8_t *payload,
                         size_t len) {
  (void)msgid;
  (void)payload;
  (void)len;
  ++((int *)ctx)[2];
}
static void note_heartbeat(void *ctx, const navlink_frame_hdr_t *hdr,
                           const navlink_heartbeat_t *msg) {
  (void)hdr;
  (void)msg;
  ++((int *)ctx)[0];
}

/* Auto-ack capture. */
static uint8_t g_ack_frame[NAVLINK_MAX_FRAME];
static uint16_t g_ack_len;
static int g_ack_calls;
static void capture_send(void *ctx, const uint8_t *f, uint16_t n) {
  (void)ctx;
  memcpy(g_ack_frame, f, n);
  g_ack_len = n;
  g_ack_calls++;
}
static navlink_ack_t arm_handler(void *ctx, const navlink_frame_hdr_t *hdr,
                                 const navlink_cmd_arm_t *msg) {
  (void)ctx;
  (void)hdr;
  (void)msg;
  return navlink_ack_result(NAVLINK_COMMAND_RESULT_DENIED);
}

/* The sender's own frame-seq counter (spec 3.5), shared by ACKs and telemetry. */
static uint8_t g_tx_seq;
static uint8_t next_seq_cb(void *ctx) {
  (void)ctx;
  return g_tx_seq++;
}

static navlink_ack_t deferred_gate(void *ctx, uint32_t cmd) {
  (void)ctx;
  (void)cmd;
  return navlink_ack_deferred();
}

struct fault_cap {
  int n;
  navlink_fault_status_t m;
};
static void fault_cb(void *ctx, const navlink_frame_hdr_t *hdr,
                     const navlink_fault_status_t *msg) {
  struct fault_cap *c = ctx;
  (void)hdr;
  c->n++;
  c->m = *msg;
}

int main(void) {
  /* CRC-16/MCRF4XX self-check (spec §16.1). */
  uint16_t crc = 0xFFFF;
  const char *s = "123456789";
  for (const char *p = s; *p; p++)
    navlink_crc_accumulate((uint8_t)*p, &crc);
  assert(crc == 0x6F91);

  /* Local round-trips. */
  {
    navlink_attitude_euler_t a = {.roll = 0.5f,
                                  .pitch = -0.25f,
                                  .yaw = 1.0f,
                                  .rollspeed = 0.1f,
                                  .pitchspeed = 0.2f,
                                  .yawspeed = 0.3f};
    navlink_attitude_euler_wire_t w;
    navlink_attitude_euler_from_aligned(&w, &a);
    uint8_t buf[64];
    size_t n = navlink_attitude_euler_pack(buf, &w);
    assert(n == sizeof w && n == NAVLINK_WIRE_SIZE_ATTITUDE_EULER);
    navlink_attitude_euler_wire_t w2;
    navlink_attitude_euler_unpack(&w2, buf, n);
    navlink_attitude_euler_t a2;
    navlink_attitude_euler_to_aligned(&a2, &w2);
    assert(a2.roll == a.roll && a2.yawspeed == a.yawspeed);
  }
  {
    navlink_command_ack_t k = {.command = 0x123456,
                               .req_seq = 7,
                               .result = 0,
                               .progress = 100,
                               .result_param2 = -3};
    navlink_command_ack_wire_t w;
    navlink_command_ack_from_aligned(&w, &k);
    navlink_command_ack_t k2;
    navlink_command_ack_to_aligned(&k2, &w);
    assert(k2.command == 0x123456 && k2.result_param2 == -3);
  }
  /* Dispatch table is sorted + binary search works. */
  for (size_t i = 1; i < NAVLINK_MSG_COUNT; i++)
    assert(navlink_msg_table[i - 1].msgid < navlink_msg_table[i].msgid);
  assert(navlink_msg_info(1034) &&
         strcmp(navlink_msg_info(1034)->name, "PERF_GLOBAL") == 0);
  assert(navlink_msg_info(0x424242) == NULL);

  /* Short unpack zero-fills the rest (spec §5.6). */
  {
    uint8_t two[2] = {7, 0};
    navlink_param_value_wire_t w;
    navlink_param_value_unpack(&w, two, 2);
    navlink_param_value_t a;
    navlink_param_value_to_aligned(&a, &w);
    assert(a.param_id[0] == 7 && a.count == 0 && a.generation == 0 &&
           a.value[7] == 0);
  }
  /* Oversize unpack is clamped to the wire size (no overrun). */
  {
    uint8_t big[64];
    memset(big, 0xAA, sizeof big);
    navlink_attitude_euler_wire_t w;
    navlink_attitude_euler_unpack(&w, big, sizeof big);
    uint8_t out[64];
    size_t n = navlink_attitude_euler_pack(out, &w);
    assert(n == NAVLINK_WIRE_SIZE_ATTITUDE_EULER);
  }
  /* Signed i8 array round-trip (motor spin = +1/-1). */
  {
    navlink_cmd_set_motor_geometry_t g;
    memset(&g, 0, sizeof g);
    g.spin[0] = 1;
    g.spin[1] = -1;
    g.spin[2] = 1;
    g.spin[3] = -1;
    navlink_cmd_set_motor_geometry_wire_t w;
    navlink_cmd_set_motor_geometry_from_aligned(&w, &g);
    navlink_cmd_set_motor_geometry_t g2;
    navlink_cmd_set_motor_geometry_to_aligned(&g2, &w);
    assert(g2.spin[1] == -1 && g2.spin[3] == -1);
  }
  /* u64 extreme + i32 sentinel round-trip. */
  {
    navlink_time_sync_t t = {.role = 1,
                             .seq = 9,
                             .t1_gcs_tx = 0xFFFFFFFFFFFFFFFFull,
                             .t3_fc_tx = 0x0102030405060708ull,
                             .commanded_offset_ms = INT32_MIN};
    navlink_time_sync_wire_t w;
    navlink_time_sync_from_aligned(&w, &t);
    navlink_time_sync_t t2;
    navlink_time_sync_to_aligned(&t2, &w);
    assert(t2.t1_gcs_tx == 0xFFFFFFFFFFFFFFFFull &&
           t2.t3_fc_tx == 0x0102030405060708ull &&
           t2.commanded_offset_ms == INT32_MIN && t2.role == 1 && t2.seq == 9);
  }

  /* Parser: a stray 0x56 right before a frame must not cost that frame (§3.4),
   * and a CRC-valid frame with an unimplemented incompat bit is dropped (§3.3). */
  {
    int hb = 0;
    navlink_handlers_t h;
    memset(&h, 0, sizeof h);
    h.ctx = &hb;
    h.on_heartbeat = count_heartbeat;
    navlink_parser_t p;
    navlink_parser_init(&p);
    navlink_heartbeat_t m;
    memset(&m, 0, sizeof m);
    m.type = 1;
    uint8_t fr[NAVLINK_MAX_FRAME + 2];
    fr[0] = NAVLINK_SYNC;
    size_t n = navlink_heartbeat_encode(fr + 1, &m, 0, 1, 1);
    navlink_parser_push(&p, &h, fr, n + 1);
    assert(hb == 1);

    n = navlink_heartbeat_encode(fr, &m, 0, 1, 1);
    fr[3] = 0x10; /* reserved incompat bit; re-CRC so only the flag is wrong */
    uint16_t c = 0xFFFF;
    for (size_t i = 1; i < n - 2; i++)
      navlink_crc_accumulate(fr[i], &c);
    navlink_crc_accumulate(NAVLINK_CRC_EXTRA_HEARTBEAT, &c);
    fr[n - 2] = (uint8_t)c;
    fr[n - 1] = (uint8_t)(c >> 8);
    navlink_parser_push(&p, &h, fr, n);
    assert(hb == 1);
    n = navlink_heartbeat_encode(fr, &m, 0, 1, 1); /* framing is not lost */
    navlink_parser_push(&p, &h, fr, n);
    assert(hb == 2);
  }

  /* #136a: a rejected frame's false sync must not swallow the good frames inside
   * its span. Counters: [0] heartbeats, [1] crc errors, [2] unknown msgids. */
  {
    int cnt[3] = {0, 0, 0};
    navlink_handlers_t h;
    memset(&h, 0, sizeof h);
    h.ctx = cnt;
    h.on_heartbeat = note_heartbeat;
    h.on_crc_error = note_crc_error;
    h.on_unknown = note_unknown;
    navlink_parser_t p;
    navlink_heartbeat_t m;
    memset(&m, 0, sizeof m);
    m.type = 3;
    uint8_t hb[NAVLINK_MAX_FRAME];
    size_t hn = navlink_heartbeat_encode(hb, &m, 0, 1, 1);
    uint8_t in[NAVLINK_MAX_FRAME * 2];

    /* False header claims a 200 B payload; its msgid bytes are junk (unknown id). */
    navlink_parser_init(&p);
    size_t n = 0;
    const uint8_t fs1[4] = {0x56, 0x02, 0xC8, 0x00};
    memcpy(in, fs1, 4);
    n = 4;
    memcpy(in + n, hb, hn);
    n += hn;
    memset(in + n, 0, 260);
    n += 260;
    navlink_parser_push(&p, &h, in, n);
    assert(cnt[0] == 1);
    assert(cnt[2] >= 1); /* the false frame reached on_unknown (unverified) */

    /* False header with a KNOWN msgid (HEARTBEAT): the CRC check fails, then rescan. */
    memset(cnt, 0, sizeof cnt);
    navlink_parser_init(&p);
    const uint8_t fs2[10] = {0x56, 0x02, 0x20, 0x00, 0, 1, 1, 0, 0, 0};
    memcpy(in, fs2, 10);
    n = 10;
    memcpy(in + n, hb, hn);
    n += hn;
    memset(in + n, 0, 60);
    n += 60;
    navlink_parser_push(&p, &h, in, n);
    assert(cnt[1] == 1 && cnt[0] == 1);

    /* Two stacked false headers, then two real frames, fed byte-at-a-time. */
    memset(cnt, 0, sizeof cnt);
    navlink_parser_init(&p);
    n = 0;
    memcpy(in + n, fs2, 10);
    n += 10;
    memcpy(in + n, fs2, 10);
    n += 10;
    memcpy(in + n, hb, hn);
    n += hn;
    memcpy(in + n, hb, hn);
    n += hn;
    memset(in + n, 0, 80);
    n += 80;
    for (size_t i = 0; i < n; i++)
      navlink_parser_push(&p, &h, in + i, 1);
    assert(cnt[0] == 2);

    /* Worst case span: header claims 255 B, frame hidden inside. */
    memset(cnt, 0, sizeof cnt);
    navlink_parser_init(&p);
    const uint8_t fs3[10] = {0x56, 0x02, 0xFF, 0x00, 0, 1, 1, 0, 0, 0};
    memcpy(in, fs3, 10);
    n = 10;
    memcpy(in + n, hb, hn);
    n += hn;
    memset(in + n, 0, 260);
    n += 260;
    navlink_parser_push(&p, &h, in, n);
    assert(cnt[0] == 1);

    /* §3.3 reject: an incompat-bit frame whose header hides a real frame. */
    memset(cnt, 0, sizeof cnt);
    navlink_parser_init(&p);
    const uint8_t fs4[4] = {0x56, 0x02, 0x00, 0x10};
    memcpy(in, fs4, 4);
    memcpy(in + 4, hb, hn);
    navlink_parser_push(&p, &h, in, 4 + hn);
    assert(cnt[0] == 1);

    /* #136b: an unknown msgid is only a diagnostic notification: never dispatched. */
    memset(cnt, 0, sizeof cnt);
    navlink_parser_init(&p);
    const uint8_t unk[12] = {0x56, 0x02, 0, 0, 0, 1, 1, 0x77, 0x77, 0x77, 0, 0};
    navlink_parser_push(&p, &h, unk, sizeof unk);
    assert(cnt[2] == 1 && cnt[0] == 0 && cnt[1] == 0);
    navlink_parser_push(&p, &h, hb, hn); /* and it does not block what follows */
    assert(cnt[0] == 1);
  }

  /* Command auto-ack with NO next_seq wired -- the legacy v2 fallback, pinned so
   * the Python parser can match it: the ack carries the handler's result and
   * reuses req_seq as its frame seq. Unmigrated code lands here (ABI.md sec 10). */
  {
    navlink_handlers_t h;
    memset(&h, 0, sizeof h);
    h.send = capture_send;
    h.sysid = 7;
    h.compid = 9;
    h.on_cmd_arm = arm_handler;
    navlink_parser_t p;
    navlink_parser_init(&p);
    navlink_cmd_arm_t c;
    memset(&c, 0, sizeof c);
    c.req_seq = 42;
    uint8_t fr[NAVLINK_MAX_FRAME];
    size_t n = navlink_cmd_arm_encode(fr, &c, 0, 1, 1);
    g_ack_calls = 0;
    navlink_parser_push(&p, &h, fr, n);
    assert(g_ack_calls == 1);
    assert(g_ack_frame[4] == 42 && g_ack_frame[5] == 7 && g_ack_frame[6] == 9);
    navlink_command_ack_wire_t w;
    navlink_command_ack_unpack(&w, g_ack_frame + NAVLINK_HEADER_LEN,
                               g_ack_frame[2]);
    navlink_command_ack_t k;
    navlink_command_ack_to_aligned(&k, &w);
    assert(k.command == NAVLINK_MSGID_CMD_ARM && k.req_seq == 42 &&
           k.result == NAVLINK_COMMAND_RESULT_DENIED);
  }

  /* next_seq wired (#131, spec 3.5): the ACK's frame seq comes from the sender's
   * own counter, never from req_seq, and it is the SAME counter the application
   * uses for its own frames -- one gap-free sequence. Also wraps at 255, and a
   * deferred ack sent later via navlink_command_ack_send() draws from it too. */
  {
    navlink_handlers_t h;
    memset(&h, 0, sizeof h);
    h.send = capture_send;
    h.sysid = 7;
    h.compid = 9;
    h.next_seq = next_seq_cb;
    h.on_cmd_arm = arm_handler;
    navlink_parser_t p;
    navlink_parser_init(&p);
    navlink_cmd_arm_t c;
    memset(&c, 0, sizeof c);
    uint8_t fr[NAVLINK_MAX_FRAME];

    g_tx_seq = 253;
    c.req_seq = 42; /* a request seq that must NOT leak into the ACK */
    size_t n = navlink_cmd_arm_encode(fr, &c, 0, 1, 1);
    g_ack_calls = 0;
    navlink_parser_push(&p, &h, fr, n);
    assert(g_ack_calls == 1 && g_ack_frame[4] == 253);
    navlink_command_ack_wire_t w;
    navlink_command_ack_unpack(&w, g_ack_frame + NAVLINK_HEADER_LEN, g_ack_frame[2]);
    navlink_command_ack_t k;
    navlink_command_ack_to_aligned(&k, &w);
    assert(k.req_seq == 42); /* correlation still by req_seq, in the payload */

    /* the application's own telemetry takes the next value of the same counter */
    navlink_attitude_euler_t a;
    memset(&a, 0, sizeof a);
    uint8_t tf[NAVLINK_MAX_FRAME];
    (void)navlink_attitude_euler_encode(tf, &a, next_seq_cb(NULL), 7, 9);
    assert(tf[4] == 254);

    c.req_seq = 42; /* same req_seq again: the ACK seq still advances */
    n = navlink_cmd_arm_encode(fr, &c, 0, 1, 1);
    navlink_parser_push(&p, &h, fr, n);
    assert(g_ack_calls == 2 && g_ack_frame[4] == 255);

    c.req_seq = 1;
    n = navlink_cmd_arm_encode(fr, &c, 0, 1, 1);
    navlink_parser_push(&p, &h, fr, n);
    assert(g_ack_calls == 3 && g_ack_frame[4] == 0); /* uint8 wrap */

    navlink_command_ack_send(&h, NAVLINK_MSGID_CMD_ARM, 99,
                             navlink_ack_result(NAVLINK_COMMAND_RESULT_ACCEPTED));
    assert(g_ack_calls == 4 && g_ack_frame[4] == 1); /* deferred path */
  }

  /* A command_gate returning navlink_ack_deferred() (result ACCEPTED) lets the
   * handler run; the ack carries the handler's result (Python parity). */
  {
    navlink_handlers_t h;
    memset(&h, 0, sizeof h);
    h.send = capture_send;
    h.on_cmd_arm = arm_handler;
    h.command_gate = deferred_gate;
    navlink_parser_t p;
    navlink_parser_init(&p);
    navlink_cmd_arm_t c;
    memset(&c, 0, sizeof c);
    uint8_t fr[NAVLINK_MAX_FRAME];
    size_t n = navlink_cmd_arm_encode(fr, &c, 0, 1, 1);
    g_ack_calls = 0;
    navlink_parser_push(&p, &h, fr, n);
    assert(g_ack_calls == 1);
    navlink_command_ack_wire_t w;
    navlink_command_ack_unpack(&w, g_ack_frame + NAVLINK_HEADER_LEN, g_ack_frame[2]);
    navlink_command_ack_t k;
    navlink_command_ack_to_aligned(&k, &w);
    assert(k.result == NAVLINK_COMMAND_RESULT_DENIED);
  }

  /* FAULT_STATUS: field order == wire order, frame round-trip, fault table. */
  {
    navlink_fault_status_t m;
    memset(&m, 0, sizeof m);
    m.id = NAVLINK_FAULT_SD_MOUNT_FAILED;
    m.severity = NAVLINK_SEVERITY_ERROR;
    m.active = NAVLINK_FAULT_ACTIVE_RAISED;
    strcpy(m.text, "SD mount failed");
    navlink_fault_status_wire_t w;
    navlink_fault_status_from_aligned(&w, &m);
    uint8_t pl[NAVLINK_WIRE_SIZE_FAULT_STATUS];
    memset(pl, 0xAA, sizeof pl);
    navlink_fault_status_pack(pl, &w);
    assert(NAVLINK_MSGID_FAULT_STATUS == 11u);
    assert(NAVLINK_WIRE_SIZE_FAULT_STATUS == 54u);
    assert(pl[0] == 0x10 && pl[1] == 0x01); /* id u16 LE */
    assert(pl[2] == 3 && pl[3] == 1);       /* severity, active */
    assert(memcmp(pl + 4, "SD mount failed", 16) == 0); /* incl. the NUL */
    assert(pl[19] == 0 && pl[53] == 0);
    uint8_t fr[NAVLINK_MAX_FRAME];
    size_t n = navlink_fault_status_encode(fr, &m, 3, 1, 1);
    struct fault_cap cap = { 0, { 0 } };
    navlink_handlers_t h;
    memset(&h, 0, sizeof h);
    h.ctx = &cap;
    h.on_fault_status = fault_cb;
    navlink_parser_t p;
    navlink_parser_init(&p);
    navlink_parser_push(&p, &h, fr, n);
    assert(cap.n == 1);
    assert(cap.m.id == 0x0110 && cap.m.active == 1);
    assert(strcmp(cap.m.text, "SD mount failed") == 0);
    for (size_t i = 0; i < NAVLINK_FAULT_COUNT; i++) {
      const navlink_fault_info_t *f = &navlink_fault_table[i];
      assert(strlen(f->text) <= 49);
      assert(navlink_fault_info(f->id) == f);
      for (size_t j = i + 1; j < NAVLINK_FAULT_COUNT; j++)
        assert(navlink_fault_table[j].id != f->id);
    }
    assert(navlink_fault_info(0) == NULL);
  }

  /* Emit parity table (msgid crc_extra wire_size). */
  for (size_t i = 0; i < NAVLINK_MSG_COUNT; i++)
    printf("TABLE %u %u %u\n", navlink_msg_table[i].msgid,
           navlink_msg_table[i].crc_extra, navlink_msg_table[i].wire_size);

  /* Emit byte vectors for every message (canonical values, must match Python). */
  navlink_emit_parity();

  fprintf(stderr, "C: %u messages, all local asserts passed\n",
          NAVLINK_MSG_COUNT);
  return 0;
}
