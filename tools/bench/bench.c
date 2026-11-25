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

/* Instruction-count bench for navlink_sec seal/open on a Cortex-M4 model. See README.md. */
#include "navlink_sec.h"
#include <stdint.h>
#ifndef N
#define N 0
#endif
#ifndef PLEN
#define PLEN 13
#endif
#ifndef MODE
#define MODE 3 /* 1 seal only, 2 open only (after seal), 3 both */
#endif
volatile uint32_t done, sink;
extern uint32_t _estack;
void reset(void);
__attribute__((section(".isr_vector"), used)) const void *vt[] = {&_estack, reset};
int main(void) {
  static uint8_t key[32], f[300], pl[255], out[255];
  static navlink_sec_tx_t tx; static navlink_sec_rx_t rx;
  for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
  navlink_sec_tx_init(&tx, key, 1); navlink_sec_rx_init(&rx, key, 1);
  navlink_sec_hdr_t h = {1, 1, 1, 7, PLEN}, ho;
  int l = 0;
  for (int i = 0; i < N; i++) {
    l = navlink_sec_seal(&tx, f, sizeof f, 2, &h, pl);
    if (MODE & 2) sink += (uint32_t)navlink_sec_open(&rx, f, (size_t)l, &ho, out);
  }
  done = 1;
  for (;;) __asm volatile("wfi");
}
void reset(void) { main(); }
