# navlink_sec bench

`run.sh` builds `bench.c` with the vendored Monocypher and `sec/navlink_sec.c`
for a Cortex-M4 (`-Os`, soft float), runs it on Renode's STM32F4 model, and
prints the instructions per `navlink_sec_seal` and `navlink_sec_open` for a 13-byte
and a 255-byte payload (200 iterations, minus an empty-loop baseline).

It counts **instructions, not cycles**. Renode charges one per instruction; a
real M4 at 84 MHz pays more for loads and branches and for flash wait states, so
cycles are expected to be above the count (somewhere between 1.0 and 1.5 times,
an estimate that has not been checked on hardware). Use it to compare changes and
to size a budget, not as a timing claim.

Measured with the code at the time of writing (Renode 1.16, arm-none-eabi-gcc 13):

| call | payload | instructions |
| --- | --- | --- |
| seal | 13 B | 7475 |
| open | 13 B | 8996 |
| seal | 255 B | 14428 |
| open | 255 B | 16082 |

About 7.1k fixed plus about 27 per payload byte. Not measured here: the
handshake, stack depth, anything on real hardware.
