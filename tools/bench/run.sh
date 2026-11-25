#!/usr/bin/env sh
# Instructions per navlink_sec seal/open on Renode's STM32F4 (Cortex-M4) model.
# Needs arm-none-eabi-gcc and renode on PATH. Prints instructions, NOT cycles.
#   tools/bench/run.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OUT=${TMPDIR:-/tmp}/navlink_bench.$$
mkdir -p "$OUT"
trap 'rm -rf "$OUT"' EXIT
F="-mcpu=cortex-m4 -mthumb -mfloat-abi=soft -Os -ffunction-sections -fdata-sections -std=c11 -I$ROOT/sec -I$ROOT/vendor/monocypher"
# N iterations; PLEN payload bytes; MODE 1 = seal, 3 = seal + open
CASES="0:13:3 200:13:1 200:13:3 200:255:1 200:255:3"
RESC="$OUT/run.resc"
: > "$RESC"
for c in $CASES; do
  N=${c%%:*}; r=${c#*:}; P=${r%%:*}; M=${r#*:}
  E="$OUT/b_${N}_${P}_${M}.elf"
  arm-none-eabi-gcc $F -DN="$N" -DPLEN="$P" -DMODE="$M" -nostartfiles --specs=nosys.specs \
    -Wl,--gc-sections -T "$HERE/link.ld" "$HERE/bench.c" "$ROOT/sec/navlink_sec.c" \
    "$ROOT/vendor/monocypher/monocypher.c" -o "$E" 2>/dev/null
  cat >> "$RESC" <<EOT
mach create "b_${N}_${P}_${M}"
machine LoadPlatformDescription @platforms/cpus/stm32f4.repl
sysbus LoadELF @$E
cpu PerformanceInMips 1
emulation RunFor "20"
echo "RESULT b_${N}_${P}_${M}"
cpu ExecutedInstructions
sysbus ReadDoubleWord \`sysbus GetSymbolAddress "done"\`
mach clear
EOT
done
echo quit >> "$RESC"
renode --disable-xwt --console -e "include @$RESC" 2>&1 | grep -E 'RESULT|^0x' | paste - - - |
python3 -c '
import sys
r = {}
for l in sys.stdin:
    _, n, ins, done = l.split()
    r[n] = (int(ins, 16), int(done, 16))
    if int(done, 16) != 1:
        sys.exit("run did not finish: " + l)
base = r["b_0_13_3"][0]
for name, label in (("b_200_13_1", "seal  13 B"), ("b_200_255_1", "seal 255 B")):
    print(label, (r[name][0] - base) / 200)
for name, s, label in (("b_200_13_3", "b_200_13_1", "open  13 B"), ("b_200_255_3", "b_200_255_1", "open 255 B")):
    print(label, (r[name][0] - r[s][0]) / 200)
'
