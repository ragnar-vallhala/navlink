# Chapter 9. Using NavLink

This is the how-to. It covers generating the codecs, wiring them into firmware, a
ground station and Python tools, and trying a link on a bench with the emulator.
The code samples are from `ABI.md`, which is the integration guide and is the
place to go for full examples.

## 9.1 Generate the codecs

```sh
python3 generate.py                 # C and Python, into ./generated
python3 generate.py --lang c        # C only
python3 generate.py --out ../dir    # somewhere else
python3 generate.py --lang html     # the browsable message tree
```

The generator needs only the Python standard library. The output is a build
product: the repositories that use NavLink (Vayu firmware, the SITL, Navigator)
run it at configure time into their build tree, and nothing generated is
committed, so it cannot drift from `dialect.json`. In the Vayu firmware the
dependency is pinned to a NavLink release in `firmware/nav.toml`.

## 9.2 On the flight controller (C)

You supply four things: the byte transport, the sequence counter, the handler
bodies and, if wanted, time sync and security.

**Receiving.** Fill in a handler table, initialise a parser, and feed it bytes
from your UART:

```c
static navlink_ack_t on_cmd_set_pid(void *ctx, const navlink_frame_hdr_t *hdr,
                                    const navlink_cmd_set_pid_t *c) {
    apply_pid(c->axis, c->kp, c->ki, c->kd, c->kff);
    return navlink_ack_result(NAVLINK_COMMAND_RESULT_ACCEPTED);
}

static const navlink_handlers_t HANDLERS = {
    .send = uart_send, .sysid = FC_SYSID, .compid = FC_COMPID,
    .on_cmd_set_pid = on_cmd_set_pid,
};

static navlink_parser_t g_parser;
void comm_init(void) { navlink_parser_init(&g_parser); }
void comm_rx_bytes(const uint8_t *buf, size_t n) {
    navlink_parser_push(&g_parser, &HANDLERS, buf, n);
}
```

A telemetry slot you leave empty is ignored. A command slot you leave empty is
answered `UNSUPPORTED` by the dispatcher.

**Sending.** One call builds a whole frame:

```c
navlink_attitude_euler_t a = { .roll = roll, .pitch = pitch, .yaw = yaw };
uint8_t frame[NAVLINK_MAX_FRAME];
size_t n = navlink_attitude_euler_encode(frame, &a, tx_seq++, FC_SYSID, FC_COMPID);
uart_write(frame, n);
```

**Firmware rules.**

- No dynamic allocation. Structs are fixed size, and a frame is at most 267 bytes.
- Read members of a packed wire struct by value. Never take the address of one
  (`&w.kp`): that is undefined behaviour on Cortex-M. For anything that needs a
  pointer or arithmetic use the aligned struct.
- One clock domain on the vehicle: `sample_time_us` for sample alignment, and
  wall-clock only from the ground-station sync.
- Until time sync succeeds, reject commands, using `command_gate`.

## 9.3 In a ground station (C++)

The ground station compiles the same generated `.c` file, since the header is
`extern "C"` guarded. The pattern mirrors the firmware: register handler thunks
whose `ctx` points at your link object, call `navlink_parser_push` from your
serial or network read, and build commands with the generated encoders.
`ABI.md` section 6 has a full example, including how to correlate a
`COMMAND_ACK` with the command it answers by (command msgid, `req_seq`). The
ground station owns link bookkeeping such as loss from `seq` gaps, round-trip
time and throughput.

## 9.4 In Python tools

```python
import navlink_msgs as nl

frame = nl.encode(nl.CmdArm(target_sys=1, target_comp=1, req_seq=7, force=0))
parser = nl.Parser(nl.Handlers(
    on_command_ack=lambda f, m: print("ack", m.command, m.result)))
parser.push(sock.recv(4096))
```

The autotuner and analysis tools use this module. `MSGID_TO_CLASS` turns any
payload into a typed object, which is what a generic logger needs.

## 9.5 Trying a link on a bench: the emulator

`sim/` holds a two-process link emulator. A flight-controller process and a
ground-station process are wired together over localhost UDP, and each impairs
what it sends, so the up and down directions can be degraded separately. The
vehicle side emits the real telemetry set at firmware-like rates, echoes pings
and answers commands. The ground-station side validates every frame, pings
periodically, sends a `CMD_SET_PID`, and reports statistics.

`python3 sim/live.py` opens an interactive console where the link settings
(latency, jitter, loss, duplication, reordering, corruption, rate) can be changed
while a status bar shows receive rate, throughput, loss, reorders, CRC errors,
round-trip time and acknowledgements. `python3 sim/live.py --scenario lossy`
starts with a preset. See `sim/README.md`.

## 9.6 Testing a change

After editing `dialect.json` or `faults.json`, regenerate and run
`python3 tests/run_tests.py`. It cross-checks the C and Python codecs byte for
byte and pins the conformance vectors from the specification.

## Sources

- `README.md` (generate); `ABI.md`, sections 5, 6 and 7
- `sim/README.md`
- Vayu repository: `build.md` section 6, `firmware/nav.toml`
- `tests/run_tests.py`
