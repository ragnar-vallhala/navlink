# Chapter 7. Services: commands, parameters, files, time sync

Telemetry on NavLink is best effort: a message is sent and may be lost. Some
jobs need an answer. These are built as ordinary messages in the same id space,
following request and response patterns. This chapter describes them. Where the
specification describes something the current dialect does not contain, it says
so.

## 7.1 Commands

A command is a typed message. Commands have ids from 8192 upward and each
starts with the same three header fields: `target_sys`, `target_comp` and
`req_seq`, followed by the command's own typed parameters. There is no generic
"command with seven floats" message.

The receiver answers with `COMMAND_ACK`, which carries the command's msgid, the
`req_seq`, a result code, progress and one extra result field. The pair
(command msgid, `req_seq`) ties an acknowledgement to the command.

The generated code does the acknowledging for you (firmware, in C):

- A command handler **returns** its result. The dispatcher builds and sends the
  `COMMAND_ACK`, so a handler cannot forget to send it or send it twice.
- A command slot that has no handler is answered `UNSUPPORTED` automatically.
- If any command slot is set, the handler table's `send`, `sysid` and `compid`
  must be filled in. Without `send`, every acknowledgement is silently dropped.
- An optional `command_gate` function is consulted before every command handler.
  A result other than `ACCEPTED` blocks the handler and becomes the
  acknowledgement. This is where the firmware refuses commands while its clock is
  not yet synchronised (section 7.4), in one place instead of in every handler.
- Whether a message owes an acknowledgement is declared in the dialect. The
  default is yes for the command range and no elsewhere, and a message can
  override it. The generator exposes it as `NAVLINK_ACK_<NAME>`,
  `requires_ack` in the message info table, and `REQUIRES_ACK` in Python.

The Python parser also acknowledges commands automatically when its handlers have
a `send` function.

## 7.2 Parameters

Four messages implement the parameter service: `PARAM_REQUEST_LIST`,
`PARAM_REQUEST_READ`, `PARAM_VALUE` and `PARAM_SET`.

- `PARAM_VALUE` carries a 16-character parameter id, an index, the count of
  parameters, a **generation** number, a type and an 8-byte value. The value is
  the real typed value, not a float bit pattern.
- A complete dump is every index from 0 to count minus 1 seen under **one**
  generation. The generation changes on every `PARAM_SET`. If it changes in the
  middle of a dump, the reader starts over, and any missing index is fetched with
  `PARAM_REQUEST_READ`.
- A write is confirmed by the updated `PARAM_VALUE` carrying the new generation.

## 7.3 File transfer and the filesystem

For log download and file upload the dialect has two groups:

- **Transfer:** `XFER_OPEN`, `XFER_CLOSE`, `XFER_INFO`, `XFER_DATA`, `XFER_ACK` and
  `XFER_SACK`. Data moves in windows with acknowledgements, so a lossy link
  recovers without restarting.
- **Filesystem:** `FS_LIST`, `FS_INFO`, `FS_DELETE`, with `FS_ENTRY` and
  `FS_INFO_REPLY` as replies. They browse and delete files on the vehicle's SD
  card.

The per-message pages `docs/reference/messages/xfer.md` and `fs_nav.md` give the
details, and `tests/test_xfer_loopback.py` and `tests/test_fs_nav_loopback.py` are
loopback tests of both.

The specification also reserves `IFLAG_CRC32` (a stronger 4-byte checksum for big
chunks) and `IFLAG_FRAGMENTED` (splitting payloads over 255 bytes into
fragments). Fragmentation is not specified in this version, and the generated
codec implements neither flag.

## 7.4 Time synchronisation

The vehicle never makes up wall-clock time. The ground station sets the
reference instant T0 and the vehicle reports time since T0 (chapter 5). The
exchange is one message, `TIME_SYNC` (msgid 10), with a `role` byte that says
whether it is a request from the ground station or a response from the vehicle.

1. The ground station sends a request with its transmit time `t1`, and may
   include a `commanded_offset_ms` correction (the value `INT32_MIN` means none).
2. The vehicle notes its receive time `t2`, applies any commanded offset, and
   replies with `t1` echoed, `t2` and its transmit time `t3`.
3. The ground station notes its own receive time `t4` (never put on the wire) and
   computes the round trip, one-way delay (half the round trip) and clock offset,
   as the Network Time Protocol does. It filters these and feeds the result back
   as the next request's commanded offset.

The delay estimate assumes the up and down paths take equal time. That is close
to true on a USB or UART bench link and only approximate on an asymmetric radio.

Schedule: a sync at startup, one every 5 hours of continuous operation to bound
crystal drift, and an extra one if the ground station sees the vehicle's stamps
drift past a threshold. T0 is fixed at the startup sync, and later syncs only
trim drift, so timestamps stay continuous.

**Safety gate.** Until the startup sync succeeds, the vehicle is unsynchronised.
It must mark its own stamps `TIME_STALE` and must reject every command (and every
secured frame). The firmware does this through `command_gate`, answering
`TEMPORARILY_REJECTED` until it is synchronised.

## 7.5 What the specification describes but the dialect does not contain

The specification also describes a mission service (`MISSION_COUNT`,
`MISSION_ITEM_INT`, `MISSION_ACK` and related messages) with atomic commit of a
whole mission. **The current dialect defines no mission messages.** Treat that
service as a design in the specification, not as something a v2.4.0 peer speaks.
The same caution applies to the specification's navigation, power and peripheral
message blocks.

## Sources

- `docs/reference/navlink-v2-spec.md`, sections 10 (time synchronisation), 12 (services) and 13 (capability negotiation)
- `ABI.md`, sections 5 and 7 (command handling in C and Python)
- `dialect.json` (the messages that exist)
- `docs/reference/messages/xfer.md`, `fs_nav.md`, `time_sync.md`, `command.md`
- `tests/test_xfer_loopback.py`, `tests/test_fs_nav_loopback.py`
