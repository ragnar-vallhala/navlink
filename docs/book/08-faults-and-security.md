# Chapter 8. Faults, capabilities and security

## 8.1 Reporting faults

A vehicle needs to tell the ground station "the barometer is missing" in a way
that is stable, short and does not depend on parsing free text. NavLink does this
with `FAULT_STATUS` (msgid 11), one latched fault per frame:

| Field | Meaning |
|---|---|
| `id` (u16) | a stable fault key |
| `severity` (u8) | the same severity enum as `STATUSTEXT` |
| `active` (u8) | 1 = raised, 0 = cleared |
| `text` (char[50]) | NUL-terminated text, at most 49 characters |

The `id` is a **stable key**: the text that belongs to an id is fixed and lives in
the shared table `faults.json`. That is different from `STATUSTEXT.id`, which only
groups the chunks of one long message.

Sending rules in the specification: every raised fault is re-sent every 5 seconds
while the vehicle is disarmed, and once on the first ground-station heartbeat
after a gap in the link, so a ground station that connects late learns the full
set. A clear is sent once with `active` 0. (The firmware's reference behaviour
lives in the Vayu repository; this chapter describes the protocol.)

## 8.2 The fault table

`faults.json` lists each fault with its id, name, severity and text. It currently
has 7 faults, in the core range starting at 0x0100:

| Id range | Use |
|---|---|
| 0x0000 | invalid or unset |
| 0x0001 to 0x00FF | reserved |
| 0x0100 to 0x01FF | core flight-controller faults (0x0100 sensors, 0x0110 storage, 0x0120 estimation, 0x0130 power, 0x0140 links) |
| 0x0200 to 0x7FFF | reserved for core growth |
| 0x8000 to 0xFFFF | vendor or experimental; core never assigns here |

Like message ids, fault ids are forever, and the text for an id never changes.
`generate.py` validates the table (unique ids and names, an assignable range, a
known severity, text of at most 49 bytes) and emits it with the codec: in C the
enum `navlink_fault_e`, the table `navlink_fault_table[]` and the lookup
`navlink_fault_info()`, and in Python `FaultId` and `FAULTS`.

## 8.3 Capabilities

Instead of a per-frame capability byte, peers exchange capabilities once when
they connect:

- `HEARTBEAT.capabilities`, a 32-bit mask of coarse capabilities, about once a
  second;
- `CAPABILITIES`, the full list on request: the protocol version, which
  `incompat_flags` bits the peer implements, the msgid ranges it handles, the
  security modes it supports and a non-secret key identifier.

The rule is simple: do not rely on an `incompat` feature the other side has not
advertised.

## 8.4 The security layer (a specification, not part of the codec)

The specification defines an optional security layer, per frame, off by default
and switched on at build time. **The generated codec does not implement it**: its
parser drops any frame that has an `incompat_flags` bit set (chapter 3). What
follows is what the specification requires of a layer that you would add.

- **Modes.** `IFLAG_SIGNED` authenticates the frame and leaves the payload
  readable. `IFLAG_ENCRYPTED` encrypts the payload and authenticates it. Both use
  one authenticated-encryption construction, with the header as associated data
  so that addressing stays readable.
- **Trailer.** The 2-byte CRC is replaced by a 6-byte timestamp (100 microsecond
  ticks since T0) and an authentication tag of 16 bytes, or 8 if truncated.
- **Cipher.** ChaCha20-Poly1305 by default, chosen because it is fast and
  constant-time in software on a Cortex-M4 with no crypto hardware. AES-GCM or
  AES-CCM may be used where hardware AES exists. A vetted library must be used,
  never a hand-written primitive.
- **Nonce.** Built from the direction, sysid, compid, seq and trailer timestamp,
  never random and never sent whole. A nonce is never reused under one key.
- **Replay protection.** A secured frame is accepted only if its timestamp is
  within a window (default 1 second) of the receiver's synchronised clock **and**
  is greater than the last timestamp accepted from that sender and direction.
  Because the anchor is the synchronised clock, a reboot cannot rewind it, so no
  counter has to be kept in flash.
- **Keys.** A pre-shared key held in `0:navlink.key` on the vehicle's SD card, read
  once at boot and never transmitted.
- **Gate.** While unsynchronised, the vehicle rejects every secured frame and every
  command (chapter 7).

## Sources

- `faults.json`, `generate.py` (fault table validation)
- `docs/reference/navlink-v2-spec.md`, sections 11 (security layer), 13 (capability negotiation) and 14.1.1 (FAULT_STATUS and the fault table)
- `ABI.md`, sections 3, 4 and 8
