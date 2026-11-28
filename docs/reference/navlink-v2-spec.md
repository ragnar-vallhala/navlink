---
title: "NavLink v2 — Protocol Specification"
subtitle: "Wire format, dialect, codegen contract, services, security & time sync"
author: "Vayu flight stack · `src/comm`, `navigator/src/protocol`, `tools/navlink`"
date: "June 2026"
version: "2.0-draft"
abstract: |
  The normative specification for **NavLink v2**, the Vayu flight stack's link
  protocol. It defines the byte-exact frame format, the CRC-16/`CRC_EXTRA`
  integrity scheme, field encoding and packed-struct layout, the JSON message
  dialect and its schema, the code-generation contract (wire/aligned structs,
  converters, dispatcher), the command/parameter/mission/file services, the
  AEAD security layer, the wall-clock time-synchronisation protocol, the full
  message catalog with its core/vendor msgid split, the v1↔v2 migration, and
  conformance test vectors. The companion document *NavLink v2 — Protocol
  Analysis & Redesign* (`navlink-v2-design.md`) gives the rationale; this
  document gives the rules.
---

## 1. Scope, conformance, and conventions

### 1.1 Scope

This document specifies NavLink v2 completely enough to write an interoperable
implementation in firmware (C, STM32F4), the ground station (C++), and tools
(Python). It covers the wire format, the integrity and security layers, the
dialect that is the single source of truth, the code generated from it, the
service protocols, and the migration from v1.

### 1.2 Requirement levels

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**,
**SHOULD NOT**, **MAY**, and **OPTIONAL** are to be interpreted as in RFC 2119.

### 1.3 Conventions

- All multi-byte integers are **little-endian** on the wire unless stated.
- Bit 0 is the least-significant bit.
- Floating point is **IEEE-754** (`f32` = binary32, `f64` = binary64).
- Hex literals are written `0x…`; byte sequences are space-separated hex.
- `A ∥ B` denotes concatenation; `X[a..b]` is bytes `a` inclusive to `b`
  exclusive; `X[a..b]` with both inclusive is written `X[a … b]` in prose.
- "FC" = flight controller; "GCS" = ground control station; "peer" = either.

### 1.4 Versioning

This document specifies wire **version `0x02`** (the value carried in header
byte 1, §3.2). The protocol identity is otherwise NavLink's own; NavLink v2 is
*not* wire-compatible with MAVLink and interoperability with any external
protocol is a non-goal.

---

## 2. Terminology

| Term | Meaning |
|------|---------|
| **frame** | one on-wire unit: header + payload + trailer (§3) |
| **msgid** | 24-bit message type identifier (§9) |
| **dialect** | the JSON catalog of all messages; single source of truth (§7) |
| **CRC_EXTRA** | 1-byte per-message layout signature folded into the checksum (§4.3) |
| **wire struct** | packed C/C++ struct matching the payload byte-for-byte (§8.2) |
| **aligned struct** | naturally-aligned application struct for the same message (§8.2) |
| **secured frame** | a frame carrying `IFLAG_SIGNED` or `IFLAG_ENCRYPTED` (§11) |
| **T0** | the synchronised reference epoch for wall-clock timestamps (§10) |

---

## 3. Frame format

### 3.1 Overview

A NavLink v2 frame is:

```
+--------+-----------------------------+-------------------+----------------------+
| sync   |  header (bytes 1 … 9)        |  payload          |  trailer             |
| 0x56   |  version,len,flags,seq,...   |  0 … 255 bytes    |  CRC or secured      |
+--------+-----------------------------+-------------------+----------------------+
```

The header is a **fixed 10 bytes** (offsets 0–9). The trailer is either a
2-byte CRC (unsecured) or a `[counter:6][tag:16]` secured trailer (§11).

### 3.2 Header layout (normative)

```
 off  size  field           value / meaning
 ---  ----  --------------  -------------------------------------------------------
  0    1    sync            0x56 ('V'). Frame start. MUST be 0x56.
  1    1    version         0x02 for this spec. Demuxes v1/v2 (§3.4).
  2    1    payload_len     number of payload bytes on the wire, 0..255 (§5.6 truncation)
  3    1    incompat_flags  unknown bit set ⇒ receiver MUST drop the frame (§3.3)
  4    1    seq             per-(sysid,compid) frame counter, rolls 0..255 (§3.5)
  5    1    sysid           sender system id, 1..255 (0 = anonymous/broadcast)
  6    1    compid          sender component id within the system
  7    3    msgid           message type, u24 little-endian, 0..16,777,215 (§9)
 10    N    payload         payload_len bytes, packed wire layout (§5)
10+N   2    checksum        CRC-16/MCRF4XX seeded with CRC_EXTRA (§4) — UNSECURED only
```

There is **no `compat_flags` byte** and **no timestamp** in the header; the
former is replaced by capability negotiation (§13), the latter lives only in the
payloads that need it (§10).

### 3.3 incompat_flags (normative)

`incompat_flags` advertises frame-structural features that a receiver MUST
understand to parse the frame at all. **If a receiver sees any bit set that it
does not implement, it MUST silently drop the frame** (it cannot be parsed
safely). Framing is not lost: `payload_len` lets the parser skip the frame and
resynchronise.

| Bit | Name | Effect |
|-----|------|--------|
| `0x01` | `IFLAG_SIGNED` | secured trailer present, payload authenticated (cleartext) — §11 |
| `0x02` | `IFLAG_ENCRYPTED` | secured trailer present, payload encrypted+authenticated — §11 |
| `0x04` | `IFLAG_CRC32` | bulk mode: 4-byte CRC-32 trailer instead of CRC-16 — §12.4 |
| `0x08` | `IFLAG_FRAGMENTED` | payload is a fragment of a larger message — §12.4.1 |
| `0x10`–`0x80` | reserved | MUST be 0 in this version |

`IFLAG_SIGNED` and `IFLAG_ENCRYPTED` are mutually exclusive on a single frame
(encryption implies authentication). When either is set, the 2-byte CRC is
**absent** and replaced by the secured trailer (§11.2).

There is exactly **one** incompat byte (8 bits). It is the one header field
whose exhaustion would force a frame-format bump, so it is deliberately a full
byte; advisory, layout-neutral capabilities are negotiated once at connect (§13)
rather than carried per frame.

### 3.4 Version demultiplexing (v1 / v2 coexistence)

v1 and v2 share the `0x56` sync byte. A receiver distinguishes them on **byte 1**:

```
read byte0
if byte0 != 0x56: resync (scan forward to next 0x56)
read byte1
if (byte1 & 0x0F) == 0x01:   parse as NavLink v1   # v1 packs (type<<4)|version, version==1
elif byte1 == 0x02:          parse as NavLink v2
else:                        resync
```

This is unambiguous: every v1 frame has low-nibble `1` in byte 1 (its version
field), and `0x02` never occurs there for v1. A future v3 takes `0x03`, etc.

### 3.5 Sequence number

`seq` increments by 1 (mod 256) for every frame a peer emits **per
(sysid, compid)**. Receivers MAY use gaps to estimate link loss. `seq`
participates in the AEAD nonce for secured frames (§11.4); a sender MUST NOT
emit two secured frames with the same `(sysid, compid, seq, counter)` under one key.

### 3.6 Sizes

| Quantity | Value |
|----------|-------|
| sync | 1 byte, `0x56` |
| header | 10 bytes |
| payload | 0–255 bytes (single frame); larger via §12.4 |
| unsecured trailer | 2 bytes (CRC-16) or 4 bytes (`IFLAG_CRC32`) |
| secured trailer | 22 bytes: 6 counter + 16 tag (§11.2) |
| max secured frame | 287 bytes (10 + 255 + 22); implementations size every frame buffer for it |
| min frame | 12 bytes (10 header + 0 payload + 2 CRC) |
| max unsecured frame | 267 bytes (10 + 255 + 2) |

---

## 4. Integrity: CRC-16 and CRC_EXTRA

### 4.1 CRC-16/MCRF4XX parameters

| Parameter | Value |
|-----------|-------|
| width | 16 |
| polynomial | `0x1021` (reflected `0x8408`) |
| init | `0xFFFF` |
| reflect in/out | true / true |
| xorout | `0x0000` |
| check (`"123456789"`) | `0x6F91` |

Reference accumulator (one byte at a time; identical to MAVLink's
`crc_accumulate`, reproduced normatively):

```c
static inline void crc_accumulate(uint8_t b, uint16_t *crc) {
    uint8_t t = b ^ (uint8_t)(*crc & 0xFF);
    t ^= (t << 4);
    *crc = (*crc >> 8) ^ ((uint16_t)t << 8) ^ ((uint16_t)t << 3) ^ ((uint16_t)t >> 4);
}
```

### 4.2 Frame checksum computation (unsecured frames)

```
crc = 0xFFFF
for b in header[1 .. 9]:          # version, payload_len, incompat_flags, seq,
    crc_accumulate(b, &crc)       #   sysid, compid, msgid[0..3) — everything after sync
for b in payload[0 .. payload_len):
    crc_accumulate(b, &crc)
crc_accumulate(CRC_EXTRA[msgid], &crc)    # the per-message seed (§4.3)
checksum = crc                    # little-endian into trailer bytes
```

The `sync` byte (offset 0) is **excluded**. The CRC_EXTRA seed is accumulated
**last**. On `IFLAG_CRC32` frames the same input is run through CRC-32 (§12.4).
Secured frames carry no CRC; integrity is the AEAD tag (§11).

A receiver MUST recompute and compare; a mismatch MUST cause the frame to be
dropped. Unlike v1, a checksum of `0x0000` is **valid** and MUST NOT be special-
cased.

### 4.3 CRC_EXTRA (per-message layout signature)

`CRC_EXTRA[msgid]` is a 1-byte value computed by codegen from the message's
*structure*, so that a sender and receiver that disagree on a message's layout
produce different seeds and the checksum **fails** rather than silently
mis-decoding.

Algorithm (over **declaration/index order**, which equals wire order, §5.2;
extension fields §5.5 are **excluded**):

```
crc = 0xFFFF
accumulate each ASCII byte of message_name
accumulate one space (0x20)
for field in non_extension_fields, in ascending index order:
    accumulate each ASCII byte of field.wire_type_name   # "u8","i32","f32",...
    accumulate one space (0x20)
    accumulate each ASCII byte of field.name
    accumulate one space (0x20)
    if field.is_array:
        accumulate (uint8_t) field.array_len
CRC_EXTRA = (uint8_t)((crc & 0xFF) ^ (crc >> 8))
```

`wire_type_name` uses the canonical names of §5.1 (a fixed-point field uses its
**integer** wire type name, e.g. `i32`, not `deg`). The receiver keeps a
generated `msgid → CRC_EXTRA` table; an unknown msgid has an unknown seed and the
frame MUST be dropped as undecodable (framing preserved via `payload_len`).

---

## 5. Field encoding

### 5.1 Scalar types

| name | wire bytes | C type | notes |
|------|-----------|--------|-------|
| `u8` / `i8` | 1 | `uint8_t` / `int8_t` | |
| `u16` / `i16` | 2 | `uint16_t` / `int16_t` | LE |
| `u24` | 3 | — | LE, used for `msgid` references |
| `u32` / `i32` | 4 | `uint32_t` / `int32_t` | LE |
| `u64` / `i64` | 8 | `uint64_t` / `int64_t` | LE |
| `f32` | 4 | `float` | IEEE-754 binary32, LE |
| `f64` | 8 | `double` | IEEE-754 binary64, LE |
| `char` | 1 | `char` | ASCII/UTF-8 code unit |

Arrays are `type[len]` with a fixed `len`; `char[len]` is a fixed-width,
NUL-padded (not necessarily NUL-terminated) string.

### 5.2 Wire order — declaration order, no reordering

Fields are emitted on the wire in **ascending `index` order** exactly as
declared in the dialect (§7). NavLink does **not** reorder fields by size (a
deliberate divergence from MAVLink). Combined with packed structs (§8.2) this
makes wire order, source order, and struct layout identical.

### 5.3 Packed layout & padding

The generated wire struct is **packed** (no implicit padding). Padding is only
present where the dialect author declares an explicit `pad` field
(`{"name":"_pad","type":"u8"}` or `"u8"[n]`). A conformant payload therefore has
no compiler-dependent gaps.

### 5.4 Fixed-point fields

A field MAY declare an integer wire `type` plus a `scale` and `unit`, meaning the
real value is `wire_value / scale` in `unit`. Use fixed-point where `f32`'s
~7-significant-digit *relative* precision is insufficient:

| quantity | type | scale | unit | resolution / range |
|----------|------|-------|------|--------------------|
| latitude/longitude | `i32` | `1e7` | deg | ~1.1 cm, ±214.7° |
| altitude | `i32` | `1e3` | m | 1 mm, ±2,147 km |
| horizontal/vertical speed | `i16` | `1e2` | m/s | 1 cm/s, ±327 m/s |
| heading | `u16` | `1e2` | deg | 0.01°, 0–655.35 |

`scale` is chosen per field so `range × scale` fits the integer width. A blanket
`×1e7` is **non-conformant** (it overflows large-range fields and cannot encode
`f64`). Small bounded quantities (angles in rad, rates, temperatures, voltages)
stay `f32`/`f64`.

### 5.5 Extension fields (forward/backward growth)

A field MAY be flagged `extension: true`. Extension fields:

1. are serialised **after** all non-extension fields, in ascending index order;
2. are **excluded** from `CRC_EXTRA` (§4.3), so adding them does not change a
   message's seed and old/new peers still validate each other's frames;
3. MUST only be appended (never inserted among, or removed from, the original
   fields).

### 5.6 Trailing-zero truncation

A sender SHOULD drop trailing all-zero **plaintext** bytes and report the
shortened length in `payload_len`. A receiver MUST zero-fill the payload back to
the message's full known length before decoding. Consequences:

- new sender → old receiver: trailing extension bytes are simply beyond what the
  old receiver reads;
- old sender → new receiver: absent (new) fields read as 0, their defined
  "absent" value.

On secured frames, truncation runs on the plaintext **before** encryption
(§11.6); `payload_len` is authenticated as AAD so the fill length cannot be
tampered.

---

## 6. Time and timestamp model

### 6.1 Wall-clock field `[s:20 | ms:12]`

The standard wall-clock timestamp is a 32-bit little-endian word carried **in the
payload** of messages that need it (there is no clock in the header, §3.2):

```
bits 31..12 : seconds  (20 bits) — integer offset from the synced epoch T0
bits 11..0  : ms        (12 bits) — sub-second milliseconds, 0..999
```

- **T0** is the reference epoch the FC's clock is disciplined to, established and
  maintained by `TIME_SYNC` (§10). T0 is **not transmitted as an epoch value**:
  the GCS measures the FC↔GCS clock relationship from the round-trip stamps and
  steers the FC with `commanded_offset_ms` so the FC's "now" tracks the GCS
  wall-clock. The GCS picks T0 (it folds it into the offset it commands) and so
  can reconstruct absolute time from the reported `now − T0`. The FC never
  invents wall-clock time on its own (§10.1).
- T0 is fixed once at the **startup** sync; periodic resyncs (§10.4) apply small
  drift corrections, **not** a T0 reset, so timestamps stay continuous. 20-bit
  seconds ⇒ range 2²⁰ s ≈ **291 h**, which dwarfs any flight, so the field never
  rolls within a session.
- 12-bit ms holds 0–999; the 2 spare high bits of the ms sub-field are reserved.
  Bit 11 is the **`TIME_STALE`** flag: the sender MUST set it before its first
  successful sync and after any clock discontinuity, and a receiver MUST treat a
  stamp with `TIME_STALE` set as unsynchronised.

> Supersedes v1's per-frame `u32` millisecond timestamp in the header: v2 takes
> time out of the header (§3.2) and into this compact payload field — and
> `sample_time_us` (§6.2) for high-rate alignment — stamped only on messages that
> need it. The v1 in-header stamp is phased out as peers migrate (§3.4 demux).

### 6.2 High-rate sample time

High-rate sensor messages additionally carry `sample_time_us` (`u32`, µs since
boot, monotonic, single clock domain) for intra-vehicle alignment finer than
1 ms. This is independent of the wall-clock field and is **not** GCS-referenced.

---

## 7. The dialect (single source of truth)

The dialect is one JSON document, `navlink/dialect.json`, from which all codecs,
the `CRC_EXTRA` table, and the dispatcher are generated (§8).

### 7.1 Authoring rules (normative)

1. **Fields are an ordered array** of objects, never a `name→type` map (JSON
   object key order is unspecified; wire order is load-bearing).
2. **Every field carries an explicit integer `index`.** Indices MUST be unique
   within a message and contiguous from 0 across the non-extension fields;
   extension fields continue the sequence. Codegen MUST reject violations.
3. **Every field declares its `type`** from the §5.1 enum; missing/unknown type
   is an error.
4. Decimal quantities that need fixed-point declare `scale` (number) and `unit`
   (string) alongside an integer `type` (§5.4).
5. Annotations go in a `doc` string per message/field (JSON has no comments);
   codegen emits them as docstrings / `//` comments.
6. 64-bit constants (e.g. defaults) are written as **hex strings** (`"0x…"`),
   because JSON numbers are IEEE-754 doubles (exact only to 2⁵³).
7. `msgid` MUST lie in the core half (`0x000000`–`0x7FFFFF`) for in-tree
   messages; vendor dialects use `0x800000`–`0xFFFFFF` (§9).
8. **Every message and enum names its `section`**, a dotted path (`flight.tuning`)
   into the top-level `sections` tree; codegen MUST reject an undeclared path.
   Sections are presentation only (docs, the HTML tree) and never enter the wire
   format or `CRC_EXTRA`, so moving a message between sections is not an ABI change.

The generator auto-assigns and then **freezes** `index` values for newly added
fields (writing them back into the file), so authors need not hand-number while
the explicit index still guarantees a stable ABI.

### 7.2 Message object schema

```
sections := { key: { "title": string, "doc": string (optional),
                     "sections": sections (optional) }, ... }
message := {
  "msgid":    integer (0 .. 16777215),
  "name":     string  (UPPER_SNAKE, unique),
  "section":  string  (dotted path into sections, e.g. "flight.tuning"),
  "replaces": string  (optional, v1 cross-reference),
  "doc":      string  (optional),
  "fields":   [ field, ... ]
}
field := {
  "index":     integer (>= 0, unique within message),
  "name":      string  (lower_snake, unique within message),
  "type":      enum    ("u8"|"i8"|"u16"|"i16"|"u24"|"u32"|"i32"|"u64"|"i64"|"f32"|"f64"|"char"),
  "len":       integer (optional, >=1; makes the field an array),
  "scale":     number  (optional; fixed-point divisor),
  "unit":      string  (optional; physical unit),
  "enum":      string  (optional; references an enums[] entry),
  "default":   number|string (optional; string = hex for 64-bit),
  "extension": boolean (optional, default false),
  "doc":       string  (optional)
}
```

### 7.3 Worked example dialect

A self-contained fragment showing a telemetry message, a fixed-point position
message with extensions, a typed command, and a typed parameter value:

```json
{
  "dialect": "vayu-core",
  "version": 2,
  "enums": {
    "command_result": {
      "doc": "COMMAND_ACK.result",
      "entries": [
        { "name": "ACCEPTED",              "value": 0 },
        { "name": "TEMPORARILY_REJECTED",  "value": 1 },
        { "name": "DENIED",                "value": 2 },
        { "name": "UNSUPPORTED",           "value": 3 },
        { "name": "FAILED",                "value": 4 },
        { "name": "IN_PROGRESS",           "value": 5 }
      ]
    },
    "param_type": {
      "entries": [
        { "name": "U8",  "value": 1 }, { "name": "I8",  "value": 2 },
        { "name": "U16", "value": 3 }, { "name": "I16", "value": 4 },
        { "name": "U32", "value": 5 }, { "name": "I32", "value": 6 },
        { "name": "U64", "value": 7 }, { "name": "I64", "value": 8 },
        { "name": "F32", "value": 9 }, { "name": "F64", "value": 10 }
      ]
    }
  },

  "messages": [
    {
      "msgid": 0, "name": "HEARTBEAT", "replaces": "0x0",
      "doc": "~1 Hz liveness, mode, advertised capabilities, wall-clock stamp.",
      "fields": [
        { "index": 0, "name": "type",          "type": "u8",  "doc": "vehicle type" },
        { "index": 1, "name": "autopilot",     "type": "u8" },
        { "index": 2, "name": "base_mode",     "type": "u8" },
        { "index": 3, "name": "system_status", "type": "u8" },
        { "index": 4, "name": "nav_state",     "type": "u8" },
        { "index": 5, "name": "capabilities",  "type": "u32", "doc": "capability bitmask (see §13)" },
        { "index": 6, "name": "timestamp",     "type": "u32", "doc": "wall-clock [s:20|ms:12] (§6.1)" }
      ]
    },

    {
      "msgid": 1026, "name": "ATTITUDE_EULER", "replaces": "0x4",
      "doc": "Euler attitude + body rates, NED frame.",
      "fields": [
        { "index": 0, "name": "roll",       "type": "f32", "unit": "rad", "doc": "NED roll" },
        { "index": 1, "name": "pitch",      "type": "f32", "unit": "rad" },
        { "index": 2, "name": "yaw",        "type": "f32", "unit": "rad" },
        { "index": 3, "name": "rollspeed",  "type": "f32", "unit": "rad/s" },
        { "index": 4, "name": "pitchspeed", "type": "f32", "unit": "rad/s" },
        { "index": 5, "name": "yawspeed",   "type": "f32", "unit": "rad/s" }
      ]
    },

    {
      "msgid": 2048, "name": "GPS_RAW_INT", "replaces": null,
      "doc": "Raw GNSS fix. Position is fixed-point (§5.4) — f32 loses >1 m globally.",
      "fields": [
        { "index": 0, "name": "fix_type",   "type": "u8" },
        { "index": 1, "name": "satellites", "type": "u8" },
        { "index": 2, "name": "lat",        "type": "i32", "scale": 1e7, "unit": "deg" },
        { "index": 3, "name": "lon",        "type": "i32", "scale": 1e7, "unit": "deg" },
        { "index": 4, "name": "alt",        "type": "i32", "scale": 1e3, "unit": "m", "doc": "AMSL" },
        { "index": 5, "name": "eph",        "type": "u16", "scale": 1e2, "unit": "m" },
        { "index": 6, "name": "epv",        "type": "u16", "scale": 1e2, "unit": "m" },
        { "index": 7, "name": "vel",        "type": "u16", "scale": 1e2, "unit": "m/s" },
        { "index": 8, "name": "cog",        "type": "u16", "scale": 1e2, "unit": "deg" },
        { "index": 9, "name": "sample_time_us", "type": "u32", "unit": "us" },

        { "index": 10, "name": "alt_ellipsoid", "type": "i32", "scale": 1e3, "unit": "m",
          "extension": true, "doc": "added later; old peers ignore it (§5.5)" }
      ]
    },

    {
      "msgid": 8195, "name": "CMD_SET_PID",
      "doc": "Typed command (§12.1). Opens with the standard command header.",
      "fields": [
        { "index": 0, "name": "target_sys",  "type": "u8" },
        { "index": 1, "name": "target_comp", "type": "u8" },
        { "index": 2, "name": "req_seq",     "type": "u8", "doc": "echoed in COMMAND_ACK" },
        { "index": 3, "name": "axis",        "type": "u8", "doc": "0=roll 1=pitch 2=yaw" },
        { "index": 4, "name": "kp",          "type": "f32" },
        { "index": 5, "name": "ki",          "type": "f32" },
        { "index": 6, "name": "kd",          "type": "f32" }
      ]
    },

    {
      "msgid": 5, "name": "COMMAND_ACK", "replaces": "0x3",
      "doc": "Acknowledges any command, correlated by (command, req_seq).",
      "fields": [
        { "index": 0, "name": "command",       "type": "u24", "doc": "acked command's msgid" },
        { "index": 1, "name": "req_seq",       "type": "u8" },
        { "index": 2, "name": "result",        "type": "u8",  "enum": "command_result" },
        { "index": 3, "name": "progress",      "type": "u8",  "doc": "0..100 for IN_PROGRESS" },
        { "index": 4, "name": "result_param2", "type": "i32" }
      ]
    },

    {
      "msgid": 12290, "name": "PARAM_VALUE",
      "doc": "Typed parameter value (§12.2). 'value' is the real type, never a float bit-cast.",
      "fields": [
        { "index": 0, "name": "param_id",   "type": "char", "len": 16 },
        { "index": 1, "name": "index",      "type": "u16" },
        { "index": 2, "name": "count",      "type": "u16" },
        { "index": 3, "name": "generation", "type": "u32", "doc": "bumped on every PARAM_SET (§12.2)" },
        { "index": 4, "name": "type",       "type": "u8",  "enum": "param_type" },
        { "index": 5, "name": "value",      "type": "u8",  "len": 8, "doc": "real value, LE, in 'type', ≤8 B" }
      ]
    }
  ]
}
```

### 7.4 Dialect JSON Schema (validation in CI)

The dialect MUST validate against this schema (Draft 2020-12) before codegen;
CI additionally checks index contiguity, msgid uniqueness, msgid range, and
`scale`-fits-width:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://vayu/navlink/dialect.schema.json",
  "type": "object",
  "required": ["dialect", "version", "messages"],
  "properties": {
    "dialect": { "type": "string" },
    "version": { "const": 2 },
    "enums": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "required": ["entries"],
        "properties": {
          "doc": { "type": "string" },
          "entries": {
            "type": "array",
            "items": {
              "type": "object",
              "required": ["name", "value"],
              "properties": {
                "name":  { "type": "string", "pattern": "^[A-Z][A-Z0-9_]*$" },
                "value": { "type": "integer", "minimum": 0 },
                "doc":   { "type": "string" }
              },
              "additionalProperties": false
            }
          }
        },
        "additionalProperties": false
      }
    },
    "messages": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["msgid", "name", "fields"],
        "properties": {
          "msgid":    { "type": "integer", "minimum": 0, "maximum": 16777215 },
          "name":     { "type": "string", "pattern": "^[A-Z][A-Z0-9_]*$" },
          "replaces": { "type": ["string", "null"] },
          "doc":      { "type": "string" },
          "fields": {
            "type": "array",
            "minItems": 1,
            "items": {
              "type": "object",
              "required": ["index", "name", "type"],
              "properties": {
                "index":     { "type": "integer", "minimum": 0 },
                "name":      { "type": "string", "pattern": "^[a-z_][a-z0-9_]*$" },
                "type":      { "enum": ["u8","i8","u16","i16","u24","u32","i32",
                                        "u64","i64","f32","f64","char"] },
                "len":       { "type": "integer", "minimum": 1 },
                "scale":     { "type": "number", "exclusiveMinimum": 0 },
                "unit":      { "type": "string" },
                "enum":      { "type": "string" },
                "default":   { "type": ["number", "string"] },
                "extension": { "type": "boolean" },
                "doc":       { "type": "string" }
              },
              "additionalProperties": false
            }
          }
        },
        "additionalProperties": false
      }
    }
  },
  "additionalProperties": false
}
```

---

## 8. Code-generation contract

`tools/navlink/generate.py` reads `dialect.json` and emits, deterministically:

- firmware: `include/comm/navlink_msgs.h`, `src/comm/navlink_msgs.c`
- GCS: `navigator/src/protocol/NavlinkMsgs.{h,cpp}`
- tools: `tools/autotune/navlink_msgs.py`

### 8.1 What is generated

1. **Enums** as C `enum` / C++ `enum class` / Python `IntEnum`.
2. **Two structs per message** (§8.2).
3. **`pack` / `unpack`** between a byte buffer and the wire struct.
4. **`to_aligned` / `from_aligned`** converters (§8.2).
5. **The `CRC_EXTRA` table** (`msgid → u8`) and a `msgid → name/size` table.
6. **The dispatcher** (§8.3).

The generated v1 codec MUST be byte-identical to the legacy hand codec
(golden-vector test against captured `v_nav.bin`).

### 8.2 The two representations

For each message `M`, codegen emits a **packed wire struct** matching the wire
byte-for-byte and a **natural-aligned application struct**:

```c
/* wire image — exact bytes, no padding */
typedef struct __attribute__((packed)) {
    uint8_t  axis;
    float    kp;        /* offset 1 — unaligned, that is fine for a packed struct */
    float    ki;
    float    kd;
} navlink_cmd_set_pid_wire_t;   /* 13 bytes */

/* application struct — naturally aligned, padded by the compiler */
typedef struct {
    uint8_t axis;
    float   kp, ki, kd;
} navlink_cmd_set_pid_t;
```

**Codec (wire ↔ bytes): one `memcpy`.** Because the wire struct is packed and
both ends are little-endian (and floats are IEEE-754 both sides), the whole
payload moves in a single copy:

```c
size_t navlink_cmd_set_pid_pack(uint8_t *buf, const navlink_cmd_set_pid_wire_t *w) {
    memcpy(buf, w, sizeof *w);          /* + trailing-zero truncation, §5.6 */
    return sizeof *w;
}
void navlink_cmd_set_pid_unpack(navlink_cmd_set_pid_wire_t *w,
                                const uint8_t *buf, size_t len) {
    memset(w, 0, sizeof *w);            /* zero-fill for truncation */
    memcpy(w, buf, len <= sizeof *w ? len : sizeof *w);
}
```

The codec MUST NOT form a typed pointer into the packed struct (`&w->kp`);
taking the address of a packed member is undefined behaviour on strict targets.
Whole-struct `memcpy` and member *reads* (which the compiler emits unaligned-safe
code for) are the only permitted accesses.

**Converters (wire ↔ aligned): field-wise, lazy.** Application code that does
arithmetic uses the aligned struct, reached via generated converters:

```c
void navlink_cmd_set_pid_to_aligned(navlink_cmd_set_pid_t *a,
                                    const navlink_cmd_set_pid_wire_t *w) {
    a->axis = w->axis; a->kp = w->kp; a->ki = w->ki; a->kd = w->kd;
}
```

Conversion is OPTIONAL per use site: pure forward/log/relay paths stay on the
wire struct and skip it. The converters are also the single place a byte-swap
would live if a big-endian host ever appeared (none today).

### 8.3 The dispatcher

Codegen emits a `msgid → { decode, handler-slot }` table so dispatch is
table-driven, not hand-written branching. On the FC:

```c
typedef void (*navlink_handler_fn)(const navlink_frame_t *hdr, const void *aligned_msg);

typedef struct {
    uint32_t          msgid;
    uint16_t          wire_size;
    uint8_t           crc_extra;
    navlink_handler_fn handler;     /* registered by the application */
} navlink_dispatch_entry_t;

extern navlink_dispatch_entry_t navlink_dispatch_table[];   /* generated, sorted by msgid */

/* generated dispatch: O(log n) binary search on msgid */
int navlink_dispatch(const navlink_frame_t *hdr, const uint8_t *payload, size_t len);
```

`navlink_dispatch` looks up `hdr->msgid`, validates `CRC_EXTRA`, `unpack`s into
the wire struct, `to_aligned`s, and calls the registered handler
(`on_CMD_SET_PID(const navlink_cmd_set_pid_t*)`). This replaces the v1 hand-
written `if/else` on packet type, the nested `if/else` on `cmd_id`, and the GCS
`std::variant` switch. The generator SHOULD warn for any msgid that has no
registered handler so a new message cannot be silently dropped.

---

## 9. Message-ID space

The 24-bit space (16,777,216 ids) is split on its **top bit**:

| Range | Owner | Rule |
|-------|-------|------|
| `0x000000`–`0x7FFFFF` | **core / FC** | assigned only in-tree (this spec) |
| `0x800000`–`0xFFFFFF` | **vendor / experimental** | `(msgid & 0x800000) != 0`; core never assigns here |

A vendor therefore picks ids freely in the upper half and can never collide with
a future official message. The core half is laid out in spaced blocks:

| Range (dec) | hex | Block |
|-------------|-----|-------|
| 0–255 | `0x000000–0x0000FF` | Core / system |
| 256–1023 | `0x000100–0x0003FF` | reserved (core growth) |
| 1024–2047 | `0x000400–0x0007FF` | Sensors / state |
| 2048–3071 | `0x000800–0x000BFF` | Navigation / position |
| 3072–4095 | `0x000C00–0x000FFF` | Power / propulsion |
| 4096–8191 | `0x001000–0x001FFF` | Peripherals / payload |
| 8192–12287 | `0x002000–0x002FFF` | Commands (typed) |
| 12288–16383 | `0x003000–0x003FFF` | Services (param/mission/file/cal) |
| 16384–65535 | `0x004000–0x00FFFF` | reserved (near-term core) |
| 65536–8388607 | `0x010000–0x7FFFFF` | deep future core reserve (~8.3 M) |

The full catalog with fields is §14.

---

## 10. Time-synchronisation protocol

### 10.1 Principle

There is no clock in the header. The FC never invents wall-clock time; the GCS
establishes the reference epoch **T0** and the FC reports `now − T0` in the
`[s:20|ms:12]` field (§6.1). The sync is a GCS-initiated **round trip** that
compensates for link latency (one-way delay at 115200 baud ≈ 1.4 ms ≈ the 1 ms
LSB, so it cannot be ignored).

### 10.2 Message

A single role-discriminated message carries the whole exchange (msgid 10,
32 bytes, little-endian). All stamps are **milliseconds**.

```
TIME_SYNC {
  role:                u8    # time_sync_role: 0 = REQUEST (GCS→FC), 1 = RESPONSE (FC→GCS)
  seq:                 u8    # request sequence, echoed in the response
  _pad:                u8[2] # reserved, zero
  t1_gcs_tx:           u64   # GCS send   (wall-clock ms)
  t2_fc_rx:            u64   # FC receive (FC ms)
  t3_fc_tx:            u64   # FC send    (FC ms)
  commanded_offset_ms: i32   # GCS→FC clock correction; INT32_MIN = none
}
```

> One message, not a pair: the `role` byte distinguishes the GCS's `REQUEST`
> from the FC's `RESPONSE`, so the catalog has a single entry. The fourth
> timestamp `t4` is the GCS's own receive time, captured locally on receipt — it
> is never put on the wire.

### 10.3 Algorithm

1. The GCS sends `TIME_SYNC{ role=REQUEST, seq, t1_gcs_tx = now }`, optionally
   with `commanded_offset_ms` set to the correction it wants the FC to apply
   (`INT32_MIN` = no command this round).
2. The FC records `t2_fc_rx` on receipt, applies `commanded_offset_ms` to its
   clock when it is not `INT32_MIN`, then replies
   `TIME_SYNC{ role=RESPONSE, seq, t1_gcs_tx echoed, t2_fc_rx, t3_fc_tx = now }`.
3. The GCS captures `t4` on receipt and computes (NTP-style):

```
rtt    = (t4 − t1) − (t3 − t2)
delay  = rtt / 2
offset = ((t2 − t1) + (t3 − t4)) / 2
```

The GCS filters `offset`/`delay` over a short window and feeds the result back as
the next request's `commanded_offset_ms`; the FC disciplines its clock to it and
thereafter reports `now − T0` (§6.1). Correcting by the filtered offset (which
already removes one-way `delay`) keeps the synced error inside the 1 ms LSB
rather than ~1.4 ms off.

> **Note (asymmetry).** `delay = rtt/2` assumes symmetric up/down latency — true
> for a USB/UART bench link, approximate on an asymmetric telemetry radio. The
> filtered `offset` term and the periodic/emergency resyncs (§10.4) bound the
> residual.

### 10.4 Schedule

1. **Startup** — at link establishment, before any FC stamp is trusted.
2. **Periodic** — every **5 h** of continuous operation (bounds crystal drift;
   a few-ppm TCXO drifts a handful of ms over 5 h, inside the 1 ms LSB).
3. **Emergency** — the GCS compares incoming FC stamps to its own clock and
   pushes an out-of-schedule `TIME_SYNC` if the error exceeds threshold.

T0 is fixed at the startup sync and the resyncs only trim accumulated drift (they
do not reset T0), so the 20-bit seconds field stays continuous; its ≈291 h span
dwarfs any flight, so it never rolls within a session (§6.1).

### 10.5 Command gate (normative)

Until the startup sync succeeds, and whenever the FC's clock and the GCS
reference disagree by more than a configured tolerance, the FC is
**unsynchronised**: it MUST set `TIME_STALE` (§6.1) on its own stamps and MUST
reject every command frame (§12.1).

This gate is about timestamps, not security. **The clock is not a security
anchor** (§11.5): `TIME_SYNC` sets the FC clock by an arbitrary offset, so
anything that can forge a `TIME_SYNC` can move it. On a link where a key is
configured (§11.7) the FC MUST accept a `TIME_SYNC` that changes its clock only in
a secured frame (§11.9); an unsecured one is dropped, so the clock cannot be used
to attack replay protection or anything else. Replay protection uses counters,
not the clock (§11.5).

---

## 11. Security layer

Replay protection and nonce uniqueness rest on **counters and per-session keys,
never on the synchronised clock** (decision D1). This revises an earlier draft
that anchored replay on the clock and kept no counter; that draft allowed a
forged clock to reopen replay and let a nonce repeat across sessions. Status:
specification only, not implemented by the generated codec.

### 11.1 Modes

Per-frame, selected by `incompat_flags` (§3.3), default-off, gated at build time
by `ENABLE_NAVLINK_CRYPTO` and advertised in `CAPABILITIES` (§13):

- `IFLAG_SIGNED`: authenticate only; payload cleartext.
- `IFLAG_ENCRYPTED`: AEAD; payload encrypted **and** authenticated.

Both use one **AEAD** construction (no separate encrypt-then-MAC). The header is
associated data, so addressing stays readable for routing and framing; only the
payload is encrypted (for `IFLAG_ENCRYPTED`). The tag is **16 bytes everywhere**
(decision D6): no truncated tag, no per-link or per-direction length, so there is
nothing to negotiate or to downgrade.

**Same on every link (decision D2).** The security policy does not depend on the
transport: USB, a serial radio and a wireless bridge are all treated alike. Once a
session exists, every frame the two ends exchange, in both directions, is
`IFLAG_ENCRYPTED`, with these exceptions only: `HEARTBEAT`, `CAPABILITIES` and the
handshake messages (§11.8), which stay unsecured so a peer can be discovered.
`IFLAG_SIGNED` remains in the frame format for tools that need readable payloads
(for example a diagnostic mode), but a conforming vehicle does not select it by
transport.

### 11.2 Secured trailer

When a security flag is set the 2-byte CRC is **absent**, replaced by:

```
[ counter : 6 ][ tag : 16 ]      the full Poly1305/GCM tag, never truncated
```

- `counter`: 48-bit frame counter, little-endian, per (session, direction),
  starting at 0 and strictly increasing by at least 1 for each secured frame the
  sender emits. It is not a time.
- `tag`: AEAD tag over (AAD ∥ ciphertext), where
  AAD = header bytes `1 … 9` ∥ `tag_len` (1 byte, always 16) ∥ `dir` (1 byte).
  Header bytes 1..9 already cover the version, `payload_len`, `incompat_flags`,
  `seq`, `sysid`, `compid` and the 24-bit `msgid`; `tag_len` and `dir` are added
  so neither can be altered or confused. `dir = 0` for FC→GCS, `1` for GCS→FC.

### 11.3 Cipher

Default **ChaCha20-Poly1305** (IETF, 96-bit nonce, 128-bit tag): fast and
constant-time in software on the Cortex-M4, no crypto peripheral required (F401,
F405 and F407 have none; only F415/417/437/439 ship CRYP). **AES-GCM** or
**AES-CCM** MAY be used where hardware AES exists. Implementations MUST use a
vetted library (for example Monocypher) tested against the RFC 8439 vectors, and
MUST NOT hand-roll the primitive.

### 11.4 Nonce construction

The 96-bit nonce is deterministic, never random, never fully transmitted:

```
nonce[12] = counter(6) ∥ seq(1) ∥ sysid(1) ∥ compid(1) ∥ 0x00 0x00 0x00
```

Each direction of each session has its **own subkey** (§11.9), so the direction
does not need a nonce byte and no two sessions share a (key, nonce) pair. Within
one subkey the counter never repeats, so the nonce never repeats. A sender MUST
NOT reuse a nonce under a key, and MUST stop sending (and close the session) when
its counter would reach 2^48 − 1.

### 11.5 Replay protection

A receiver MUST accept a secured frame only if its tag verifies **and** its
`counter` has not been accepted before in that (session, direction) **and** is
not more than `W` below the highest counter accepted so far (`W` is at most 64;
`W = 0` is the strict rule "greater than the last"). `W` is set per direction:
**GCS→FC (commands) MUST use `W = 0`**, because a window lets a captured command
be held back and delivered after a later one, which reorders commands; FC→GCS
(telemetry) uses `W` = 16 in the reference code.
The receiver keeps the highest accepted counter and a bitmap of the `W` counters
below it, so a frame that UDP or a radio link delivered a few places late is
still taken, once. The first frame of a session is accepted at any counter,
including 0. The check uses no clock: a captured frame is rejected as soon as it
has been accepted once, or once `W` newer counters have been accepted, and a
captured frame from a past session fails the tag because the session key differs
(§11.9). The receiver MUST verify the tag **before** updating the highest counter
or the bitmap, so a forged frame cannot advance either. A lost frame leaves a gap
in the counter, which is fine. The window does not weaken nonce uniqueness (that is
a sender property, §11.4). It does let an attacker who captured a frame that the
receiver has NOT yet seen deliver it up to `W` counters late; that is why commands
use `W = 0`, and for telemetry it is a delay of at most `W` frames, and a frame the receiver already accepted is
never taken twice.

### 11.6 Order of operations

Sender: truncate trailing-zero **plaintext** (§5.6), set `payload_len`, encrypt
the truncated plaintext (stream cipher preserves length), compute the tag over
(AAD ∥ ciphertext) with the §11.4 nonce, emit. Receiver: verify the tag, check
the counter, decrypt, zero-fill to full message length, decode. `payload_len` is
in the authenticated header, so the fill length cannot be tampered.

### 11.7 Keys

**Long-term key.** A 32-byte pre-shared key K, held by the FC and the GCS, never
transmitted. `CAPABILITIES.key_id` is a **non-secret** 32-bit identifier (the first
four bytes of a keyed hash of K under a fixed label, which reveals nothing about
K) so both ends confirm a shared key at connect rather than failing silently.

**Storage on the FC (decision D3).** The long-term key lives in a reserved flash
sector with readout protection enabled (RDP level 1 on the STM32F4), so it cannot
be read back through the debug port or by a bootloader dump without erasing the
flash, and it survives swapping the SD card. The SD card is **not** a key store:
a card is trivially copied or swapped, so the FC MUST NOT read a key from it, and
a key file found on a card is ignored. No secure element is assumed: an attacker
with a debugger on a powered board, or one who can defeat readout protection,
still reads the key; this raises the cost, it does not remove the risk. The FC
reads K at boot and holds it in RAM only. Readout protection changes how the
board is re-flashed and debugged (level 1 to level 0 erases the flash, and the
key with it), which is accepted. Every connection uses a **fresh session key**
(§11.9); the stored key is only the root and never encrypts a frame directly.
**On the GCS** the key MUST be encrypted at rest (an OS keystore or a
passphrase-wrapped file) and MUST NOT appear in a log, a crash report or a
configuration file in clear.

**Provisioning and rotation (decision D5).** Setting, replacing or removing K is
permitted only over the **USB** link, only while **disarmed**, only when no
secured session is active, and only within a fixed window after boot (a build-time
setting; 60 s is the recommended length). It MUST NOT be possible over any
wireless link, over any other serial link, in flight, or over a secured session (a
stolen GCS must not be able to rotate the vehicle away from its owner). No
physical action (button, jumper) is required by this specification. Revoking a
lost GCS means replacing K over USB. An unkeyed FC behaves as an unsecured FC and
advertises `sec_modes = none`.

An **X25519 (ECDH) handshake** for forward secrecy MAY be added later, negotiated
via `CAPABILITIES`; it is not part of the first cut.

### 11.8 Downgrade and strict mode

A peer that sets a security flag the receiver did not negotiate is dropped (the
flags are `incompat`, §3.3). Once a key is present the FC runs in **strict mode**
(decision D4): it MUST refuse every unsecured command, and every other unsecured
frame of these kinds: parameter write, mission, filesystem write, and any
`TIME_SYNC` that changes the clock. Strict mode is not a setting a link can turn
off; it ends only when the key is removed over the wired provisioning path (§11.7). It MAY accept `HEARTBEAT`, `CAPABILITIES` and the handshake messages
unsecured, so a GCS can discover the vehicle and see that it is keyed. The FC
sends secured telemetry only to a peer that completed a handshake; before that it
sends only `HEARTBEAT` and `CAPABILITIES`.

### 11.9 Sessions and the handshake

A session key is derived per connection from K, so a counter restarting at 0 can
never meet an old key.

1. The GCS sends `HELLO { gcs_nonce[16] }`, 16 fresh random bytes.
2. The FC replies with `fc_boot_ctr` (32 bit), `fc_hs_ctr` (32 bit) and its device
   UID, authenticated by a keyed hash (BLAKE2b, key K) over a fixed label, both
   nonces and every field of the reply.
3. Each side derives the two direction subkeys:
   `Ks_dir = BLAKE2b-keyed(K, "navlink-session" ∥ dir ∥ gcs_nonce ∥ fc_boot_ctr ∥ fc_hs_ctr ∥ uid)`.

`fc_boot_ctr` is a 32-bit counter kept across power cycles. The STM32F401 has no
random number generator, so a random value cannot come from the FC; a counter plus
the device UID can. The FC MUST write the incremented value and read it back
**before** deriving any session key; if the write fails, or the counter is
exhausted, no secured session is established (the link fails closed, see §11.10).
`fc_hs_ctr` is a counter in RAM, incremented for every handshake the FC accepts
within a boot, so replaying a captured HELLO in the same boot still yields a
different `Ks`. The FC also remembers recent `gcs_nonce` values and drops a
repeat. Handshake attempts are rate-limited (at most one per second) so they
cannot be used to burn CPU.

The two handshake messages travel in the clear (`HS_HELLO` id 6, `HS_REPLY` id 7):
`HS_HELLO` is `gcs_nonce[16]`. `HS_REPLY` is `gcs_nonce[16]` (echoed), `fc_boot_ctr`
(u32), `fc_hs_ctr` (u32), `uid[12]` and `mac[16]`, where `mac` is BLAKE2b-128 keyed with
K over the ASCII label `navlink-hs-reply` followed by those same fields in order,
integers little-endian. The ground station computes the mac over its **own** nonce and
accepts the reply only if it matches and the echoed nonce is its own, so a reply made
for any other HELLO fails; it takes at most one reply per HELLO. A reply proves the
vehicle holds K; it does not by itself make a session live (above). The ground station MUST also compare the authenticated `uid` with the vehicle it meant to reach: the mac only proves the replier holds K, and vehicles that share K on one link could otherwise answer for each other.

The ground station drops its old keys when it sends its first frame under the new ones, while the vehicle drops an unconfirmed pending session after 5 s and keeps the old live one. If that first frame, and every frame in the next 5 s, is lost, neither side can read the other. The ground station therefore MUST send a new HELLO when no vehicle frame has verified under the new keys within 3 s of switching (a single lost frame followed by another inside the window is fine: any frame that verifies promotes).

**A HELLO creates a pending session, never a live one.** `HELLO` is not
authenticated (the vehicle cannot yet know who sent it), so accepting one MUST NOT
replace or disturb the session in use: otherwise anyone, with no key, could send a
HELLO and cut the real ground station off in flight. The vehicle keeps at most one
**live** session and at most one **pending** session. A HELLO that passes the rate
limit fills the pending slot (a later HELLO replaces an earlier pending one) and
the reply is sent; the live session is untouched and keeps working. The pending
session becomes live, and the old live session is dropped, **only when the first
secured GCS→FC frame verifies under the pending session's keys**: that frame
proves the sender holds K. A pending session that is not confirmed within a
timeout (5 s recommended) is discarded. The rate limit applies to filling the
pending slot, so it cannot starve a legitimate reconnect: the live session is
never affected by it, and a genuine HELLO is confirmed within one round trip. An
attacker who floods HELLOs can at worst delay a reconnect while the old session
is already gone (for example after a ground-station restart); it cannot cut a live
link. That residual delay is a known limit. The ground station switches its own
side to the new keys when it sends its first frame under them. When there is no
live session (first connection, or the old one has been dropped) the pending
session is promoted by the same rule.

**One counter per sender per direction.** For each direction of a session the
sender keeps exactly one counter, shared by **all** components (every `compid`)
that send in that direction. It is not per component. The receiver keeps one
last-accepted counter per (session, direction) and applies §11.5 to it, so
counters held per component would get each other's frames rejected. Nonce
uniqueness still holds because the counter alone is unique under the subkey;
`seq`, `sysid` and `compid` stay in the nonce as additional separation, not as
the source of uniqueness. A multi-component sender therefore needs one shared
counter source (an atomic increment) across its transmit paths.

### 11.9.1 Parser hook (informative, the reference codec)

The generated parser (C and Python) routes secured frames through two optional
handler slots, `secure_open` and `accept_unsecured`. With `secure_open` unset
(the default) the parser behaves exactly as it did before §11: a frame with any
`incompat_flags` bit set is rejected at the header. With it set, only
`IFLAG_ENCRYPTED` (exactly `0x02`; every other value is still rejected at the
header) is routed: the parser assembles `10 + payload_len + 22` bytes (at most
`NAVLINK_MAX_FRAME`, the size of its buffer) and hands the whole frame to the
hook, which authenticates and decrypts it and returns the plaintext length (which
must equal `payload_len`) or a negative value to drop. The AEAD tag **replaces**
the CRC: no CRC is computed on a secured frame, and nothing is dispatched until
the tag has verified (the order of §11.6: tag, msgid lookup, dispatch). A rejected
secured frame is rescanned like a CRC failure; an authentic frame with an unknown
msgid is consumed. `accept_unsecured` is called for each CRC-valid unsecured frame
before dispatch and may drop it (strict mode, §11.8); secured frames are not
subject to it.
With `secure_open` set and `accept_unsecured` unset the reference parser is strict
by default: only `HEARTBEAT`, `CAPABILITIES`, `HS_HELLO` and `HS_REPLY` are taken
unsecured (the messages §11.8 allows), and every other unsecured frame is
consumed. A caller that needs another policy sets `accept_unsecured`; one that
returns true for every frame restores the old accept-all behaviour explicitly.
With `secure_open` unset nothing is keyed and nothing is refused.

### 11.10 Failure handling (normative)

Cryptography MUST NOT be on, or able to block, the flight-critical path. RC input,
sensor acquisition, estimation, control, the motors and the failsafe logic never
call it and never wait on it. It runs only in the link's receive and transmit
tasks, with bounded work per frame (fixed maximum length, no loop bounded by an
attacker-controlled value), no heap and no blocking wait.

Any failure (bad tag, wrong key, counter not increasing, missing or unreadable
key, failed counter write, handshake timeout) has exactly one effect: the frame
is dropped and a counter is incremented. It MUST NOT change the arm state, start a
failsafe or a landing, or disarm. Failing closed applies to the **link only**: the
vehicle goes quiet on navlink (unsecured-silent), it does not stop flying.

---

## 12. Services

All services are ordinary messages (one ID space). Telemetry is best-effort;
these are the request/response/transactional patterns.

### 12.1 Command service

A command is a **typed message** in the command range (§9), opening with the
shared header `{ target_sys:u8, target_comp:u8, req_seq:u8 }` followed by typed
parameters (no float box, no `COMMAND_LONG`/`COMMAND_INT` split). The receiver
answers with `COMMAND_ACK { command:u24, req_seq:u8, result, progress,
result_param2 }`, correlated by `(command msgid, req_seq)`. An FC that is
unsynchronised (§10.5) MUST reject commands. Codegen enforces this in one place:
the generated dispatch consults an optional `command_gate(ctx, command)` before
**every** ack-requiring handler — a non-`ACCEPTED` result blocks the handler and
becomes the `COMMAND_ACK`, so the rule cannot be forgotten when a command is
added. The FC wires the gate to its clock state (`time_sync_is_synced()`),
returning `TEMPORARILY_REJECTED` until the startup sync succeeds. (Skew-triggered
de-sync, the other half of §10.5, lands with the §11 security layer.)

Whether a message owes a `COMMAND_ACK` is **declared in the dialect**: it defaults
to `true` for the command range and `false` elsewhere, and any message may set an
explicit `"ack"` boolean to override. Codegen surfaces it as
`NAVLINK_ACK_<NAME>`, `navlink_msg_info_t.requires_ack`, and (Python)
`<Msg>.REQUIRES_ACK`, so senders/receivers consult one source of truth instead of
hard-coding the rule.

### 12.2 Parameter service

- `PARAM_VALUE { param_id:char[16], index:u16, count:u16, generation:u32,
  type:u8, value:u8[8] }` — `value` is the real typed value (≤8 B, LE), never a
  float bit-cast. Metadata (type/unit/scale/range/default) comes from the dialect.
- **Transactional dump:** every value carries `generation` (bumped on any
  `PARAM_SET`). A complete set is all `count` indices under one `generation`; a
  mid-dump generation change forces re-sync; missing indices are re-requested by
  `PARAM_REQUEST_READ { index }`.
- **Confirmed writes:** a `PARAM_SET` is answered by the updated `PARAM_VALUE`
  carrying the new `generation`.
- Also: `PARAM_REQUEST_LIST`, `PARAM_REQUEST_READ { param_id | index }`,
  `PARAM_SET { param_id, type, value }`.

#### 12.2.1 Catalog, staging and acknowledgement (capability `PARAMS`, bit 8)

A device that sets capability bit `PARAMS` follows this subsection. It is
additive: a device or GCS that does not know it keeps the behaviour above.

- **Catalog.** `params.json`, beside `dialect.json`, is the single source of
  every parameter: `id` (at most 16 characters, `[A-Z][A-Z0-9_]*`), `type`
  (`U8 I8 U16 I16 U32 I32 F32`), closed range `min..max`, `default`, flags
  (`READ_ONLY`, `LOCKED_WHEN_ARMED`, `REBOOT_REQUIRED`, `PERSISTED`), `group`,
  and a `range_why` that says why the range is what it is. The generator
  refuses a catalog with a duplicate or over-long id, `min > max`, a default
  outside the range, a NaN or infinite bound, or a group that mixes locked and
  unlocked members. `PARAM_VALUE.index` is the position in the catalog, so a
  catalog only ever appends.
- **Table.** The firmware compiles the generated table: `id[16]`, `type`,
  `flags`, `group`, then `min`, `max`, `default` as 4 raw bytes each (the value
  in its own type, little-endian, zero-padded; `F32` is the IEEE-754 pattern).
- **`SYS_PTBL_CRC`.** A read-only `U32`: CRC-32 (as zlib) over `id`, `type`,
  `flags`, `group`, `min`, `max`, `default` of every entry in order, except
  itself. The default is in it so that a changed default is noticed. A GCS
  reads it first; a different value than its own catalog means the catalog is
  not the one this firmware runs, and the GCS shows raw values read-only.
- **`PARAM_SET.req_seq`.** An extension field. A non-zero `req_seq` asks for a
  `COMMAND_ACK` (`command` = `PARAM_SET`), sent by the generated dispatch like
  any other command. `0` means no acknowledgement is wanted (an older GCS).
  Result mapping: not yet synchronised → `TEMPORARILY_REJECTED`; unknown id or
  wrong type → `UNSUPPORTED`; read-only, locked while armed, out of range or
  non-finite → `DENIED`; storage failure → `FAILED`.
- **`PARAM_VALUE.flags`.** An extension field: bit 0 staged, bit 1 unsaved,
  bit 2 differs from default, bit 3 reboot pending.
- **Live and staged.** A parameter with `group` 0 applies at once and is marked
  unsaved. A grouped parameter is only staged. `CMD_PARAM_COMMIT { req_seq, op,
  group }` (`op` 0 commit, 1 discard; `group` 0 means every group) validates the
  whole group, re-checks the armed lock, applies it as one unit and then
  persists; the `COMMAND_ACK` is sent after the apply and the save are
  accepted. Parameters that share an invariant (for example a lower and an
  upper bound) must share a group.
- **`CMD_NOTCH_AUTOBAND`.** Asks the device to choose the notch band from the
  measured spectrum; acknowledged like any command.

### 12.3 Mission service

`MISSION_COUNT`, `MISSION_REQUEST_INT { seq }`, `MISSION_ITEM_INT { seq, frame,
command, x, y, z, … }`, `MISSION_ACK`, `MISSION_CURRENT`, `MISSION_CLEAR_ALL`.
A mission carries a `generation` and **commits atomically**: the FC applies it
only once all `MISSION_COUNT` items have arrived and validated; a partial upload
never commits. `MISSION_ACK` returns the committed `generation`.

### 12.4 Bulk transfer

`FILE_TRANSFER { session:u8, offset:u32, len:u8, data:u8[] }` with windowed ACKs,
for SD-card log download (`0:v_nav.bin`) and blob upload. Large chunks MAY set
`IFLAG_CRC32` (§3.3) so the stronger 4-byte CRC-32 protects multi-kB payloads.

#### 12.4.1 Fragmentation (`IFLAG_FRAGMENTED`) — reserved

Frame-level fragmentation of payloads larger than 255 bytes is reserved behind
`IFLAG_FRAGMENTED`; its header extension and reassembly rules are **not yet
specified** in this version. Until specified, bulk data uses the application-
level `FILE_TRANSFER` windowing above.

---

## 13. Capability negotiation

In place of a per-frame `compat_flags` byte, capabilities are exchanged once at
connect:

- `HEARTBEAT.capabilities` — a `u32` bitmask of coarse capabilities, sent ~1 Hz.
- `CAPABILITIES { protocol_version:u8, incompat_supported:u32, msgid_ranges:…,
  sec_modes:u8, key_id:u32 }` — the full list, on request at connect.
  `sec_modes` advertises `none/sign/encrypt`; `key_id` is the non-secret key
  identifier (§11.7); `incompat_supported` lets a peer learn which `incompat`
  bits the other implements before relying on them.

A peer MUST NOT rely on an `incompat` feature the other has not advertised.

---

## 14. Message catalog

IDs are normative block bases; codegen assigns exact values within a block.
Field-level detail is in the dialect (§7); this is the index.

### 14.1 Core / system (0–255)

| msgid | message | key fields |
|-------|---------|-----------|
| 0 | `HEARTBEAT` | type, autopilot, base_mode, system_status, nav_state, capabilities, timestamp `[s:20\|ms:12]` |
| 1 | `SYS_STATUS` | sensors_present/enabled/health bitmasks, load, voltage |
| 2 | `SYSTEM_HEALTH` | tx_overflow, imu_drop, log_wrap, cpu_load |
| 3 | `FLIGHT_MODE` | mode, source |
| 4 | `STATUSTEXT` | severity, text[50], id, chunk_seq |
| 5 | `COMMAND_ACK` | command:u24, req_seq, result, progress, result_param2 |
| 8 | `PING` | seq, target |
| 6 | `HS_HELLO` | gcs_nonce[16] (§11.9) |
| 7 | `HS_REPLY` | gcs_nonce[16], fc_boot_ctr, fc_hs_ctr, uid[12], mac[16] (§11.9) |
| 9 | `CAPABILITIES` | protocol_version, incompat_supported, msgid_ranges, sec_modes, key_id |
| 10 | `TIME_SYNC` | role, seq, t1_gcs_tx, t2_fc_rx, t3_fc_tx, commanded_offset_ms (one role-discriminated round-trip message, §10) |
| 11 | `FAULT_STATUS` | id:u16, severity, active, text[50] — one raised/cleared fault per frame (§14.1.1) |

#### 14.1.1 FAULT_STATUS and the fault table

`FAULT_STATUS` (msgid 11, 54 bytes) reports one latched fault per frame:
`id:u16`, `severity:u8` (the `severity` enum, as `STATUSTEXT.severity`),
`active:u8` (`1` = raised, `0` = cleared; enum `fault_active`) and `text[50]`
(NUL-terminated and NUL-padded like `STATUSTEXT.text`, so at most 49 characters).

- `id` is a **stable fault key**: the text for an id is fixed and lives in the
  shared table `faults.json`. This differs from `STATUSTEXT.id`, which only
  groups the chunks of one message.
- Every raised fault is re-sent every 5 s while disarmed, and once on the first
  GCS heartbeat after a link gap, so a GCS that connects late learns the full set.
- A clear is sent once with `active = 0`.
- msgid 11 is free in the core/system block: 1 is `SYS_STATUS`, 6 and 7 are
  reserved (design journal §10.1), and 11 is the first id after `TIME_SYNC`.

`faults.json` fault-id ranges (u16, assigned only in that file):

| Range | Use |
|-------|-----|
| `0x0000` | invalid / unset |
| `0x0001`–`0x00FF` | reserved |
| `0x0100`–`0x01FF` | core FC faults (`0x0100` sensors, `0x0110` storage, `0x0120` estimation, `0x0130` power, `0x0140` links) |
| `0x0200`–`0x7FFF` | reserved (core growth) |
| `0x8000`–`0xFFFF` | vendor / experimental; core never assigns here |

`generate.py` validates the table (unique ids and names, assignable range,
severity in the enum, text ≤ 49 bytes) and emits it with the codec: C
`navlink_fault_e`, `navlink_fault_table[]`, `navlink_fault_info()`; Python
`FaultId`, `FAULTS`.

### 14.2 Sensors / state (1024–2047)

| msgid | message | key fields |
|-------|---------|-----------|
| 1024 | `IMU_RAW` | acc[3], gyr[3], mag[3], temp, sample_time_us |
| 1025 | `IMU_COMPRESSED` | f16 deltas + ref seq |
| 1026 | `ATTITUDE_EULER` | roll, pitch, yaw, rollspeed, pitchspeed, yawspeed |
| 1027 | `ATTITUDE_QUATERNION` | q[4], rollspeed, pitchspeed, yawspeed (NED) |
| 1028 | `RC_CHANNELS` | chan[18]:u16, rssi, count |
| 1029 | `MOTOR_TELEMETRY` | cmd[8] |
| 1030 | `CONTROL_TRACE` | 18×f32 PID/loop trace |
| 1031 | `VIBRATION` | vib_x/y/z, clip counts |
| 1032 | `SCALED_PRESSURE` | abs/diff pressure, temp |
| 1033 | `EST_PERF` | est_peak_us, est_mean_us, decimation, rate_hz — estimator loop timing (§14.8) |
| 1034 | `PERF_GLOBAL` | seq, scheduler/ISR/IPC/heap snapshot — one per report (§14.8) |
| 1035 | `PERF_TASK` | seq, per-task: id, prio, state, stack hwm/size, cycles, switches, burst (§14.8) |
| 1036 | `PERF_FIFO` | seq, per-fifo: id, peak, capacity, drops (§14.8) |
| 1037 | `PERF_TASKNAME_REQUEST` | target_sys, target_comp, task_id — GCS→FC (§14.8) |
| 1038 | `PERF_TASKNAME` | task_id, name[32] — FC→GCS reply (§14.8) |

### 14.3 Navigation / position (2048–3071)

| msgid | message | key fields (fixed-point per §5.4) |
|-------|---------|-----------|
| 2048 | `GPS_RAW_INT` | fix_type, lat(degE7), lon(degE7), alt(mm), eph, epv, vel, cog, satellites |
| 2049 | `GLOBAL_POSITION_INT` | lat, lon, alt, rel_alt, vx, vy, vz, hdg |
| 2050 | `LOCAL_POSITION_NED` | x, y, z, vx, vy, vz |
| 2051 | `HOME_POSITION` | lat, lon, alt |
| 2052 | `ALTITUDE` | alt_monotonic, alt_amsl, alt_local, alt_terrain |
| 2053 | `ESTIMATOR_STATUS` | flags, pos/vel/hgt ratios |

### 14.4 Power / propulsion (3072–4095)

| msgid | message | key fields |
|-------|---------|-----------|
| 3072 | `BATTERY_STATUS` | id, voltages[10], current, consumed_mAh, remaining%, temp |
| 3073 | `ESC_TELEMETRY` | per-esc rpm, voltage, current, temp |
| 3074 | `POWER_STATUS` | Vcc, Vservo, flags |

### 14.5 Peripherals / payload (4096–8191)

`GIMBAL_DEVICE_ATTITUDE_STATUS`, `CAMERA_TRIGGER`, `OBSTACLE_DISTANCE`,
`COLLISION`, `ADSB_VEHICLE`, `TUNNEL` (vendor passthrough),
`DEBUG_VECT` / `NAMED_VALUE_FLOAT` (schema-free dev telemetry).

### 14.6 Commands (8192–12287)

Each opens with `{ target_sys, target_comp, req_seq }`; acked by `COMMAND_ACK`.

| msgid | command | params |
|-------|---------|--------|
| 8192 | `CMD_ARM` | force:u8 |
| 8193 | `CMD_DISARM` | force:u8 |
| 8194 | `CMD_CALIBRATE_IMU` | which:u8 |
| 8195 | `CMD_SET_PID` | axis:u8, kp:f32, ki:f32, kd:f32 |
| 8196 | `CMD_SET_GYRO_LPF` | cutoff_hz:u16 |
| 8197 | `CMD_SET_MOTOR_GEOMETRY` | layout:u8, n:u8, mix[]:f32 |
| 8198 | `CMD_SET_FLIGHT_MODE` | mode:u8, source:u8 |

### 14.7 Services (12288–16383)

| msgid | block | service |
|-------|-------|---------|
| 12288–12299 | `PARAM_*` | §12.2 |
| 12300–12311 | `MISSION_*` | §12.3 |
| 12312–12319 | `FILE_TRANSFER` | §12.4 |
| 12320 | `CALIBRATION_STATUS` | step, progress, mag-axis coverage — IMU calibration progress/instruction (§14.8) |
| 12321–12329 | calibration (reserved) | future per-sensor cal commands/status |

### 14.8 Firmware observability & calibration (Vayu additions)

The catalog §14.1–§14.7 was drawn for the conventional flight-telemetry set
(GPS, battery, ESC, mission, params). It did **not** cover the messages the live
Vayu firmware actually emits for its RTOS/kernel observability subsystem (vaios
`PERF`), the estimator-loop timing, or the IMU calibration wizard — yet those are
fully wired today (firmware `src/comm/perf_telemetry.c`, `telemetry_task.c`; GCS
kernel-stats / task-list / FIFO-monitor / calibration-wizard widgets). They map
to no existing catalog entry, so they are first-class v2 messages defined here.
They migrate from the v1 carriers: `PACKET_TYPE_PERF_STATS` (0x9),
`PACKET_TYPE_PERF_TASKNAME` (0xA), and the `SYSTEM_STATUS` origins `EST_PERF`
(0x08) and `CALIBRATION` (0x01).

**Report structure (no struct-array type).** v1 packed many task/fifo rows into
one fragmented `PERF_STATS` packet behind a `[schema|section|index|count|seq]`
fragment header. v2 fields are scalars and `char` only (§5.1) — there is **no
array-of-struct type** — so the chunked rows become **one message per row**:
`PERF_GLOBAL` carries the once-per-report snapshot (including `total_tasks` /
`total_fifos`), and each `PERF_TASK` / `PERF_FIFO` carries a single row. All
three share a `seq` field (the v1 fragment-header `seq`, now a payload field);
the GCS opens a report on a new `seq`/`PERF_GLOBAL` and collects rows until it has
`total_tasks` + `total_fifos` of them. This replaces application-level
fragmentation with ordinary dispatcher-routed messages (§8.3) and needs neither
`IFLAG_FRAGMENTED` (§12.4.1, reserved) nor a fragment header.

#### `EST_PERF` (1033) — estimator loop timing

Distinct from `ESTIMATOR_STATUS` (2053), which reports *filter health* (flags,
innovation ratios); this reports the estimator task's *timing/observability*.

```json
{
  "msgid": 1033, "name": "EST_PERF", "replaces": "0x6/0x08",
  "doc": "Estimator loop timing. v1: SYSTEM_STATUS origin EST_PERF.",
  "fields": [
    { "index": 0, "name": "peak_us",    "type": "f32", "unit": "us" },
    { "index": 1, "name": "mean_us",    "type": "f32", "unit": "us" },
    { "index": 2, "name": "decimation", "type": "f32" },
    { "index": 3, "name": "rate_hz",    "type": "f32", "unit": "Hz" }
  ]
}
```

#### `PERF_GLOBAL` (1034) — kernel snapshot, one per report

```json
{
  "msgid": 1034, "name": "PERF_GLOBAL", "replaces": "0x9 (GLOBAL)",
  "doc": "vaios PERF scheduler/ISR/IPC/heap snapshot. One per report; PERF_TASK/PERF_FIFO share `seq`.",
  "fields": [
    { "index": 0,  "name": "seq",                 "type": "u32", "doc": "report id shared by all fragments" },
    { "index": 1,  "name": "flags",               "type": "u8",  "doc": "bit0 = PERF compiled-in & live" },
    { "index": 2,  "name": "total_tasks",         "type": "u8" },
    { "index": 3,  "name": "total_fifos",         "type": "u8" },
    { "index": 4,  "name": "_pad",                "type": "u8" },
    { "index": 5,  "name": "uptime_ticks",        "type": "u32" },
    { "index": 6,  "name": "sched_switches",      "type": "u32" },
    { "index": 7,  "name": "cpu_cycles_lo",       "type": "u32", "doc": "low 32 bits of 64-bit cycle counter" },
    { "index": 8,  "name": "idle_cycles_lo",      "type": "u32" },
    { "index": 9,  "name": "systick_count",       "type": "u32" },
    { "index": 10, "name": "systick_last_cyc",    "type": "u32" },
    { "index": 11, "name": "systick_max_cyc",     "type": "u32" },
    { "index": 12, "name": "systick_preemptions", "type": "u32" },
    { "index": 13, "name": "ipc_takes",           "type": "u32" },
    { "index": 14, "name": "ipc_takes_blocked",   "type": "u32" },
    { "index": 15, "name": "ipc_gives",           "type": "u32" },
    { "index": 16, "name": "ipc_timeouts",        "type": "u32" },
    { "index": 17, "name": "heap_allocs",         "type": "u32" },
    { "index": 18, "name": "heap_frees",          "type": "u32" },
    { "index": 19, "name": "heap_oom",            "type": "u32" },
    { "index": 20, "name": "heap_peak_bytes",     "type": "u32" },
    { "index": 21, "name": "heap_total_bytes",    "type": "u32" }
  ]
}
```

#### `PERF_TASK` (1035) — one task's runtime stats

```json
{
  "msgid": 1035, "name": "PERF_TASK", "replaces": "0x9 (TASKS row)",
  "doc": "One task row; `seq` ties it to a PERF_GLOBAL report. Collect total_tasks of these per seq.",
  "fields": [
    { "index": 0, "name": "seq",           "type": "u32" },
    { "index": 1, "name": "task_id",       "type": "u8" },
    { "index": 2, "name": "priority",      "type": "u8" },
    { "index": 3, "name": "state",         "type": "u8", "doc": "Task_Status" },
    { "index": 4, "name": "_pad",          "type": "u8" },
    { "index": 5, "name": "stack_peak",    "type": "u16", "unit": "B", "doc": "high-water bytes" },
    { "index": 6, "name": "stack_size",    "type": "u16", "unit": "B" },
    { "index": 7, "name": "cycles_lo",     "type": "u32", "doc": "low 32 bits of total cycles" },
    { "index": 8, "name": "switches_in",   "type": "u32" },
    { "index": 9, "name": "max_burst_cyc", "type": "u32" }
  ]
}
```

#### `PERF_FIFO` (1036) — one FIFO's fill stats

```json
{
  "msgid": 1036, "name": "PERF_FIFO", "replaces": "0x9 (FIFOS row)",
  "doc": "One SPSC FIFO row; collect total_fifos per seq. fifo_id is the stable perf_fifo_id enum.",
  "fields": [
    { "index": 0, "name": "seq",      "type": "u32" },
    { "index": 1, "name": "fifo_id",  "type": "u8",  "enum": "perf_fifo_id" },
    { "index": 2, "name": "_pad",     "type": "u8" },
    { "index": 3, "name": "peak",     "type": "u16", "doc": "high-water fill (elements)" },
    { "index": 4, "name": "capacity", "type": "u16", "doc": "usable capacity (elements)" },
    { "index": 5, "name": "drops",    "type": "u16", "doc": "items lost, saturating at 0xFFFF" }
  ]
}
```

#### `PERF_TASKNAME_REQUEST` (1037) / `PERF_TASKNAME` (1038) — id↔name resolution

Task names are static, so they are not streamed every report; the GCS resolves
`task_id → name` on demand and caches it (v1: `PACKET_TYPE_PERF_TASKNAME`
request/reply, disambiguated by direction — now two msgids).

```json
{
  "msgid": 1037, "name": "PERF_TASKNAME_REQUEST",
  "doc": "GCS → FC: resolve one task id to its name.",
  "fields": [
    { "index": 0, "name": "target_sys",  "type": "u8" },
    { "index": 1, "name": "target_comp", "type": "u8" },
    { "index": 2, "name": "task_id",     "type": "u8" }
  ]
},
{
  "msgid": 1038, "name": "PERF_TASKNAME",
  "doc": "FC → GCS reply. name is NUL-padded char[32] (PERF_TASKNAME_MAX).",
  "fields": [
    { "index": 0, "name": "task_id", "type": "u8" },
    { "index": 1, "name": "name",    "type": "char", "len": 32 }
  ]
}
```

#### `CALIBRATION_STATUS` (12320) — IMU calibration progress/instruction

v1 sent a variable byte buffer under `SYSTEM_STATUS` origin `CALIBRATION`; v2
makes it typed. `step` carries either a progress update or an operator
instruction ("place nose-up", …); `coverage` is populated only for the mag
axis-coverage step.

```json
{
  "msgid": 12320, "name": "CALIBRATION_STATUS", "replaces": "0x6/0x01",
  "doc": "IMU calibration progress + operator instruction. Drives the GCS calibration wizard.",
  "fields": [
    { "index": 0, "name": "step",     "type": "u8",  "enum": "calib_step" },
    { "index": 1, "name": "progress", "type": "u8",  "doc": "0..100 percent, for the PROGRESS step" },
    { "index": 2, "name": "coverage", "type": "f32", "len": 3,
      "doc": "mag axis coverage x/y/z for MAG_AXIS_COVERAGE; 0 otherwise" }
  ]
}
```

These additions occupy free ids inside the already-reserved Sensors/state
(1024–2047, §14.2) and Services calibration (12320–12329, §14.7) blocks; no
msgid-space (§9) change is required. The matching enums are in §17.

---

## 15. Migration (v1 ↔ v2)

A dual parser keys on the version byte (§3.4); v1 (`byte1 & 0x0F == 1`) and v2
(`byte1 == 0x02`) coexist on one UART with no flag day.

| Phase | Content |
|-------|---------|
| **0** | Author `dialect.json` (incl. all v1 messages); ship `generate.py`; generated v1 codec byte-identical to legacy (golden vectors). Kills the three hand codecs. |
| **1** | v2 framing behind `ENABLE_NAVLINK_V2`; dual parser; add seq/sysid/compid/CRC-16+CRC_EXTRA/incompat byte; capability exchange; link stats from `seq` gaps. |
| **2** | Dual-emit telemetry (v1+v2), GCS prefers v2; move the seven `SYSTEM_STATUS` sub-messages to first-class v2 msgids; validate parity on SITL + flight. |
| **3** | Typed command/param/mission services + `COMMAND_ACK`; shim legacy `cmd_id`→command msgid; autotuner waits on `COMMAND_ACK`/`PARAM_VALUE`. |
| **4** | Drop v1 emit + v1 parse (keep v1 decoder for old logs); bump `incompat` baseline. |

**Touch-points.** FC: `comm_types.h`, `serializer.c`, `deserializer.c`,
`comm_processor.c`, `telemetry_task.c`, `variables.h`. GCS:
`DroneProtocol.{cpp,h}`, `PacketDecoder.{cpp,h}`, `core/Types.h`, `crc.cpp`.
Tools: `tools/autotune/protocol.py`. New: `navlink/dialect.json` (+ schema),
`tools/navlink/generate.py`, generated codecs in all three trees.

---

## 16. Conformance & test vectors

An implementation is conformant if it (a) frames/parses per §3, (b) computes
CRC/CRC_EXTRA per §4, (c) encodes fields per §5–§6, (d) generates from the
dialect per §7–§8, (e) implements the time gate §10.5 and security §11 when
crypto is enabled, and (f) passes the vectors below.

### 16.1 CRC-16/MCRF4XX self-check

`crc16("123456789")` (the nine ASCII digits) MUST equal **`0x6F91`**.

### 16.2 CRC_EXTRA worked example

For `ATTITUDE_EULER` (§7.3) the CRC_EXTRA input string is:

```
"ATTITUDE_EULER " "f32 roll " "f32 pitch " "f32 yaw "
"f32 rollspeed " "f32 pitchspeed " "f32 yawspeed "
```

(no array-length bytes — no arrays; extension fields excluded). Implementations
MUST agree on the resulting `CRC_EXTRA` byte; codegen emits it into the table and
the golden-vector test pins it.

### 16.3 Unsecured frame round-trip

A `HEARTBEAT` (msgid 0, 7-field payload of §7.3) from `sysid=1, compid=1, seq=0`
MUST:

1. serialise to `0x56 0x02 <len> 0x00 0x00 0x01 0x01 0x00 0x00 0x00 <payload> <crc_lo> <crc_hi>`;
2. round-trip through `pack`/`unpack`/`to_aligned` to an identical aligned struct;
3. survive trailing-zero truncation (drop trailing-zero `nav_state=0`… bytes,
   shorten `payload_len`, zero-fill on receive) with an identical decode.

### 16.4 Secured frame

With `IFLAG_ENCRYPTED`, a frame MUST: carry no CRC; carry `[counter:6][tag:16]`;
use the §11.4 nonce under the session subkey of its direction; verify the tag
over (AAD ∥ ciphertext) with AAD = header[1..9] ∥ tag_len ∥ dir; be rejected if
its `counter` is not strictly greater than the last accepted in that
(session, direction); and be rejected, with nothing else changed, on any failure
(§11.10). Conformance vectors (RFC 8439 for the cipher; golden handshake and frame
bytes) are added with the implementation.

### 16.5 Version demux

Bytes `0x56 0x31 …` (v1: type 3, version 1) MUST route to the v1 parser; `0x56
0x02 …` to v2; `0x56 0x07 …` MUST trigger resync.

---

## 17. Appendix — reference enumerations

```c
/* incompat_flags */
enum { IFLAG_SIGNED = 0x01, IFLAG_ENCRYPTED = 0x02,
       IFLAG_CRC32  = 0x04, IFLAG_FRAGMENTED = 0x08 };

/* COMMAND_ACK.result */
enum { RESULT_ACCEPTED = 0, RESULT_TEMPORARILY_REJECTED = 1, RESULT_DENIED = 2,
       RESULT_UNSUPPORTED = 3, RESULT_FAILED = 4, RESULT_IN_PROGRESS = 5 };

/* PARAM_VALUE.type */
enum { PT_U8=1, PT_I8=2, PT_U16=3, PT_I16=4, PT_U32=5, PT_I32=6,
       PT_U64=7, PT_I64=8, PT_F32=9, PT_F64=10 };

/* security modes (CAPABILITIES.sec_modes bitmask) */
enum { SEC_NONE = 0x01, SEC_SIGN = 0x02, SEC_ENCRYPT = 0x04 };

/* TIME_SYNC.role (§10) */
enum { TIME_SYNC_REQUEST = 0, TIME_SYNC_RESPONSE = 1 };

/* PERF_GLOBAL.flags (§14.8) */
enum { PERF_FLAG_ENABLED = 0x01 };   /* PERF module compiled in & live */

/* PERF_FIFO.fifo_id — stable ids so rows label regardless of send order (§14.8) */
enum { PF_IMU_RAW = 0,            /* reserved: legacy ring, no longer emitted */
       PF_IMU_TELEMETRY = 1,  PF_IMU_CONTROL = 2,     PF_IMU_CALIB = 3,
       PF_IMU_CALIB_TELEM = 4, PF_ATTITUDE_TELEMETRY = 5, PF_ATTITUDE_CONTROL = 6,
       PF_RC_TELEMETRY = 7,    PF_RC_CONTROL = 8,      PF_TELEMETRY = 9 };

/* CALIBRATION_STATUS.step (§14.8) */
enum { CAL_PROGRESS = 0, CAL_NOSE_UP = 1, CAL_NOSE_DOWN = 2, CAL_RIGHT_DOWN = 3,
       CAL_LEFT_DOWN = 4, CAL_UPRIGHT = 5, CAL_UPSIDE_DOWN = 6, CAL_FREE_ROT = 7,
       CAL_MAG_AXIS_COVERAGE = 8, CAL_COMPLETE = 9, CAL_FAILED = 10,
       CAL_EDGE_1 = 11, CAL_EDGE_2 = 12, CAL_EDGE_3 = 13, CAL_EDGE_4 = 14,
       CAL_EDGE_5 = 15, CAL_EDGE_6 = 16 };
```

*End of specification.*
