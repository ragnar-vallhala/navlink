# Chapter 3. The frame

Every NavLink v2 message travels in a frame. This chapter gives the layout, the
header fields, the limits and the message id space. All multi-byte integers are
little-endian.

## 3.1 Layout

A frame is a one-byte sync, nine more header bytes, a payload of 0 to 255 bytes,
and a trailer. For ordinary frames the trailer is a 2-byte CRC.

```
 offset  size  field            meaning
   0      1    sync             0x56 ('V'), start of frame
   1      1    version          0x02 for NavLink v2
   2      1    payload_len      payload bytes on the wire, 0..255
   3      1    incompat_flags   0 for plain frames
   4      1    seq              per-sender counter, rolls 0..255
   5      1    sysid            sender system id (0 = anonymous/broadcast)
   6      1    compid           sender component id
   7      3    msgid            message type, 24 bits
  10      N    payload
 10+N     2    CRC              CRC-16/MCRF4XX, CRC_EXTRA folded in last (chapter 4)
```

The header is a fixed 10 bytes. There is no timestamp in the header. Time lives
only in the payloads that need it (chapter 5).

## 3.2 Sizes

| Quantity | Value |
|---|---|
| minimum frame | 12 bytes (10 header, 0 payload, 2 CRC) |
| maximum plain frame | 267 bytes (10 + 255 + 2); the C constant `NAVLINK_MAX_FRAME` |
| payload, single frame | 0 to 255 bytes |

## 3.3 incompat_flags

`incompat_flags` marks features of the frame structure that a receiver must
understand to parse the frame at all. The rule is strict: **a receiver that sees
a bit it does not implement drops the frame.** The length field lets it skip the
frame and resynchronise.

| Bit | Name | Meaning |
|---|---|---|
| 0x01 | IFLAG_SIGNED | secured trailer, payload authenticated |
| 0x02 | IFLAG_ENCRYPTED | secured trailer, payload encrypted and authenticated |
| 0x04 | IFLAG_CRC32 | bulk mode, 4-byte CRC-32 trailer |
| 0x08 | IFLAG_FRAGMENTED | payload is a fragment of a larger message |
| 0x10 to 0x80 | reserved | must be 0 |

The specification defines these flags. The **generated codec does not implement
any of them**: its parser drops every frame that has an `incompat_flags` bit set
(ABI.md, section 4). The secured and bulk modes are therefore specification
features for a layer you would add yourself (chapter 8).

## 3.4 The sequence number

`seq` goes up by one, modulo 256, for each frame a sender emits, counted per
(sysid, compid). A receiver may use gaps in it to estimate link loss. Setting the
counter is part of your glue; the generated encoders take `seq` as an argument.

## 3.5 Message ids

The 24-bit msgid space is split on its top bit:

| Range | Owner |
|---|---|
| 0x000000 to 0x7FFFFF | core, assigned only in the NavLink tree |
| 0x800000 to 0xFFFFFF | vendor or experimental; core never assigns here |

A vendor can therefore choose ids in the upper half and never collide with a
future core message. Ids are never reused ("msgids are forever"). The core half
is laid out in blocks, for example 0x000400 to 0x0007FF for sensors and state,
0x002000 to 0x002FFF for typed commands, and 0x003000 to 0x003FFF for services
such as parameters, missions, files and calibration. Chapter 6 lists the catalog.

## 3.6 Finding frames in a byte stream

The generated parser (`navlink_parser_push` in C, `Parser` in Python) works on a
stream. It looks for 0x56, checks the version byte, reads the length, and checks
the CRC against the message's CRC_EXTRA. Then it calls the handler for that
message. A frame that is rejected (bad CRC, an unimplemented incompat bit, or an
unknown msgid) is rescanned from the byte after its 0x56, so a false sync cannot
swallow the good frames inside the span it claimed.

- A bad CRC calls `on_crc_error`.
- An unknown msgid has no CRC_EXTRA, so its CRC cannot be checked. It is never
  dispatched or acknowledged. `on_unknown` exists for diagnostics only, and its
  contents are unverified.

## 3.7 Older frames

An earlier protocol version, v1, shares the 0x56 sync byte. The two are told
apart by byte 1: a value of 0x02 is v2, and a value whose low nibble is 1 is v1.
The generated v2 parser ignores frames that are not v2. The migration is
historical background and is covered in chapter 10.

## Sources

- `docs/reference/navlink-v2-spec.md`, sections 3 (frame format) and 9 (message id space)
- `ABI.md`, section 4 (the frame) and section 3 (generated API surface)
- `docs/reference/README.md`
