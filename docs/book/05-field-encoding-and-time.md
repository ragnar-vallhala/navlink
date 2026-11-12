# Chapter 5. Field encoding and time

This chapter is about the payload: how fields are laid out, how a message can
grow without breaking old peers, and how time is carried.

## 5.1 Types

Fields use a small set of fixed-size types, all little-endian:

| Type | Bytes | Notes |
|---|---|---|
| `u8`, `i8` | 1 | |
| `u16`, `i16` | 2 | |
| `u24` | 3 | used for msgid references |
| `u32`, `i32` | 4 | |
| `u64`, `i64` | 8 | |
| `f32`, `f64` | 4, 8 | IEEE-754 |
| `char` | 1 | a `char[n]` field is a fixed-width, NUL-padded string |

A field with a `len` is a fixed-length array. The dialect in use today declares
fields of `char`, `f32`, `i8`, `i16`, `i32`, `u8`, `u16`, `u24`, `u32` and `u64`.

## 5.2 Wire order is declaration order

Fields go on the wire in the order of their `index` in the dialect. NavLink does
**not** reorder fields by size (MAVLink does; this is a deliberate difference).
The wire struct is packed, with no compiler padding, so wire order, source order
and struct layout are the same. If padding is wanted, the dialect author declares
an explicit pad field.

## 5.3 Two structs per message

For each message the generator writes:

- a **packed wire struct** that matches the payload byte for byte. Read its
  members by value only, since they may be unaligned;
- a **naturally aligned application struct** that the compiler pads as usual.

`pack` and `unpack` move between bytes and the wire struct, and
`to_aligned` and `from_aligned` convert between the two structs. Application code
works with the aligned struct.

## 5.4 Fixed-point fields

Where `f32` does not have enough precision, a field can be an integer with a
`scale` and a `unit`: the real value is the wire value divided by the scale.
The specification gives these examples:

| Quantity | Wire type | Scale | Resolution |
|---|---|---|---|
| latitude, longitude | i32 | 1e7 | about 1.1 cm |
| altitude | i32 | 1e3 | 1 mm |
| speed | i16 | 1e2 | 1 cm/s |
| heading | u16 | 1e2 | 0.01 degree |

The scale is chosen per field so that range times scale fits the integer. Small
bounded quantities such as angles in radians, rates and voltages stay `f32`.

## 5.5 Growing a message: extension fields

A field marked `extension: true`:

1. is written after all the ordinary fields;
2. is excluded from CRC_EXTRA (chapter 4), so adding it does not change the
   message's signature;
3. may only be **appended**, never inserted among or removed from the original
   fields.

Reordering or retyping an existing field is an incompatible change and must not
be done.

## 5.6 Trailing-zero truncation

A sender may drop trailing all-zero bytes from the payload and put the shorter
length in `payload_len`. A receiver zero-fills back to the message's full length
before decoding. This is what makes extension fields safe in both directions:

- new sender, old receiver: the extra trailing bytes lie beyond what the old
  receiver reads;
- old sender, new receiver: the missing new fields read as 0, their defined
  "absent" value.

The generated `pack` does the truncation, and `unpack` zero-fills short input and
clamps long input.

## 5.7 Time

There is no clock in the frame header. Two kinds of time appear in payloads:

**Wall-clock stamp.** Messages that need wall-clock time carry a 32-bit word:
the upper 20 bits are seconds and the lower 12 bits hold milliseconds. The
seconds count from a reference instant T0 that the ground station sets during
time synchronisation (chapter 7). The field spans about 291 hours, longer than any
flight. Bit 11 is a `TIME_STALE` flag: a sender sets it before its first
successful sync and after any clock jump, and a receiver treats such a stamp as
unsynchronised. The FC never invents wall-clock time on its own.

**Sample time.** High-rate sensor messages also carry `sample_time_us`, a 32-bit
count of microseconds since boot on one monotonic clock. It is for aligning
samples inside the vehicle, finer than a millisecond, and is not tied to the
ground station's clock.

## Sources

- `docs/reference/navlink-v2-spec.md`, sections 5 (field encoding), 6 (time and timestamp model) and 8.2
- `ABI.md`, sections 2 and 3
- `dialect.json` (the types in use)
