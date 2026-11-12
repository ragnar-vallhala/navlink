# Chapter 4. Integrity: CRC-16 and CRC_EXTRA

A link between a flight controller and a ground station will lose and corrupt
bytes, and the two ends can also disagree about what a message looks like. The
frame checksum is built to catch both.

## 4.1 The checksum

Plain frames end with a 2-byte CRC. The algorithm is CRC-16/MCRF4XX:

| Parameter | Value |
|---|---|
| width | 16 |
| polynomial | 0x1021 (reflected 0x8408) |
| initial value | 0xFFFF |
| reflect in and out | yes |
| final xor | 0x0000 |
| check value of the ASCII text `123456789` | 0x6F91 |

The generator checks that its own implementation returns 0x6F91 for the test
text before it writes any output (chapter 2).

## 4.2 What the CRC covers

The CRC runs over header bytes 1 to 9 (everything after the sync byte), then the
payload bytes as they are on the wire, and finally one more byte: the message's
**CRC_EXTRA**. The result goes into the two trailer bytes, low byte first.

The sync byte is not covered. A CRC of 0x0000 is a valid value and is not
special-cased. A receiver recomputes the CRC and drops the frame on a mismatch.

## 4.3 CRC_EXTRA: a signature of the message layout

CRC_EXTRA is one byte per message, computed by the generator from the message's
structure: the message name, then for each non-extension field, in index order,
its wire type name, its field name, and its array length if it is an array. The
two bytes of the resulting CRC are folded together into one.

Because the receiver folds its own CRC_EXTRA for that msgid into the CRC (as the last byte, after the payload), the
two ends must agree on the layout for the checksum to pass. If a field is added,
removed, retyped or renamed on one side only, the values differ and the frame
fails its CRC. A layout mismatch is therefore **detected and dropped**, not
decoded into wrong numbers.

Two things follow:

- **Extension fields** are left out of CRC_EXTRA on purpose (chapter 5), so a
  field appended as an extension does not change the signature and old and new
  peers still accept each other's frames.
- A message id the receiver does not know has no CRC_EXTRA, so its CRC cannot be
  checked at all. Such a frame is dropped as undecodable. The parser reports it
  to `on_unknown` for diagnostics only; the contents are unverified.

## 4.4 What it does not give you

The CRC detects accidental corruption. It does not authenticate the sender and
does not stop a deliberate attacker. The specification defines a separate
secured trailer (signing or encryption) for that. The generated codec does not
implement it (chapters 3 and 8).

## 4.5 Test vectors

The specification has a conformance section with fixed test vectors, and the
repository's tests pin them. The harness also encodes the same frames in C and
in Python and asserts that the bytes are identical.

## Sources

- `docs/reference/navlink-v2-spec.md`, sections 4 (integrity) and 16 (conformance and test vectors)
- `ABI.md`, sections 2 and 4
- `generate.py` (the self-check), `tests/run_tests.py`
