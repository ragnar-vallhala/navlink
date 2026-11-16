# Chapter 2. Architecture: dialect, generator, codecs

## 2.1 The pipeline

```
   dialect.json  +  faults.json
          |
          |  generate.py        (validates, then writes)
          v
   generated codec + framing    C: navlink_msgs.h / navlink_msgs.c
                                Python: navlink_msgs.py
          ^
          |   the ABI boundary
          |
   your glue (written once per tree)
          transport (UART / socket), seq policy, handler bodies,
          optional time sync and security
```

Everything above the boundary is generated and must not be edited. Everything
below it is yours.

## 2.2 What the generator checks first

Before it writes anything, `generate.py` validates the dialect: message ids are
in range and unique, field indices are contiguous, and no payload exceeds 255
bytes. It also checks its own CRC implementation against the standard test value
(`crc16("123456789") == 0x6F91`) and validates `faults.json`. A dialect that
fails any check produces no output.

Run it with `python3 generate.py` (both languages, into `./generated`),
`--lang c` for C only, or `--out DIR` to write elsewhere. The `generated/`
directory is a build product: it is not committed to the repository.

## 2.3 What is generated for each message

For every message the generator writes:

- its **msgid** and its **CRC_EXTRA**, a one-byte signature of the field layout
  (chapter 4);
- a **packed wire struct** that matches the payload byte for byte, and a
  **naturally aligned struct** for application code (chapter 5);
- `pack` and `unpack` between bytes and the wire struct, and converters between
  the wire and aligned structs;
- an **encoder** that builds a complete frame (header, payload, CRC);
- a slot in the **handler table**, which the parser calls when a valid frame of
  that message arrives.

Across all messages it also generates the enums, the table from msgid to
`{name, size, crc_extra}`, and one incremental **parser** that finds frames in a
byte stream, checks the CRC, and calls the handlers.

## 2.4 What you still write

Per tree, once:

1. the byte **transport**: reading and writing the UART or socket;
2. the **sequence counter** policy for frames you send (chapter 3);
3. the **handler bodies**: what your program does when a message arrives;
4. optionally the time synchronisation and security layers (chapters 7 and 8).
   The generated codec does not provide them.

## 2.5 The three trees stay in step

Because all three codecs come from the same `dialect.json`, a change lands in
all of them in one commit. The repository's tests enforce it: the test harness
encodes frames in both C and Python and asserts that the bytes are identical,
and it pins the conformance vectors from the spec (chapter 4).

## 2.6 Repository map

| Path | Role |
|---|---|
| `dialect.json`, `faults.json`, `dialect.schema.json` | the sources of truth |
| `generate.py` | the generator |
| `ABI.md` | the contract and the integration guide |
| `docs/reference/navlink-v2-spec.md` | the normative specification |
| `docs/reference/messages/` | per-message reference pages |
| `tests/` | generator self-tests, C and Python parity, loopback tests |
| `sim/` | a two-process link emulator and an interactive console |

## Sources

- `README.md` (files, generate, what is generated)
- `ABI.md`, sections 1 to 3
- `docs/reference/navlink-v2-spec.md`, section 8 (code generation contract)
- `tests/run_tests.py`
