# Chapter 1. What NavLink is, and why there is one dialect

NavLink is the link protocol of the Vayu flight stack: the bytes that pass
between the flight controller (FC), the ground station (GCS) and the tools that
talk to either. This chapter says what it is, what problem it removes, and who
uses it. Version numbers in this book are taken from the repository's git tags
(the current release is v2.4.0), not from the spec file's header.

## 1.1 The problem

A flight controller and its ground station are written by different people, in
different languages, on different machines: C on a Cortex-M4, C++ with Qt on a
desktop, Python in tooling. If each hand-writes its own parser for the same
bytes, the three copies drift. A field is added on one side and forgotten on
another, and the failure shows up in flight as a value that is silently wrong.

NavLink removes the copies. There is **one** description of every message, and
the code that reads and writes the bytes is generated from it for each language.

## 1.2 The one source of truth

`dialect.json` is the message catalog. It currently defines 57 messages
(dialect name `vayu-core`, dialect version 2). `faults.json` is a second shared
table: the list of fault ids carried by the FAULT_STATUS message, with their
severities and texts. `dialect.schema.json` is the JSON Schema the dialect must
satisfy. `generate.py` reads the dialect, checks it, and writes the codecs.
It uses only the Python standard library.

You change the protocol by editing `dialect.json` and regenerating. You never
edit generated files.

## 1.3 What NavLink is not

- It is **not MAVLink** and is not wire-compatible with it. Interoperating with
  an external protocol is an explicit non-goal (spec section 1.4).
- It is not a transport. NavLink defines frames, not how bytes travel. The
  firmware reads and writes a UART; a ground station may use a serial port or a
  network socket. That glue is yours to write in each tree (chapter 9).
- It does not itself decide what the FC does with a message. The handlers you
  register do.

## 1.4 Who uses it

| Consumer | Language | How it takes NavLink |
|---|---|---|
| FC firmware (Vayu) | C | pins a navlink release as a submodule and generates the C codec into its build |
| Ground station (Navigator) | C and C++ | the generated C codec compiles as C++ (the header is `extern "C"` guarded) |
| Tools (autotune, headless SDK, test harnesses) | Python | the generated Python codec |

The Vayu repository currently pins navlink v2.4.0 (`firmware/nav.toml`).

## 1.5 What you get from reading the rest

Chapter 2 shows the generator pipeline. Chapters 3 to 5 describe the bytes on
the wire. Chapter 6 covers the dialect and the message catalog. Chapter 7 covers
the services built on top (commands, parameters, files, time sync). Chapter 8
covers faults and security. Chapter 9 is the how-to, and chapter 10 covers
compatibility rules and limits.

## Sources

- `README.md` (what it is, files, generate)
- `docs/reference/navlink-v2-spec.md`, sections 1 and 2 (scope, terminology)
- `ABI.md`, section 1 (the three layers)
- `dialect.json`, `faults.json`, `dialect.schema.json`
- Vayu repository: `firmware/nav.toml` (the pinned version)
