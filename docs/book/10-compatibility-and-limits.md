# Chapter 10. Compatibility, versioning and limits

## 10.1 What is stable

The stable contract is the **wire image** plus the **generated C struct
layout**. A message's msgid and CRC_EXTRA together identify its layout, and a
disagreement between two peers is caught by the CRC (chapter 4).

## 10.2 The rules that keep it stable

1. Never edit generated files. Change `dialect.json` and regenerate.
2. Never reorder or retype an existing field and never insert among them. Only
   append, and append growth fields as `extension: true` (chapter 5).
3. Message ids are forever, and so are fault ids. The text for a fault id never
   changes. Core ids are 0x000000 to 0x7FFFFF; vendor and experimental are
   0x800000 to 0xFFFFFF.
4. Regenerate every consumer from the same `dialect.json` in the same change.

## 10.3 The change checklist

- Edit `dialect.json`, run `generate.py`, run `tests/run_tests.py`.
- Add fields only at the end, and new growth fields as extensions.
- A **new message** is additive. It takes a fresh msgid and does not change the
  frame version byte, the dialect version (the schema pins it to 2, the wire
  version), or any existing message's CRC_EXTRA. Peers that do not know it drop
  it. A feature change does not bump the release version; that happens in the
  release change.
- A frame with an unknown msgid, or whose CRC_EXTRA does not match, is dropped.
  Treat that as "ignore", not as an error.
- Advertise capabilities at connect and do not rely on an incompat feature a peer
  has not advertised.
- Generated output is not committed (`generated/` is build output), so there is
  no drift check in CI; its test suite checks directly that the generator is
  deterministic. `ABI.md` section 8 still says to commit the regenerated trees
  and that CI fails on a difference. That line is out of date; this book follows
  the CI file and `.gitignore`.

## 10.4 Things not to do

- Do not edit anything under `generated/`.
- Do not take the address of a member of a packed wire struct.
- Do not assume `payload_len` equals the message's full size. Senders drop
  trailing zeros and `unpack` restores them.
- Do not reuse the same (sysid, compid, seq) for two secured frames.

## 10.5 Versions

| Thing | Value | Where it comes from |
|---|---|---|
| NavLink release | v2.4.0 at the time of writing | the repository's git tags |
| Wire version | 0x02 | header byte 1 |
| Dialect | `vayu-core`, version 2, 57 messages | `dialect.json` |
| Specification file | headed "2.0-draft", dated June 2026 | `docs/reference/navlink-v2-spec.md` |

The specification file's header is older than the releases. For what the code does
today, follow the releases, `dialect.json` and `ABI.md`.

## 10.6 Limits and what is not covered

- **No transport.** NavLink defines frames, not how to move them (chapter 1).
- **Security, signing, encryption, the 4-byte CRC and fragmentation** are defined
  or reserved by the specification, but the generated codec implements none of
  them. A parser drops any frame with an `incompat_flags` bit set.
- **No mission messages** are in the dialect, although the specification describes a
  mission service. The specification's navigation, power and peripheral id blocks
  are likewise empty in the dialect today.
- **One frame holds at most 255 bytes of payload.** Larger data goes through the
  file transfer messages.
- **Not MAVLink.** There is no compatibility with it, and none is planned.
- **The time-sync delay estimate** assumes equal up and down latency, which only
  approximately holds on an asymmetric radio link.
- **Reference pages** under `docs/reference/messages/` may lag the dialect; where
  they differ, the dialect is right.

## 10.7 The older v1 protocol and the migration

Before v2, the stack used a hand-written v1 frame: an 8-byte header with a 4-bit
message type and a CRC-32. v2 replaced it with the generated frame. The two
share the 0x56 sync byte and are told apart by byte 1, so they could coexist on
one link. The specification describes a five-phase migration (author the dialect,
add v2 framing behind a flag, send both, move services and commands, then drop
v1). `INTEGRATION.md` is the working plan for that migration. It is **historical**:
read it for why the frame changed, not for how to use NavLink today. For use,
see chapter 9 and `ABI.md`.

## Sources

- `ABI.md`, sections 2, 8 and 9
- `docs/reference/navlink-v2-spec.md`, sections 1.4, 15 (migration) and 16 (conformance)
- `INTEGRATION.md` (historical)
- `dialect.json`, `faults.json`, `README.md`
