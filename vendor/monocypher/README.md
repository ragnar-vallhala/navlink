# Monocypher (vendored, unmodified)

Source: https://github.com/LoupVaillant/Monocypher, tag `4.0.2`
(archive `https://github.com/LoupVaillant/Monocypher/archive/refs/tags/4.0.2.tar.gz`,
SHA-256 of the archive as downloaded:
`bc1ca30b1b2654e4e7daf2492c0d204200e55137f23fda6b7142fd7d523bd6b4`).

The files here are `src/monocypher.c` and `src/monocypher.h` from that archive,
byte for byte, plus its `LICENCE.md` (2-clause BSD or CC-0, your choice) and
`AUTHORS.md`. SHA-256 of the two source files:

```
02174117935699d418443c75a558a287deb06ef8cf7c1adced61d9047d2f323d  monocypher.c
fcaf6ed771358bb4f40fba016f6518ae86ec02b1b877d2cc35ad92d3a26fd7b3  monocypher.h
```

Nothing in this directory is edited. Only `crypto_aead_*` (IETF ChaCha20-Poly1305,
RFC 8439), `crypto_blake2b_keyed`, `crypto_verify16` and `crypto_wipe` are used.
The checks in `tests/test_sec.c` and `tests/test_sec.py` run the RFC 8439
vectors against it, so a wrong or tampered copy fails the suite.

To update: download the new tag, replace the two files, update this file and run
the suite. Do not patch the files in place.
