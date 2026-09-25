# Changelog

All notable changes to `tc_md` are documented in this file.

## 0.1.0 - 2026-09-25

Initial release.

### Added

- `Md2Digest` (RFC 1319), `Md4Digest` (RFC 1320) and `Md5Digest` (RFC 1321),
  ported from Bouncy Castle. Each implements `tc_digest::TryDigest` with
  `core::convert::Infallible` as its error type, and so `tc_digest::Digest`,
  and has `const fn new`, `Default` and `Clone`. `Display` writes the
  algorithm name.
- `do_final` writes the 16-byte digest to the start of the output buffer and
  resets the digest; a buffer shorter than 16 bytes panics before any state
  changes.
- Timing documentation on every digest type and internal helper, enforced by
  a test that scans the source.
- `no_std` builds without an allocator or `unsafe` code, enforced by
  `#![forbid(unsafe_code)]`; missing public documentation is rejected by
  `#![deny(missing_docs)]`. The crate documentation carries an executable
  example.
- Known-answer tests for the full RFC 1319, 1320 and 1321 suites, OpenSSL
  digests for MD4 and MD5 on the padding boundaries and for one million
  `'a'` bytes, and contract tests covering split updates, output length,
  resets and clones.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends only on `tc_digest` 0.1.
- MD4 and MD5 are constant time. MD2 is variable time: it indexes an S-box
  with message-derived bytes and must hash only public data.
- All three algorithms are cryptographically broken and provided only for
  legacy interoperability.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
