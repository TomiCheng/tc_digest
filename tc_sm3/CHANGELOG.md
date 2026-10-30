# Changelog

All notable changes to `tc_sm3` are documented in this file.

## 0.1.0 - 2026-10-30

Initial release.

### Added

- `Sm3Digest`, SM3 (GB/T 32905-2016), ported from Bouncy Castle. It
  implements `tc_digest::TryDigest` with `core::convert::Infallible` as its
  error type, and so `tc_digest::Digest`, and has `const fn new`, `Default`
  and `Clone`. `Display` writes the algorithm name.
- `do_final` writes the 32-byte digest to the start of the output buffer and
  resets the digest; a buffer shorter than 32 bytes panics before any state
  changes.
- The digest wipes its state on drop with volatile writes through
  `tc_zeroize`, and resetting wipes the previous state the same way.
- Timing documentation on the digest type and every internal helper, enforced
  by a test that scans the source.
- `no_std` builds without an allocator or `unsafe` code, enforced by
  `#![forbid(unsafe_code)]`; missing public documentation is rejected by
  `#![deny(missing_docs)]`. The crate documentation carries an executable
  example.
- Known-answer tests with the examples of GB/T 32905-2016, Bouncy Castle's
  vectors including 64 KiB of counting bytes and one million `'a'` bytes, and
  OpenSSL digests on the padding boundaries; and contract tests covering
  split updates, output length, resets, clones and the destructor.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_digest` 0.1 and `tc_zeroize` 0.1.
- The digest is constant time.
- Copies the compression leaves in registers or on the stack, and copies a
  move leaves behind, are not wiped. Drop-based wiping requires the destructor
  to run.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
