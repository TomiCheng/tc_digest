# Changelog

All notable changes to `tc_ripemd` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `RipeMd128Digest`, `RipeMd160Digest`, `RipeMd256Digest` and
  `RipeMd320Digest` (ISO/IEC 10118-3), ported from Bouncy Castle with its
  unrolled compression. Each implements `tc_digest::TryDigest` with
  `core::convert::Infallible` as its error type, and so `tc_digest::Digest`,
  and has `const fn new`, `Default` and `Clone`. `Display` writes Bouncy
  Castle's algorithm name.
- `do_final` writes the digest to the start of the output buffer and resets
  the digest; a buffer shorter than the digest panics before any state
  changes.
- Every digest wipes its state on drop with volatile writes through
  `tc_zeroize`, and resetting wipes the previous state the same way.
- Timing documentation on every digest type and internal helper, enforced by
  a test that scans the source.
- `no_std` builds without an allocator or `unsafe` code, enforced by
  `#![forbid(unsafe_code)]`; missing public documentation is rejected by
  `#![deny(missing_docs)]`. The crate documentation carries an executable
  example.
- Known-answer tests with the RIPEMD test suite, including one million `'a'`
  bytes, and Bouncy Castle digests on the padding boundaries, confirmed by
  OpenSSL for RIPEMD-160; and contract tests covering split updates, output
  length, resets, clones and destructors.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_digest` 0.1 and `tc_zeroize` 0.1.
- Every digest is constant time.
- RIPEMD-256 and RIPEMD-320 offer only the security level of RIPEMD-128 and
  RIPEMD-160.
- Copies the compression leaves in registers or on the stack, and copies a
  move leaves behind, are not wiped. Drop-based wiping requires the destructor
  to run.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
