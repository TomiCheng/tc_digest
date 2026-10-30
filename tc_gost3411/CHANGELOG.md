# Changelog

All notable changes to `tc_gost3411` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `Gost3411Digest`, GOST R 34.11-94 (RFC 5831), and
  `Gost3411_2012_256Digest` and `Gost3411_2012_512Digest`, GOST R 34.11-2012
  or Streebog (RFC 6986), ported from Bouncy Castle. Each implements
  `tc_digest::TryDigest` with `core::convert::Infallible` as its error type,
  and so `tc_digest::Digest`, and has `const fn new`, `Default` and `Clone`.
  `Display` writes Bouncy Castle's algorithm name.
- `Gost3411Digest::new` uses the CryptoPro D-A S-box, as Bouncy Castle does,
  and `Gost3411Digest::with_s_box` takes any GOST 28147-89 S-box; resetting
  keeps it.
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
- Known-answer tests for GOST R 34.11-94 with Bouncy Castle's vectors for the
  CryptoPro and test S-boxes, including one million `'a'` bytes, and the
  examples of RFC 5831, and for Streebog with the examples of RFC 6986; and
  contract tests covering split updates, output length, resets, clones and
  destructors.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_digest` 0.1, `tc_gost28147` 0.1, `tc_block_cipher` 0.1 and
  `tc_zeroize` 0.1.
- Every digest is variable time: GOST R 34.11-94 runs GOST 28147-89, which
  indexes its S-box with secret nibbles, and Streebog indexes lookup tables
  with bytes of its state.
- Copies the compression leaves in registers or on the stack, and copies a
  move leaves behind, are not wiped. Drop-based wiping requires the destructor
  to run.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
