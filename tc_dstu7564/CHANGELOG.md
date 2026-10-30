# Changelog

All notable changes to `tc_dstu7564` are documented in this file.

## 0.1.0 - 2026-10-30

Initial release.

### Added

- `Dstu7564Digest`, DSTU 7564:2014 (Kupyna) with 256-, 384- and 512-bit
  output, ported from Bouncy Castle. `new` takes the length in bits and
  panics on any other, and resetting keeps it. It implements
  `tc_digest::TryDigest` with `core::convert::Infallible` as its error type,
  and so `tc_digest::Digest`, and `Clone`. `Display` writes Bouncy Castle's
  algorithm name.
- `do_final` writes the digest to the start of the output buffer and resets
  the digest; a buffer shorter than the digest panics before any state
  changes.
- The digest wipes its state on drop with volatile writes through
  `tc_zeroize`, and resetting wipes the previous state the same way.
- Timing documentation on the digest type and every internal helper, enforced
  by a test that scans the source.
- `no_std` builds without an allocator or `unsafe` code, enforced by
  `#![forbid(unsafe_code)]`; missing public documentation is rejected by
  `#![deny(missing_docs)]`. The crate documentation carries an executable
  example.
- Known-answer tests with the examples of DSTU 7564:2014, Bouncy Castle's
  vectors including the 64-byte padding boundaries, and Bouncy Castle digests
  on the 128-byte padding boundaries and for one million `'a'` bytes; and
  contract tests covering split updates, output length, resets, clones,
  unsupported lengths and the destructor.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_digest` 0.1 and `tc_zeroize` 0.1.
- The digest is variable time: its permutations index S-boxes with bytes of
  the state.
- Copies the compression leaves in registers or on the stack, and copies a
  move leaves behind, are not wiped. Drop-based wiping requires the destructor
  to run.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
