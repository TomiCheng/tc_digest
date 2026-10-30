# Changelog

All notable changes to `tc_skein` are documented in this file.

## 0.1.0 - 2026-10-30

Initial release.

### Added

- `SkeinDigest` and `SkeinEngine`, Skein 1.3 with a 256-, 512- or 1024-bit
  state and any whole number of output bytes, ported from Bouncy Castle,
  including its precomputed initial states. `SkeinDigest` implements
  `tc_digest::TryDigest` with `core::convert::Infallible` as its error type,
  and so `tc_digest::Digest`, and `Clone`. `Display` writes Bouncy Castle's
  algorithm name.
- The `SkeinParams` trait, which supplies the key, personalisation, public
  key, key identifier and nonce, each absent by default; `SkeinParamsRef`,
  which borrows them; and, with the `alloc` feature, `SkeinParamsOwned`,
  which owns them, wipes them on drop and redacts them from `Debug`.
- `init` on both types, which accepts any `SkeinParams`, applies them in the
  order of the specification and returns `InitError::KeyTooShort` for a key
  shorter than 16 bytes. Resetting keeps the parameters.
- `do_final` writes the digest to the start of the output buffer and resets
  the digest; a buffer shorter than the digest panics before any state
  changes.
- Both types wipe their state on drop with volatile writes through
  `tc_zeroize`.
- Timing documentation on every type and internal helper, enforced by a test
  that scans the source.
- `no_std` builds without `unsafe` code, enforced by `#![forbid(unsafe_code)]`,
  and without an allocator unless the `alloc` feature is on; missing public
  documentation is rejected by `#![deny(missing_docs)]`. The crate
  documentation carries an executable example.
- Known-answer tests with the golden digest and MAC vectors of the Skein 1.3
  submission, as Bouncy Castle carries them, and Bouncy Castle digests under
  each parameter; and contract tests covering split updates, output length,
  resets, clones, parameters, unsupported sizes and destructors.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_digest` 0.1, `tc_threefish` 0.1, `tc_block_cipher` 0.1 and
  `tc_zeroize` 0.1. Only the `alloc` feature, off by default, needs an
  allocator.
- Skein is constant time.
- Unlike Bouncy Castle, which throws in these cases, parameters without a key
  and several further parameters at once are accepted, as the specification
  allows. Bouncy Castle's generic parameter types and its date-based
  personalisation helper are not provided.
- Copies the compression leaves in registers or on the stack, and copies a
  move leaves behind, are not wiped. Drop-based wiping requires the destructor
  to run.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
