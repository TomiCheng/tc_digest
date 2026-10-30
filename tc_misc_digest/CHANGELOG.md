# Changelog

All notable changes to `tc_misc_digest` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- Six digests ported from Bouncy Castle, one Cargo feature each, none on by
  default: `Haraka256Digest`, `Haraka512Digest` and `HarakaError` (`haraka`),
  `PhotonBeetleDigest` (`photon-beetle`), `SparkleDigest` with
  `SparkleParameters` for ESCH-256 and ESCH-384 (`sparkle`), `TigerDigest`
  (`tiger`), `WhirlpoolDigest` (`whirlpool`) and `XoodyakDigest` (`xoodyak`).
  Each implements `tc_digest::TryDigest`, with `core::convert::Infallible` as
  its error type except Haraka, which returns `HarakaError` for inputs that
  are not exactly 32 or 64 bytes and for short output buffers. Each has a
  `const fn` constructor and `Clone`, and `Display` writes Bouncy Castle's
  algorithm name.
- Haraka runs on AES-NI when `tc_runtime` detects it together with SSE2 and
  on portable AES rounds otherwise; the AES-NI rounds are the only `unsafe`
  code.
- `do_final` writes the digest to the start of the output buffer and resets
  the digest; a short buffer panics, or for Haraka returns an error, before
  any state changes.
- Every digest wipes its state on drop with volatile writes through
  `tc_zeroize`, and resetting wipes the previous state the same way.
- Timing documentation on every digest type and internal helper, enforced by
  a test that scans every module.
- `no_std` builds without an allocator; missing public documentation is
  rejected by `#![deny(missing_docs)]` and `unsafe` code by
  `#![deny(unsafe_code)]` outside Haraka's AES-NI rounds. The crate
  documentation carries an executable example.
- Known-answer tests for each feature, from the Haraka v2 paper, the NIST
  lightweight cryptography KATs, Bouncy Castle's tests, Bouncy Castle digests
  and OpenSSL digests; and contract tests covering split updates, output
  length, resets, clones and destructors.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_digest` 0.1 and `tc_zeroize` 0.1, and with `haraka` on x86
  on `tc_runtime` 0.1.
- ESCH and Xoodyak are constant time. Tiger, Whirlpool and PHOTON-Beetle are
  variable time: they index S-boxes or tables with state bytes or nibbles.
  Haraka is constant time on AES-NI and variable time on its portable rounds.
- `PhotonBeetleDigest::byte_length` returns the 4-byte absorption rate, where
  Bouncy Castle throws `NotImplementedException`. Bouncy Castle's SSE2 path
  for ESCH-384 and its Haraka overloads with caller-supplied round constants
  are not provided.
- Copies the compression leaves in registers or on the stack, and copies a
  move leaves behind, are not wiped. Drop-based wiping requires the destructor
  to run.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
