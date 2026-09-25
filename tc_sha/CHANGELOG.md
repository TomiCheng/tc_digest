# Changelog

All notable changes to `tc_sha` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `Sha1Digest`, `Sha224Digest`, `Sha256Digest`, `Sha384Digest`,
  `Sha512Digest` and `Sha512tDigest` (FIPS 180-4), ported from Bouncy Castle.
  Each implements `tc_digest::TryDigest` with `core::convert::Infallible` as
  its error type, and so `tc_digest::Digest`, and implements `Clone` and
  `Display`, which writes the FIPS name, such as `SHA-256`. All but
  `Sha512tDigest` have `const fn new` and `Default`.
- `Sha512tDigest::new(t)` accepts any multiple of 8 from 8 to 504 other than
  384 and derives the initial hash value for `t` as FIPS 180-4 specifies. It
  panics for any other `t`; unlike Bouncy Castle, it also rejects zero, which
  FIPS 180-4 excludes. It needs no allocator: `Display` writes its name,
  such as `SHA-512/256`, from `t`.
- `do_final` writes the digest to the start of the output buffer and resets
  the digest; a buffer shorter than `digest_size` panics before any state
  changes.
- Timing documentation on every digest type and internal helper, enforced by
  a test that scans the source.
- `no_std` builds without an allocator or `unsafe` code, enforced by
  `#![forbid(unsafe_code)]`; missing public documentation is rejected by
  `#![deny(missing_docs)]`. The crate documentation carries an executable
  example.
- Known-answer tests for FIPS 180-4's examples and SHA-512/t initial hash
  values, OpenSSL digests on the 64- and 128-byte padding boundaries and for
  one million `'a'` bytes, and contract tests covering split updates, output
  length, resets and clones.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends only on `tc_digest` 0.1.
- Every digest is constant time.
- SHA-1 is broken for collision resistance and provided for legacy
  interoperability.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
