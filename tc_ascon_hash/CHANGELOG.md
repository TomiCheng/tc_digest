# Changelog

All notable changes to `tc_ascon_hash` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `AsconHash256`, `AsconXof128` and `AsconCXof128` of NIST SP 800-232; the
  XOFs also as extendable-output functions.
- `AsconDigest` and `AsconXof`, the Ascon v1.2 hashes and XOFs, deprecated and
  kept to read hashes made before the standard, behind the `legacy` feature,
  off by default.
- `IsapDigest`, ISAP Hash, behind the `legacy` feature as well.
- `Display` writes Bouncy Castle's name for every digest, such as
  `Ascon-Hash256` or `Ascon-CXOF128`.
- Every digest is constant time and wipes its state on drop and on reset with
  volatile writes through `tc_zeroize`.

### Compatibility

- Requires Rust 1.85. Depends on `tc_digest` 0.1 and `tc_zeroize` 0.1, needs
  no allocator and contains no `unsafe` code.
- `do_final` panics for an output buffer shorter than the digest, before
  changing any state. Absorbing after reading output panics until the digest
  is reset.
- Copies the permutation leaves in registers or on the stack, the block copies
  made while absorbing and padding, and copies a move leaves behind are not
  wiped. Drop-based wiping requires the destructor to run.
