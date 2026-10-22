# Changelog

All notable changes to `tc_keccak` are documented in this file.

## 0.1.0 - 2026-10-22

Initial release.

### Added

- `KeccakDigest`, raw Keccak with 128, 224, 256, 288, 384 or 512 bits of
  output.
- `Sha3Digest`, SHA3-224, SHA3-256, SHA3-384 and SHA3-512 of FIPS 202.
- `ShakeDigest`, SHAKE128 and SHAKE256 of FIPS 202, as digests and as
  extendable-output functions.
- `CShakeDigest`, `TupleHash` and `ParallelHash` of NIST SP 800-185, as
  digests and as extendable-output functions.
- `Display` writes Bouncy Castle's name for every digest, such as `SHA3-256`,
  `SHAKE128` or `CSHAKE128`.
- Every digest is constant time and wipes its sponge state on drop and on
  reset with volatile writes through `tc_zeroize`.

### Compatibility

- Requires Rust 1.85. Depends on `tc_digest` 0.1 and `tc_zeroize` 0.1, needs
  no allocator and contains no `unsafe` code.
- The constructors take sizes in bits and panic for a size the algorithm does
  not define, as Bouncy Castle throws. Absorbing after reading output panics
  until the digest is reset.
- Copies the permutation leaves in registers or on the stack, ParallelHash's
  chaining values on the stack, and copies a move leaves behind are not wiped.
  Drop-based wiping requires the destructor to run.
