# Changelog

All notable changes to `tc_blake` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `Blake2bDigest` and `Blake2sDigest` of RFC 7693, with an optional key, salt
  and personalization.
- `Blake2xsDigest`, the BLAKE2xs extendable-output function.
- `Blake3Digest` and `Blake3PortableDigest`, BLAKE3 in unkeyed, keyed-hash and
  derive-key mode, as digests and as extendable-output functions.
- `Blake3UpstreamDigest` and the `blake3` feature, which runs `Blake3Digest`
  on the `blake3` crate.
- AVX2 code for BLAKE2b and SSE2 code for BLAKE2s on x86 and x86-64, chosen at
  run time through `tc_runtime`.
- `Display` writes Bouncy Castle's name for every digest, such as `BLAKE2b` or
  `BLAKE3`.
- Every digest is constant time and wipes its state, buffers and key on drop.

### Compatibility

- Requires Rust 1.85. Depends on `tc_digest` 0.1 and `tc_zeroize` 0.1, and on
  x86 and x86-64 on `tc_runtime` 0.1; the `blake3` feature adds `blake3` 1.8
  and `zeroize` 1, and building it needs a C compiler for the target. Needs no
  allocator.
- `unsafe` code is limited to the x86 vector compression functions, each run
  behind run-time feature detection.
- `do_final` panics for an output buffer shorter than the digest, before
  changing any state. Absorbing after reading output panics until the digest
  is reset.
- Copies the compression functions leave in registers or on the stack, and
  copies a move leaves behind, are not wiped. Drop-based wiping requires the
  destructor to run.
