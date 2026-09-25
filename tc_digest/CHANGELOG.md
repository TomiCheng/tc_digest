# Changelog

All notable changes to `tc_digest` are documented in this file.

## 0.1.0 - 2026-09-25

Initial release.

### Added

- `TryDigest`, a streaming message digest whose `try_update`,
  `try_update_byte`, `try_do_final` and `try_reset` return a `Result` with the
  implementation's associated error type, and which reports its
  `digest_size` and internal block length, `byte_length`. The trait carries
  no algorithm name and does not require `Display`; implementations name
  themselves through `Display`. `try_update_byte` has a default
  implementation over `try_update`. A successful `try_do_final` resets the
  digest.
- `TryXof`, an extendable-output function built on `TryDigest`: `try_output`
  starts or continues squeezing, and `try_output_final` squeezes and resets.
- `Digest` and `Xof`, the infallible forms with `update`, `update_byte`,
  `do_final`, `reset`, `output` and `output_final`. Blanket implementations
  provide them for every `TryDigest` and `TryXof` whose error type is
  `core::convert::Infallible`, including unsized types, so implementations
  never write them by hand. All four traits are dyn-compatible.
- `no_std` builds without `unsafe` code, enforced by `#![forbid(unsafe_code)]`;
  missing public documentation is rejected by `#![deny(missing_docs)]`. The
  crate documentation carries an executable example implementing `TryDigest`.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Has no dependencies and needs no allocator.
- The traits make no constant-time promise; output-buffer checks and timing
  are defined by each implementation.
- Whether an XOF accepts input after squeezing has started is defined by each
  implementation.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
