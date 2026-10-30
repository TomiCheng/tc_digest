# tc_digest

A Rust workspace for message digests. It holds `tc_digest`, the shared traits
through which a digest or an extendable-output function absorbs a message and
writes its output, and the digest crates built on it: `tc_ascon_hash`,
`tc_blake`, `tc_dstu7564`, `tc_gost3411`, `tc_keccak`, `tc_md`,
`tc_misc_digest`, `tc_ripemd`, `tc_sha`, `tc_skein` and `tc_sm3`.
Each crate is published separately and keeps its own README, changelog, and
validation commands.

[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_ascon_hash`](tc_ascon_hash) | [![crates.io](https://img.shields.io/crates/v/tc_ascon_hash.svg)](https://crates.io/crates/tc_ascon_hash) [![docs.rs](https://docs.rs/tc_ascon_hash/badge.svg)](https://docs.rs/tc_ascon_hash) | Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 (NIST SP 800-232); the deprecated Ascon v1.2 hashes and XOFs and ISAP Hash with the `legacy` feature. Every digest is constant time and wipes its state on drop. `no_std`, no allocator, no `unsafe`; depends on `tc_digest` and `tc_zeroize`. |
| [`tc_blake`](tc_blake) | [![crates.io](https://img.shields.io/crates/v/tc_blake.svg)](https://crates.io/crates/tc_blake) [![docs.rs](https://docs.rs/tc_blake/badge.svg)](https://docs.rs/tc_blake) | BLAKE2b, BLAKE2s and BLAKE2xs (RFC 7693) and BLAKE3, with AVX2 and SSE2 code for BLAKE2 on x86 and, with the `blake3` feature, BLAKE3 on the `blake3` crate. Every digest is constant time and wipes its state on drop. `no_std`, no allocator, `unsafe` only in the x86 vector code; depends on `tc_digest` and `tc_zeroize`, and on x86 on `tc_runtime`. |
| [`tc_digest`](tc_digest) | [![crates.io](https://img.shields.io/crates/v/tc_digest.svg)](https://crates.io/crates/tc_digest) [![docs.rs](https://docs.rs/tc_digest/badge.svg)](https://docs.rs/tc_digest) | Streaming digest and extendable-output function traits, each in a fallible form and an infallible form that blanket implementations supply. No algorithm; with the `alloc` feature, the `util` module of `NullDigest`, `Prehash` and `ShortenedDigest` adapters. `no_std`, no `unsafe`; without the feature no allocator and no dependencies, with it `tc_zeroize`. |
| [`tc_dstu7564`](tc_dstu7564) | [![crates.io](https://img.shields.io/crates/v/tc_dstu7564.svg)](https://crates.io/crates/tc_dstu7564) [![docs.rs](https://docs.rs/tc_dstu7564/badge.svg)](https://docs.rs/tc_dstu7564) | DSTU 7564:2014 (Kupyna), the Ukrainian national hash standard, with 256-, 384- and 512-bit output. Variable time and wipes its state on drop. `no_std`, no allocator, no `unsafe`; depends on `tc_digest` and `tc_zeroize`. |
| [`tc_gost3411`](tc_gost3411) | [![crates.io](https://img.shields.io/crates/v/tc_gost3411.svg)](https://crates.io/crates/tc_gost3411) [![docs.rs](https://docs.rs/tc_gost3411/badge.svg)](https://docs.rs/tc_gost3411) | GOST R 34.11-94 (RFC 5831), with the CryptoPro or a caller-supplied S-box, and GOST R 34.11-2012, Streebog-256 and Streebog-512 (RFC 6986). Every digest is variable time and wipes its state on drop. `no_std`, no allocator, no `unsafe`; depends on `tc_digest`, `tc_gost28147`, `tc_block_cipher` and `tc_zeroize`. |
| [`tc_keccak`](tc_keccak) | [![crates.io](https://img.shields.io/crates/v/tc_keccak.svg)](https://crates.io/crates/tc_keccak) [![docs.rs](https://docs.rs/tc_keccak/badge.svg)](https://docs.rs/tc_keccak) | Keccak, SHA3-224 to SHA3-512, SHAKE128 and SHAKE256 (FIPS 202), and cSHAKE, TupleHash and ParallelHash (NIST SP 800-185). Every digest is constant time and wipes its state on drop. `no_std`, no allocator, no `unsafe`; depends on `tc_digest` and `tc_zeroize`. |
| [`tc_md`](tc_md) | [![crates.io](https://img.shields.io/crates/v/tc_md.svg)](https://crates.io/crates/tc_md) [![docs.rs](https://docs.rs/tc_md/badge.svg)](https://docs.rs/tc_md) | MD2, MD4 and MD5 for legacy interoperability. MD4 and MD5 are constant time; MD2 is variable time. Every digest wipes its state on drop. `no_std`, no allocator, no `unsafe`; depends on `tc_digest` and `tc_zeroize`. |
| [`tc_misc_digest`](tc_misc_digest) | [![crates.io](https://img.shields.io/crates/v/tc_misc_digest.svg)](https://crates.io/crates/tc_misc_digest) [![docs.rs](https://docs.rs/tc_misc_digest/badge.svg)](https://docs.rs/tc_misc_digest) | Haraka, PHOTON-Beetle, ESCH, Tiger, Whirlpool and Xoodyak, one feature each. ESCH and Xoodyak are constant time; Tiger, Whirlpool and PHOTON-Beetle are variable time; Haraka is constant time on AES-NI. Every digest wipes its state on drop. `no_std`, no allocator, `unsafe` only in Haraka's AES-NI rounds; depends on `tc_digest` and `tc_zeroize`, and with `haraka` on x86 on `tc_runtime`. |
| [`tc_ripemd`](tc_ripemd) | [![crates.io](https://img.shields.io/crates/v/tc_ripemd.svg)](https://crates.io/crates/tc_ripemd) [![docs.rs](https://docs.rs/tc_ripemd/badge.svg)](https://docs.rs/tc_ripemd) | RIPEMD-128, RIPEMD-160, RIPEMD-256 and RIPEMD-320 (ISO/IEC 10118-3). Every digest is constant time and wipes its state on drop. `no_std`, no allocator, no `unsafe`; depends on `tc_digest` and `tc_zeroize`. |
| [`tc_sha`](tc_sha) | [![crates.io](https://img.shields.io/crates/v/tc_sha.svg)](https://crates.io/crates/tc_sha) [![docs.rs](https://docs.rs/tc_sha/badge.svg)](https://docs.rs/tc_sha) | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 and SHA-512/t (FIPS 180-4). Every digest is constant time and wipes its state on drop. `no_std`, no allocator, no `unsafe`; depends on `tc_digest` and `tc_zeroize`. |
| [`tc_skein`](tc_skein) | [![crates.io](https://img.shields.io/crates/v/tc_skein.svg)](https://crates.io/crates/tc_skein) [![docs.rs](https://docs.rs/tc_skein/badge.svg)](https://docs.rs/tc_skein) | Skein 1.3 with a 256-, 512- or 1024-bit state and any whole number of output bytes, optionally keyed as a MAC or personalised, with owned parameters under the `alloc` feature. Constant time and wipes its state on drop. `no_std`, no `unsafe`, and without the feature no allocator; depends on `tc_digest`, `tc_threefish`, `tc_block_cipher` and `tc_zeroize`. |
| [`tc_sm3`](tc_sm3) | [![crates.io](https://img.shields.io/crates/v/tc_sm3.svg)](https://crates.io/crates/tc_sm3) [![docs.rs](https://docs.rs/tc_sm3/badge.svg)](https://docs.rs/tc_sm3) | SM3 (GB/T 32905-2016), the Chinese national hash standard. Constant time and wipes its state on drop. `no_std`, no allocator, no `unsafe`; depends on `tc_digest` and `tc_zeroize`. |

`tc_digest` defines the contract and knows no algorithm; each digest crate
implements it and documents its own output lengths, buffer checks and timing
guarantees.

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std` and
without an allocator. Five crates have Cargo features, all off by default:
`tc_digest`'s `alloc` adds the adapter digests, which need an allocator,
`tc_skein`'s `alloc` adds `SkeinParamsOwned`, which needs one too,
`tc_ascon_hash`'s `legacy` adds the pre-standard Ascon digests and no
dependency, `tc_blake`'s `blake3` runs BLAKE3 on the `blake3` crate, and
`tc_misc_digest` has one feature per digest, of which `haraka` adds
`tc_runtime` on x86.

Rust 1.85 is the earliest compiler for edition 2024, and it is guaranteed for
every crate in this workspace, tests included: the first-party dependencies,
`tc_zeroize`, `tc_runtime`, `tc_block_cipher`, `tc_gost28147` and
`tc_threefish`, require
Rust 1.85 as well, and the only
third-party ones, the `blake3` crate and its dependencies behind `tc_blake`'s
`blake3` feature, build on it, as does Criterion 0.7, `tc_blake`'s benchmark
dev-dependency. The workspace lock tracks the latest dependency
releases, so CI on stable tests what a user on a current toolchain resolves.

## Workspace checks

```text
cargo test --locked
cargo test --locked --all-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo doc --locked --no-deps --all-features
```

CI additionally runs these on Linux x64, i686 and ARM64, macOS ARM64, and
Windows x64, runs the tests on Rust 1.85.0, checks the
`wasm32-unknown-unknown` and `aarch64-unknown-none` targets and each crate's
dependency set, and verifies the package archives. See
[.github/workflows/ci.yml](.github/workflows/ci.yml).

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
