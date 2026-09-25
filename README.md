# tc_digest

A Rust workspace for message digests. It holds `tc_digest`, the shared traits
through which a digest or an extendable-output function absorbs a message and
writes its output, and the digest crates built on it: `tc_md` and `tc_sha`.
Each crate is published separately and keeps its own README, changelog, and
validation commands.

[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_digest`](tc_digest) | [![crates.io](https://img.shields.io/crates/v/tc_digest.svg)](https://crates.io/crates/tc_digest) [![docs.rs](https://docs.rs/tc_digest/badge.svg)](https://docs.rs/tc_digest) | Streaming digest and extendable-output function traits, each in a fallible form and an infallible form that blanket implementations supply. No algorithm. `no_std`, no allocator, no `unsafe`, no dependencies. |
| [`tc_md`](tc_md) | [![crates.io](https://img.shields.io/crates/v/tc_md.svg)](https://crates.io/crates/tc_md) [![docs.rs](https://docs.rs/tc_md/badge.svg)](https://docs.rs/tc_md) | MD2, MD4 and MD5 for legacy interoperability. MD4 and MD5 are constant time; MD2 is variable time. `no_std`, no allocator, no `unsafe`; depends on `tc_digest`. |
| [`tc_sha`](tc_sha) | [![crates.io](https://img.shields.io/crates/v/tc_sha.svg)](https://crates.io/crates/tc_sha) [![docs.rs](https://docs.rs/tc_sha/badge.svg)](https://docs.rs/tc_sha) | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 and SHA-512/t (FIPS 180-4). Every digest is constant time. `no_std`, no allocator, no `unsafe`; depends on `tc_digest`. |

`tc_digest` defines the contract and knows no algorithm; each digest crate
implements it and documents its own output lengths, buffer checks and timing
guarantees.

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std` and
without an allocator, and none has a Cargo feature.

Rust 1.85 is the earliest compiler for edition 2024, and it is guaranteed for
every crate in this workspace, tests included: no crate depends on anything
outside the workspace. The workspace lock tracks the latest dependency
releases, so CI on stable tests what a user on a current toolchain resolves.

## Workspace checks

```text
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo doc --locked --no-deps
```

CI additionally runs these on Linux x64, i686 and ARM64, macOS ARM64, and
Windows x64, runs the tests on Rust 1.85.0, checks the
`wasm32-unknown-unknown` and `aarch64-unknown-none` targets and each crate's
dependency set, and verifies the package archives. See
[.github/workflows/ci.yml](.github/workflows/ci.yml).

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
