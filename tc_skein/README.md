# tc_skein

[![crates.io](https://img.shields.io/crates/v/tc_skein.svg)](https://crates.io/crates/tc_skein)
[![docs.rs](https://docs.rs/tc_skein/badge.svg)](https://docs.rs/tc_skein)
[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The Skein 1.3 hash function, ported from Bouncy Castle: a 256-, 512- or
1024-bit state, any whole number of output bytes, and optionally a key, which
makes it a MAC, and the personalisation, public key, key identifier and nonce
of the specification. The digest implements the
[`tc_digest`](https://crates.io/crates/tc_digest) traits.

The crate is `no_std` and contains no `unsafe` code. It needs no allocator
unless the `alloc` feature, off by default, adds `SkeinParamsOwned`. It
depends on `tc_digest`, on [`tc_threefish`](https://crates.io/crates/tc_threefish)
and its [`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits
for the Threefish block cipher, and on
[`tc_zeroize`](https://crates.io/crates/tc_zeroize), which wipes the state.

Requires Rust 1.85 or later (edition 2024).

## Types

- `SkeinDigest` — Skein with a 32-, 64- or 128-byte state and block and any
  whole number of output bytes; constant time.
- `SkeinEngine` — the Unique Block Iteration chaining underneath, for callers
  that build on Skein directly, such as a Skein MAC; constant time.
- `SkeinParams` — the trait through which `init` reads the key,
  personalisation, public key, key identifier and nonce, each optional and
  absent by default.
- `SkeinParamsRef` — borrowed parameters, set one by one with `with_key`,
  `with_nonce` and so on.
- `SkeinParamsOwned` — owned parameters, with the `alloc` feature; wiped on
  drop, and its `Debug` prints only lengths.
- `InitError` — why `init` rejected parameters: a key shorter than 16 bytes.

`SkeinDigest::new` takes the state size, 256, 512 or 1024 bits, and the
digest size, a positive multiple of 8 bits, and panics on anything else, as
Bouncy Castle throws. `init` applies any `SkeinParams` and starts a new
message;
empty parameters return to the plain digest, and a rejected key leaves the
digest unchanged. Resetting keeps the parameters. The parameters are hashed in
the order of the specification, so a key and several further parameters can
be combined.

`SkeinDigest` implements `TryDigest` with `core::convert::Infallible` as its
error type, and so `Digest` as well. It implements `Clone`, so a digest can be
forked partway through a message. `Display` writes Bouncy Castle's algorithm
name, such as `Skein-512-256`.

`do_final` writes the digest to the start of the output buffer, leaves any
longer tail untouched, returns its length, and resets the digest. It panics if
the buffer is shorter than the digest, before changing any state.

## Timing

Skein is constant time: Threefish uses only additions, rotations and XORs, and
the running time depends only on the lengths of the message, the parameters
and the output.

## Wiping

Dropping a digest or an engine wipes its state with volatile writes through
`tc_zeroize`: the chaining value, the state after the key and parameters, and
the buffered block. Each Threefish engine it creates wipes its own key. A
clone is wiped when it is dropped in turn. Copies the compression leaves in
registers or on the stack, such as the Threefish key bytes, and copies a move
leaves behind are not wiped, and drop-based wiping requires the destructor to
run. `SkeinParamsOwned` wipes its inputs on drop; borrowed parameters and the
output buffer belong to the caller.

## Usage

```toml
[dependencies]
tc_digest = "0.1.0"
tc_skein = "0.1.0"
```

Import `Digest` to reach the digest's methods:

```rust
use tc_digest::Digest;
use tc_skein::SkeinDigest;

let mut skein = SkeinDigest::new(512, 512);
skein.update(b"message");
let mut output = [0; 64];
assert_eq!(skein.do_final(&mut output), 64);
```

## Validation

The tests check the digest against the digest and MAC vectors of Bouncy
Castle's `SkeinDigestTest` and `SkeinMacTest`, taken from the Skein 1.3
submission's `skein_golden_kat.txt`, and against Bouncy Castle digests under
a key with each further parameter. Bouncy Castle rejects two further
parameters at once and further parameters without a key, so those
combinations have no reference vector. Unit tests check the precomputed
initial states against the configuration block and the 96-bit position
arithmetic of the tweak. Contract tests check, for several sizes and under a
key, that splitting a message across updates never changes the digest, that
`do_final` writes exactly the digest length and resets, that a short output
buffer panics without changing state and that a clone continues
independently; and that the engine and the digest agree, that owned,
borrowed and caller-defined parameters give the same digest, that empty
parameters return to the plain digest, that a short key is rejected without
changing state, that unsupported sizes panic and that both types run a
destructor. Unit tests check that `SkeinParamsOwned` wipes every input and
redacts them from `Debug`. Another test requires every type and internal helper to document
whether it is constant or variable time. Missing public documentation is
rejected by a crate-level lint, and `unsafe` code is forbidden.

Run these commands from the workspace root:

```text
cargo test -p tc_skein --locked
cargo test -p tc_skein --all-features --locked
cargo clippy -p tc_skein --all-targets --locked -- -D warnings
cargo clippy -p tc_skein --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_skein --check
cargo doc -p tc_skein --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_skein --list --locked
cargo publish -p tc_skein --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
source and the tests. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
