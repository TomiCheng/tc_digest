# tc_keccak

[![crates.io](https://img.shields.io/crates/v/tc_keccak.svg)](https://crates.io/crates/tc_keccak)
[![docs.rs](https://docs.rs/tc_keccak/badge.svg)](https://docs.rs/tc_keccak)
[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Keccak and the SHA-3 family from FIPS 202 and NIST SP 800-185: raw Keccak,
SHA3-224 to SHA3-512, the SHAKE128 and SHAKE256 extendable-output functions,
cSHAKE, TupleHash and ParallelHash, ported from Bouncy Castle. Every digest
implements the [`tc_digest`](https://crates.io/crates/tc_digest) traits and is
constant time.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_digest` and on [`tc_zeroize`](https://crates.io/crates/tc_zeroize),
which wipes the sponge state.

Requires Rust 1.85 or later (edition 2024).

## Types

- `KeccakDigest` — raw Keccak, the SHA-3 competition version, with 128, 224,
  256, 288, 384 or 512 bits of output.
- `Sha3Digest` — SHA3-224, SHA3-256, SHA3-384 or SHA3-512.
- `ShakeDigest` — SHAKE128 or SHAKE256.
- `CShakeDigest` — cSHAKE128 or cSHAKE256 with a function name and a
  customization string.
- `TupleHash` — TupleHash128 or TupleHash256 of a tuple of byte strings, one
  element per `update`.
- `ParallelHash` — ParallelHash128 or ParallelHash256 over fixed-size blocks.

Each implements `TryDigest` with `core::convert::Infallible` as its error type,
and so `Digest` as well, and implements `Clone`, so a digest can be forked
partway through a message. `ShakeDigest`, `CShakeDigest`, `TupleHash` and
`ParallelHash` also implement `TryXof` and so `Xof`, which reads any amount of
output; read as a plain digest they write twice their security strength, as
Bouncy Castle does. `Display` writes Bouncy Castle's name, such as `SHA3-256`,
`SHAKE128` or `CSHAKE128`.

The constructors take the size as a number of bits and panic for one the
algorithm does not define, as Bouncy Castle throws. `do_final` writes the digest
to the start of the output buffer, returns its length and resets; it panics if
the buffer is shorter than `digest_size`, before changing any state. Absorbing
after reading output with `output` panics until the digest is reset.

## Timing

Every digest is constant time. The Keccak-f\[1600\] permutation uses only XOR,
AND, OR, NOT and fixed rotations, and the running time depends only on the
lengths of the input and the output and on the parameters chosen at
construction.

## Wiping

Dropping a digest, or resetting it, which `do_final` and `output_final` also do,
wipes its sponge state and position with volatile writes through `tc_zeroize`;
cSHAKE's saved prefix and ParallelHash's block counts are wiped too. Copies the
permutation leaves in registers or on the stack, ParallelHash's chaining values
on the stack, and copies a move leaves behind are not wiped, and drop-based
wiping requires the destructor to run. The output buffer belongs to the caller.

## Usage

```toml
[dependencies]
tc_digest = "0.1.0"
tc_keccak = "0.1.0"
```

Import `Digest`, and `Xof` for the extendable-output functions:

```rust
use tc_digest::{Digest, Xof};
use tc_keccak::{Sha3Digest, ShakeDigest};

let mut sha3 = Sha3Digest::new(256);
sha3.update(b"abc");
let mut digest = [0; 32];
assert_eq!(sha3.do_final(&mut digest), 32);
assert_eq!(digest[..4], [0x3a, 0x98, 0x5d, 0xa7]);

let mut shake = ShakeDigest::new(128);
shake.update(b"abc");
let mut output = [0; 100];
shake.output_final(&mut output);
```

## Validation

The tests check each digest against FIPS 202's examples and NIST's SP 800-185
samples, SHAKE against FIPS 202's 512-byte outputs, SHA-3 against OpenSSL on
messages around the rate and on FIPS 202's 1600-bit message, and SHAKE against
OpenSSL for outputs that cross a squeeze block. Contract tests check that
splitting the input or the output never changes the bytes, that a short output
buffer panics without changing state, and that every digest runs a destructor.
Another test requires every digest type and internal helper to document whether
it is constant or variable time. Missing public documentation is rejected by a
crate-level lint, and `unsafe` code is forbidden.

Run these commands from the workspace root:

```text
cargo test -p tc_keccak --locked
cargo clippy -p tc_keccak --all-targets --locked -- -D warnings
cargo fmt -p tc_keccak --check
cargo doc -p tc_keccak --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_keccak --list --locked
cargo publish -p tc_keccak --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
source and the tests. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
