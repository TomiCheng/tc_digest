# tc_blake

[![crates.io](https://img.shields.io/crates/v/tc_blake.svg)](https://crates.io/crates/tc_blake)
[![docs.rs](https://docs.rs/tc_blake/badge.svg)](https://docs.rs/tc_blake)
[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

BLAKE2b, BLAKE2s and BLAKE2xs (RFC 7693 and the BLAKE2X paper) and BLAKE3,
ported from Bouncy Castle. Every digest implements the
[`tc_digest`](https://crates.io/crates/tc_digest) traits and is constant time.

The crate is `no_std` and needs no allocator. It depends on `tc_digest`, on
[`tc_zeroize`](https://crates.io/crates/tc_zeroize), which wipes the state,
and on x86 and x86-64 on [`tc_runtime`](https://crates.io/crates/tc_runtime),
which detects AVX2 and SSE2 without `std`. The `blake3` feature adds the
[`blake3`](https://crates.io/crates/blake3) and
[`zeroize`](https://crates.io/crates/zeroize) crates.

Requires Rust 1.85 or later (edition 2024).

## Types

- `Blake2bDigest` — BLAKE2b with 1 to 64 bytes of output and an optional key,
  salt and personalization.
- `Blake2sDigest` — BLAKE2s with 1 to 32 bytes of output and an optional key,
  salt and personalization.
- `Blake2xsDigest` — BLAKE2xs, the extendable-output function on BLAKE2s,
  with a fixed or unknown output length.
- `Blake3Digest` — BLAKE3 in unkeyed, keyed-hash or derive-key mode, on the
  portable code or, with the `blake3` feature, on the `blake3` crate.
- `Blake3PortableDigest` — BLAKE3 on the portable code, whatever the features.
- `Blake3UpstreamDigest` — BLAKE3 on the `blake3` crate, with the `blake3`
  feature.

Each implements `TryDigest` with `core::convert::Infallible` as its error type,
and so `Digest` as well, and implements `Clone`, so a digest can be forked
partway through a message. `Blake2xsDigest` and the BLAKE3 types also
implement `TryXof` and so `Xof`, which reads any amount of output. `Display`
writes Bouncy Castle's name, such as `BLAKE2b` or `BLAKE3`.

The constructors panic for a size, key, salt or personalization the algorithm
does not define, as Bouncy Castle throws. `do_final` writes the digest to the
start of the output buffer, returns its length and resets; it panics if the
buffer is shorter than `digest_size`, before changing any state. Absorbing
after reading output with `output` panics until the digest is reset.

## Features

- `blake3` — `Blake3Digest` runs on the BLAKE3 team's `blake3` crate, which
  hashes several chunks at once and picks SSE2, SSE4.1, AVX2, AVX-512 or NEON
  at run time; the output is the same. That crate compiles C or assembly for
  those paths, so building it needs a C compiler for the target.

## Vector code

On x86 and x86-64, BLAKE2b uses AVX2 and BLAKE2s uses SSE2 when the CPU has
them, as Bouncy Castle's `Blake2b_X86` and `Blake2s_X86` do, and falls back to
the portable code otherwise; other targets use the portable code. This is the
only `unsafe` code in the crate: each intrinsic runs behind a detection token
from `tc_runtime`, and the crate denies `unsafe` code everywhere else.

## Timing

Every digest is constant time. The compression functions use only additions,
XOR and fixed rotations, the message words are picked by public permutations,
and the running time depends only on the lengths of the input and the output
and on the parameters chosen at construction. The CPU, not the data, picks
between the vector and the portable code.

## Wiping

Dropping a digest wipes its state, buffers and key with volatile writes
through `tc_zeroize`, or through the `zeroize` crate for the `blake3` backend;
resetting, which `do_final` and `output_final` also do, overwrites them.
Copies the compression functions leave in registers or on the stack, and
copies a move leaves behind, are not wiped, and drop-based wiping requires the
destructor to run. The output buffer belongs to the caller.

## Usage

```toml
[dependencies]
tc_digest = "0.1.0"
tc_blake = "0.1.0"
```

Import `Digest`, and `Xof` for the extendable-output functions:

```rust
use tc_blake::{Blake2bDigest, Blake3Digest};
use tc_digest::{Digest, Xof};

let mut blake2b = Blake2bDigest::new();
blake2b.update(b"abc");
let mut digest = [0; 64];
assert_eq!(blake2b.do_final(&mut digest), 64);
assert_eq!(digest[..4], [0xba, 0x80, 0xa5, 0x3f]);

let mut blake3 = Blake3Digest::new();
blake3.update(b"abc");
let mut output = [0; 100];
blake3.output_final(&mut output);
```

## Validation

The tests check BLAKE2b and BLAKE2s against RFC 7693 and Bouncy Castle's
vectors, BLAKE2xs against the 512 keyed vectors of the BLAKE2 team's
`blake2-kat.json`, and BLAKE3 in all three modes against the BLAKE3 team's
`test_vectors.json`, as Bouncy Castle uses them. On x86 the vector compression
functions are checked against the portable ones, and the `blake3` backend
against the portable BLAKE3. Contract tests check that splitting the input or
the output never changes the bytes, that a short output buffer panics without
changing state, and that every digest runs a destructor. Another test requires
every digest type and helper to document whether it is constant or variable
time. Missing public documentation is rejected by a crate-level lint.

Run these commands from the workspace root:

```text
cargo test -p tc_blake --locked
cargo test -p tc_blake --all-features --locked
cargo clippy -p tc_blake --all-targets --locked -- -D warnings
cargo clippy -p tc_blake --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_blake --check
cargo doc -p tc_blake --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_blake --list --locked
cargo publish -p tc_blake --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
source and the tests. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
