# tc_ripemd

[![crates.io](https://img.shields.io/crates/v/tc_ripemd.svg)](https://crates.io/crates/tc_ripemd)
[![docs.rs](https://docs.rs/tc_ripemd/badge.svg)](https://docs.rs/tc_ripemd)
[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The RIPEMD-128, RIPEMD-160, RIPEMD-256 and RIPEMD-320 message digests
(ISO/IEC 10118-3), ported from Bouncy Castle. Every digest implements the
[`tc_digest`](https://crates.io/crates/tc_digest) traits.

RIPEMD-160 is the member in common use, in Bitcoin addresses and OpenPGP among
others. RIPEMD-128 has only a 128-bit output and should be kept to legacy
data. RIPEMD-256 and RIPEMD-320 give longer output but only the security level
of RIPEMD-128 and RIPEMD-160.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_digest` and on [`tc_zeroize`](https://crates.io/crates/tc_zeroize),
which wipes the digest state.

Requires Rust 1.85 or later (edition 2024).

## Types

- `RipeMd128Digest` — RIPEMD-128, 16-byte digest, 64-byte blocks; constant
  time.
- `RipeMd160Digest` — RIPEMD-160, 20-byte digest, 64-byte blocks; constant
  time.
- `RipeMd256Digest` — RIPEMD-256, 32-byte digest, 64-byte blocks; constant
  time.
- `RipeMd320Digest` — RIPEMD-320, 40-byte digest, 64-byte blocks; constant
  time.

Each digest implements `TryDigest` with `core::convert::Infallible` as its
error type, and so `Digest` as well. It has `const fn new` and `Default`, and
implements `Clone`, so a digest can be forked partway through a message.
`Display` writes Bouncy Castle's algorithm name: `RIPEMD128`, `RIPEMD160`,
`RIPEMD256` or `RIPEMD320`.

`do_final` writes the digest to the start of the output buffer, leaves any
longer tail untouched, returns its length, and resets the digest. It panics if
the buffer is shorter than the digest, before changing any state.

## Timing

Every digest here uses only additions, rotations and bitwise operations, so
its running time depends only on the message length.

## Wiping

Dropping a digest, or resetting it, which `do_final` also does, wipes its
state with volatile writes through `tc_zeroize`: the chaining registers, the
buffered block and its fill level, and the length count. A clone is wiped when
it is dropped in turn. Copies the compression leaves in registers or on the
stack, such as the message words it reads, and copies a move leaves behind are
not wiped, and drop-based wiping requires the destructor to run. The output
buffer belongs to the caller.

## Usage

```toml
[dependencies]
tc_digest = "0.1.0"
tc_ripemd = "0.1.0"
```

Import `Digest` to reach the digest's methods:

```rust
use tc_digest::Digest;
use tc_ripemd::RipeMd160Digest;

let mut ripemd = RipeMd160Digest::new();
ripemd.update(b"abc");
let mut output = [0; 20];
assert_eq!(ripemd.do_final(&mut output), 20);
assert_eq!(output[..4], [0x8e, 0xb2, 0x08, 0xf7]);
```

## Validation

The tests check every digest against the test suite of the RIPEMD authors,
which Bouncy Castle's `RipeMD*DigestTest` carry, including one million `'a'`
bytes, and against digests computed by Bouncy Castle for messages on the
64-byte padding boundaries, which OpenSSL confirms for RIPEMD-160. Contract
tests check, for every digest, that splitting a message across updates never
changes the digest, that `do_final` writes exactly the digest length and
resets, that a short output buffer panics without changing state, that a clone
continues independently and that every digest runs a destructor. A unit test
checks that the block buffer's wipe clears its buffered bytes, fill level and
length count. Another test requires every digest type and internal helper to
document whether it is constant or variable time. Missing public documentation
is rejected by a crate-level lint, and `unsafe` code is forbidden.

Run these commands from the workspace root:

```text
cargo test -p tc_ripemd --locked
cargo clippy -p tc_ripemd --all-targets --locked -- -D warnings
cargo fmt -p tc_ripemd --check
cargo doc -p tc_ripemd --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_ripemd --list --locked
cargo publish -p tc_ripemd --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
source and the tests. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
