# tc_sm3

[![crates.io](https://img.shields.io/crates/v/tc_sm3.svg)](https://crates.io/crates/tc_sm3)
[![docs.rs](https://docs.rs/tc_sm3/badge.svg)](https://docs.rs/tc_sm3)
[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The SM3 message digest (GB/T 32905-2016), the Chinese national hash standard
used by SM2 signatures and key exchange and by the TLS 1.3 cipher suites of
RFC 8998, ported from Bouncy Castle. The digest implements the
[`tc_digest`](https://crates.io/crates/tc_digest) traits.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_digest` and on [`tc_zeroize`](https://crates.io/crates/tc_zeroize),
which wipes the digest state.

Requires Rust 1.85 or later (edition 2024).

## Types

- `Sm3Digest` — SM3, 32-byte digest, 64-byte blocks; constant time.

`Sm3Digest` implements `TryDigest` with `core::convert::Infallible` as its
error type, and so `Digest` as well. It has `const fn new` and `Default`, and
implements `Clone`, so a digest can be forked partway through a message.
`Display` writes the algorithm name, `SM3`.

`do_final` writes the 32-byte digest to the start of the output buffer, leaves
any longer tail untouched, returns 32, and resets the digest. It panics if the
buffer is shorter than 32 bytes, before changing any state.

## Timing

SM3 uses only additions, rotations and bitwise operations, so its running time
depends only on the message length.

## Wiping

Dropping the digest, or resetting it, which `do_final` also does, wipes its
state with volatile writes through `tc_zeroize`: the chaining registers, the
buffered block and its fill level, and the length count. A clone is wiped when
it is dropped in turn. Copies the compression leaves in registers or on the
stack, such as the expanded message words, and copies a move leaves behind are
not wiped, and drop-based wiping requires the destructor to run. The output
buffer belongs to the caller.

## Usage

```toml
[dependencies]
tc_digest = "0.1.0"
tc_sm3 = "0.1.0"
```

Import `Digest` to reach the digest's methods:

```rust
use tc_digest::Digest;
use tc_sm3::Sm3Digest;

let mut sm3 = Sm3Digest::new();
sm3.update(b"abc");
let mut output = [0; 32];
assert_eq!(sm3.do_final(&mut output), 32);
assert_eq!(output[..4], [0x66, 0xc7, 0xf0, 0xf4]);
```

## Validation

The tests check the digest against the two examples of GB/T 32905-2016, the
further vectors of Bouncy Castle's `SM3DigestTest`, including 64 KiB of
counting bytes and one million `'a'` bytes, and digests computed by OpenSSL
for messages on the 64-byte padding boundaries. Contract tests check that
splitting a message across updates never changes the digest, that `do_final`
writes exactly 32 bytes and resets, that a short output buffer panics without
changing state, that a clone continues independently and that the digest runs
a destructor. A unit test checks that the block buffer's wipe clears its
buffered bytes, fill level and length count. Another test requires the digest
type and every internal helper to document whether it is constant or variable
time. Missing public documentation is rejected by a crate-level lint, and
`unsafe` code is forbidden.

Run these commands from the workspace root:

```text
cargo test -p tc_sm3 --locked
cargo clippy -p tc_sm3 --all-targets --locked -- -D warnings
cargo fmt -p tc_sm3 --check
cargo doc -p tc_sm3 --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_sm3 --list --locked
cargo publish -p tc_sm3 --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
source and the tests. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
