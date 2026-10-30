# tc_gost3411

[![crates.io](https://img.shields.io/crates/v/tc_gost3411.svg)](https://crates.io/crates/tc_gost3411)
[![docs.rs](https://docs.rs/tc_gost3411/badge.svg)](https://docs.rs/tc_gost3411)
[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The Russian GOST R 34.11-94 (RFC 5831) and GOST R 34.11-2012, Streebog
(RFC 6986), message digests, ported from Bouncy Castle. Every digest
implements the [`tc_digest`](https://crates.io/crates/tc_digest) traits.

GOST R 34.11-94 has been withdrawn in favour of Streebog; use it to
interoperate with existing data. It runs the GOST 28147-89 block cipher from
[`tc_gost28147`](https://crates.io/crates/tc_gost28147).

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_digest`, `tc_gost28147` and its
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits, and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize), which wipes the digest
state.

Requires Rust 1.85 or later (edition 2024).

## Types

- `Gost3411Digest` — GOST R 34.11-94, 32-byte digest, 32-byte blocks; variable
  time.
- `Gost3411_2012_256Digest` — Streebog-256, 32-byte digest, 64-byte blocks;
  variable time.
- `Gost3411_2012_512Digest` — Streebog-512, 64-byte digest, 64-byte blocks;
  variable time.

`Gost3411Digest::new` uses the CryptoPro D-A S-box of RFC 4357, as Bouncy
Castle does, and `Gost3411Digest::with_s_box` takes any other GOST 28147-89
S-box, such as `tc_gost28147::s_box::D_TEST`, the test parameters of
RFC 5831's examples. Resetting keeps the chosen S-box.

Each digest implements `TryDigest` with `core::convert::Infallible` as its
error type, and so `Digest` as well. It has `const fn new` and `Default`, and
implements `Clone`, so a digest can be forked partway through a message.
`Display` writes Bouncy Castle's algorithm name: `Gost3411`,
`GOST3411-2012-256` or `GOST3411-2012-512`.

`do_final` writes the digest to the start of the output buffer, leaves any
longer tail untouched, returns its length, and resets the digest. It panics if
the buffer is shorter than the digest, before changing any state.

## Timing

Every digest here is variable time. GOST R 34.11-94 encrypts its chaining state
with GOST 28147-89 under keys derived from the message, and the cipher indexes
its S-box with secret nibbles. Streebog indexes eight 2 KiB lookup tables with
bytes of its state. Either can leak the message through cache timing: hash
only public data with them, or accept that leak in the threat model.

## Wiping

Dropping a digest, or resetting it, which `do_final` also does, wipes its
state with volatile writes through `tc_zeroize`: the chaining value, the
checksum, the buffered block and its fill level, and the length count, and
for GOST R 34.11-94 the S-box on drop. Each GOST 28147-89 engine the digest
creates wipes its own key. A clone is wiped when it is dropped in turn. Copies
the compression leaves in registers or on the stack, such as the derived keys,
and copies a move leaves behind are not wiped, and drop-based wiping requires
the destructor to run. The output buffer belongs to the caller.

## Usage

```toml
[dependencies]
tc_digest = "0.1.0"
tc_gost3411 = "0.1.0"
```

Import `Digest` to reach the digest's methods:

```rust
use tc_digest::Digest;
use tc_gost3411::Gost3411_2012_256Digest;

let mut streebog = Gost3411_2012_256Digest::new();
streebog.update(b"012345678901234567890123456789012345678901234567890123456789012");
let mut output = [0; 32];
assert_eq!(streebog.do_final(&mut output), 32);
assert_eq!(output[..4], [0x9d, 0x15, 0x1e, 0xef]);
```

## Validation

The tests check GOST R 34.11-94 against Bouncy Castle's `GOST3411DigestTest`
vectors with the CryptoPro D-A and the test S-boxes, including one million
`'a'` bytes, two of which RFC 5831 section 7.3 prints, and Streebog-256 and
Streebog-512 against the examples of RFC 6986 section 10. Contract tests check,
for every digest, that splitting a message across updates never changes the
digest, that `do_final` writes exactly the digest length and resets, that a
short output buffer panics without changing state, that a clone continues
independently and that every digest runs a destructor. Another test requires
every digest type and internal helper to document whether it is constant or
variable time. Missing public documentation is rejected by a crate-level lint,
and `unsafe` code is forbidden.

Run these commands from the workspace root:

```text
cargo test -p tc_gost3411 --locked
cargo clippy -p tc_gost3411 --all-targets --locked -- -D warnings
cargo fmt -p tc_gost3411 --check
cargo doc -p tc_gost3411 --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_gost3411 --list --locked
cargo publish -p tc_gost3411 --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
source and the tests. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
