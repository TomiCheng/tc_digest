# tc_misc_digest

[![crates.io](https://img.shields.io/crates/v/tc_misc_digest.svg)](https://crates.io/crates/tc_misc_digest)
[![docs.rs](https://docs.rs/tc_misc_digest/badge.svg)](https://docs.rs/tc_misc_digest)
[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Less common message digests, ported from Bouncy Castle, one Cargo feature
each and none on by default: Haraka, PHOTON-Beetle, ESCH, Tiger, Whirlpool and
Xoodyak. Every digest implements the
[`tc_digest`](https://crates.io/crates/tc_digest) traits.

The crate is `no_std` and needs no allocator. It depends on `tc_digest` and on
[`tc_zeroize`](https://crates.io/crates/tc_zeroize), which wipes the digest
state, and with the `haraka` feature on x86 on
[`tc_runtime`](https://crates.io/crates/tc_runtime), which detects AES-NI.
Haraka's AES-NI rounds are the only `unsafe` code.

Requires Rust 1.85 or later (edition 2024).

## Features and types

- `haraka`: `Haraka256Digest` and `Haraka512Digest`, Haraka v2 with inputs of
  exactly 32 or 64 bytes and a 32-byte digest; `HarakaError` reports other
  lengths. Constant time on AES-NI, variable time on the portable rounds.
- `photon-beetle`: `PhotonBeetleDigest`, PHOTON-Beetle-Hash, 32-byte digest;
  variable time.
- `sparkle`: `SparkleDigest` with `SparkleParameters::Esch256` or
  `Esch384`, ESCH-256 and ESCH-384, 32- or 48-byte digest; constant time.
- `tiger`: `TigerDigest`, Tiger, 24-byte digest, 64-byte blocks; variable
  time.
- `whirlpool`: `WhirlpoolDigest`, Whirlpool, 64-byte digest, 64-byte blocks;
  variable time.
- `xoodyak`: `XoodyakDigest`, Xoodyak Hash, 32-byte digest; constant time.

Every digest has a `const fn` constructor and implements `Clone`. `Display`
writes Bouncy Castle's algorithm name. Every digest except Haraka implements
`TryDigest` with `core::convert::Infallible` as its error type, and so
`Digest`; `do_final` writes the digest to the start of the output buffer,
returns its length and resets, and panics if the buffer is shorter than the
digest, before changing any state. Haraka's `TryDigest` returns a
`HarakaError` instead of panicking, also before changing any state.

## Timing

ESCH and Xoodyak use only additions, rotations and bitwise operations, so
their running time depends only on the message length. Tiger, Whirlpool and
PHOTON-Beetle index S-boxes or lookup tables with bytes or nibbles of their
state, which can leak the message through cache timing. Haraka runs on AES-NI
when `tc_runtime` detects it with SSE2, which makes no data-dependent memory
accesses, and otherwise on portable AES rounds that look up an S-box. Hash
only public data with a variable-time digest, or accept that leak in the
threat model.

## Wiping

Dropping a digest, or resetting it, which `do_final` also does, wipes its
state with volatile writes through `tc_zeroize`: the chaining state or sponge
state, the buffered input and its position, and the length count. A clone is
wiped when it is dropped in turn. Copies the compression leaves in registers
or on the stack and copies a move leaves behind are not wiped, and drop-based
wiping requires the destructor to run. The output buffer belongs to the
caller.

## Usage

```toml
[dependencies]
tc_digest = "0.1.0"
tc_misc_digest = { version = "0.1.0", features = ["whirlpool"] }
```

Import `Digest` to reach the digest's methods:

```rust
use tc_digest::Digest;
use tc_misc_digest::WhirlpoolDigest;

let mut whirlpool = WhirlpoolDigest::new();
whirlpool.update(b"abc");
let mut output = [0; 64];
assert_eq!(whirlpool.do_final(&mut output), 64);
```

## Validation

Each feature has its own test file:

- Haraka: the examples of the Haraka v2 paper and the Monte Carlo,
  offset-output and error cases of Bouncy Castle's tests; tests that the
  AES-NI and portable rounds agree on a thousand inputs.
- PHOTON-Beetle, ESCH and Xoodyak: entries of the NIST lightweight
  cryptography KAT files that Bouncy Castle's tests read, chosen around the
  rate and block boundaries, up to 1024 bytes.
- Tiger: every vector of Bouncy Castle's `TigerDigestTest`, with 64 KiB of
  counting bytes, and Bouncy Castle digests for a million `'a'` bytes and on
  the padding boundaries.
- Whirlpool: the ISO/IEC 10118-3 vectors of Bouncy Castle's
  `WhirlpoolDigestTest`, with a million `'a'` bytes, and OpenSSL digests on
  the padding boundaries.

Contract tests check, for every digest, that splitting a message across
updates never changes the digest, that `do_final` writes exactly the digest
length and resets, that a short output buffer is rejected without changing
state, that a clone continues independently and that the digest runs a
destructor; for Haraka also that wrong input lengths are rejected without
changing state. A unit test checks that the block buffer's wipe clears its
buffered bytes, fill level and length count. Another test requires every
digest type and internal helper to document whether it is constant or
variable time. Missing public documentation is rejected by a crate-level
lint, and `unsafe` code is denied outside Haraka's AES-NI rounds.

Run these commands from the workspace root:

```text
cargo test -p tc_misc_digest --all-features --locked
cargo clippy -p tc_misc_digest --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_misc_digest --check
cargo doc -p tc_misc_digest --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_misc_digest --list --locked
cargo publish -p tc_misc_digest --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
source and the tests. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
