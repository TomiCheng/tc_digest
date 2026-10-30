# tc_dstu7564

[![crates.io](https://img.shields.io/crates/v/tc_dstu7564.svg)](https://crates.io/crates/tc_dstu7564)
[![docs.rs](https://docs.rs/tc_dstu7564/badge.svg)](https://docs.rs/tc_dstu7564)
[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The DSTU 7564:2014 (Kupyna) message digest, the Ukrainian national hash
standard, with 256-, 384- and 512-bit output, ported from Bouncy Castle. The
digest implements the [`tc_digest`](https://crates.io/crates/tc_digest)
traits.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_digest` and on [`tc_zeroize`](https://crates.io/crates/tc_zeroize),
which wipes the digest state.

Requires Rust 1.85 or later (edition 2024).

## Types

- `Dstu7564Digest` — DSTU 7564, 32-, 48- or 64-byte digest; 64-byte blocks for
  the 256-bit digest, 128-byte blocks for the longer ones; variable time.

`Dstu7564Digest::new` takes the digest length in bits, 256, 384 or 512, and
panics on any other length, as Bouncy Castle throws. Resetting keeps the
length.

`Dstu7564Digest` implements `TryDigest` with `core::convert::Infallible` as
its error type, and so `Digest` as well. It has `Clone`, so a digest can be
forked partway through a message. `Display` writes Bouncy Castle's algorithm
name, `DSTU7564`.

`do_final` writes the digest to the start of the output buffer, leaves any
longer tail untouched, returns its length, and resets the digest. It panics if
the buffer is shorter than the digest, before changing any state.

## Timing

`Dstu7564Digest` is variable time. Its permutations index four 256-byte
S-boxes with bytes of the state, which can leak the message through cache
timing: hash only public data with it, or accept that leak in the threat
model.

## Wiping

Dropping the digest, or resetting it, which `do_final` also does, wipes its
state with volatile writes through `tc_zeroize`: the chaining state, the
buffered block and its fill level, and the length count. A clone is wiped when
it is dropped in turn. Copies the compression leaves in registers or on the
stack, such as the permuted states, and copies a move leaves behind are not
wiped, and drop-based wiping requires the destructor to run. The output buffer
belongs to the caller.

## Usage

```toml
[dependencies]
tc_digest = "0.1.0"
tc_dstu7564 = "0.1.0"
```

Import `Digest` to reach the digest's methods:

```rust
use tc_digest::Digest;
use tc_dstu7564::Dstu7564Digest;

let mut kupyna = Dstu7564Digest::new(256);
kupyna.update(b"abc");
let mut output = [0; 32];
assert_eq!(kupyna.do_final(&mut output), 32);
assert_eq!(output[..4], [0x0b, 0xd1, 0xb3, 0x61]);
```

## Validation

The tests check the digest against the examples of DSTU 7564:2014 and the
further vectors of Bouncy Castle's `Dstu7564Test`, which include messages on
the padding boundaries of the 64-byte block, and against digests computed by
Bouncy Castle on the padding boundaries of the 128-byte block and for one
million `'a'` bytes. Contract tests check, for every length, that splitting a
message across updates never changes the digest, that `do_final` writes
exactly the digest length and resets, that a short output buffer panics
without changing state and that a clone continues independently; and that
resetting keeps the length, that unsupported lengths panic and that the digest
runs a destructor. A unit test checks that the block buffer's wipe clears its
buffered bytes, fill level and length count. Another test requires the digest
type and every internal helper to document whether it is constant or variable
time. Missing public documentation is rejected by a crate-level lint, and
`unsafe` code is forbidden.

Run these commands from the workspace root:

```text
cargo test -p tc_dstu7564 --locked
cargo clippy -p tc_dstu7564 --all-targets --locked -- -D warnings
cargo fmt -p tc_dstu7564 --check
cargo doc -p tc_dstu7564 --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_dstu7564 --list --locked
cargo publish -p tc_dstu7564 --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
source and the tests. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
