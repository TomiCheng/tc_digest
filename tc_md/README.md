# tc_md

[![crates.io](https://img.shields.io/crates/v/tc_md.svg)](https://crates.io/crates/tc_md)
[![docs.rs](https://docs.rs/tc_md/badge.svg)](https://docs.rs/tc_md)
[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The MD2 (RFC 1319), MD4 (RFC 1320) and MD5 (RFC 1321) message digests, ported
from Bouncy Castle, for interoperability with legacy data and protocols. Every
digest implements the [`tc_digest`](https://crates.io/crates/tc_digest)
traits.

All three algorithms are cryptographically broken. Collisions are cheap for
each of them, chosen-prefix collisions included for MD5, and MD2 and MD4 also
fall to preimage attacks. Never use them for signatures, integrity against an
attacker, password hashing or any new design; use a SHA-2 digest from
[`tc_sha`](https://crates.io/crates/tc_sha) instead.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends only on `tc_digest`.

Requires Rust 1.85 or later (edition 2024).

## Types

- `Md2Digest` — MD2, 16-byte digest, 16-byte blocks; variable time.
- `Md4Digest` — MD4, 16-byte digest, 64-byte blocks; constant time.
- `Md5Digest` — MD5, 16-byte digest, 64-byte blocks; constant time.

Each digest implements `TryDigest` with `core::convert::Infallible` as its
error type, and so `Digest` as well. It has `const fn new` and `Default`, and
implements `Clone`, so a digest can be forked partway through a message.
`Display` writes the algorithm name, `MD2`, `MD4` or `MD5`.

`do_final` writes the 16-byte digest to the start of the output buffer, leaves
any longer tail untouched, returns 16, and resets the digest. It panics if the
buffer is shorter than 16 bytes, before changing any state.

## Timing

MD4 and MD5 use only additions, rotations and bitwise operations, so their
running time depends only on the message length. MD2 indexes a 256-byte S-box
with bytes derived from the message, which can leak the message through cache
timing: hash only public data with `Md2Digest`.

## Usage

```toml
[dependencies]
tc_digest = "0.1.0"
tc_md = "0.1.0"
```

Import `Digest` to reach the digest's methods:

```rust
use tc_digest::Digest;
use tc_md::Md5Digest;

let mut md5 = Md5Digest::new();
md5.update(b"message ");
md5.update(b"digest");
let mut output = [0; 16];
assert_eq!(md5.do_final(&mut output), 16);
assert_eq!(output[..4], [0xf9, 0x6b, 0x69, 0x7d]);
```

## Validation

The tests check each digest against the complete test suites of RFC 1319,
RFC 1320 and RFC 1321, and MD4 and MD5 against digests computed by OpenSSL for
messages on the 64-byte padding boundaries and for one million `'a'` bytes.
Contract tests check, for every digest, that splitting a message across
updates never changes the digest, that `do_final` writes exactly 16 bytes and
resets, that a short output buffer panics without changing state, and that a
clone continues independently. Another test requires every digest type and
internal helper to document whether it is constant or variable time. Missing
public documentation is rejected by a crate-level lint, and `unsafe` code is
forbidden.

Run these commands from the workspace root:

```text
cargo test -p tc_md --locked
cargo clippy -p tc_md --all-targets --locked -- -D warnings
cargo fmt -p tc_md --check
cargo doc -p tc_md --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_md --list --locked
cargo publish -p tc_md --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
source and the tests. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
