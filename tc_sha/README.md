# tc_sha

[![crates.io](https://img.shields.io/crates/v/tc_sha.svg)](https://crates.io/crates/tc_sha)
[![docs.rs](https://docs.rs/tc_sha/badge.svg)](https://docs.rs/tc_sha)
[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

SHA-1 and the SHA-2 family of message digests from FIPS 180-4: SHA-224,
SHA-256, SHA-384, SHA-512 and SHA-512/t, ported from Bouncy Castle. Every
digest implements the [`tc_digest`](https://crates.io/crates/tc_digest)
traits and is constant time.

SHA-1 is broken for collision resistance, chosen-prefix collisions included.
It is kept for legacy interoperability, such as verifying existing signatures
or HMAC-SHA1, which does not rely on collision resistance; use a SHA-2 digest
for new signatures and designs.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends only on `tc_digest`.

Requires Rust 1.85 or later (edition 2024).

## Types

- `Sha1Digest` — SHA-1, 20-byte digest, 64-byte blocks.
- `Sha224Digest` — SHA-224, 28-byte digest, 64-byte blocks.
- `Sha256Digest` — SHA-256, 32-byte digest, 64-byte blocks.
- `Sha384Digest` — SHA-384, 48-byte digest, 128-byte blocks.
- `Sha512Digest` — SHA-512, 64-byte digest, 128-byte blocks.
- `Sha512tDigest` — SHA-512/t, `t / 8`-byte digest, 128-byte blocks; `t` is
  chosen at construction.

Each digest implements `TryDigest` with `core::convert::Infallible` as its
error type, and so `Digest` as well, and implements `Clone`, so a digest can be
forked partway through a message. Every digest except `Sha512tDigest` has
`const fn new` and `Default`. `Display` writes the FIPS name, such as
`SHA-256` or `SHA-512/256`.

`Sha512tDigest::new(t)` accepts any multiple of 8 from 8 to 504 other than
384, which is SHA-384's length, and derives the initial hash value for `t` as
FIPS 180-4 specifies, so SHA-512/256 is not a truncated SHA-512. It panics for
any other `t`, zero included. SHA-512/224 and SHA-512/256 are the lengths
FIPS 180-4 approves.

`do_final` writes the digest to the start of the output buffer, leaves any
longer tail untouched, returns the digest length, and resets the digest. It
panics if the buffer is shorter than `digest_size`, before changing any state.

## Timing

Every digest is constant time. The compressions use only additions,
rotations, shifts and bitwise operations, and the running time depends only on
the message length and, for SHA-512/t, on `t`.

## Usage

```toml
[dependencies]
tc_digest = "0.1.0"
tc_sha = "0.1.0"
```

Import `Digest` to reach the digest's methods:

```rust
use tc_digest::Digest;
use tc_sha::{Sha256Digest, Sha512tDigest};

let mut sha256 = Sha256Digest::new();
sha256.update(b"abc");
let mut output = [0; 32];
assert_eq!(sha256.do_final(&mut output), 32);
assert_eq!(output[..4], [0xba, 0x78, 0x16, 0xbf]);

let mut sha512_256 = Sha512tDigest::new(256);
sha512_256.update(b"abc");
assert_eq!(sha512_256.do_final(&mut output), 32);
assert_eq!(output[..4], [0x53, 0x04, 0x8e, 0x26]);
```

## Validation

The tests check each digest against FIPS 180-4's examples, the derived
SHA-512/224 and SHA-512/256 initial hash values against the values FIPS 180-4
lists, and every digest against OpenSSL for messages on the 64- and 128-byte
padding boundaries and for one million `'a'` bytes. Contract tests check, for
every digest and for SHA-512/t at `t` of 8, 224, 256 and 504, that splitting a
message across updates never changes the digest, that `do_final` writes
exactly `digest_size` bytes and resets, that a short output buffer panics
without changing state, and that a clone continues independently. Another test
requires every digest type and internal helper to document whether it is
constant or variable time. Missing public documentation is rejected by a
crate-level lint, and `unsafe` code is forbidden.

Run these commands from the workspace root:

```text
cargo test -p tc_sha --locked
cargo clippy -p tc_sha --all-targets --locked -- -D warnings
cargo fmt -p tc_sha --check
cargo doc -p tc_sha --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_sha --list --locked
cargo publish -p tc_sha --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
source and the tests. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
