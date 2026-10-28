# tc_ascon_hash

[![crates.io](https://img.shields.io/crates/v/tc_ascon_hash.svg)](https://crates.io/crates/tc_ascon_hash)
[![docs.rs](https://docs.rs/tc_ascon_hash/badge.svg)](https://docs.rs/tc_ascon_hash)
[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The Ascon hashes and extendable-output functions of NIST SP 800-232 and of
Ascon v1.2, and the ISAP hash that runs on the same permutation, ported from
Bouncy Castle. Every digest implements the
[`tc_digest`](https://crates.io/crates/tc_digest) traits and is constant time.
The Ascon AEAD is a separate crate,
[`tc_ascon_aead`](https://crates.io/crates/tc_ascon_aead).

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_digest` and on [`tc_zeroize`](https://crates.io/crates/tc_zeroize),
which wipes the state.

Requires Rust 1.85 or later (edition 2024).

## Types

- `AsconHash256` — Ascon-Hash256 of NIST SP 800-232, 32 bytes of output.
- `AsconXof128` — Ascon-XOF128 of NIST SP 800-232.
- `AsconCXof128` — Ascon-CXOF128 of NIST SP 800-232, with a customization
  string of up to 256 bytes.
- `AsconDigest` — the Ascon v1.2 Ascon-Hash or Ascon-HashA, deprecated, with
  the `legacy` feature.
- `AsconXof` — the Ascon v1.2 Ascon-Xof or Ascon-XofA, deprecated, with the
  `legacy` feature.
- `IsapDigest` — ISAP Hash, whose outputs equal the Ascon v1.2 hash, with the
  `legacy` feature.

Each implements `TryDigest` with `core::convert::Infallible` as its error type,
and so `Digest` as well, and implements `Clone`, so a digest can be forked
partway through a message. `AsconXof128`, `AsconCXof128` and `AsconXof` also
implement `TryXof` and so `Xof`, which reads any amount of output; read as a
plain digest they write 32 bytes. `Display` writes Bouncy Castle's name, such
as `Ascon-Hash256` or `Ascon-CXOF128`.

The pre-standard types are behind the `legacy` feature, off by default. The
Ascon v1.2 types are kept only to read hashes made before the standard; they do
not interoperate with the SP 800-232 types, and `AsconParameters` and
`AsconXofParameters` choose their variant. ISAP Hash comes from ISAP, a
candidate of NIST's lightweight cryptography project that was not
standardized.

`do_final` writes the digest to the start of the output buffer, returns its
length and resets; it panics if the buffer is shorter than `digest_size`,
before changing any state. Absorbing after reading output with `output` panics
until the digest is reset. `AsconCXof128::with_customization` panics for a
customization string longer than 256 bytes, as Bouncy Castle throws.

## Timing

Every digest is constant time. The Ascon permutation uses only XOR, AND, NOT
and fixed rotations, and the running time depends only on the lengths of the
input and the output and on the variant chosen at construction.

## Wiping

Dropping a digest, or resetting it, which `do_final` and `output_final` also do,
wipes its state and buffered bytes with volatile writes through `tc_zeroize`;
`AsconCXof128`'s customized initial state is wiped too. Copies the permutation
leaves in registers or on the stack, the block copies made while absorbing and
padding, and copies a move leaves behind are not wiped, and drop-based wiping
requires the destructor to run. The output buffer belongs to the caller.

## Usage

```toml
[dependencies]
tc_digest = "0.1.0"
tc_ascon_hash = "0.1.0"
```

Import `Digest`, and `Xof` for the extendable-output functions:

```rust
use tc_ascon_hash::{AsconHash256, AsconXof128};
use tc_digest::{Digest, Xof};

let mut hash = AsconHash256::new();
hash.update(b"");
let mut digest = [0; 32];
assert_eq!(hash.do_final(&mut digest), 32);
assert_eq!(digest[..4], [0x0b, 0x3b, 0xe5, 0x85]);

let mut xof = AsconXof128::new();
xof.update(b"abc");
let mut output = [0; 100];
xof.output_final(&mut output);
```

## Validation

The tests check Ascon-XOF128, Ascon-CXOF128 and the Ascon v1.2 XOFs against
their full known-answer files, Ascon-Hash256 against selected vectors of
ascon-c's NIST SP 800-232 known answers, and the Ascon v1.2 hashes and ISAP
Hash against Bouncy Castle's 1025-message known-answer files. Contract tests
check that splitting the input or the output never changes the bytes, that a
short output buffer panics without changing state, and that every digest runs
a destructor. Another test requires every digest type and internal helper to
document whether it is constant or variable time. Missing public documentation
is rejected by a crate-level lint, and `unsafe` code is forbidden.

Run these commands from the workspace root:

```text
cargo test -p tc_ascon_hash --locked
cargo test -p tc_ascon_hash --all-features --locked
cargo clippy -p tc_ascon_hash --all-targets --locked -- -D warnings
cargo clippy -p tc_ascon_hash --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_ascon_hash --check
cargo doc -p tc_ascon_hash --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_ascon_hash --list --locked
cargo publish -p tc_ascon_hash --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
source and the tests. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
