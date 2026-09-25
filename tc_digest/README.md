# tc_digest

[![crates.io](https://img.shields.io/crates/v/tc_digest.svg)](https://crates.io/crates/tc_digest)
[![docs.rs](https://docs.rs/tc_digest/badge.svg)](https://docs.rs/tc_digest)
[![CI](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_digest/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Shared traits for streaming message digests and extendable-output functions
(XOFs). Digest crates such as [`tc_sha`](https://crates.io/crates/tc_sha) and
[`tc_md`](https://crates.io/crates/tc_md) implement them, and generic code that
hashes a message names only the capabilities it uses. The crate implements no
algorithm.

It is `no_std`, needs no allocator, contains no `unsafe` code, and has no
dependencies.

Requires Rust 1.85 or later (edition 2024).

## Traits

- `TryDigest` — absorbs input with `try_update`, writes the digest with
  `try_do_final` and resets; each operation returns a `Result` with the
  implementation's error type.
- `Digest` — the infallible form: `update`, `update_byte`, `do_final` and
  `reset`.
- `TryXof` — an extendable-output function: `try_output` squeezes any amount of
  output, `try_output_final` squeezes and resets.
- `Xof` — the infallible form: `output` and `output_final`.

An implementation writes only `TryDigest`, and `TryXof` for an XOF. When its
error type is `core::convert::Infallible`, blanket implementations supply
`Digest` and `Xof`, so callers of an infallible digest never handle a `Result`.
All four traits are dyn-compatible, so `&mut dyn Digest` works wherever the
digest is chosen at run time.

Besides processing, a digest reports `algorithm_name`, such as `"SHA-256"`,
`digest_size`, the number of bytes `do_final` writes, and `byte_length`, its
internal block length, which HMAC pads its key to.

## Usage

Add the crate next to a digest crate:

```toml
[dependencies]
tc_digest = "0.1.0"
tc_sha = "0.1.0"
```

Import `Digest` to reach a digest's methods:

```rust
use tc_digest::Digest;
use tc_sha::Sha256Digest;

let mut sha256 = Sha256Digest::new();
sha256.update(b"hello, ");
sha256.update(b"world");
let mut output = [0; 32];
assert_eq!(sha256.do_final(&mut output), 32);
```

The crate documentation has an executable example of implementing
`TryDigest` for a digest.

## Contract and limitations

`try_do_final` and `do_final` need an output buffer of at least
`digest_size` bytes; each implementation documents whether a shorter buffer
panics or returns an error. A successful finalization resets the digest for the
next message, and so does `try_output_final` for an XOF. Once an XOF has
started squeezing, later `try_output` calls continue the same output stream;
whether it still accepts input is up to the implementation.

The traits make no constant-time promise. Whether a digest's running time
depends on the message is documented by each implementation. A digest provides
no authentication on its own; use a MAC such as HMAC to protect messages.

## Validation

The crate documentation carries an executable example that implements
`TryDigest` and uses it through `&mut dyn Digest`. Unit tests check that
infallible implementations receive `Digest` and `Xof`, that XOF output
continues across calls and restarts after `output_final`, and that both
infallible traits work as trait objects. Missing public documentation is
rejected by a crate-level lint, and `unsafe` code is forbidden. The digests in
`tc_md` and `tc_sha` exercise the traits against published known-answer
vectors.

Run these commands from the workspace root:

```text
cargo test -p tc_digest --locked
cargo clippy -p tc_digest --all-targets --locked -- -D warnings
cargo fmt -p tc_digest --check
cargo doc -p tc_digest --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_digest --list --locked
cargo publish -p tc_digest --dry-run --locked
```

The archive includes both license texts, this README, the changelog and the
source. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
