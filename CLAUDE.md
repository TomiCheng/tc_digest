# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules

- Comments and documentation are written in English only — doc comments,
  README, changelog, and inline comments alike.
- Never wire a README into rustdoc (`#![doc = include_str!("../README.md")]`).
  The README's badges and relative links do not survive rustdoc rendering.
  Crate documentation lives in `//!` and `///` comments; the README repeats what
  a reader on crates.io needs.
- No breaking changes. Public API work is additive: adding items, trait
  implementations, or default methods. If a change cannot be made additively,
  stop and raise it rather than altering an existing signature or behavior.
  The `TryDigest` and `TryXof` signatures in particular are shared by every
  digest crate built on `tc_digest`.
- Every crate README opens with the badge block: crates.io, docs.rs, CI,
  license, and rustc.
- Crate READMEs use no Markdown tables; crates.io renders them badly. Traits,
  types and features are flat one-line bullets (`` `Item` — what it does. ``),
  with any further detail in the paragraph below the list.

The crate list and workspace-wide checks live in the root
[README.md](README.md); read it rather than restating it here. Every crate is
`no_std` and, by default, needs no allocator. Three crates have a Cargo
feature, all off by default: `tc_digest`'s `alloc` adds the adapter digests,
which need an allocator and `tc_zeroize`; `tc_ascon_hash`'s `legacy` adds the
pre-standard Ascon digests and no dependency; and `tc_blake`'s `blake3` runs
BLAKE3 on the third-party `blake3` crate. CI runs every job with and without `--all-features`, except that the
`aarch64-unknown-none` check leaves out `tc_blake`'s feature, whose NEON C code
needs a cross compiler there. `extern crate alloc` appears only under
`#[cfg(test)]`, and under `tc_digest`'s `alloc` feature. `tc_digest` has no
dependencies without that feature; the digest crates depend on
`tc_digest` and `tc_zeroize`, `tc_gost3411` also on `tc_gost28147` and its
`tc_block_cipher` traits for GOST R 34.11-94's cipher, and `tc_blake` also on
`tc_runtime` on x86 and, with its feature, on `blake3` and `zeroize`. `tc_blake` is the only crate with
`unsafe` code, its x86 BLAKE2 vector compression behind `tc_runtime` detection
tokens; it denies `unsafe_code` and allows it only there. CI enforces each crate's
dependency set with `cargo tree` on the `wasm32-unknown-unknown`,
`aarch64-unknown-none` and x86 targets. `tc_digest` carries no hash algorithm:
the traits fix no output length, block size, output-buffer check or timing
guarantee, which belong to each implementation. Generic adapters built on the
traits, such as `NullDigest`, `Prehash` and `ShortenedDigest` in the `util`
module under the `alloc` feature, may live in `tc_digest`; like any digest, each documents its own
output length, buffer check and timing, which `tc_digest/tests/documentation.rs`
checks, and the scanned file list there must grow with the module.

Digests name themselves through `Display`, not through the traits: `TryDigest`
has no name method and does not require `Display`, just as `BlockCipher` and
`StreamCipher` do not. Generic code that needs a name adds a `Display` bound.
Each `Display` implementation writes a fixed name without inspecting the
digest state, and its `fmt` documents its timing like any other helper.

Every digest in `tc_ascon_hash`, `tc_blake`, `tc_keccak`, `tc_sha` and `tc_sm3` and MD4
and MD5 in `tc_md` are constant time; MD2 is variable time because it indexes its S-box
with message-derived bytes, and every `tc_gost3411` digest is variable time
because GOST 28147-89 and Streebog index S-boxes and tables with secret bytes.
`tests/documentation.rs` in each digest crate requires every `*Digest` type,
`pub`/`pub(crate)` function and compression helper to say which, and the
scanned file list there must grow with the crate. Keep the timing contract of
each item stated in its doc comment.

Every digest wipes its state on drop. `MdBuffer` implements
`tc_zeroize::Zeroize` and wipes itself on drop, so a digest's own `Drop` wipes
only its registers, and resets that assign a fresh value wipe the old one on
the way. A new field that holds message-derived state must be wiped too.
Copies on the stack, in registers or left behind by moves are a documented
limitation, as in `tc_aes`, not wiped per block; each digest's doc comment and
README say so.

Each digest's `do_final` asserts the output length before touching any state,
so a short buffer panics and leaves the digest usable; keep that order.
`tc_md`, `tc_sha` and `tc_sm3` each hold a private copy of `md_buffer.rs`, the shared
Merkle–Damgård block buffer. The copies must stay byte-for-byte identical, and
CI compares them; change them together.

Rust 1.85 is guaranteed for every build in the workspace, tests included,
because the first-party dependencies outside the workspace, `tc_zeroize`,
`tc_runtime`, `tc_block_cipher` and `tc_gost28147`, require 1.85 as well, the only third-party ones, the `blake3`
crate and its dependencies behind `tc_blake`'s feature, build on 1.85, and
the only third-party dev-dependency, `tc_blake`'s Criterion for its
benchmarks, is held at 0.7 because 0.8 needs Rust 1.86. The MSRV job
therefore runs `cargo test`, which builds dev-dependencies, on 1.85, with
and without `--all-features`.
APIs stabilized after 1.85, such as `<[T]>::as_chunks` (1.88) and
`is_multiple_of` (1.87), are rejected by clippy's `incompatible_msrv` lint,
which reads the inherited `rust-version`; the incubator's copies of these
crates used both. `.cargo/config.toml` sets
`incompatible-rust-versions = "allow"` so `Cargo.lock` tracks the latest
releases. Adding any third-party dependency or dev-dependency hands part of
the 1.85 guarantee to that crate; raise it before doing so.

A crate depends on a workspace sibling through `path` plus `version`, so the
workspace builds and tests against the local crate while the published package
requires the release. When a change needs a sibling API that is not released
yet, raise the `version` requirement to the release that adds it; that release
has to be published first.

## Conventions

Each crate ships its own `README.md`, `CHANGELOG.md`, `LICENSE-MIT`,
`LICENSE-APACHE`, and an explicit `include` list in `Cargo.toml`. Changelog
entries are written as `## <version> - Unreleased` and dated in a separate
commit at release, with `### Added` and `### Compatibility` sections.

Adding a crate to the workspace means five edits beyond the crate itself: the
`members` list, a `-p <crate>` on the single `cargo package --locked` step in
the CI `quality` job (the only place package archives are verified; packaging
the crates in one invocation checks each against its siblings' local sources
rather than their releases), a `cargo tree` check of its dependency set in the
CI `portable` job, a row in the root `README.md`, and
workspace inheritance for `edition`, `rust-version`, `license`, and
`repository`. A missing `rust-version` also leaves clippy suggesting APIs newer
than 1.85. A new Merkle–Damgård digest crate that copies `md_buffer.rs` joins
the `cmp` in the `quality` job as well.

Documentation is part of the contract: crates use `#![deny(missing_docs)]`,
doctests carry the executable examples, and CI runs `cargo doc` with
`RUSTDOCFLAGS: -D warnings`. An additive public API change belongs in the
crate README's contract lists — "Traits" in `tc_digest/README.md`, "Types" in
`tc_md/README.md`, `tc_sha/README.md`, `tc_gost3411/README.md` and
`tc_sm3/README.md` — and in the
changelog, not only in the code. Known-answer vectors cite their source: an
RFC, FIPS 180-4, digests computed by OpenSSL, or Bouncy Castle's own tests.

Work happens on `feat/*` branches off `develop`; pull requests target `develop`,
which merges to `main`. Commit messages use an imperative subject and a wrapped
body that explains the reasoning, not a bullet list of the diff.

Note: the root `Cargo.toml` uses CRLF line endings while the rest of the tree
uses LF. Tools that rewrite whole files will flip it and produce a noisy diff.
