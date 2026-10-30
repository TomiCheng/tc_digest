//! Less common message digests on the [`tc_digest`] traits, ported from
//! Bouncy Castle, one Cargo feature each and none on by default:
//!
//! - `haraka`: Haraka-256/256 and Haraka-512/256, the short-input hashes of
//!   SPHINCS+, on AES-NI when the CPU has it.
//! - `photon-beetle`: PHOTON-Beetle-Hash, a NIST lightweight cryptography
//!   finalist.
//! - `sparkle`: ESCH-256 and ESCH-384 on the SPARKLE permutations.
//! - `tiger`: Tiger, the 192-bit digest of Anderson and Biham.
//! - `whirlpool`: Whirlpool (ISO/IEC 10118-3).
//! - `xoodyak`: Xoodyak Hash on the Xoodoo permutation.
//!
//! Every digest except Haraka implements the traits with an infallible error
//! type, so the [`Digest`](tc_digest::Digest) methods are available directly.
//! Haraka takes inputs of exactly 32 or 64 bytes and reports other lengths as
//! a `HarakaError`.
//!
//! # Timing
//!
//! ESCH and Xoodyak are constant time. Tiger, Whirlpool and PHOTON-Beetle are
//! variable time: they index S-boxes or lookup tables with bytes or nibbles
//! of their state, which can leak the message through cache timing. Haraka is
//! constant time on AES-NI and variable time on its portable rounds. Hash only
//! public data with a variable-time digest, or accept that leak in the threat
//! model.
//!
//! # Example
//!
//! Whirlpool of `"abc"`, with the `whirlpool` feature:
//!
//! ```
//! # #[cfg(feature = "whirlpool")]
//! # {
//! use tc_digest::Digest;
//! use tc_misc_digest::WhirlpoolDigest;
//!
//! let mut whirlpool = WhirlpoolDigest::new();
//! whirlpool.update(b"abc");
//! let mut output = [0u8; 64];
//! assert_eq!(whirlpool.do_final(&mut output), 64);
//! assert_eq!(output[..4], [0x4e, 0x24, 0x48, 0xa4]);
//! # }
//! ```

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]

#[cfg(test)]
extern crate alloc;

#[cfg(feature = "haraka")]
mod haraka;
#[cfg(any(feature = "tiger", feature = "whirlpool"))]
// Tiger pads through `update` alone, so `finish` is unused without Whirlpool.
#[cfg_attr(not(feature = "whirlpool"), allow(dead_code))]
mod md_buffer;
#[cfg(feature = "photon-beetle")]
mod photon_beetle;
#[cfg(feature = "sparkle")]
mod sparkle;
#[cfg(feature = "tiger")]
mod tiger;
#[cfg(feature = "whirlpool")]
mod whirlpool;
#[cfg(feature = "xoodyak")]
mod xoodyak;

#[cfg(feature = "haraka")]
pub use haraka::{Haraka256Digest, Haraka512Digest, HarakaError};
#[cfg(feature = "photon-beetle")]
pub use photon_beetle::PhotonBeetleDigest;
#[cfg(feature = "sparkle")]
pub use sparkle::{SparkleDigest, SparkleParameters};
#[cfg(feature = "tiger")]
pub use tiger::TigerDigest;
#[cfg(feature = "whirlpool")]
pub use whirlpool::WhirlpoolDigest;
#[cfg(feature = "xoodyak")]
pub use xoodyak::XoodyakDigest;
