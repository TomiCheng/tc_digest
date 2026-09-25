//! Shared message-digest and extendable-output function (XOF) traits.
//!
//! Digest crates such as [`tc_sha`](https://crates.io/crates/tc_sha) implement
//! these traits, and generic code that hashes a message names only the
//! capabilities it uses. The crate implements no algorithm.
//!
//! Each capability comes in two forms. [`TryDigest`] and [`TryXof`] return a
//! `Result` from every operation, with an error type chosen by the
//! implementation. [`Digest`] and [`Xof`] are their infallible counterparts:
//! an implementation whose error type is [`Infallible`](core::convert::Infallible)
//! receives them automatically through blanket implementations, so it never
//! implements them by hand.
//!
//! # Example
//!
//! A toy digest that sums its input bytes. It implements [`TryDigest`] with an
//! infallible error type and so gains the [`Digest`] methods:
//!
//! ```
//! use core::convert::Infallible;
//! use tc_digest::{Digest, TryDigest};
//!
//! #[derive(Default)]
//! struct Sum8 {
//!     sum: u8,
//! }
//!
//! impl TryDigest for Sum8 {
//!     type Error = Infallible;
//!
//!     fn algorithm_name(&self) -> &str {
//!         "SUM-8"
//!     }
//!
//!     fn digest_size(&self) -> usize {
//!         1
//!     }
//!
//!     fn byte_length(&self) -> usize {
//!         1
//!     }
//!
//!     fn try_update(&mut self, input: &[u8]) -> Result<(), Infallible> {
//!         for &byte in input {
//!             self.sum = self.sum.wrapping_add(byte);
//!         }
//!         Ok(())
//!     }
//!
//!     fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Infallible> {
//!         output[0] = self.sum;
//!         self.sum = 0;
//!         Ok(1)
//!     }
//!
//!     fn try_reset(&mut self) -> Result<(), Infallible> {
//!         self.sum = 0;
//!         Ok(())
//!     }
//! }
//!
//! // Generic code asks only for the capability it uses.
//! fn hash_parts(digest: &mut dyn Digest, parts: &[&[u8]], output: &mut [u8]) -> usize {
//!     for part in parts {
//!         digest.update(part);
//!     }
//!     digest.do_final(output)
//! }
//!
//! let mut output = [0u8; 1];
//! assert_eq!(hash_parts(&mut Sum8::default(), &[&[1, 2], &[3]], &mut output), 1);
//! assert_eq!(output, [6]);
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod digest;
mod xof;

pub use digest::{Digest, TryDigest};
pub use xof::{TryXof, Xof};
