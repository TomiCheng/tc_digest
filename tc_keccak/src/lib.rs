//! Keccak and the SHA-3 family of FIPS 202 and NIST SP 800-185: the raw
//! Keccak digest, SHA3-224 to SHA3-512, the SHAKE128 and SHAKE256
//! extendable-output functions, cSHAKE, TupleHash and ParallelHash, ported
//! from Bouncy Castle.
//!
//! Every digest implements the [`tc_digest`] traits with an infallible error
//! type, so the [`Digest`](tc_digest::Digest) methods are available directly;
//! SHAKE, cSHAKE, TupleHash and ParallelHash also implement
//! [`Xof`](tc_digest::Xof).
//!
//! # Timing
//!
//! Every digest is constant time: the Keccak-f\[1600\] permutation uses only
//! XOR, AND, OR, NOT and fixed rotations, and the running time depends only on
//! the lengths of the input and the output and on the parameters chosen at
//! construction.
//!
//! # Wiping
//!
//! Dropping a digest, or resetting it, which `do_final` and `output_final` also
//! do, wipes its sponge state with volatile writes through `tc_zeroize`.
//! Copies left in registers or on the stack are not wiped.
//!
//! # Example
//!
//! SHA3-256 of `"abc"`, then SHAKE128 read as an extendable-output function:
//!
//! ```
//! use tc_digest::{Digest, Xof};
//! use tc_keccak::{Sha3Digest, ShakeDigest};
//!
//! let mut sha3 = Sha3Digest::new(256);
//! sha3.update(b"abc");
//! let mut digest = [0u8; 32];
//! sha3.do_final(&mut digest);
//! assert_eq!(digest[..4], [0x3a, 0x98, 0x5d, 0xa7]);
//!
//! // An XOF hands out as many bytes as asked, here 100 in two reads.
//! let mut shake = ShakeDigest::new(128);
//! shake.update(b"abc");
//! let mut output = [0u8; 100];
//! shake.output(&mut output[..40]);
//! shake.output_final(&mut output[40..]);
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate alloc;

mod cshake;
mod keccak;
mod parallelhash;
mod sha3;
mod shake;
mod tuplehash;
mod xof_utils;

pub use cshake::CShakeDigest;
pub use keccak::KeccakDigest;
pub use parallelhash::ParallelHash;
pub use sha3::Sha3Digest;
pub use shake::ShakeDigest;
pub use tuplehash::TupleHash;
