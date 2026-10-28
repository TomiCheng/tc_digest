//! BLAKE2b, BLAKE2s and BLAKE2xs (RFC 7693 and the BLAKE2X paper) and BLAKE3,
//! ported from Bouncy Castle.
//!
//! Every digest implements the [`tc_digest`] traits with an infallible error
//! type, so the [`Digest`](tc_digest::Digest) methods are available directly;
//! BLAKE2xs and BLAKE3 also implement [`Xof`](tc_digest::Xof).
//!
//! On x86 and x86-64, BLAKE2b and BLAKE2s detect AVX2 and SSE2 at run time
//! through `tc_runtime`, without `std`, and use them when present; other
//! targets use the portable code. With the `blake3` feature, [`Blake3Digest`]
//! runs on the BLAKE3 team's `blake3` crate instead of
//! [`Blake3PortableDigest`]; both produce the same output.
//!
//! # Timing
//!
//! Every digest is constant time: the compression functions use only
//! additions, XOR and fixed rotations, the message words are picked by public
//! permutations, and the running time depends only on the lengths of the input
//! and the output and on the parameters chosen at construction. The CPU, not
//! the data, picks between the vector and the portable code.
//!
//! # Wiping
//!
//! Dropping a digest wipes its state, buffers and key with volatile writes
//! through `tc_zeroize`, or through the `zeroize` crate for the `blake3`
//! backend; resetting, which `do_final` and `output_final` also do, overwrites
//! them. Copies left in registers or on the stack are not wiped.
//!
//! # Example
//!
//! BLAKE2b-512 of `"abc"`, then BLAKE3 read as an extendable-output function:
//!
//! ```
//! use tc_blake::{Blake2bDigest, Blake3Digest};
//! use tc_digest::{Digest, Xof};
//!
//! let mut blake2b = Blake2bDigest::new();
//! blake2b.update(b"abc");
//! let mut digest = [0u8; 64];
//! blake2b.do_final(&mut digest);
//! assert_eq!(digest[..4], [0xba, 0x80, 0xa5, 0x3f]);
//!
//! // An XOF hands out as many bytes as asked, here 100 in two reads.
//! let mut blake3 = Blake3Digest::new();
//! blake3.update(b"abc");
//! let mut output = [0u8; 100];
//! blake3.output(&mut output[..40]);
//! blake3.output_final(&mut output[40..]);
//! ```

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]

#[cfg(test)]
extern crate alloc;

mod blake2b;
mod blake2s;
mod blake2xs;
mod blake3;
mod blake3_portable;
#[cfg(feature = "blake3")]
mod blake3_upstream;

pub use blake2b::Blake2bDigest;
pub use blake2s::Blake2sDigest;
pub use blake2xs::Blake2xsDigest;
// `self::` keeps the module apart from the `blake3` crate of the same name.
pub use self::blake3::Blake3Digest;
pub use blake3_portable::Blake3PortableDigest;
#[cfg(feature = "blake3")]
pub use blake3_upstream::Blake3UpstreamDigest;
