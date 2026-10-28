//! The Ascon hashes and extendable-output functions of NIST SP 800-232 and of
//! Ascon v1.2, and the ISAP hash that runs on the same permutation, ported
//! from Bouncy Castle.
//!
//! Every digest implements the [`tc_digest`] traits with an infallible error
//! type, so the [`Digest`](tc_digest::Digest) methods are available directly;
//! the XOFs also implement [`Xof`](tc_digest::Xof).
//!
//! The pre-standard digests are behind the `legacy` feature, off by default:
//! the deprecated Ascon v1.2 hashes and XOFs, `AsconDigest` and `AsconXof`,
//! kept only to read hashes made before the standard, and ISAP Hash,
//! `IsapDigest`, whose outputs equal the Ascon v1.2 hash.
//!
//! # Timing
//!
//! Every digest is constant time: the Ascon permutation uses only XOR, AND,
//! NOT and fixed rotations, and the running time depends only on the lengths
//! of the input and the output and on the variant chosen at construction.
//!
//! # Wiping
//!
//! Dropping a digest, or resetting it, which `do_final` and `output_final` also
//! do, wipes its state and buffered bytes with volatile writes through
//! `tc_zeroize`. Copies left in registers or on the stack are not wiped.
//!
//! # Example
//!
//! Ascon-Hash256 of the empty message, then Ascon-XOF128 read as an
//! extendable-output function:
//!
//! ```
//! use tc_ascon_hash::{AsconHash256, AsconXof128};
//! use tc_digest::{Digest, Xof};
//!
//! let mut hash = AsconHash256::new();
//! let mut digest = [0u8; 32];
//! hash.do_final(&mut digest);
//! assert_eq!(digest[..4], [0x0b, 0x3b, 0xe5, 0x85]);
//!
//! // An XOF hands out as many bytes as asked, here 100 in two reads.
//! let mut xof = AsconXof128::new();
//! xof.update(b"abc");
//! let mut output = [0u8; 100];
//! xof.output(&mut output[..40]);
//! xof.output_final(&mut output[40..]);
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate alloc;

mod ascon_core;
mod ascon_cxof128;
mod ascon_hash256;
#[cfg(feature = "legacy")]
mod ascon_legacy;
mod ascon_xof128;
#[cfg(feature = "legacy")]
mod ascon_xof_legacy;
#[cfg(feature = "legacy")]
mod isap;

pub use ascon_cxof128::AsconCXof128;
pub use ascon_hash256::AsconHash256;
#[cfg(feature = "legacy")]
#[allow(deprecated)]
pub use ascon_legacy::{AsconDigest, AsconParameters};
#[cfg(feature = "legacy")]
#[allow(deprecated)]
pub use ascon_xof_legacy::{AsconXof, AsconXofParameters};
pub use ascon_xof128::AsconXof128;
#[cfg(feature = "legacy")]
pub use isap::IsapDigest;
