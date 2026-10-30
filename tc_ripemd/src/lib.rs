//! The RIPEMD-128, RIPEMD-160, RIPEMD-256 and RIPEMD-320 message digests
//! (ISO/IEC 10118-3).
//!
//! Every digest implements the [`tc_digest`] traits with an infallible error
//! type, so the [`Digest`](tc_digest::Digest) methods are available directly.
//!
//! RIPEMD-160 is the member in common use, in Bitcoin addresses and OpenPGP
//! among others. RIPEMD-128 has only a 128-bit output and should be kept to
//! legacy data. RIPEMD-256 and RIPEMD-320 give longer output but only the
//! security level of RIPEMD-128 and RIPEMD-160.
//!
//! # Timing
//!
//! Every digest here is constant time: it uses only additions, rotations and
//! bitwise operations, and its running time depends only on the message
//! length.
//!
//! # Example
//!
//! The RIPEMD-160 digest of `"abc"`:
//!
//! ```
//! use tc_digest::Digest;
//! use tc_ripemd::RipeMd160Digest;
//!
//! let mut ripemd = RipeMd160Digest::new();
//! ripemd.update(b"abc");
//! let mut output = [0u8; 20];
//! assert_eq!(ripemd.do_final(&mut output), 20);
//! assert_eq!(output[..4], [0x8e, 0xb2, 0x08, 0xf7]);
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate alloc;

mod functions;
mod md_buffer;
mod ripemd128;
mod ripemd160;
mod ripemd256;
mod ripemd320;

pub use ripemd128::RipeMd128Digest;
pub use ripemd160::RipeMd160Digest;
pub use ripemd256::RipeMd256Digest;
pub use ripemd320::RipeMd320Digest;
