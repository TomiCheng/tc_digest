//! SHA-1 and the SHA-2 family (FIPS 180-4) of message digests: SHA-224,
//! SHA-256, SHA-384, SHA-512 and SHA-512/t.
//!
//! Every digest implements the [`tc_digest`] traits with an infallible error
//! type, so the [`Digest`](tc_digest::Digest) methods are available directly.
//!
//! SHA-1 is broken for collision resistance and kept for legacy
//! interoperability; use a SHA-2 digest for new designs.
//!
//! # Timing
//!
//! Every digest is constant time: the compressions use only additions,
//! rotations, shifts and bitwise operations, and the running time depends only
//! on the message length and, for SHA-512/t, on `t`.
//!
//! # Example
//!
//! The SHA-256 digest of `"abc"` from FIPS 180-4's examples:
//!
//! ```
//! use tc_digest::Digest;
//! use tc_sha::Sha256Digest;
//!
//! let mut sha256 = Sha256Digest::new();
//! sha256.update(b"abc");
//! let mut output = [0u8; 32];
//! assert_eq!(sha256.do_final(&mut output), 32);
//! assert_eq!(
//!     output,
//!     [
//!         0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
//!         0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
//!         0xf2, 0x00, 0x15, 0xad,
//!     ]
//! );
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate alloc;

mod md_buffer;
mod sha1;
mod sha224;
mod sha256;
mod sha256_core;
mod sha384;
mod sha512;
mod sha512_core;
mod sha512t;

pub use sha1::Sha1Digest;
pub use sha224::Sha224Digest;
pub use sha256::Sha256Digest;
pub use sha384::Sha384Digest;
pub use sha512::Sha512Digest;
pub use sha512t::Sha512tDigest;
