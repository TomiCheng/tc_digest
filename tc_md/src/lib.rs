//! MD2 (RFC 1319), MD4 (RFC 1320) and MD5 (RFC 1321) message digests.
//!
//! Every digest implements the [`tc_digest`] traits with an infallible error
//! type, so the [`Digest`](tc_digest::Digest) methods are available directly.
//!
//! All three algorithms are cryptographically broken: collisions are cheap to
//! find, and MD2 and MD4 fall to preimage attacks as well. Use them only to
//! interoperate with existing data and protocols, never for new designs.
//!
//! # Timing
//!
//! [`Md4Digest`] and [`Md5Digest`] are constant time: they use only additions,
//! rotations and bitwise operations, and their running time depends only on
//! the message length. [`Md2Digest`] is variable time: it indexes a 256-byte
//! S-box with message-derived bytes, which can leak the message through cache
//! timing. Hash only public data with it.
//!
//! # Example
//!
//! The MD5 digest of `"abc"` from RFC 1321, appendix A.5:
//!
//! ```
//! use tc_digest::Digest;
//! use tc_md::Md5Digest;
//!
//! let mut md5 = Md5Digest::new();
//! md5.update(b"abc");
//! let mut output = [0u8; 16];
//! assert_eq!(md5.do_final(&mut output), 16);
//! assert_eq!(
//!     output,
//!     [
//!         0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
//!         0x7f, 0x72,
//!     ]
//! );
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate alloc;

mod md2;
mod md4;
mod md5;
mod md_buffer;

pub use md2::Md2Digest;
pub use md4::Md4Digest;
pub use md5::Md5Digest;
