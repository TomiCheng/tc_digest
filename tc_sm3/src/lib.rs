//! The SM3 message digest (GB/T 32905-2016), the Chinese national hash
//! standard used by SM2 signatures and key exchange and by the TLS 1.3 cipher
//! suites of RFC 8998.
//!
//! [`Sm3Digest`] implements the [`tc_digest`] traits with an infallible error
//! type, so the [`Digest`](tc_digest::Digest) methods are available directly.
//!
//! # Timing
//!
//! [`Sm3Digest`] is constant time: it uses only additions, rotations and
//! bitwise operations, and its running time depends only on the message
//! length.
//!
//! # Example
//!
//! The SM3 digest of `"abc"`, the first example of GB/T 32905-2016:
//!
//! ```
//! use tc_digest::Digest;
//! use tc_sm3::Sm3Digest;
//!
//! let mut sm3 = Sm3Digest::new();
//! sm3.update(b"abc");
//! let mut output = [0u8; 32];
//! assert_eq!(sm3.do_final(&mut output), 32);
//! assert_eq!(output[..4], [0x66, 0xc7, 0xf0, 0xf4]);
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate alloc;

mod md_buffer;
mod sm3;

pub use sm3::Sm3Digest;
