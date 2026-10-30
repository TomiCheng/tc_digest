//! The DSTU 7564:2014 (Kupyna) message digest, the Ukrainian national hash
//! standard, with 256-, 384- and 512-bit output.
//!
//! [`Dstu7564Digest`] implements the [`tc_digest`] traits with an infallible
//! error type, so the [`Digest`](tc_digest::Digest) methods are available
//! directly.
//!
//! # Timing
//!
//! [`Dstu7564Digest`] is variable time: its permutations index S-boxes with
//! bytes of the state, which can leak the message through cache timing. Hash
//! only public data with it, or accept that leak in the threat model.
//!
//! # Example
//!
//! The 256-bit digest of the 512-bit message `00 01 ... 3f`, the first example
//! of DSTU 7564:2014:
//!
//! ```
//! use tc_digest::Digest;
//! use tc_dstu7564::Dstu7564Digest;
//!
//! let message: Vec<u8> = (0..64).collect();
//! let mut kupyna = Dstu7564Digest::new(256);
//! kupyna.update(&message);
//! let mut output = [0u8; 32];
//! assert_eq!(kupyna.do_final(&mut output), 32);
//! assert_eq!(output[..4], [0x08, 0xf4, 0xee, 0x6f]);
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate alloc;

mod dstu7564;
mod md_buffer;

pub use dstu7564::Dstu7564Digest;
