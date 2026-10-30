//! GOST R 34.11-94 and GOST R 34.11-2012 (Streebog) message digests.
//!
//! Every digest implements the [`tc_digest`] traits with an infallible error
//! type, so the [`Digest`](tc_digest::Digest) methods are available directly.
//!
//! - [`Gost3411Digest`] is GOST R 34.11-94 (RFC 5831), a 256-bit digest built
//!   on the GOST 28147-89 block cipher. It uses the CryptoPro D-A S-box of
//!   RFC 4357 by default, as Bouncy Castle does, or any S-box the caller
//!   passes. The standard has been withdrawn in favour of Streebog; use it to
//!   interoperate with existing data.
//! - [`Gost3411_2012_256Digest`] and [`Gost3411_2012_512Digest`] are
//!   GOST R 34.11-2012 (RFC 6986), Streebog, with 256- and 512-bit output.
//!
//! # Timing
//!
//! Every digest here is variable time. GOST R 34.11-94 runs GOST 28147-89,
//! whose rounds index its S-box with nibbles derived from the message and the
//! chaining state, and Streebog indexes eight 2 KiB lookup tables with bytes
//! of its state. Either can leak the message through cache timing, so hash
//! only public data with them, or accept that leak in the threat model.
//!
//! # Example
//!
//! The Streebog-256 digest of RFC 6986's first example message, the 63 digits
//! `"0123...012"`:
//!
//! ```
//! use tc_digest::Digest;
//! use tc_gost3411::Gost3411_2012_256Digest;
//!
//! let mut streebog = Gost3411_2012_256Digest::new();
//! streebog.update(b"012345678901234567890123456789012345678901234567890123456789012");
//! let mut output = [0u8; 32];
//! assert_eq!(streebog.do_final(&mut output), 32);
//! assert_eq!(output[..4], [0x9d, 0x15, 0x1e, 0xef]);
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod gost3411;
mod gost3411_2012;

pub use gost3411::Gost3411Digest;
pub use gost3411_2012::{Gost3411_2012_256Digest, Gost3411_2012_512Digest};
