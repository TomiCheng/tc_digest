//! The Skein 1.3 hash function, with a 256-, 512- or 1024-bit state and any
//! whole number of output bytes, keyed or personalised through
//! [`SkeinParams`].
//!
//! [`SkeinDigest`] implements the [`tc_digest`] traits with an infallible
//! error type, so the [`Digest`](tc_digest::Digest) methods are available
//! directly. [`SkeinEngine`] is the Unique Block Iteration chaining
//! underneath, over the Threefish block cipher of `tc_threefish`.
//!
//! The parameters come through the [`SkeinParams`] trait: [`SkeinParamsRef`]
//! borrows them, and with the `alloc` feature `SkeinParamsOwned` owns them
//! and wipes them on drop.
//!
//! # Timing
//!
//! Skein is constant time: Threefish uses only additions, rotations and XORs,
//! and the running time depends only on the lengths of the message, the
//! parameters and the output.
//!
//! # Example
//!
//! Skein-512-256 of `"abc"`, then the same message under a key:
//!
//! ```
//! use tc_digest::Digest;
//! use tc_skein::{SkeinDigest, SkeinParamsRef};
//!
//! let mut skein = SkeinDigest::new(512, 256);
//! skein.update(b"abc");
//! let mut plain = [0u8; 32];
//! assert_eq!(skein.do_final(&mut plain), 32);
//!
//! skein.init(&SkeinParamsRef::new().with_key(&[0x42; 32]))?;
//! skein.update(b"abc");
//! let mut keyed = [0u8; 32];
//! skein.do_final(&mut keyed);
//! assert_ne!(plain, keyed);
//! # Ok::<(), tc_skein::InitError>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod engine;
mod error;
mod params;
mod skein;
mod traits;

pub use engine::SkeinEngine;
pub use error::InitError;
#[cfg(feature = "alloc")]
pub use params::SkeinParamsOwned;
pub use params::SkeinParamsRef;
pub use skein::SkeinDigest;
pub use traits::SkeinParams;
