//! Digests built on the traits that are not hash algorithms, ported from
//! Bouncy Castle: [`NullDigest`] writes its input back unchanged, [`Prehash`]
//! passes through one digest value computed elsewhere, and [`ShortenedDigest`]
//! truncates another digest's output.
//!
//! Available with the `alloc` feature: each needs an allocator, and wipes what
//! it holds through `tc_zeroize`.

mod null;
mod prehash;
mod shortened;

pub use null::NullDigest;
pub use prehash::{Prehash, PrehashError};
pub use shortened::ShortenedDigest;
