//! The output-truncating digest, ported from Bouncy Castle's `ShortenedDigest`.

use alloc::vec;
use core::fmt;

use tc_zeroize::Zeroize;

use crate::TryDigest;

/// A digest whose output is the first `length` bytes of a base digest, Bouncy
/// Castle's `ShortenedDigest`. Input goes to the base unchanged.
///
/// This is plain truncation: the first 28 bytes of SHA-256 are not SHA-224,
/// which starts from different initial values. `do_final` panics if the output
/// buffer is shorter than `length`, before changing any state; the base's full
/// output is computed into a buffer that is wiped once the prefix is copied.
///
/// Constant time when the base digest is; the truncation adds only fixed-length
/// copies.
#[derive(Clone)]
pub struct ShortenedDigest<D> {
    base: D,
    length: usize,
}

impl<D: TryDigest> ShortenedDigest<D> {
    /// Truncates `base` to its first `length` bytes. Constant time.
    ///
    /// # Panics
    ///
    /// Panics if `length` is greater than the base's digest size, as Bouncy
    /// Castle throws.
    pub fn new(base: D, length: usize) -> Self {
        assert!(
            length <= base.digest_size(),
            "ShortenedDigest: length exceeds the base digest size"
        );
        Self { base, length }
    }

    /// The base digest. Constant time.
    pub fn base(&self) -> &D {
        &self.base
    }
}

impl<D: TryDigest> TryDigest for ShortenedDigest<D> {
    type Error = D::Error;

    fn digest_size(&self) -> usize {
        self.length
    }

    fn byte_length(&self) -> usize {
        self.base.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.base.try_update(input)
    }

    fn try_update_byte(&mut self, input: u8) -> Result<(), Self::Error> {
        self.base.try_update_byte(input)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let length = self.length;
        assert!(
            output.len() >= length,
            "output buffer shorter than the {length}-byte digest"
        );
        let mut full = vec![0; self.base.digest_size()];
        let result = self.base.try_do_final(&mut full);
        if result.is_ok() {
            output[..length].copy_from_slice(&full[..length]);
        }
        full.zeroize();
        result.map(|_| length)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.base.try_reset()
    }
}

impl<D: fmt::Display> fmt::Display for ShortenedDigest<D> {
    /// Writes the base's name and the output length in bits, such as
    /// `SHA-256(128)`, as Bouncy Castle names it. Constant time with respect to
    /// the message when the base's `Display` is; output timing depends on the
    /// formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.base, self.length * 8)
    }
}
