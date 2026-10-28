//! BLAKE3 hash / XOF that picks its backend from the `blake3` feature.

use core::convert::Infallible;
use core::fmt;

use tc_digest::{TryDigest, TryXof};

#[cfg(not(feature = "blake3"))]
type Backend = crate::Blake3PortableDigest;
#[cfg(feature = "blake3")]
type Backend = crate::Blake3UpstreamDigest;

/// The BLAKE3 hash / extendable-output function, as Bouncy Castle's
/// `Blake3Digest`: unkeyed, keyed-hash and derive-key modes.
///
/// Runs on [`Blake3PortableDigest`](crate::Blake3PortableDigest), or with the
/// `blake3` feature on `Blake3UpstreamDigest`. Both accept the same keys and
/// contexts and produce the same output, so the feature only changes speed.
/// Constant time.
#[derive(Clone, Default)]
pub struct Blake3Digest(Backend);

impl Blake3Digest {
    /// Creates an unkeyed BLAKE3 with the default 32-byte digest. Constant time.
    pub fn new() -> Self {
        Self(Backend::new())
    }

    /// Creates an unkeyed BLAKE3 with a default output size in bits.
    /// Constant time.
    pub fn with_digest_size(digest_bits: usize) -> Self {
        Self(Backend::with_digest_size(digest_bits))
    }

    /// Creates a keyed BLAKE3 (keyed-hash mode) with a 32-byte key.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not exactly 32 bytes.
    pub fn with_key(digest_bits: usize, key: &[u8]) -> Self {
        Self(Backend::with_key(digest_bits, key))
    }

    /// Creates a BLAKE3 in derive-key mode from a context string. Constant
    /// time with respect to the contents of `context`; its length is public.
    pub fn with_derive_key(digest_bits: usize, context: &[u8]) -> Self {
        Self(Backend::with_derive_key(digest_bits, context))
    }
}

impl TryDigest for Blake3Digest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.0.digest_size()
    }

    fn byte_length(&self) -> usize {
        self.0.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.0.try_update(input)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.try_do_final(output)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.0.try_reset()
    }
}

impl TryXof for Blake3Digest {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.try_output(output)
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.try_output_final(output)
    }
}

impl fmt::Display for Blake3Digest {
    /// Writes `BLAKE3` without inspecting the state. Constant time with respect
    /// to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
