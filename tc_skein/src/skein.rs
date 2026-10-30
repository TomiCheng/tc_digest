//! The Skein digest, ported from Bouncy Castle's `SkeinDigest`.

use core::{convert::Infallible, fmt};

use tc_digest::TryDigest;

use crate::{InitError, SkeinEngine, SkeinParams};

/// Skein 1.3 (Bouncy Castle `SkeinDigest`) with a 256-, 512- or 1024-bit state
/// and any whole number of output bytes, as a [`tc_digest`] digest.
///
/// [`init`](Self::init) applies a key, which makes it a MAC, and the other
/// [`SkeinParams`]; resetting, which `do_final` also does, keeps them.
///
/// Constant time: Threefish uses only additions, rotations and XORs, and the
/// running time depends only on the lengths of the message, the parameters
/// and the output.
///
/// Dropping the digest wipes its chaining value, its state after the key and
/// parameters, and its buffered block with volatile writes. Copies the
/// compression leaves in registers or on the stack, such as the Threefish key
/// bytes, and copies a move leaves behind are not wiped.
///
/// `do_final` panics if the output buffer is shorter than the digest.
#[derive(Clone)]
pub struct SkeinDigest {
    /// The UBI engine.
    engine: SkeinEngine,
}

impl SkeinDigest {
    /// The 256-bit state size, in bits.
    pub const SKEIN_256: usize = SkeinEngine::SKEIN_256;
    /// The 512-bit state size, in bits.
    pub const SKEIN_512: usize = SkeinEngine::SKEIN_512;
    /// The 1024-bit state size, in bits.
    pub const SKEIN_1024: usize = SkeinEngine::SKEIN_1024;

    /// Creates an unkeyed digest with a `state_size_bits` of 256, 512 or 1024
    /// and a `digest_size_bits` that is a positive multiple of 8.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics on any other state size or digest size, as Bouncy Castle
    /// throws an `ArgumentException`.
    pub fn new(state_size_bits: usize, digest_size_bits: usize) -> Self {
        SkeinDigest {
            engine: SkeinEngine::new(state_size_bits, digest_size_bits),
        }
    }

    /// Applies `params` and starts a new message (Bouncy Castle `Init`); empty
    /// parameters return to the plain digest. Constant time with respect to
    /// the parameter contents; their lengths are public.
    ///
    /// Returns [`InitError::KeyTooShort`] for a key shorter than 16 bytes,
    /// leaving the digest unchanged.
    pub fn init<P: SkeinParams + ?Sized>(&mut self, params: &P) -> Result<(), InitError> {
        self.engine.init(params)
    }
}

impl fmt::Display for SkeinDigest {
    /// Writes Bouncy Castle's name, `Skein-` followed by the state and digest
    /// sizes in bits, without inspecting the digest state. Constant time with
    /// respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Skein-{}-{}",
            self.engine.block_size() * 8,
            self.engine.output_size() * 8
        )
    }
}

impl TryDigest for SkeinDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.engine.output_size()
    }

    fn byte_length(&self) -> usize {
        self.engine.block_size()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.engine.update(input);
        Ok(())
    }

    /// Writes the digest to the start of `output` and resets, keeping the
    /// parameters.
    ///
    /// # Panics
    ///
    /// Panics if `output` is shorter than the digest, before changing any
    /// state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(self.engine.do_final(output))
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.engine.reset();
        Ok(())
    }
}
