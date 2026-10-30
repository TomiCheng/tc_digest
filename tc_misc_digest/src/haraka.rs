//! Haraka v2 with a 256-bit output, Haraka-256/256 and Haraka-512/256,
//! ported from Bouncy Castle's `Haraka256Digest` and `Haraka512Digest`.
//!
//! Haraka is a short-input hash built from AES rounds. Haraka-256/256 maps
//! exactly 32 bytes and Haraka-512/256 exactly 64 bytes to a 32-byte digest:
//! five rounds of two AES rounds on every 128-bit lane followed by a mix of
//! the lanes' 32-bit words, then the input XORed back in, truncated to 32
//! bytes for Haraka-512.
//!
//! The portable rounds of `portable` are always available. On x86 and
//! x86-64, AES-NI and SSE2 are detected at run time through `tc_runtime`,
//! without needing `std`, and the rounds of `aesni` run when both are
//! present, as Bouncy Castle picks `Haraka256_X86` and `Haraka512_X86`.
//! Detection happens on every `try_do_final`, so the constructors stay
//! `const`; `tc_runtime` caches both answers, so it costs two atomic loads.

mod portable;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod aesni;

use core::fmt;

use tc_digest::TryDigest;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use tc_runtime::intrinsics::x86::{Aes, Sse2};
use tc_zeroize::Zeroize;

/// The digest length in bytes of both variants (Bouncy Castle `DIGEST_SIZE`).
const DIGEST_LENGTH: usize = 32;
/// The fixed input length in bytes of Haraka-256/256.
const INPUT_LENGTH_256: usize = 32;
/// The fixed input length in bytes of Haraka-512/256.
const INPUT_LENGTH_512: usize = 64;

/// One 128-bit lane of the state, as the AES round sees it.
type Block = [u8; 16];

// The 40 Haraka v2 round constants (Bouncy Castle `HarakaBase.RC`), one per
// AES round, as the bytes of the AES round key.
#[rustfmt::skip]
const ROUND_CONSTANTS: [Block; 40] = [
    [0x9d, 0x7b, 0x81, 0x75, 0xf0, 0xfe, 0xc5, 0xb2, 0x0a, 0xc0, 0x20, 0xe6, 0x4c, 0x70, 0x84, 0x06],
    [0x17, 0xf7, 0x08, 0x2f, 0xa4, 0x6b, 0x0f, 0x64, 0x6b, 0xa0, 0xf3, 0x88, 0xe1, 0xb4, 0x66, 0x8b],
    [0x14, 0x91, 0x02, 0x9f, 0x60, 0x9d, 0x02, 0xcf, 0x98, 0x84, 0xf2, 0x53, 0x2d, 0xde, 0x02, 0x34],
    [0x79, 0x4f, 0x5b, 0xfd, 0xaf, 0xbc, 0xf3, 0xbb, 0x08, 0x4f, 0x7b, 0x2e, 0xe6, 0xea, 0xd6, 0x0e],
    [0x44, 0x70, 0x39, 0xbe, 0x1c, 0xcd, 0xee, 0x79, 0x8b, 0x44, 0x72, 0x48, 0xcb, 0xb0, 0xcf, 0xcb],
    [0x7b, 0x05, 0x8a, 0x2b, 0xed, 0x35, 0x53, 0x8d, 0xb7, 0x32, 0x90, 0x6e, 0xee, 0xcd, 0xea, 0x7e],
    [0x1b, 0xef, 0x4f, 0xda, 0x61, 0x27, 0x41, 0xe2, 0xd0, 0x7c, 0x2e, 0x5e, 0x43, 0x8f, 0xc2, 0x67],
    [0x3b, 0x0b, 0xc7, 0x1f, 0xe2, 0xfd, 0x5f, 0x67, 0x07, 0xcc, 0xca, 0xaf, 0xb0, 0xd9, 0x24, 0x29],
    [0xee, 0x65, 0xd4, 0xb9, 0xca, 0x8f, 0xdb, 0xec, 0xe9, 0x7f, 0x86, 0xe6, 0xf1, 0x63, 0x4d, 0xab],
    [0x33, 0x7e, 0x03, 0xad, 0x4f, 0x40, 0x2a, 0x5b, 0x64, 0xcd, 0xb7, 0xd4, 0x84, 0xbf, 0x30, 0x1c],
    [0x00, 0x98, 0xf6, 0x8d, 0x2e, 0x8b, 0x02, 0x69, 0xbf, 0x23, 0x17, 0x94, 0xb9, 0x0b, 0xcc, 0xb2],
    [0x8a, 0x2d, 0x9d, 0x5c, 0xc8, 0x9e, 0xaa, 0x4a, 0x72, 0x55, 0x6f, 0xde, 0xa6, 0x78, 0x04, 0xfa],
    [0xd4, 0x9f, 0x12, 0x29, 0x2e, 0x4f, 0xfa, 0x0e, 0x12, 0x2a, 0x77, 0x6b, 0x2b, 0x9f, 0xb4, 0xdf],
    [0xee, 0x12, 0x6a, 0xbb, 0xae, 0x11, 0xd6, 0x32, 0x36, 0xa2, 0x49, 0xf4, 0x44, 0x03, 0xa1, 0x1e],
    [0xa6, 0xec, 0xa8, 0x9c, 0xc9, 0x00, 0x96, 0x5f, 0x84, 0x00, 0x05, 0x4b, 0x88, 0x49, 0x04, 0xaf],
    [0xec, 0x93, 0xe5, 0x27, 0xe3, 0xc7, 0xa2, 0x78, 0x4f, 0x9c, 0x19, 0x9d, 0xd8, 0x5e, 0x02, 0x21],
    [0x73, 0x01, 0xd4, 0x82, 0xcd, 0x2e, 0x28, 0xb9, 0xb7, 0xc9, 0x59, 0xa7, 0xf8, 0xaa, 0x3a, 0xbf],
    [0x6b, 0x7d, 0x30, 0x10, 0xd9, 0xef, 0xf2, 0x37, 0x17, 0xb0, 0x86, 0x61, 0x0d, 0x70, 0x60, 0x62],
    [0xc6, 0x9a, 0xfc, 0xf6, 0x53, 0x91, 0xc2, 0x81, 0x43, 0x04, 0x30, 0x21, 0xc2, 0x45, 0xca, 0x5a],
    [0x3a, 0x94, 0xd1, 0x36, 0xe8, 0x92, 0xaf, 0x2c, 0xbb, 0x68, 0x6b, 0x22, 0x3c, 0x97, 0x23, 0x92],
    [0xb4, 0x71, 0x10, 0xe5, 0x58, 0xb9, 0xba, 0x6c, 0xeb, 0x86, 0x58, 0x22, 0x38, 0x92, 0xbf, 0xd3],
    [0x8d, 0x12, 0xe1, 0x24, 0xdd, 0xfd, 0x3d, 0x93, 0x77, 0xc6, 0xf0, 0xae, 0xe5, 0x3c, 0x86, 0xdb],
    [0xb1, 0x12, 0x22, 0xcb, 0xe3, 0x8d, 0xe4, 0x83, 0x9c, 0xa0, 0xeb, 0xff, 0x68, 0x62, 0x60, 0xbb],
    [0x7d, 0xf7, 0x2b, 0xc7, 0x4e, 0x1a, 0xb9, 0x2d, 0x9c, 0xd1, 0xe4, 0xe2, 0xdc, 0xd3, 0x4b, 0x73],
    [0x4e, 0x92, 0xb3, 0x2c, 0xc4, 0x15, 0x14, 0x4b, 0x43, 0x1b, 0x30, 0x61, 0xc3, 0x47, 0xbb, 0x43],
    [0x99, 0x68, 0xeb, 0x16, 0xdd, 0x31, 0xb2, 0x03, 0xf6, 0xef, 0x07, 0xe7, 0xa8, 0x75, 0xa7, 0xdb],
    [0x2c, 0x47, 0xca, 0x7e, 0x02, 0x23, 0x5e, 0x8e, 0x77, 0x59, 0x75, 0x3c, 0x4b, 0x61, 0xf3, 0x6d],
    [0xf9, 0x17, 0x86, 0xb8, 0xb9, 0xe5, 0x1b, 0x6d, 0x77, 0x7d, 0xde, 0xd6, 0x17, 0x5a, 0xa7, 0xcd],
    [0x5d, 0xee, 0x46, 0xa9, 0x9d, 0x06, 0x6c, 0x9d, 0xaa, 0xe9, 0xa8, 0x6b, 0xf0, 0x43, 0x6b, 0xec],
    [0xc1, 0x27, 0xf3, 0x3b, 0x59, 0x11, 0x53, 0xa2, 0x2b, 0x33, 0x57, 0xf9, 0x50, 0x69, 0x1e, 0xcb],
    [0xd9, 0xd0, 0x0e, 0x60, 0x53, 0x03, 0xed, 0xe4, 0x9c, 0x61, 0xda, 0x00, 0x75, 0x0c, 0xee, 0x2c],
    [0x50, 0xa3, 0xa4, 0x63, 0xbc, 0xba, 0xbb, 0x80, 0xab, 0x0c, 0xe9, 0x96, 0xa1, 0xa5, 0xb1, 0xf0],
    [0x39, 0xca, 0x8d, 0x93, 0x30, 0xde, 0x0d, 0xab, 0x88, 0x29, 0x96, 0x5e, 0x02, 0xb1, 0x3d, 0xae],
    [0x42, 0xb4, 0x75, 0x2e, 0xa8, 0xf3, 0x14, 0x88, 0x0b, 0xa4, 0x54, 0xd5, 0x38, 0x8f, 0xbb, 0x17],
    [0xf6, 0x16, 0x0a, 0x36, 0x79, 0xb7, 0xb6, 0xae, 0xd7, 0x7f, 0x42, 0x5f, 0x5b, 0x8a, 0xbb, 0x34],
    [0xde, 0xaf, 0xba, 0xff, 0x18, 0x59, 0xce, 0x43, 0x38, 0x54, 0xe5, 0xcb, 0x41, 0x52, 0xf6, 0x26],
    [0x78, 0xc9, 0x9e, 0x83, 0xf7, 0x9c, 0xca, 0xa2, 0x6a, 0x02, 0xf3, 0xb9, 0x54, 0x9a, 0xe9, 0x4c],
    [0x35, 0x12, 0x90, 0x22, 0x28, 0x6e, 0xc0, 0x40, 0xbe, 0xf7, 0xdf, 0x1b, 0x1a, 0xa5, 0x51, 0xae],
    [0xcf, 0x59, 0xa6, 0x48, 0x0f, 0xbc, 0x73, 0xc1, 0x2b, 0xd2, 0x7e, 0xba, 0x3c, 0x61, 0xc1, 0xa0],
    [0xa1, 0x9d, 0xc5, 0xe9, 0xfd, 0xbd, 0xd6, 0x4a, 0x88, 0x82, 0x28, 0x02, 0x03, 0xcc, 0x6a, 0x75],
];

/// Haraka-256/256 of `input` into `output`, on AES-NI when `tc_runtime`
/// detects it together with SSE2 and on the portable rounds otherwise.
/// Variable time on the portable path, through its S-box lookups; the CPU,
/// not the data, picks the path.
fn hash256(input: &[u8; INPUT_LENGTH_256], output: &mut [u8; DIGEST_LENGTH]) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let (Some(aes), Some(sse2)) = (Aes::detect(), Sse2::detect()) {
        aesni::hash256(input, output, aes, sse2);
        return;
    }
    portable::hash256(input, output);
}

/// Haraka-512/256 of `input` into `output`, on AES-NI when `tc_runtime`
/// detects it together with SSE2 and on the portable rounds otherwise.
/// Variable time on the portable path, through its S-box lookups; the CPU,
/// not the data, picks the path.
fn hash512(input: &[u8; INPUT_LENGTH_512], output: &mut [u8; DIGEST_LENGTH]) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let (Some(aes), Some(sse2)) = (Aes::detect(), Sse2::detect()) {
        aesni::hash512(input, output, aes, sse2);
        return;
    }
    portable::hash512(input, output);
}

/// Appends `input` to the `*position` bytes already in `buffer`, or returns
/// [`HarakaError::InputTooLong`] without changing anything when it does not
/// fit (Bouncy Castle `BlockUpdate`). Constant time with respect to the
/// message: only the lengths, which are public, decide the outcome.
fn absorb<const N: usize>(
    buffer: &mut [u8; N],
    position: &mut usize,
    input: &[u8],
) -> Result<(), HarakaError> {
    if input.len() > N - *position {
        return Err(HarakaError::InputTooLong {
            limit: N,
            attempted: position.saturating_add(input.len()),
        });
    }
    let end = *position + input.len();
    buffer[*position..end].copy_from_slice(input);
    *position = end;
    Ok(())
}

/// Checks that all `N` input bytes have arrived and that `output` holds the
/// 32-byte digest, in that order, as Bouncy Castle `DoFinal` does before it
/// hashes, and returns the first 32 bytes of `output`. Constant time with
/// respect to the message: only the lengths, which are public, decide the
/// outcome.
fn checked_output<const N: usize>(
    position: usize,
    output: &mut [u8],
) -> Result<&mut [u8; DIGEST_LENGTH], HarakaError> {
    if position != N {
        return Err(HarakaError::IncorrectLength {
            expected: N,
            actual: position,
        });
    }
    let actual = output.len();
    output
        .first_chunk_mut::<DIGEST_LENGTH>()
        .ok_or(HarakaError::OutputTooShort {
            required: DIGEST_LENGTH,
            actual,
        })
}

/// An input or output length that the fixed-input Haraka digests reject, where
/// Bouncy Castle throws an `ArgumentException`.
///
/// Constant time: the variants carry only lengths, which are public, never
/// message bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarakaError {
    /// An update would take the input past the fixed input length.
    InputTooLong {
        /// The fixed input length in bytes: 32 or 64.
        limit: usize,
        /// The input length in bytes the update would have reached.
        attempted: usize,
    },
    /// `try_do_final` was called before the whole fixed input arrived.
    IncorrectLength {
        /// The fixed input length in bytes: 32 or 64.
        expected: usize,
        /// The number of input bytes absorbed.
        actual: usize,
    },
    /// The output buffer passed to `try_do_final` is shorter than the
    /// 32-byte digest.
    OutputTooShort {
        /// The digest length in bytes: 32.
        required: usize,
        /// The length of the output buffer in bytes.
        actual: usize,
    },
}

impl fmt::Display for HarakaError {
    /// Writes Bouncy Castle's wording for the error with the lengths it
    /// carries. Constant time with respect to the message; output timing
    /// depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InputTooLong { limit, attempted } => write!(
                f,
                "total input cannot be more than {limit} bytes, attempted {attempted}"
            ),
            Self::IncorrectLength { expected, actual } => {
                write!(f, "input must be exactly {expected} bytes, got {actual}")
            }
            Self::OutputTooShort { required, actual } => write!(
                f,
                "output too short to receive digest: need {required} bytes, got {actual}"
            ),
        }
    }
}

impl core::error::Error for HarakaError {}

/// Haraka-256/256 (Haraka v2), a short-input hash of exactly 32 bytes into a
/// 32-byte digest (Bouncy Castle `Haraka256Digest`).
///
/// Variable time on the portable path: its AES rounds look up the S-box with
/// bytes of the state, which can leak the input through cache timing. On x86
/// and x86-64 with AES-NI and SSE2, detected at run time through `tc_runtime`,
/// the rounds run on the `AESENC` instruction instead, without table lookups
/// or branches on the data, and the running time does not depend on the
/// input; the CPU, not the data, picks the path. Without AES-NI, hash only
/// public data with it, or accept that leak in the threat model.
/// `tc_runtime::intrinsics::x86::Aes::detect` tells which path runs; its
/// `disable-x86-aes-ni` feature, enabled anywhere in the build, forces the
/// portable path.
///
/// Dropping or resetting the digest, which `do_final` also does, wipes the
/// buffered input with volatile writes. Copies the rounds leave in registers
/// or on the stack, such as the lane states, and copies a move leaves behind
/// are not wiped.
///
/// The input must be exactly 32 bytes, in any number of updates. An update
/// past 32 bytes returns [`HarakaError::InputTooLong`]; `try_do_final` returns
/// [`HarakaError::IncorrectLength`] before all 32 bytes have arrived and
/// [`HarakaError::OutputTooShort`] if the output buffer is shorter than 32
/// bytes. Each error leaves the state unchanged.
#[derive(Clone)]
pub struct Haraka256Digest {
    /// The fixed input absorbed so far; the bytes past `position` are zero.
    buffer: [u8; INPUT_LENGTH_256],
    /// The number of input bytes in `buffer`, at most 32.
    position: usize,
}

impl Default for Haraka256Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Haraka256Digest {
    /// Creates an empty Haraka-256/256 digest. Constant time.
    pub const fn new() -> Self {
        Haraka256Digest {
            buffer: [0; INPUT_LENGTH_256],
            position: 0,
        }
    }
}

impl Drop for Haraka256Digest {
    /// Wipes the buffered input and its length. Constant time.
    fn drop(&mut self) {
        self.buffer.zeroize();
        self.position.zeroize();
    }
}

impl fmt::Display for Haraka256Digest {
    /// Writes `Haraka-256` without inspecting the digest state. Constant time
    /// with respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Haraka-256")
    }
}

impl TryDigest for Haraka256Digest {
    type Error = HarakaError;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        INPUT_LENGTH_256
    }

    /// Appends `input` to the fixed input. Constant time with respect to the
    /// message.
    ///
    /// # Errors
    ///
    /// Returns [`HarakaError::InputTooLong`] if the input would pass 32 bytes,
    /// without changing any state.
    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        absorb(&mut self.buffer, &mut self.position, input)
    }

    /// Writes the 32-byte digest to the start of `output` and resets.
    /// Variable time on the portable path, as the type documentation explains.
    ///
    /// # Errors
    ///
    /// Returns [`HarakaError::IncorrectLength`] if fewer than 32 bytes were
    /// absorbed, and otherwise [`HarakaError::OutputTooShort`] if `output` is
    /// shorter than 32 bytes, both before changing any state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let digest = checked_output::<INPUT_LENGTH_256>(self.position, output)?;
        hash256(&self.buffer, digest);
        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        *self = Self::new();
        Ok(())
    }
}

/// Haraka-512/256 (Haraka v2), a short-input hash of exactly 64 bytes into a
/// 32-byte digest (Bouncy Castle `Haraka512Digest`).
///
/// Variable time on the portable path: its AES rounds look up the S-box with
/// bytes of the state, which can leak the input through cache timing. On x86
/// and x86-64 with AES-NI and SSE2, detected at run time through `tc_runtime`,
/// the rounds run on the `AESENC` instruction instead, without table lookups
/// or branches on the data, and the running time does not depend on the
/// input; the CPU, not the data, picks the path. Without AES-NI, hash only
/// public data with it, or accept that leak in the threat model.
/// `tc_runtime::intrinsics::x86::Aes::detect` tells which path runs; its
/// `disable-x86-aes-ni` feature, enabled anywhere in the build, forces the
/// portable path.
///
/// Dropping or resetting the digest, which `do_final` also does, wipes the
/// buffered input with volatile writes. Copies the rounds leave in registers
/// or on the stack, such as the lane states, and copies a move leaves behind
/// are not wiped.
///
/// The input must be exactly 64 bytes, in any number of updates. An update
/// past 64 bytes returns [`HarakaError::InputTooLong`]; `try_do_final` returns
/// [`HarakaError::IncorrectLength`] before all 64 bytes have arrived and
/// [`HarakaError::OutputTooShort`] if the output buffer is shorter than 32
/// bytes. Each error leaves the state unchanged.
#[derive(Clone)]
pub struct Haraka512Digest {
    /// The fixed input absorbed so far; the bytes past `position` are zero.
    buffer: [u8; INPUT_LENGTH_512],
    /// The number of input bytes in `buffer`, at most 64.
    position: usize,
}

impl Default for Haraka512Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Haraka512Digest {
    /// Creates an empty Haraka-512/256 digest. Constant time.
    pub const fn new() -> Self {
        Haraka512Digest {
            buffer: [0; INPUT_LENGTH_512],
            position: 0,
        }
    }
}

impl Drop for Haraka512Digest {
    /// Wipes the buffered input and its length. Constant time.
    fn drop(&mut self) {
        self.buffer.zeroize();
        self.position.zeroize();
    }
}

impl fmt::Display for Haraka512Digest {
    /// Writes `Haraka-512` without inspecting the digest state. Constant time
    /// with respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Haraka-512")
    }
}

impl TryDigest for Haraka512Digest {
    type Error = HarakaError;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        INPUT_LENGTH_512
    }

    /// Appends `input` to the fixed input. Constant time with respect to the
    /// message.
    ///
    /// # Errors
    ///
    /// Returns [`HarakaError::InputTooLong`] if the input would pass 64 bytes,
    /// without changing any state.
    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        absorb(&mut self.buffer, &mut self.position, input)
    }

    /// Writes the 32-byte digest to the start of `output` and resets.
    /// Variable time on the portable path, as the type documentation explains.
    ///
    /// # Errors
    ///
    /// Returns [`HarakaError::IncorrectLength`] if fewer than 64 bytes were
    /// absorbed, and otherwise [`HarakaError::OutputTooShort`] if `output` is
    /// shorter than 32 bytes, both before changing any state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let digest = checked_output::<INPUT_LENGTH_512>(self.position, output)?;
        hash512(&self.buffer, digest);
        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        *self = Self::new();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 32-byte value of 64 hexadecimal digits.
    fn decoded(text: &str) -> [u8; 32] {
        assert_eq!(text.len(), 64);
        core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }

    /// Appendix B of the Haraka v2 paper and the Monte Carlo vectors of Bouncy
    /// Castle's `Haraka256DigestTest` and `Haraka512DigestTest`, on the
    /// portable rounds alone; the public digests may run on AES-NI instead.
    #[test]
    fn the_portable_rounds_reproduce_the_published_vectors() {
        let mut output = [0u8; 32];
        portable::hash256(&core::array::from_fn(|i| i as u8), &mut output);
        assert_eq!(
            output,
            decoded("8027ccb87949774b78d0545fb72bf70c695c2a0923cbd47bba1159efbf2b2c1c")
        );
        portable::hash512(&core::array::from_fn(|i| i as u8), &mut output);
        assert_eq!(
            output,
            decoded("be7f723b4e80a99813b292287f306f625a6d57331cae5f34dd9277b0945be2aa")
        );

        for (start, expected) in [
            (
                0x00,
                "e78599d7163ab58f1c90f0171c6fc4e852eb4b8cc29a4af63194fd9977c1de84",
            ),
            (
                0xff,
                "c4cebda63c00c4cd312f36ea92afd4b0f6048507c5b367326ef9d8fdd2d5c09a",
            ),
        ] {
            let mut result: [u8; 32] = if start == 0 {
                core::array::from_fn(|i| i as u8)
            } else {
                [0xff; 32]
            };
            for _ in 0..1000 {
                let input = result;
                portable::hash256(&input, &mut result);
            }
            assert_eq!(result, decoded(expected));
        }

        for (start, expected) in [
            (
                0x00,
                "abe210fe673f3b28e70e5100c476d82f61a7e2bdb3d8423fb0a15e5de3d3a4de",
            ),
            (
                0xff,
                "5f5ecb52c61f5036c96be555d2e18c520ab3ed093954700c283a322d14dbfe02",
            ),
        ] {
            let mut input: [u8; 64] = if start == 0 {
                core::array::from_fn(|i| i as u8)
            } else {
                [0xff; 64]
            };
            for step in 0..1000 {
                portable::hash512(&input, &mut output);
                let half = if step & 1 == 1 { 0 } else { 32 };
                input[half..half + 32].copy_from_slice(&output);
            }
            assert_eq!(output, decoded(expected));
        }
    }

    /// Compares both paths on 1000 chained inputs per variant, each derived
    /// from the previous digest and starting from zero, then on all-ones and
    /// counting inputs. The public digests
    /// pick one path, so only this test can reach the other.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn the_aes_ni_rounds_agree_with_the_portable_rounds() {
        let (Some(aes), Some(sse2)) = (Aes::detect(), Sse2::detect()) else {
            return;
        };

        let mut input256 = [0u8; 32];
        let mut input512 = [0u8; 64];
        for step in 0..1002 {
            if step == 1000 {
                input256 = [0xff; 32];
                input512 = [0xff; 64];
            } else if step == 1001 {
                input256 = core::array::from_fn(|i| i as u8);
                input512 = core::array::from_fn(|i| i as u8);
            }

            let mut portable = [0u8; 32];
            let mut accelerated = [0u8; 32];
            portable::hash256(&input256, &mut portable);
            aesni::hash256(&input256, &mut accelerated, aes, sse2);
            assert_eq!(accelerated, portable, "Haraka-256 at step {step}");
            input256 = portable;

            portable::hash512(&input512, &mut portable);
            aesni::hash512(&input512, &mut accelerated, aes, sse2);
            assert_eq!(accelerated, portable, "Haraka-512 at step {step}");
            let half = if step & 1 == 1 { 0 } else { 32 };
            input512[half..half + 32].copy_from_slice(&portable);
        }
    }
}
