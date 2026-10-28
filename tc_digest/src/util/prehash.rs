//! The fixed-length pass-through for a digest value already computed, ported
//! from Bouncy Castle's `Prehash`.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use tc_zeroize::Zeroize;

use crate::TryDigest;

/// A failure of [`Prehash`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrehashError {
    /// An update would go past the digest size; nothing was taken.
    InputTooLong {
        /// The digest size.
        limit: usize,
        /// The number of bytes the update would have reached.
        attempted: usize,
    },
    /// Finalization came before exactly the digest size was supplied; the
    /// prehash was reset.
    IncorrectLength {
        /// The digest size.
        expected: usize,
        /// The number of bytes supplied.
        actual: usize,
    },
}

impl fmt::Display for PrehashError {
    /// Constant time: the fields are public lengths.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrehashError::InputTooLong { limit, attempted } => write!(
                f,
                "prehash input too long: limit is {limit} bytes, attempted {attempted} bytes"
            ),
            PrehashError::IncorrectLength { expected, actual } => write!(
                f,
                "incorrect prehash length: expected {expected} bytes, got {actual} bytes"
            ),
        }
    }
}

impl core::error::Error for PrehashError {}

/// The fixed-length pass-through for a digest value already computed, Bouncy
/// Castle's `Prehash`: it takes exactly `digest_size` bytes, the digest of a
/// message hashed elsewhere, and `try_do_final` writes them back unchanged.
/// PSS signers use it to sign a hash computed by the caller.
///
/// Unlike [`NullDigest`](super::NullDigest), a wrong length is an error rather
/// than a panic, so it implements only [`TryDigest`], with [`PrehashError`].
/// `try_do_final` still panics if the output buffer is shorter than the digest
/// size, before changing any state. The bytes are wiped when written out, on
/// reset and on drop.
///
/// Constant time with respect to the bytes; their number is public.
#[derive(Clone)]
pub struct Prehash {
    name: String,
    buffer: Vec<u8>,
    position: usize,
}

impl Prehash {
    /// A prehash of `digest_size` bytes that writes `name` through `Display`.
    /// Constant time.
    pub fn new(name: impl Into<String>, digest_size: usize) -> Self {
        Self {
            name: name.into(),
            buffer: vec![0; digest_size],
            position: 0,
        }
    }

    /// A prehash with the name and digest size of `digest`, Bouncy Castle's
    /// `Prehash.ForDigest`. Constant time.
    pub fn for_digest<D: TryDigest + fmt::Display + ?Sized>(digest: &D) -> Self {
        Self::new(digest.to_string(), digest.digest_size())
    }

    /// The number of bytes supplied so far. Constant time.
    pub fn len(&self) -> usize {
        self.position
    }

    /// Whether no byte has been supplied yet. Constant time.
    pub fn is_empty(&self) -> bool {
        self.position == 0
    }
}

impl TryDigest for Prehash {
    type Error = PrehashError;

    fn digest_size(&self) -> usize {
        self.buffer.len()
    }

    /// The digest size. Bouncy Castle's `Prehash` has no block length and
    /// throws here; this returns the one length the prehash has. Constant time.
    fn byte_length(&self) -> usize {
        self.buffer.len()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if input.len() > self.buffer.len() - self.position {
            return Err(PrehashError::InputTooLong {
                limit: self.buffer.len(),
                attempted: self.position.saturating_add(input.len()),
            });
        }
        let end = self.position + input.len();
        self.buffer[self.position..end].copy_from_slice(input);
        self.position = end;
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let expected = self.buffer.len();
        assert!(
            output.len() >= expected,
            "output buffer shorter than the {expected}-byte digest"
        );
        let actual = self.position;
        if actual != expected {
            self.try_reset()?;
            return Err(PrehashError::IncorrectLength { expected, actual });
        }
        output[..expected].copy_from_slice(&self.buffer);
        self.try_reset()?;
        Ok(expected)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.buffer[..self.position].zeroize();
        self.position = 0;
        Ok(())
    }
}

impl Drop for Prehash {
    /// Wipes the supplied bytes. Constant time with respect to the bytes;
    /// their number is public.
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

impl fmt::Debug for Prehash {
    /// Shows the name, the digest size and the bytes supplied so far, not the
    /// bytes themselves. Constant time with respect to the bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prehash")
            .field("name", &self.name)
            .field("digest_size", &self.buffer.len())
            .field("position", &self.position)
            .finish()
    }
}

impl fmt::Display for Prehash {
    /// Writes the name given at construction, without inspecting the bytes.
    /// Constant time with respect to the bytes; output timing depends on the
    /// formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}
