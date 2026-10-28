//! The pass-through digest, ported from Bouncy Castle's `NullDigest`.

use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;

use tc_zeroize::Zeroize;

use crate::TryDigest;

/// The pass-through digest, Bouncy Castle's `NullDigest`: not a hash, it keeps
/// every input byte and `do_final` writes them back unchanged. Signers use it
/// where a digest is expected but the message is already the value to sign.
///
/// [`digest_size`](TryDigest::digest_size) is the number of bytes kept so far,
/// not a constant, and [`byte_length`](TryDigest::byte_length) is 0, as in
/// Bouncy Castle. `do_final` panics if the output buffer is shorter than the
/// bytes kept, before changing any state. The kept bytes are wiped when
/// written out, on reset and on drop.
///
/// Constant time with respect to the bytes; their number is public.
#[derive(Clone, Default)]
pub struct NullDigest {
    buffer: Vec<u8>,
}

impl NullDigest {
    /// An empty pass-through digest. Constant time.
    pub fn new() -> Self {
        Self::default()
    }
}

impl TryDigest for NullDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.buffer.len()
    }

    fn byte_length(&self) -> usize {
        0
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.buffer.extend_from_slice(input);
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.buffer.len();
        assert!(
            output.len() >= len,
            "output buffer shorter than the {len} bytes kept"
        );
        output[..len].copy_from_slice(&self.buffer);
        self.buffer.zeroize();
        Ok(len)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.buffer.zeroize();
        Ok(())
    }
}

impl Drop for NullDigest {
    /// Wipes the kept bytes. Constant time with respect to the bytes; their
    /// number is public.
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

impl fmt::Display for NullDigest {
    /// Writes `NULL`, Bouncy Castle's name, without inspecting the bytes.
    /// Constant time with respect to the bytes; output timing depends on the
    /// formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NULL")
    }
}
