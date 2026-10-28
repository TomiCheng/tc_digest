//! Ascon-XOF128 from NIST SP 800-232, ported from Bouncy Castle's `AsconXof128`.
//!
//! The non-customizable sibling of [`AsconCXof128`](crate::AsconCXof128): the
//! same Ascon-p\[12\] sponge XOF with an 8-byte rate, but a fixed initial state
//! and no customization string.

use core::convert::Infallible;

use tc_digest::{TryDigest, TryXof};
use tc_zeroize::Zeroize;

use crate::ascon_core::p12;

const DIGEST_LENGTH: usize = 32;
const RATE: usize = 8;

// Bouncy Castle's precomputed initial state, p12 of the seed 0x0000080000cc0003.
const IV: [u64; 5] = [
    0xda82_ce76_8d94_47eb,
    0xcc7c_e6c7_5f1e_f969,
    0xe750_8fd7_8008_5631,
    0x0ee0_ea53_416b_58cc,
    0xe054_7524_db6f_0bde,
];

/// The Ascon extendable-output function (Ascon-XOF128) from NIST SP 800-232.
/// Read as a plain digest it writes 32 bytes. Constant time.
#[derive(Clone)]
pub struct AsconXof128 {
    state: [u64; 5],
    /// The input buffer while absorbing; the current output block while squeezing.
    buffer: [u8; RATE],
    /// Bytes buffered while absorbing; bytes of the output block already read
    /// while squeezing, where `RATE` means the next read permutes first.
    buffer_position: usize,
    squeezing: bool,
}

impl Default for AsconXof128 {
    fn default() -> Self {
        Self::new()
    }
}

impl AsconXof128 {
    /// Creates a new Ascon-XOF128. Constant time.
    pub fn new() -> Self {
        AsconXof128 {
            state: IV,
            buffer: [0; RATE],
            buffer_position: 0,
            squeezing: false,
        }
    }

    /// XORs one block into the rate and permutes. Constant time.
    #[inline]
    fn absorb_block(&mut self, block: &[u8; RATE]) {
        self.state[0] ^= u64::from_le_bytes(*block);
        p12(&mut self.state);
    }

    /// XORs the buffered bytes and the `0x01` padding into the rate, without
    /// permuting. Constant time.
    fn pad(&mut self) {
        let mut last = [0u8; RATE];
        last[..self.buffer_position].copy_from_slice(&self.buffer[..self.buffer_position]);
        last[self.buffer_position] = 0x01;
        self.state[0] ^= u64::from_le_bytes(last);
    }
}

impl TryDigest for AsconXof128 {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        RATE
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        assert!(
            !self.squeezing,
            "Ascon-XOF128: attempt to absorb while squeezing"
        );
        if input.is_empty() {
            return Ok(());
        }

        if self.buffer_position != 0 {
            let remaining = RATE - self.buffer_position;
            let copied = remaining.min(input.len());
            self.buffer[self.buffer_position..self.buffer_position + copied]
                .copy_from_slice(&input[..copied]);
            self.buffer_position += copied;
            input = &input[copied..];

            if self.buffer_position == RATE {
                let block = self.buffer;
                self.absorb_block(&block);
                self.buffer_position = 0;
            } else {
                return Ok(());
            }
        }

        while input.len() >= RATE {
            let block: &[u8; RATE] = input[..RATE].try_into().expect("8-byte Ascon block");
            self.absorb_block(block);
            input = &input[RATE..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_position = input.len();
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        assert!(
            output.len() >= DIGEST_LENGTH,
            "output buffer shorter than the {DIGEST_LENGTH}-byte digest"
        );
        self.try_output_final(&mut output[..DIGEST_LENGTH])
    }

    // A fresh digest replaces this one, which the drop wipes.
    fn try_reset(&mut self) -> Result<(), Self::Error> {
        *self = Self::new();
        Ok(())
    }
}

impl TryXof for AsconXof128 {
    fn try_output(&mut self, mut output: &mut [u8]) -> Result<usize, Self::Error> {
        let total = output.len();

        if !self.squeezing {
            self.pad();
            self.squeezing = true;
            self.buffer_position = RATE;
        } else if self.buffer_position < RATE {
            let available = RATE - self.buffer_position;
            if output.len() <= available {
                let end = self.buffer_position + output.len();
                output.copy_from_slice(&self.buffer[self.buffer_position..end]);
                self.buffer_position = end;
                return Ok(total);
            }
            output[..available].copy_from_slice(&self.buffer[self.buffer_position..RATE]);
            output = &mut output[available..];
            self.buffer_position = RATE;
        }

        while output.len() >= RATE {
            p12(&mut self.state);
            output[..RATE].copy_from_slice(&self.state[0].to_le_bytes());
            output = &mut output[RATE..];
        }

        if !output.is_empty() {
            p12(&mut self.state);
            self.buffer = self.state[0].to_le_bytes();
            let n = output.len();
            output.copy_from_slice(&self.buffer[..n]);
            self.buffer_position = n;
        }

        Ok(total)
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let written = self.try_output(output)?;
        self.try_reset()?;
        Ok(written)
    }
}

impl Drop for AsconXof128 {
    /// Wipes the state and the buffered bytes. Constant time.
    fn drop(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.buffer_position.zeroize();
    }
}

impl core::fmt::Display for AsconXof128 {
    /// Writes `Ascon-XOF128` without inspecting the state. Constant time with
    /// respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ascon-XOF128")
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use tc_digest::{Digest, Xof};

    #[test]
    fn accessors() {
        let d = AsconXof128::new();
        assert_eq!(d.to_string(), "Ascon-XOF128");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 8);
    }

    // The initial state is p12 of the seed, as Bouncy Castle's comment records.
    #[test]
    fn iv_matches_seed_derivation() {
        let mut s = [0x0000_0800_00cc_0003u64, 0, 0, 0, 0];
        p12(&mut s);
        assert_eq!(s, IV);
    }

    #[test]
    fn output_final_resets() {
        let mut a = AsconXof128::new();
        a.update(b"first");
        let mut o1 = [0u8; 32];
        a.output_final(&mut o1);
        a.update(b"first");
        let mut o2 = [0u8; 32];
        a.output_final(&mut o2);
        assert_eq!(o1, o2);
    }

    #[test]
    fn streamed_output_matches_single() {
        let mut a = AsconXof128::new();
        a.update(b"the quick brown fox");
        let mut whole = [0u8; 100];
        a.output(&mut whole);

        let mut b = AsconXof128::new();
        b.update(b"the quick brown fox");
        let mut streamed = [0u8; 100];
        let (mut off, sizes) = (0usize, [1usize, 7, 8, 9, 3, 40, 32]);
        for s in sizes {
            b.output(&mut streamed[off..off + s]);
            off += s;
        }
        assert_eq!(whole, streamed);
    }
}
