//! Ascon-CXOF128 from NIST SP 800-232, ported from Bouncy Castle's `AsconCXof128`.
//!
//! A customizable extendable-output function (XOF) over the Ascon-p\[12\]
//! permutation with an 8-byte rate: the customization string is absorbed at
//! construction, and every reset returns to that state.

use core::convert::Infallible;

use tc_digest::{TryDigest, TryXof};
use tc_zeroize::Zeroize;

use crate::ascon_core::p12;

const DIGEST_LENGTH: usize = 32;
const RATE: usize = 8;
const MAX_CUSTOMIZATION: usize = 256;

// Bouncy Castle's precomputed state for an empty customization string.
const IV_EMPTY: [u64; 5] = [
    0x500c_ccc8_94e3_c9e8,
    0x5bed_06f2_8f71_248d,
    0x3b03_a0f9_30af_d512,
    0x112e_f093_aa5c_698b,
    0x00c8_3563_40a3_47f0,
];

// The initial state before a non-empty customization string is absorbed.
const IV_CUSTOM: [u64; 5] = [
    0x6755_27c2_a0e8_de03,
    0x43d1_2d7d_c037_7bbc,
    0xe990_1dec_426e_81b5,
    0x2ab1_4907_7207_80b6,
    0x8f3f_1d02_d432_bc46,
];

/// The customizable Ascon extendable-output function (Ascon-CXOF128) from
/// NIST SP 800-232. Read as a plain digest it writes 32 bytes. Constant time.
#[derive(Clone)]
pub struct AsconCXof128 {
    state: [u64; 5],
    /// The state after the customization string, restored on reset.
    initial: [u64; 5],
    /// The input buffer while absorbing; the current output block while squeezing.
    buffer: [u8; RATE],
    /// Bytes buffered while absorbing; bytes of the output block already read
    /// while squeezing, where `RATE` means the next read permutes first.
    buffer_position: usize,
    squeezing: bool,
}

impl Default for AsconCXof128 {
    fn default() -> Self {
        Self::new()
    }
}

impl AsconCXof128 {
    /// Creates an Ascon-CXOF128 with an empty customization string. Constant time.
    pub fn new() -> Self {
        Self::from_initial(IV_EMPTY)
    }

    /// Creates an Ascon-CXOF128 with the customization string `z`.
    /// Constant time with respect to the contents of `z`; its length is public.
    ///
    /// # Panics
    ///
    /// Panics if `z` is longer than 256 bytes, as Bouncy Castle throws.
    pub fn with_customization(z: &[u8]) -> Self {
        assert!(
            z.len() <= MAX_CUSTOMIZATION,
            "Ascon-CXOF128: customization string too long (max 256 bytes)"
        );

        let state = if z.is_empty() {
            IV_EMPTY
        } else {
            let mut state = IV_CUSTOM;
            state[0] ^= (z.len() as u64) << 3;
            p12(&mut state);

            let chunks = z.chunks_exact(RATE);
            let rem = chunks.remainder();
            for block in chunks {
                state[0] ^= u64::from_le_bytes(block.try_into().unwrap());
                p12(&mut state);
            }
            let mut last = [0u8; RATE];
            last[..rem.len()].copy_from_slice(rem);
            last[rem.len()] = 0x01;
            state[0] ^= u64::from_le_bytes(last);
            p12(&mut state);

            state
        };

        Self::from_initial(state)
    }

    /// A fresh XOF starting from `initial`. Constant time.
    fn from_initial(initial: [u64; 5]) -> Self {
        AsconCXof128 {
            state: initial,
            initial,
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

impl TryDigest for AsconCXof128 {
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
            "Ascon-CXOF128: attempt to absorb while squeezing"
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

    // A fresh XOF replaces this one, which the drop wipes.
    fn try_reset(&mut self) -> Result<(), Self::Error> {
        *self = Self::from_initial(self.initial);
        Ok(())
    }
}

impl TryXof for AsconCXof128 {
    fn try_output(&mut self, mut output: &mut [u8]) -> Result<usize, Self::Error> {
        let total = output.len();

        if !self.squeezing {
            // Finish absorbing; `RATE` marks that no output block is buffered yet.
            self.pad();
            self.squeezing = true;
            self.buffer_position = RATE;
        } else if self.buffer_position < RATE {
            // Hand out what is left of the previous output block first.
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

        // Whole blocks: permute and write the rate straight out.
        while output.len() >= RATE {
            p12(&mut self.state);
            output[..RATE].copy_from_slice(&self.state[0].to_le_bytes());
            output = &mut output[RATE..];
        }

        // A partial block: permute once, buffer the block and record how much was read.
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

impl Drop for AsconCXof128 {
    /// Wipes the state, the customized initial state and the buffered bytes.
    /// Constant time.
    fn drop(&mut self) {
        self.state.zeroize();
        self.initial.zeroize();
        self.buffer.zeroize();
        self.buffer_position.zeroize();
    }
}

impl core::fmt::Display for AsconCXof128 {
    /// Writes `Ascon-CXOF128` without inspecting the state. Constant time with
    /// respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ascon-CXOF128")
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use alloc::{vec, vec::Vec};

    use super::*;
    use tc_digest::{Digest, Xof};

    // Reading in pieces that do not line up with the rate gives the same bytes.
    #[test]
    fn streamed_output_matches_single() {
        let mut a = AsconCXof128::new();
        a.update(b"the quick brown fox");
        let mut whole = [0u8; 100];
        a.output(&mut whole);

        let mut b = AsconCXof128::new();
        b.update(b"the quick brown fox");
        let mut streamed = [0u8; 100];
        let (mut off, sizes) = (0usize, [1usize, 7, 8, 9, 3, 40, 32]);
        for s in sizes {
            b.output(&mut streamed[off..off + s]);
            off += s;
        }
        assert_eq!(whole, streamed);
    }

    // output_final resets, so the XOF takes a new message straight away.
    #[test]
    fn output_final_resets() {
        let mut a = AsconCXof128::new();
        a.update(b"first");
        let mut o1 = [0u8; 32];
        a.output_final(&mut o1);
        a.update(b"first");
        let mut o2 = [0u8; 32];
        a.output_final(&mut o2);
        assert_eq!(o1, o2);
    }

    #[test]
    fn do_final_is_32_byte_output_final() {
        let mut a = AsconCXof128::new();
        a.update(b"abc");
        let mut viafinal = [0u8; 32];
        a.do_final(&mut viafinal);

        let mut b = AsconCXof128::new();
        b.update(b"abc");
        let mut viaxof = [0u8; 32];
        b.output_final(&mut viaxof);
        assert_eq!(viafinal, viaxof);
    }

    #[test]
    fn customization_changes_output() {
        let mut a = AsconCXof128::new();
        a.update(b"msg");
        let mut oa = [0u8; 32];
        a.output_final(&mut oa);

        let mut b = AsconCXof128::with_customization(b"ctx");
        b.update(b"msg");
        let mut ob = [0u8; 32];
        b.output_final(&mut ob);
        assert_ne!(oa, ob);
    }

    #[test]
    fn accessors() {
        let d = AsconCXof128::new();
        assert_eq!(d.to_string(), "Ascon-CXOF128");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 8);
    }

    // The empty customization string run through the general path, that is
    // IV_CUSTOM, p12, the 0x01 padding and p12 again, must give IV_EMPTY: the
    // two constants agree with each other and with NIST SP 800-232.
    #[test]
    fn init_constants_match_ascon_derivation() {
        let mut s = IV_CUSTOM;
        p12(&mut s);
        s[0] ^= 0x01;
        p12(&mut s);
        assert_eq!(s, IV_EMPTY);
    }

    #[test]
    fn chunked_absorb_matches_whole() {
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut a = AsconCXof128::new();
        a.update(&msg);
        let mut oa = vec![0u8; 48];
        a.output_final(&mut oa);

        let mut b = AsconCXof128::new();
        for c in msg.chunks(5) {
            b.update(c);
        }
        let mut ob = vec![0u8; 48];
        b.output_final(&mut ob);
        assert_eq!(oa, ob);
    }

    // A reset returns to the customized state, not to the empty one.
    #[test]
    fn reset_keeps_the_customization() {
        let mut fresh = AsconCXof128::with_customization(b"ctx");
        fresh.update(b"msg");
        let mut want = [0u8; 32];
        fresh.output_final(&mut want);

        let mut reused = AsconCXof128::with_customization(b"ctx");
        reused.update(b"discarded");
        reused.reset();
        reused.update(b"msg");
        let mut got = [0u8; 32];
        reused.output_final(&mut got);
        assert_eq!(got, want);
    }
}
