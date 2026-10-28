//! ISAP Hash, ported from Bouncy Castle's `IsapDigest`.
//!
//! ISAP Hash is the fixed-output hashing component of the ISAP lightweight
//! authenticated-encryption family. It absorbs at an 8-byte rate into a
//! 320-bit state and applies the 12-round Ascon permutation between blocks;
//! its outputs equal those of the Ascon v1.2 hash.

use core::convert::Infallible;

use tc_digest::TryDigest;
use tc_zeroize::Zeroize;

use crate::ascon_core::p12;

const DIGEST_LENGTH: usize = 32;
const BYTE_LENGTH: usize = 8;
const IV: [u64; 5] = [
    0xee93_98aa_db67_f03d,
    0x8bb2_1831_c60f_1002,
    0xb48a_92db_98d5_da62,
    0x4318_9921_b8f8_e3e8,
    0x348f_a5c9_d525_e140,
];

/// The 256-bit ISAP Hash digest. Constant time.
#[derive(Clone)]
pub struct IsapDigest {
    state: [u64; 5],
    buffer: [u8; BYTE_LENGTH],
    buffer_position: usize,
}

impl Default for IsapDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl IsapDigest {
    /// Creates a new ISAP Hash digest. Constant time.
    pub fn new() -> Self {
        IsapDigest {
            state: IV,
            buffer: [0; BYTE_LENGTH],
            buffer_position: 0,
        }
    }

    /// XORs one block into the rate and permutes. Constant time.
    #[inline]
    fn absorb_block(&mut self, block: &[u8; BYTE_LENGTH]) {
        self.state[0] ^= u64::from_be_bytes(*block);
        p12(&mut self.state);
    }
}

impl TryDigest for IsapDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if input.is_empty() {
            return Ok(());
        }

        if self.buffer_position != 0 {
            let remaining = BYTE_LENGTH - self.buffer_position;
            let copied = remaining.min(input.len());
            self.buffer[self.buffer_position..self.buffer_position + copied]
                .copy_from_slice(&input[..copied]);
            self.buffer_position += copied;
            input = &input[copied..];

            if self.buffer_position == BYTE_LENGTH {
                let block = self.buffer;
                self.absorb_block(&block);
                self.buffer_position = 0;
            } else {
                return Ok(());
            }
        }

        while input.len() >= BYTE_LENGTH {
            let block: &[u8; BYTE_LENGTH] = input[..BYTE_LENGTH]
                .try_into()
                .expect("8-byte ISAP Hash block");
            self.absorb_block(block);
            input = &input[BYTE_LENGTH..];
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
        let mut final_block = [0u8; BYTE_LENGTH];
        final_block[..self.buffer_position].copy_from_slice(&self.buffer[..self.buffer_position]);
        final_block[self.buffer_position] = 0x80;
        self.state[0] ^= u64::from_be_bytes(final_block);

        for chunk in output[..DIGEST_LENGTH].chunks_exact_mut(BYTE_LENGTH) {
            p12(&mut self.state);
            chunk.copy_from_slice(&self.state[0].to_be_bytes());
        }

        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    // A fresh digest replaces this one, which the drop wipes.
    fn try_reset(&mut self) -> Result<(), Self::Error> {
        *self = Self::new();
        Ok(())
    }
}

impl Drop for IsapDigest {
    /// Wipes the state and the buffered bytes. Constant time.
    fn drop(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.buffer_position.zeroize();
    }
}

impl core::fmt::Display for IsapDigest {
    /// Writes `ISAP Hash` without inspecting the state. Constant time with
    /// respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ISAP Hash")
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use alloc::{format, string::String, vec::Vec};

    use super::*;
    use tc_digest::Digest;

    fn hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push_str(&format!("{byte:02x}"));
        }
        encoded
    }

    fn digest_hex(digest: &mut IsapDigest, input: &[u8]) -> String {
        digest.update(input);
        let mut output = [0u8; DIGEST_LENGTH];
        digest.do_final(&mut output);
        hex(&output)
    }

    #[test]
    fn accessors_clone_bytewise_and_reset() {
        let message: Vec<u8> = (0..129).map(|i| i as u8).collect();
        let expected = digest_hex(&mut IsapDigest::new(), &message);

        let mut digest = IsapDigest::new();
        assert_eq!(digest.to_string(), "ISAP Hash");
        assert_eq!(digest.digest_size(), 32);
        assert_eq!(digest.byte_length(), 8);

        digest.update(&message[..37]);
        let mut cloned = digest.clone();
        digest.update(&message[37..]);
        cloned.update(&message[37..]);
        assert_eq!(digest_hex(&mut digest, b""), expected);
        assert_eq!(digest_hex(&mut cloned, b""), expected);

        for byte in &message {
            digest.update_byte(*byte);
        }
        assert_eq!(digest_hex(&mut digest, b""), expected);

        digest.update(b"discarded state");
        digest.reset();
        digest.update(&message);
        assert_eq!(digest_hex(&mut digest, b""), expected);
    }
}
