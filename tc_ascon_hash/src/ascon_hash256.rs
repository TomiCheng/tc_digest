//! Ascon-Hash256 from NIST SP 800-232.
//!
//! This is the standardized Ascon hash, not the older Ascon v1.2 hash. The
//! NIST version uses little-endian word encoding, an 8-byte rate, the
//! Ascon-p\[12\] permutation, and a fixed 256-bit output.

use core::convert::Infallible;

use tc_digest::TryDigest;
use tc_zeroize::Zeroize;

use crate::ascon_core::p12;

const DIGEST_LENGTH: usize = 32;
const RATE: usize = 8;
const IV: [u64; 5] = [
    0x9b1e_5494_e934_d681,
    0x4bc3_a01e_3337_51d2,
    0xae65_396c_6b34_b81a,
    0x3c7f_d4a4_d56a_4db3,
    0x1a5c_4649_06c5_976d,
];

/// The standardized 256-bit Ascon hash from NIST SP 800-232. Constant time.
#[derive(Clone)]
pub struct AsconHash256 {
    state: [u64; 5],
    buffer: [u8; RATE],
    buffer_position: usize,
}

impl Default for AsconHash256 {
    fn default() -> Self {
        Self::new()
    }
}

impl AsconHash256 {
    /// Creates a new Ascon-Hash256 digest. Constant time.
    pub fn new() -> Self {
        AsconHash256 {
            state: IV,
            buffer: [0; RATE],
            buffer_position: 0,
        }
    }

    /// XORs one block into the rate and permutes. Constant time.
    #[inline]
    fn absorb_block(&mut self, block: &[u8; RATE]) {
        self.state[0] ^= u64::from_le_bytes(*block);
        p12(&mut self.state);
    }
}

impl TryDigest for AsconHash256 {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        RATE
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
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
            let block: &[u8; RATE] = input[..RATE]
                .try_into()
                .expect("8-byte Ascon-Hash256 block");
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
        let mut final_block = [0u8; RATE];
        final_block[..self.buffer_position].copy_from_slice(&self.buffer[..self.buffer_position]);
        final_block[self.buffer_position] = 0x01;
        self.state[0] ^= u64::from_le_bytes(final_block);
        p12(&mut self.state);

        for (index, chunk) in output[..DIGEST_LENGTH].chunks_exact_mut(RATE).enumerate() {
            if index != 0 {
                p12(&mut self.state);
            }
            chunk.copy_from_slice(&self.state[0].to_le_bytes());
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

impl Drop for AsconHash256 {
    /// Wipes the state and the buffered bytes. Constant time.
    fn drop(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.buffer_position.zeroize();
    }
}

impl core::fmt::Display for AsconHash256 {
    /// Writes `Ascon-Hash256` without inspecting the state. Constant time with
    /// respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ascon-Hash256")
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

    fn digest_hex(digest: &mut AsconHash256, input: &[u8]) -> String {
        digest.update(input);
        let mut output = [0u8; DIGEST_LENGTH];
        digest.do_final(&mut output);
        hex(&output)
    }

    #[test]
    fn accessors_clone_bytewise_and_reset() {
        let message: Vec<u8> = (0..129).map(|i| i as u8).collect();
        let expected = digest_hex(&mut AsconHash256::new(), &message);

        let mut digest = AsconHash256::new();
        assert_eq!(digest.to_string(), "Ascon-Hash256");
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
