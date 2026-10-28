//! Legacy Ascon v1.2 hash functions.
//!
//! These functions use the pre-standard Ascon v1.2 encoding and are retained
//! only for compatibility with existing hashes. New applications should use
//! [`crate::AsconHash256`], standardized in NIST SP 800-232.

#![allow(deprecated)]

use core::convert::Infallible;

use tc_digest::TryDigest;
use tc_zeroize::Zeroize;

use crate::ascon_core::{p8, p12};

const DIGEST_LENGTH: usize = 32;
const RATE: usize = 8;

const HASH_IV: [u64; 5] = [
    0xee93_98aa_db67_f03d,
    0x8bb2_1831_c60f_1002,
    0xb48a_92db_98d5_da62,
    0x4318_9921_b8f8_e3e8,
    0x348f_a5c9_d525_e140,
];

const HASH_A_IV: [u64; 5] = [
    0x0147_0194_fc65_28a6,
    0x738e_c38a_c0ad_ffa7,
    0x2ec8_e329_6c76_384c,
    0xd6f6_a54d_7f52_377d,
    0xa13c_42a2_23be_8d87,
];

/// Selects one of the obsolete Ascon v1.2 hash variants.
#[deprecated(
    since = "0.1.0",
    note = "legacy Ascon v1.2 compatibility only; use AsconHash256 for new applications"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AsconParameters {
    /// Ascon-Hash with 12-round intermediate permutations.
    AsconHash,
    /// Ascon-HashA with 8-round intermediate permutations.
    AsconHashA,
}

/// Legacy Ascon v1.2 Hash/HashA digest. Constant time.
///
/// This type is retained for compatibility with pre-standard hashes. It is not
/// interoperable with the standardized [`crate::AsconHash256`].
#[deprecated(
    since = "0.1.0",
    note = "legacy Ascon v1.2 compatibility only; use AsconHash256 for new applications"
)]
#[derive(Clone)]
pub struct AsconDigest {
    parameters: AsconParameters,
    state: [u64; 5],
    buffer: [u8; RATE],
    buffer_position: usize,
}

impl AsconDigest {
    /// Creates a legacy Ascon v1.2 Hash or HashA digest. Constant time.
    pub fn new(parameters: AsconParameters) -> Self {
        Self {
            parameters,
            state: initial_state(parameters),
            buffer: [0; RATE],
            buffer_position: 0,
        }
    }

    /// Ascon-p\[12\] for Ascon-Hash, Ascon-p\[8\] for Ascon-HashA. Constant time.
    #[inline]
    fn intermediate_permutation(&mut self) {
        match self.parameters {
            AsconParameters::AsconHash => p12(&mut self.state),
            AsconParameters::AsconHashA => p8(&mut self.state),
        }
    }

    /// XORs one block into the rate and permutes. Constant time.
    #[inline]
    fn absorb_block(&mut self, block: &[u8; RATE]) {
        self.state[0] ^= u64::from_be_bytes(*block);
        self.intermediate_permutation();
    }
}

impl TryDigest for AsconDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        RATE
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if self.buffer_position != 0 {
            let available = RATE - self.buffer_position;
            let copied = available.min(input.len());
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
            let block: &[u8; RATE] = input[..RATE].try_into().expect("8-byte legacy Ascon block");
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
        final_block[self.buffer_position] = 0x80;
        self.state[0] ^= u64::from_be_bytes(final_block);
        p12(&mut self.state);

        for (index, chunk) in output[..DIGEST_LENGTH].chunks_exact_mut(RATE).enumerate() {
            if index != 0 {
                self.intermediate_permutation();
            }
            chunk.copy_from_slice(&self.state[0].to_be_bytes());
        }

        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    // A fresh digest replaces this one, which the drop wipes.
    fn try_reset(&mut self) -> Result<(), Self::Error> {
        *self = Self::new(self.parameters);
        Ok(())
    }
}

/// The initial state of `parameters`. Constant time.
const fn initial_state(parameters: AsconParameters) -> [u64; 5] {
    match parameters {
        AsconParameters::AsconHash => HASH_IV,
        AsconParameters::AsconHashA => HASH_A_IV,
    }
}

impl Drop for AsconDigest {
    /// Wipes the state and the buffered bytes. Constant time.
    fn drop(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.buffer_position.zeroize();
    }
}

impl core::fmt::Display for AsconDigest {
    /// Writes `Ascon-Hash` or `Ascon-HashA` without inspecting the state.
    /// Constant time with respect to the message; output timing depends on the
    /// formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self.parameters {
            AsconParameters::AsconHash => "Ascon-Hash",
            AsconParameters::AsconHashA => "Ascon-HashA",
        })
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

    fn digest_hex(digest: &mut AsconDigest, input: &[u8]) -> String {
        digest.update(input);
        let mut output = [0u8; DIGEST_LENGTH];
        digest.do_final(&mut output);
        hex(&output)
    }

    #[test]
    fn accessors_clone_bytewise_and_reset() {
        for parameters in [AsconParameters::AsconHash, AsconParameters::AsconHashA] {
            let message: Vec<u8> = (0..129).map(|i| i as u8).collect();
            let expected = digest_hex(&mut AsconDigest::new(parameters), &message);
            let mut digest = AsconDigest::new(parameters);

            assert_eq!(digest.digest_size(), 32);
            assert_eq!(digest.byte_length(), 8);
            assert_eq!(
                digest.to_string(),
                match parameters {
                    AsconParameters::AsconHash => "Ascon-Hash",
                    AsconParameters::AsconHashA => "Ascon-HashA",
                }
            );

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
            assert_eq!(digest_hex(&mut digest, &message), expected);
        }
    }
}
