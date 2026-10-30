//! Owned Skein parameters.

use alloc::vec::Vec;
use core::fmt;

use tc_zeroize::{Zeroize, ZeroizeOnDrop};

use crate::SkeinParams;

/// Owned Skein parameters, each input optional, all wiped on drop.
///
/// Available with the `alloc` feature. The setters take the vectors without
/// copying them. This is a plain container: `init` checks it. Wiping does not
/// erase copies held elsewhere. `Debug` prints the lengths, never the bytes.
///
/// # Example
///
/// ```
/// use tc_skein::{SkeinParams, SkeinParamsOwned};
///
/// let params = SkeinParamsOwned::new()
///     .with_key(vec![0x42; 32])
///     .with_personalisation(b"20261030 me@example.com app".to_vec());
/// assert_eq!(params.key().map(<[u8]>::len), Some(32));
/// ```
#[derive(Default)]
pub struct SkeinParamsOwned {
    key: Option<Vec<u8>>,
    personalisation: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    key_identifier: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

impl SkeinParamsOwned {
    /// Creates parameters with every input absent, which give the plain
    /// digest. Constant time.
    pub const fn new() -> Self {
        SkeinParamsOwned {
            key: None,
            personalisation: None,
            public_key: None,
            key_identifier: None,
            nonce: None,
        }
    }

    /// Sets the key, wiping any previous one. Constant time: moves the vector
    /// without inspecting its bytes.
    pub fn with_key(mut self, key: Vec<u8>) -> Self {
        self.key.zeroize();
        self.key = Some(key);
        self
    }

    /// Sets the personalisation string, wiping any previous one.
    /// Constant time: moves the vector without inspecting its bytes.
    pub fn with_personalisation(mut self, personalisation: Vec<u8>) -> Self {
        self.personalisation.zeroize();
        self.personalisation = Some(personalisation);
        self
    }

    /// Sets the public key, wiping any previous one. Constant time: moves
    /// the vector without inspecting its bytes.
    pub fn with_public_key(mut self, public_key: Vec<u8>) -> Self {
        self.public_key.zeroize();
        self.public_key = Some(public_key);
        self
    }

    /// Sets the key identifier, wiping any previous one. Constant time:
    /// moves the vector without inspecting its bytes.
    pub fn with_key_identifier(mut self, key_identifier: Vec<u8>) -> Self {
        self.key_identifier.zeroize();
        self.key_identifier = Some(key_identifier);
        self
    }

    /// Sets the nonce, wiping any previous one. Constant time: moves the
    /// vector without inspecting its bytes.
    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce.zeroize();
        self.nonce = Some(nonce);
        self
    }
}

impl SkeinParams for SkeinParamsOwned {
    /// Returns the stored key without copying it. Constant time.
    fn key(&self) -> Option<&[u8]> {
        self.key.as_deref()
    }

    /// Returns the stored personalisation string. Constant time.
    fn personalisation(&self) -> Option<&[u8]> {
        self.personalisation.as_deref()
    }

    /// Returns the stored public key. Constant time.
    fn public_key(&self) -> Option<&[u8]> {
        self.public_key.as_deref()
    }

    /// Returns the stored key identifier. Constant time.
    fn key_identifier(&self) -> Option<&[u8]> {
        self.key_identifier.as_deref()
    }

    /// Returns the stored nonce. Constant time.
    fn nonce(&self) -> Option<&[u8]> {
        self.nonce.as_deref()
    }
}

impl fmt::Debug for SkeinParamsOwned {
    /// Writes the input lengths, never their bytes. Constant time; output
    /// timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SkeinParamsOwned")
            .field("key_len", &self.key.as_ref().map(Vec::len))
            .field(
                "personalisation_len",
                &self.personalisation.as_ref().map(Vec::len),
            )
            .field("public_key_len", &self.public_key.as_ref().map(Vec::len))
            .field(
                "key_identifier_len",
                &self.key_identifier.as_ref().map(Vec::len),
            )
            .field("nonce_len", &self.nonce.as_ref().map(Vec::len))
            .finish()
    }
}

impl Zeroize for SkeinParamsOwned {
    /// Overwrites every input with zeros, leaving it absent. Constant time.
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.personalisation.zeroize();
        self.public_key.zeroize();
        self.key_identifier.zeroize();
        self.nonce.zeroize();
    }
}

impl Drop for SkeinParamsOwned {
    /// Wipes every input. Constant time.
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SkeinParamsOwned {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;
    use std::vec;

    use super::*;

    #[test]
    fn exposes_each_input_that_was_set() {
        let params = SkeinParamsOwned::new()
            .with_key(vec![1; 16])
            .with_nonce(vec![2; 3]);
        assert_eq!(params.key(), Some(&[1; 16][..]));
        assert_eq!(params.nonce(), Some(&[2; 3][..]));
        assert_eq!(params.personalisation(), None);
        assert_eq!(params.public_key(), None);
        assert_eq!(params.key_identifier(), None);
    }

    #[test]
    fn zeroize_clears_every_input() {
        let mut params = SkeinParamsOwned::new()
            .with_key(vec![0xff; 32])
            .with_personalisation(vec![0xff; 8])
            .with_public_key(vec![0xff; 8])
            .with_key_identifier(vec![0xff; 8])
            .with_nonce(vec![0xff; 8]);
        params.zeroize();
        assert_eq!(params.key(), None);
        assert_eq!(params.personalisation(), None);
        assert_eq!(params.public_key(), None);
        assert_eq!(params.key_identifier(), None);
        assert_eq!(params.nonce(), None);
    }

    #[test]
    fn debug_redacts_every_input() {
        let params = SkeinParamsOwned::new()
            .with_key(vec![0xa5; 32])
            .with_nonce(vec![0x5a; 16]);
        assert_eq!(
            format!("{params:?}"),
            "SkeinParamsOwned { key_len: Some(32), personalisation_len: None, \
             public_key_len: None, key_identifier_len: None, nonce_len: Some(16) }"
        );
    }
}
