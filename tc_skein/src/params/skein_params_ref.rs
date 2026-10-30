//! Borrowed Skein parameters.

use crate::SkeinParams;

/// Borrowed Skein parameters, each input optional.
///
/// This is a plain container: `init` checks it. It implements no `Debug`, so
/// the key cannot leak through a log. Callers with their own parameter type
/// can implement [`SkeinParams`] directly.
///
/// # Example
///
/// ```
/// use tc_skein::{SkeinParams, SkeinParamsRef};
///
/// let params = SkeinParamsRef::new()
///     .with_key(&[0x42; 32])
///     .with_nonce(b"nonce");
/// assert_eq!(params.nonce(), Some(&b"nonce"[..]));
/// assert_eq!(params.personalisation(), None);
/// ```
#[derive(Clone, Copy, Default)]
pub struct SkeinParamsRef<'a> {
    key: Option<&'a [u8]>,
    personalisation: Option<&'a [u8]>,
    public_key: Option<&'a [u8]>,
    key_identifier: Option<&'a [u8]>,
    nonce: Option<&'a [u8]>,
}

impl<'a> SkeinParamsRef<'a> {
    /// Creates parameters with every input absent, which give the plain
    /// digest. Constant time.
    pub const fn new() -> Self {
        SkeinParamsRef {
            key: None,
            personalisation: None,
            public_key: None,
            key_identifier: None,
            nonce: None,
        }
    }

    /// Sets the key. Constant time.
    pub const fn with_key(mut self, key: &'a [u8]) -> Self {
        self.key = Some(key);
        self
    }

    /// Sets the personalisation string. Constant time.
    pub const fn with_personalisation(mut self, personalisation: &'a [u8]) -> Self {
        self.personalisation = Some(personalisation);
        self
    }

    /// Sets the public key. Constant time.
    pub const fn with_public_key(mut self, public_key: &'a [u8]) -> Self {
        self.public_key = Some(public_key);
        self
    }

    /// Sets the key identifier. Constant time.
    pub const fn with_key_identifier(mut self, key_identifier: &'a [u8]) -> Self {
        self.key_identifier = Some(key_identifier);
        self
    }

    /// Sets the nonce. Constant time.
    pub const fn with_nonce(mut self, nonce: &'a [u8]) -> Self {
        self.nonce = Some(nonce);
        self
    }
}

impl SkeinParams for SkeinParamsRef<'_> {
    /// Borrows the key without inspecting it. Constant time.
    fn key(&self) -> Option<&[u8]> {
        self.key
    }

    /// Borrows the personalisation string. Constant time.
    fn personalisation(&self) -> Option<&[u8]> {
        self.personalisation
    }

    /// Borrows the public key. Constant time.
    fn public_key(&self) -> Option<&[u8]> {
        self.public_key
    }

    /// Borrows the key identifier. Constant time.
    fn key_identifier(&self) -> Option<&[u8]> {
        self.key_identifier
    }

    /// Borrows the nonce. Constant time.
    fn nonce(&self) -> Option<&[u8]> {
        self.nonce
    }
}
