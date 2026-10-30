//! The Skein parameter contract.

/// Supplies the optional inputs of a Skein hash (Bouncy Castle
/// `SkeinParameters`): a key, which makes Skein a MAC, and the
/// personalisation, public key, key identifier and nonce of the Skein 1.3
/// specification.
///
/// [`SkeinEngine::init`](crate::SkeinEngine::init) and
/// [`SkeinDigest::init`](crate::SkeinDigest::init) check the values and hash
/// each present one in its own UBI block, in the order of the specification:
/// key, configuration, personalisation, public key, key identifier, nonce.
/// Every method returns `None` by default, so an implementation supplies only
/// what it has; with every input absent, Skein is the plain digest.
/// [`SkeinParamsRef`](crate::SkeinParamsRef) borrows its inputs, and
/// `SkeinParamsOwned`, with the `alloc` feature, owns them and wipes them on
/// drop.
pub trait SkeinParams {
    /// Returns the key, which `init` requires to be at least 16 bytes.
    /// Constant time by default; the timing of an override is
    /// implementation-defined.
    fn key(&self) -> Option<&[u8]> {
        None
    }

    /// Returns the personalisation string. Constant time by default; the
    /// timing of an override is implementation-defined.
    fn personalisation(&self) -> Option<&[u8]> {
        None
    }

    /// Returns the public key. Constant time by default; the timing of an
    /// override is implementation-defined.
    fn public_key(&self) -> Option<&[u8]> {
        None
    }

    /// Returns the key identifier. Constant time by default; the timing of an
    /// override is implementation-defined.
    fn key_identifier(&self) -> Option<&[u8]> {
        None
    }

    /// Returns the nonce. Constant time by default; the timing of an override
    /// is implementation-defined.
    fn nonce(&self) -> Option<&[u8]> {
        None
    }
}
