//! Message-digest contracts.

use core::convert::Infallible;

/// A streaming message digest whose operations may fail.
///
/// Input is absorbed in any number of [`try_update`](TryDigest::try_update)
/// calls; [`try_do_final`](TryDigest::try_do_final) writes the digest of
/// everything absorbed since the last reset and resets the digest for the
/// next message.
///
/// The trait makes no constant-time promise. Whether a digest's running time
/// depends on the message contents is documented by each implementation.
pub trait TryDigest {
    /// The failure type returned by digest operations.
    type Error: core::error::Error;

    /// Returns the algorithm's display name, such as `"SHA-256"`.
    fn algorithm_name(&self) -> &str;

    /// Returns the digest length in bytes, which is the number of bytes
    /// [`try_do_final`](TryDigest::try_do_final) writes.
    fn digest_size(&self) -> usize;

    /// Returns the digest's internal block length in bytes, the block size to
    /// which HMAC pads its key.
    fn byte_length(&self) -> usize;

    /// Adds bytes to the message being digested.
    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Adds one byte to the message being digested.
    fn try_update_byte(&mut self, input: u8) -> Result<(), Self::Error> {
        self.try_update(&[input])
    }

    /// Finalizes the digest into `output` and returns the bytes written.
    ///
    /// `output` must hold at least [`digest_size`](TryDigest::digest_size)
    /// bytes; the implementation decides whether a shorter buffer panics or
    /// returns an error. A successful call resets the digest for reuse.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Resets the digest to its initial state.
    fn try_reset(&mut self) -> Result<(), Self::Error>;
}

/// An infallible streaming message digest.
///
/// Implement [`TryDigest`] with [`Infallible`] as its error type to receive
/// this convenience API automatically.
pub trait Digest: TryDigest<Error = Infallible> {
    /// Adds bytes to the message being digested.
    fn update(&mut self, input: &[u8]);

    /// Adds one byte to the message being digested.
    fn update_byte(&mut self, input: u8);

    /// Finalizes the digest into `output` and returns the bytes written.
    ///
    /// `output` must hold at least [`digest_size`](TryDigest::digest_size)
    /// bytes. The call resets the digest for reuse.
    fn do_final(&mut self, output: &mut [u8]) -> usize;

    /// Resets the digest to its initial state.
    fn reset(&mut self);
}

impl<D> Digest for D
where
    D: TryDigest<Error = Infallible> + ?Sized,
{
    fn update(&mut self, input: &[u8]) {
        match self.try_update(input) {
            Ok(()) => (),
        }
    }

    fn update_byte(&mut self, input: u8) {
        match self.try_update_byte(input) {
            Ok(()) => (),
        }
    }

    fn do_final(&mut self, output: &mut [u8]) -> usize {
        match self.try_do_final(output) {
            Ok(written) => written,
        }
    }

    fn reset(&mut self) {
        match self.try_reset() {
            Ok(()) => (),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use super::{Digest, TryDigest};

    #[derive(Default)]
    struct SumDigest {
        sum: u8,
    }

    impl TryDigest for SumDigest {
        type Error = Infallible;

        fn algorithm_name(&self) -> &str {
            "SUM-8"
        }

        fn digest_size(&self) -> usize {
            1
        }

        fn byte_length(&self) -> usize {
            1
        }

        fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
            for byte in input {
                self.sum = self.sum.wrapping_add(*byte);
            }
            Ok(())
        }

        fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            output[0] = self.sum;
            self.sum = 0;
            Ok(1)
        }

        fn try_reset(&mut self) -> Result<(), Self::Error> {
            self.sum = 0;
            Ok(())
        }
    }

    #[test]
    fn infallible_implementation_receives_digest_api() {
        let mut digest = SumDigest::default();
        digest.update(&[1, 2, 3]);
        digest.update_byte(4);

        let mut output = [0_u8; 1];
        assert_eq!(digest.do_final(&mut output), 1);
        assert_eq!(output, [10]);
    }

    #[test]
    fn digest_supports_dynamic_dispatch() {
        let mut concrete = SumDigest::default();
        let digest: &mut dyn Digest = &mut concrete;

        digest.update(&[5, 6]);
        let mut output = [0_u8; 1];
        assert_eq!(digest.do_final(&mut output), 1);
        assert_eq!(output, [11]);
    }
}
