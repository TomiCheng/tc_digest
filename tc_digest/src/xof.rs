//! Extendable-output function contracts.

use core::convert::Infallible;

use crate::{Digest, TryDigest};

/// A streaming extendable-output function whose operations may fail.
///
/// Input is absorbed through [`TryDigest::try_update`]. The first call to
/// [`try_output`](TryXof::try_output) starts squeezing. Later calls continue
/// the same output stream until the XOF is reset. Whether input may still be
/// absorbed once squeezing has started is up to the implementation.
///
/// [`TryDigest::try_do_final`] writes [`digest_size`](TryDigest::digest_size)
/// bytes of output and resets the XOF, like
/// [`try_output_final`](TryXof::try_output_final) with a buffer of that length.
pub trait TryXof: TryDigest {
    /// Starts or continues squeezing output without resetting the XOF.
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Fills `output`, then resets the XOF for a new message.
    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;
}

/// An infallible streaming extendable-output function.
///
/// Implement [`TryDigest`] and [`TryXof`] with [`Infallible`] as the error
/// type to receive this convenience API automatically.
pub trait Xof: TryXof<Error = Infallible> + Digest {
    /// Starts or continues squeezing output without resetting the XOF.
    fn output(&mut self, output: &mut [u8]) -> usize;

    /// Fills `output`, then resets the XOF for a new message.
    fn output_final(&mut self, output: &mut [u8]) -> usize;
}

impl<T> Xof for T
where
    T: TryXof<Error = Infallible> + Digest + ?Sized,
{
    fn output(&mut self, output: &mut [u8]) -> usize {
        match self.try_output(output) {
            Ok(written) => written,
        }
    }

    fn output_final(&mut self, output: &mut [u8]) -> usize {
        match self.try_output_final(output) {
            Ok(written) => written,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use super::{TryXof, Xof};
    use crate::{Digest, TryDigest};

    #[derive(Default)]
    struct CounterXof {
        sum: u8,
        next: u8,
        squeezing: bool,
    }

    impl TryDigest for CounterXof {
        type Error = Infallible;

        fn algorithm_name(&self) -> &str {
            "COUNTER-XOF"
        }

        fn digest_size(&self) -> usize {
            1
        }

        fn byte_length(&self) -> usize {
            1
        }

        fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
            assert!(!self.squeezing, "cannot absorb after squeezing starts");
            for byte in input {
                self.sum = self.sum.wrapping_add(*byte);
            }
            Ok(())
        }

        fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            self.try_output_final(&mut output[..1])
        }

        fn try_reset(&mut self) -> Result<(), Self::Error> {
            self.sum = 0;
            self.next = 0;
            self.squeezing = false;
            Ok(())
        }
    }

    impl TryXof for CounterXof {
        fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            if !self.squeezing {
                self.next = self.sum;
                self.squeezing = true;
            }

            for byte in &mut *output {
                *byte = self.next;
                self.next = self.next.wrapping_add(1);
            }
            Ok(output.len())
        }

        fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            let written = self.try_output(output)?;
            self.try_reset()?;
            Ok(written)
        }
    }

    #[test]
    fn infallible_implementation_receives_xof_api() {
        let mut xof = CounterXof::default();
        xof.update(&[1, 2]);

        let mut first = [0_u8; 2];
        let mut second = [0_u8; 3];
        assert_eq!(xof.output(&mut first), 2);
        assert_eq!(xof.output(&mut second), 3);
        assert_eq!(first, [3, 4]);
        assert_eq!(second, [5, 6, 7]);
    }

    #[test]
    fn output_final_resets_the_xof() {
        let mut xof = CounterXof::default();
        xof.update(&[4, 5]);

        let mut output = [0_u8; 3];
        assert_eq!(xof.output_final(&mut output), 3);
        assert_eq!(output, [9, 10, 11]);

        xof.update(&[20]);
        assert_eq!(xof.output_final(&mut output), 3);
        assert_eq!(output, [20, 21, 22]);
    }

    #[test]
    fn xof_supports_dynamic_dispatch() {
        let mut concrete = CounterXof::default();
        let xof: &mut dyn Xof = &mut concrete;

        xof.update(&[7]);
        let mut output = [0_u8; 2];
        assert_eq!(xof.output_final(&mut output), 2);
        assert_eq!(output, [7, 8]);
    }
}
