//! SHAKE128 and SHAKE256 of FIPS 202, ported from Bouncy Castle's
//! `ShakeDigest`: the Keccak sponge with the domain pad `0x1f`, read as an
//! extendable-output function through [`tc_digest::Xof`].
//!
//! Used as a plain [`tc_digest::Digest`], each writes twice its security
//! strength, 32 bytes for SHAKE128 and 64 for SHAKE256, as Bouncy Castle's
//! `GetDigestSize`.

use core::convert::Infallible;
use core::fmt;

use tc_digest::{TryDigest, TryXof};

use crate::keccak::KeccakDigest;

/// SHAKE128 or SHAKE256 of FIPS 202. Constant time.
#[derive(Clone)]
pub struct ShakeDigest {
    sponge: KeccakDigest,
    // The security strength in bits, 128 or 256, which sets the name and the
    // default output length.
    bit_length: usize,
}

impl Default for ShakeDigest {
    /// SHAKE128, as Bouncy Castle's default constructor. Constant time.
    fn default() -> Self {
        Self::new(128)
    }
}

impl ShakeDigest {
    /// SHAKE with a `bit_length` security strength: 128 or 256. Constant time.
    ///
    /// # Panics
    ///
    /// Panics for any other strength, as Bouncy Castle throws.
    pub fn new(bit_length: usize) -> Self {
        assert!(
            matches!(bit_length, 128 | 256),
            "SHAKE: bit length must be 128 or 256"
        );
        ShakeDigest {
            sponge: KeccakDigest::with_domain(bit_length, 0x1f),
            bit_length,
        }
    }
}

impl fmt::Display for ShakeDigest {
    /// Writes `SHAKE` and the security strength, such as `SHAKE128`, without
    /// inspecting the state. Constant time with respect to the message; output
    /// timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SHAKE{}", self.bit_length)
    }
}

impl TryDigest for ShakeDigest {
    type Error = Infallible;

    // Twice the security strength in bytes, as Bouncy Castle's
    // fixedOutputLength >> 2.
    fn digest_size(&self) -> usize {
        self.bit_length / 4
    }

    fn byte_length(&self) -> usize {
        self.sponge.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.sponge.try_update(input)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.digest_size();
        assert!(
            output.len() >= len,
            "output buffer shorter than the {len}-byte digest"
        );
        self.try_output_final(&mut output[..len])
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.sponge.try_reset()
    }
}

impl TryXof for ShakeDigest {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.sponge.xof_output(output);
        Ok(output.len())
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let written = self.try_output(output)?;
        self.try_reset()?;
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec};

    use super::*;
    use tc_digest::{Digest, Xof};

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn accessors() {
        let d = ShakeDigest::new(128);
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 168); // a 1344-bit rate
        assert_eq!(format!("{d}"), "SHAKE128");

        let d = ShakeDigest::new(256);
        assert_eq!(d.digest_size(), 64);
        assert_eq!(d.byte_length(), 136); // a 1088-bit rate
        assert_eq!(format!("{d}"), "SHAKE256");
    }

    // The first 32 bytes of FIPS 202's SHAKE128 of the empty message.
    #[test]
    fn shake128_empty_default() {
        let mut d = ShakeDigest::new(128);
        let mut out = [0u8; 32];
        d.do_final(&mut out);
        assert_eq!(
            hex(&out),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
    }

    // The first 64 bytes, the default output, of FIPS 202's SHAKE256 of the
    // empty message.
    #[test]
    fn shake256_empty_default() {
        let mut d = ShakeDigest::new(256);
        let mut out = [0u8; 64];
        d.do_final(&mut out);
        assert_eq!(
            hex(&out),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
             d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
    }

    // do_final resets, so the second call hashes the empty message.
    #[test]
    fn do_final_resets() {
        let mut d = ShakeDigest::new(128);
        d.update(b"discarded");
        let mut o = [0u8; 32];
        d.do_final(&mut o);
        d.do_final(&mut o);
        assert_eq!(
            hex(&o),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
    }

    // Reading in pieces across the rate gives the stream read at once.
    #[test]
    fn streamed_output_matches_single() {
        let mut a = ShakeDigest::new(256);
        a.update(b"the quick brown fox");
        let mut whole = [0u8; 400];
        a.output(&mut whole);

        let mut b = ShakeDigest::new(256);
        b.update(b"the quick brown fox");
        let mut streamed = [0u8; 400];
        let (mut off, sizes) = (0usize, [1usize, 135, 136, 3, 40]);
        for s in sizes {
            b.output(&mut streamed[off..off + s]);
            off += s;
        }
        b.output(&mut streamed[off..]);
        assert_eq!(whole, streamed);
    }

    // Absorbing after squeezing panics, where Bouncy Castle throws.
    #[test]
    #[should_panic(expected = "attempt to absorb while squeezing")]
    fn absorb_after_squeeze_panics() {
        let mut d = ShakeDigest::new(128);
        let mut o = [0u8; 16];
        d.output(&mut o);
        d.update(b"nope");
    }

    #[test]
    fn output_final_resets() {
        let mut a = ShakeDigest::new(128);
        a.update(b"first");
        let mut o1 = vec![0u8; 40];
        a.output_final(&mut o1);
        a.update(b"first");
        let mut o2 = vec![0u8; 40];
        a.output_final(&mut o2);
        assert_eq!(o1, o2);
    }
}
