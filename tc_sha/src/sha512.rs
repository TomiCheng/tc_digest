//! SHA-512 message digest (FIPS 180-4), ported from Bouncy Castle's
//! `Sha512Digest` and its `LongDigest` base class.

use core::convert::Infallible;

use tc_digest::TryDigest;

use crate::md_buffer::MdBuffer;
use crate::sha512_core::{IV, compress};

const DIGEST_LENGTH: usize = 64;
const BYTE_LENGTH: usize = 128;

/// The SHA-512 digest (FIPS 180-4), producing a 64-byte hash.
///
/// Constant time: the compression uses only additions, rotations, shifts and
/// bitwise operations, and the running time depends only on the message
/// length.
///
/// `do_final` panics if the output buffer is shorter than 64 bytes.
#[derive(Clone)]
pub struct Sha512Digest {
    /// The eight 64-bit chaining registers H1..H8.
    h: [u64; 8],
    /// The shared 128-byte block buffer.
    buf: MdBuffer<128>,
}

impl Default for Sha512Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512Digest {
    /// Creates a fresh SHA-512 digest. Constant time.
    pub const fn new() -> Self {
        Sha512Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }
}

impl TryDigest for Sha512Digest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "SHA-512"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let Self { h, buf } = self;
        buf.update(input, |block| compress(h, block));
        Ok(())
    }

    /// Writes the 64-byte digest to the start of `output` and resets.
    ///
    /// # Panics
    ///
    /// Panics if `output` is shorter than 64 bytes, before changing any
    /// state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        assert!(
            output.len() >= DIGEST_LENGTH,
            "output buffer shorter than the 64-byte SHA-512 digest"
        );
        {
            let Self { h, buf } = self;
            // The SHA-512 length field is the bit length as a big-endian u128.
            let bit_len = (buf.byte_count() as u128) << 3;
            buf.finish(&bit_len.to_be_bytes(), |block| compress(h, block));
            for (i, &word) in h.iter().enumerate() {
                output[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
            }
        }
        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        *self = Self::new();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec::Vec};

    use super::*;
    use tc_digest::Digest;

    fn sha512_hex(input: &[u8]) -> String {
        let mut d = Sha512Digest::new();
        d.update(input);
        let mut out = [0u8; 64];
        d.do_final(&mut out);
        let mut s = String::with_capacity(128);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // Known-answer vectors from FIPS 180-4's examples.
    #[test]
    fn known_vectors() {
        assert_eq!(
            sha512_hex(b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            sha512_hex(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        // A 112-byte message: the padding spills into a second 128-byte block.
        assert_eq!(
            sha512_hex(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                  ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            ),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
    }

    #[test]
    fn accessors() {
        let d = Sha512Digest::new();
        assert_eq!(d.algorithm_name(), "SHA-512");
        assert_eq!(d.digest_size(), 64);
        assert_eq!(d.byte_length(), 128);
    }

    #[test]
    fn do_final_leaves_reset() {
        let mut d = Sha512Digest::new();
        d.update(b"abc");
        let mut out = [0u8; 64];
        d.do_final(&mut out);
        d.do_final(&mut out); // the empty-message digest, so it was reset
        assert_eq!(
            {
                let mut s = String::new();
                for b in out {
                    s.push_str(&format!("{b:02x}"));
                }
                s
            },
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..400).map(|i| i as u8).collect();
        let mut a = Sha512Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 64];
        a.do_final(&mut oa);

        let mut b = Sha512Digest::new();
        b.update(&msg[..1]);
        b.update(&msg[1..128]);
        b.update(&msg[128..260]);
        b.update(&msg[260..]);
        let mut ob = [0u8; 64];
        b.do_final(&mut ob);

        assert_eq!(oa, ob);
    }
}
