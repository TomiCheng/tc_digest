//! SHA-256 message digest (FIPS 180-4), ported from Bouncy Castle's
//! `Sha256Digest`.

use core::convert::Infallible;

use tc_digest::TryDigest;

use crate::md_buffer::MdBuffer;
use crate::sha256_core::compress;

const DIGEST_LENGTH: usize = 32;
const BYTE_LENGTH: usize = 64;

// The initial hash value: the first 32 bits of the fractional parts of the
// square roots of the first 8 primes.
const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The SHA-256 digest (FIPS 180-4), producing a 32-byte hash.
///
/// Constant time: the compression uses only additions, rotations, shifts and
/// bitwise operations, and the running time depends only on the message
/// length.
///
/// `do_final` panics if the output buffer is shorter than 32 bytes.
#[derive(Clone)]
pub struct Sha256Digest {
    /// The eight chaining registers H1..H8.
    h: [u32; 8],
    /// The shared 64-byte block buffer.
    buf: MdBuffer<64>,
}

impl Default for Sha256Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Digest {
    /// Creates a fresh SHA-256 digest. Constant time.
    pub const fn new() -> Self {
        Sha256Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }
}

impl TryDigest for Sha256Digest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "SHA-256"
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

    /// Writes the 32-byte digest to the start of `output` and resets.
    ///
    /// # Panics
    ///
    /// Panics if `output` is shorter than 32 bytes, before changing any
    /// state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        assert!(
            output.len() >= DIGEST_LENGTH,
            "output buffer shorter than the 32-byte SHA-256 digest"
        );
        {
            let Self { h, buf } = self;
            // The SHA-256 length field is the bit length as a big-endian u64.
            let bit_len = buf.byte_count() << 3;
            buf.finish(&bit_len.to_be_bytes(), |block| compress(h, block));
            for (i, &word) in h.iter().enumerate() {
                output[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
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

    fn sha256_hex(input: &[u8]) -> String {
        let mut d = Sha256Digest::new();
        d.update(input);
        let mut out = [0u8; 32];
        d.do_final(&mut out);
        let mut s = String::with_capacity(64);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // Known-answer vectors from FIPS 180-4's examples.
    #[test]
    fn known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"message digest"),
            "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"
        );
        assert_eq!(
            sha256_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"
        );
        // A 56-byte message: the padding spills into a second block.
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            sha256_hex(b"The quick brown fox jumps over the lazy dog"),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }

    #[test]
    fn accessors() {
        let d = Sha256Digest::new();
        assert_eq!(d.algorithm_name(), "SHA-256");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 64);
    }

    #[test]
    fn do_final_leaves_reset() {
        let mut d = Sha256Digest::new();
        d.update(b"abc");
        let mut out = [0u8; 32];
        d.do_final(&mut out);
        d.do_final(&mut out); // the empty-message digest, so it was reset
        let mut s = String::new();
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        assert_eq!(
            s,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut a = Sha256Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 32];
        a.do_final(&mut oa);

        let mut b = Sha256Digest::new();
        b.update(&msg[..1]);
        b.update(&msg[1..64]);
        b.update(&msg[64..130]);
        b.update(&msg[130..]);
        let mut ob = [0u8; 32];
        b.do_final(&mut ob);

        assert_eq!(oa, ob);
    }
}
