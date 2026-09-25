//! SHA-224 message digest (FIPS 180-4), ported from Bouncy Castle's
//! `Sha224Digest`.
//!
//! SHA-224 is SHA-256 with a different IV and its output truncated to 28 bytes;
//! it reuses `sha256_core::compress` unchanged.

use core::{convert::Infallible, fmt};

use tc_digest::TryDigest;

use crate::md_buffer::MdBuffer;
use crate::sha256_core::compress;

const DIGEST_LENGTH: usize = 28;
const BYTE_LENGTH: usize = 64;

// The initial hash value (FIPS 180-4): the second 32 bits of the fractional
// parts of the square roots of the 9th through 16th primes.
const IV: [u32; 8] = [
    0xc105_9ed8,
    0x367c_d507,
    0x3070_dd17,
    0xf70e_5939,
    0xffc0_0b31,
    0x6858_1511,
    0x64f9_8fa7,
    0xbefa_4fa4,
];

/// The SHA-224 digest (FIPS 180-4), producing a 28-byte hash.
///
/// Constant time: the compression uses only additions, rotations, shifts and
/// bitwise operations, and the running time depends only on the message
/// length.
///
/// `do_final` panics if the output buffer is shorter than 28 bytes.
#[derive(Clone)]
pub struct Sha224Digest {
    /// The eight chaining registers; the output uses the first seven.
    h: [u32; 8],
    /// The shared 64-byte block buffer.
    buf: MdBuffer<64>,
}

impl Default for Sha224Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha224Digest {
    /// Creates a fresh SHA-224 digest. Constant time.
    pub const fn new() -> Self {
        Sha224Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }
}

impl fmt::Display for Sha224Digest {
    /// Writes `SHA-224` without inspecting the digest state. Constant time with
    /// respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SHA-224")
    }
}

impl TryDigest for Sha224Digest {
    type Error = Infallible;

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

    /// Writes the 28-byte digest to the start of `output` and resets.
    ///
    /// # Panics
    ///
    /// Panics if `output` is shorter than 28 bytes, before changing any
    /// state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        assert!(
            output.len() >= DIGEST_LENGTH,
            "output buffer shorter than the 28-byte SHA-224 digest"
        );
        {
            let Self { h, buf } = self;
            let bit_len = buf.byte_count() << 3;
            buf.finish(&bit_len.to_be_bytes(), |block| compress(h, block));
            // Output only the first seven registers (28 bytes), dropping H8.
            for (i, &word) in h.iter().take(7).enumerate() {
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

    fn sha224_hex(input: &[u8]) -> String {
        let mut d = Sha224Digest::new();
        d.update(input);
        let mut out = [0u8; 28];
        d.do_final(&mut out);
        let mut s = String::with_capacity(56);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // Known-answer vectors from FIPS 180-4's examples.
    #[test]
    fn known_vectors() {
        assert_eq!(
            sha224_hex(b""),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            sha224_hex(b"abc"),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
        // A 56-byte message: the padding spills into a second block.
        assert_eq!(
            sha224_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
        );
    }

    #[test]
    fn accessors() {
        let d = Sha224Digest::new();
        assert_eq!(format!("{d}"), "SHA-224");
        assert_eq!(d.digest_size(), 28);
        assert_eq!(d.byte_length(), 64);
    }

    #[test]
    fn do_final_leaves_reset() {
        let mut d = Sha224Digest::new();
        d.update(b"abc");
        let mut out = [0u8; 28];
        d.do_final(&mut out);
        d.do_final(&mut out); // the empty-message digest, so it was reset
        let mut s = String::new();
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        assert_eq!(
            s,
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut a = Sha224Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 28];
        a.do_final(&mut oa);

        let mut b = Sha224Digest::new();
        b.update(&msg[..64]);
        b.update(&msg[64..]);
        let mut ob = [0u8; 28];
        b.do_final(&mut ob);

        assert_eq!(oa, ob);
    }
}
