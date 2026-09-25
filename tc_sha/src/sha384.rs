//! SHA-384 message digest (FIPS 180-4), ported from Bouncy Castle's
//! `Sha384Digest`.
//!
//! SHA-384 is SHA-512 with a different IV and its output truncated to 48 bytes;
//! it reuses `sha512_core::compress` unchanged.

use core::{convert::Infallible, fmt};

use tc_digest::TryDigest;

use crate::md_buffer::MdBuffer;
use crate::sha512_core::compress;

const DIGEST_LENGTH: usize = 48;
const BYTE_LENGTH: usize = 128;

// The initial hash value (FIPS 180-4): the first 64 bits of the fractional
// parts of the square roots of the 9th through 16th primes.
const IV: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,
    0x629a_292a_367c_d507,
    0x9159_015a_3070_dd17,
    0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,
    0x8eb4_4a87_6858_1511,
    0xdb0c_2e0d_64f9_8fa7,
    0x47b5_481d_befa_4fa4,
];

/// The SHA-384 digest (FIPS 180-4), producing a 48-byte hash.
///
/// Constant time: the compression uses only additions, rotations, shifts and
/// bitwise operations, and the running time depends only on the message
/// length.
///
/// `do_final` panics if the output buffer is shorter than 48 bytes.
#[derive(Clone)]
pub struct Sha384Digest {
    /// The eight 64-bit chaining registers; the output uses the first six.
    h: [u64; 8],
    /// The shared 128-byte block buffer.
    buf: MdBuffer<128>,
}

impl Default for Sha384Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha384Digest {
    /// Creates a fresh SHA-384 digest. Constant time.
    pub const fn new() -> Self {
        Sha384Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }
}

impl fmt::Display for Sha384Digest {
    /// Writes `SHA-384` without inspecting the digest state. Constant time with
    /// respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SHA-384")
    }
}

impl TryDigest for Sha384Digest {
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

    /// Writes the 48-byte digest to the start of `output` and resets.
    ///
    /// # Panics
    ///
    /// Panics if `output` is shorter than 48 bytes, before changing any
    /// state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        assert!(
            output.len() >= DIGEST_LENGTH,
            "output buffer shorter than the 48-byte SHA-384 digest"
        );
        {
            let Self { h, buf } = self;
            let bit_len = (buf.byte_count() as u128) << 3;
            buf.finish(&bit_len.to_be_bytes(), |block| compress(h, block));
            // Output only the first six registers (48 bytes), dropping H7 and H8.
            for (i, &word) in h.iter().take(6).enumerate() {
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

    fn sha384_hex(input: &[u8]) -> String {
        let mut d = Sha384Digest::new();
        d.update(input);
        let mut out = [0u8; 48];
        d.do_final(&mut out);
        let mut s = String::with_capacity(96);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // Known-answer vectors from FIPS 180-4's examples.
    #[test]
    fn known_vectors() {
        assert_eq!(
            sha384_hex(b""),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743\
             4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            sha384_hex(b"abc"),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163\
             1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        // A 112-byte message: the padding spills into a second block.
        assert_eq!(
            sha384_hex(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                  ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            ),
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2\
             2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
        );
    }

    #[test]
    fn accessors() {
        let d = Sha384Digest::new();
        assert_eq!(format!("{d}"), "SHA-384");
        assert_eq!(d.digest_size(), 48);
        assert_eq!(d.byte_length(), 128);
    }

    #[test]
    fn do_final_leaves_reset() {
        let mut d = Sha384Digest::new();
        d.update(b"abc");
        let mut out = [0u8; 48];
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
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743\
             4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..400).map(|i| i as u8).collect();
        let mut a = Sha384Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 48];
        a.do_final(&mut oa);

        let mut b = Sha384Digest::new();
        b.update(&msg[..128]);
        b.update(&msg[128..]);
        let mut ob = [0u8; 48];
        b.do_final(&mut ob);

        assert_eq!(oa, ob);
    }
}
