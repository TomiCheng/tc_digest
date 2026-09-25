//! SHA-1 message digest (FIPS 180-4), ported from Bouncy Castle's
//! `Sha1Digest`.

use core::{convert::Infallible, fmt};

use tc_digest::TryDigest;

use crate::md_buffer::MdBuffer;

const DIGEST_LENGTH: usize = 20;
const BYTE_LENGTH: usize = 64;

// The initial hash value (IV).
const IV: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

// The additive constants of the four rounds.
const Y1: u32 = 0x5a82_7999;
const Y2: u32 = 0x6ed9_eba1;
const Y3: u32 = 0x8f1b_bcdc;
const Y4: u32 = 0xca62_c1d6;

/// The SHA-1 digest (FIPS 180-4), producing a 20-byte hash.
///
/// SHA-1 is broken for collision resistance: collisions, chosen-prefix
/// collisions included, are practical. Keep it for legacy interoperability,
/// such as verifying existing signatures or HMAC-SHA1, which does not rely on
/// collision resistance; do not use it for new signatures or designs.
///
/// Constant time: the compression uses only additions, rotations, shifts and
/// bitwise operations, and the running time depends only on the message
/// length.
///
/// `do_final` panics if the output buffer is shorter than 20 bytes.
#[derive(Clone)]
pub struct Sha1Digest {
    /// The five chaining registers H1..H5.
    h: [u32; 5],
    /// The shared 64-byte block buffer, replacing Bouncy Castle's
    /// `GeneralDigest` base class.
    buf: MdBuffer<64>,
}

impl Default for Sha1Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1Digest {
    /// Creates a fresh SHA-1 digest. Constant time.
    pub const fn new() -> Self {
        Sha1Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }

    /// Compresses one 64-byte block into the registers `h` (Bouncy Castle
    /// `ProcessBlock`). Constant time.
    fn compress(h: &mut [u32; 5], block: &[u8; 64]) {
        // SHA-1 is big-endian: read 16 big-endian words, then expand to 80.
        let mut w = [0u32; 80];
        for (word, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes(chunk.try_into().expect("4-byte chunk"));
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];

        for (i, &wi) in w.iter().enumerate() {
            // Pick the round function f and constant k by the public round index.
            let (f, k) = if i < 20 {
                ((b & c) | (!b & d), Y1)
            } else if i < 40 {
                (b ^ c ^ d, Y2)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), Y3)
            } else {
                (b ^ c ^ d, Y4)
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
}

impl fmt::Display for Sha1Digest {
    /// Writes `SHA-1` without inspecting the digest state. Constant time with
    /// respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SHA-1")
    }
}

impl TryDigest for Sha1Digest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let Self { h, buf } = self;
        buf.update(input, |block| Sha1Digest::compress(h, block));
        Ok(())
    }

    /// Writes the 20-byte digest to the start of `output` and resets.
    ///
    /// # Panics
    ///
    /// Panics if `output` is shorter than 20 bytes, before changing any
    /// state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        assert!(
            output.len() >= DIGEST_LENGTH,
            "output buffer shorter than the 20-byte SHA-1 digest"
        );
        {
            let Self { h, buf } = self;
            // The SHA-1 length field is the bit length as a big-endian u64.
            let bit_len = buf.byte_count() << 3;
            buf.finish(&bit_len.to_be_bytes(), |block| {
                Sha1Digest::compress(h, block)
            });
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

    fn sha1_hex(input: &[u8]) -> String {
        let mut d = Sha1Digest::new();
        d.update(input);
        let mut out = [0u8; 20];
        d.do_final(&mut out);
        let mut s = String::with_capacity(40);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // Known-answer vectors from FIPS 180-4 and RFC 3174.
    #[test]
    fn known_vectors() {
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1_hex(b"message digest"),
            "c12252ceda8be8994d5fa0290a47231c1d16aae3"
        );
        assert_eq!(
            sha1_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "32d10c7b8cf96570ca04ce37f2a19d84240d3a89"
        );
        assert_eq!(
            sha1_hex(b"The quick brown fox jumps over the lazy dog"),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
        // A 448-bit message: the padding spills into a second block.
        assert_eq!(
            sha1_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn accessors() {
        let d = Sha1Digest::new();
        assert_eq!(format!("{d}"), "SHA-1");
        assert_eq!(d.digest_size(), 20);
        assert_eq!(d.byte_length(), 64);
    }

    #[test]
    fn do_final_leaves_reset() {
        let mut d = Sha1Digest::new();
        d.update(b"abc");
        let mut out = [0u8; 20];
        d.do_final(&mut out);
        d.do_final(&mut out); // the empty-message digest, so it was reset
        let mut s = String::new();
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        assert_eq!(s, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut a = Sha1Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 20];
        a.do_final(&mut oa);

        let mut b = Sha1Digest::new();
        b.update(&msg[..1]);
        b.update(&msg[1..64]);
        b.update(&msg[64..130]);
        b.update(&msg[130..]);
        let mut ob = [0u8; 20];
        b.do_final(&mut ob);

        assert_eq!(oa, ob);
    }
}
