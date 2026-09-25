//! MD5 message digest (RFC 1321), ported from Bouncy Castle's `MD5Digest`.
//!
//! MD5 is cryptographically broken; it is kept only for legacy
//! interoperability.

use core::{convert::Infallible, fmt};

use tc_digest::TryDigest;

use crate::md_buffer::MdBuffer;

const DIGEST_LENGTH: usize = 16;
const BYTE_LENGTH: usize = 64;

// The initial chaining value (IV), the same as MD4's.
const IV: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// The MD5 digest (RFC 1321), producing a 16-byte hash.
///
/// MD5 is cryptographically broken: collisions, chosen-prefix collisions
/// included, are practical. It is kept only for interoperability with legacy
/// data; do not use it for new designs.
///
/// Constant time: the compression uses only additions, rotations and bitwise
/// operations, and the running time depends only on the message length.
///
/// `do_final` panics if the output buffer is shorter than 16 bytes.
#[derive(Clone)]
pub struct Md5Digest {
    /// The four chaining registers H1..H4.
    h: [u32; 4],
    /// The shared 64-byte block buffer, replacing Bouncy Castle's
    /// `GeneralDigest` base class.
    buf: MdBuffer<64>,
}

impl Default for Md5Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5Digest {
    /// Creates a fresh MD5 digest. Constant time.
    pub const fn new() -> Self {
        Md5Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }

    /// Compresses one 64-byte block into the registers `h` (Bouncy Castle
    /// `ProcessBlock`). Constant time.
    fn compress(h: &mut [u32; 4], block: &[u8; 64]) {
        // MD5 is little-endian: read the block as 16 little-endian words.
        let mut x = [0u32; 16];
        for (word, chunk) in x.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes(chunk.try_into().expect("4-byte chunk"));
        }

        // The four auxiliary functions; G and K differ from MD4's.
        fn f(u: u32, v: u32, w: u32) -> u32 {
            (u & v) | (!u & w)
        }
        fn g(u: u32, v: u32, w: u32) -> u32 {
            (u & w) | (v & !w)
        }
        fn h_(u: u32, v: u32, w: u32) -> u32 {
            u ^ v ^ w
        }
        fn k(u: u32, v: u32, w: u32) -> u32 {
            v ^ (u | !w)
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];

        // Each step: t = rotl(t + phi(p, q, r) + X[k] + constant, s) + p, all
        // wrapping. The register added back is always phi's first argument.
        macro_rules! step {
            ($phi:ident, $t:ident, $p:ident, $q:ident, $r:ident, $k:expr, $c:expr, $s:expr) => {
                $t = $t
                    .wrapping_add($phi($p, $q, $r))
                    .wrapping_add(x[$k])
                    .wrapping_add($c)
                    .rotate_left($s)
                    .wrapping_add($p);
            };
        }

        // Round 1, F. Rotations 7, 12, 17, 22.
        step!(f, a, b, c, d, 0, 0xd76a_a478, 7);
        step!(f, d, a, b, c, 1, 0xe8c7_b756, 12);
        step!(f, c, d, a, b, 2, 0x2420_70db, 17);
        step!(f, b, c, d, a, 3, 0xc1bd_ceee, 22);
        step!(f, a, b, c, d, 4, 0xf57c_0faf, 7);
        step!(f, d, a, b, c, 5, 0x4787_c62a, 12);
        step!(f, c, d, a, b, 6, 0xa830_4613, 17);
        step!(f, b, c, d, a, 7, 0xfd46_9501, 22);
        step!(f, a, b, c, d, 8, 0x6980_98d8, 7);
        step!(f, d, a, b, c, 9, 0x8b44_f7af, 12);
        step!(f, c, d, a, b, 10, 0xffff_5bb1, 17);
        step!(f, b, c, d, a, 11, 0x895c_d7be, 22);
        step!(f, a, b, c, d, 12, 0x6b90_1122, 7);
        step!(f, d, a, b, c, 13, 0xfd98_7193, 12);
        step!(f, c, d, a, b, 14, 0xa679_438e, 17);
        step!(f, b, c, d, a, 15, 0x49b4_0821, 22);

        // Round 2, G. Rotations 5, 9, 14, 20.
        step!(g, a, b, c, d, 1, 0xf61e_2562, 5);
        step!(g, d, a, b, c, 6, 0xc040_b340, 9);
        step!(g, c, d, a, b, 11, 0x265e_5a51, 14);
        step!(g, b, c, d, a, 0, 0xe9b6_c7aa, 20);
        step!(g, a, b, c, d, 5, 0xd62f_105d, 5);
        step!(g, d, a, b, c, 10, 0x0244_1453, 9);
        step!(g, c, d, a, b, 15, 0xd8a1_e681, 14);
        step!(g, b, c, d, a, 4, 0xe7d3_fbc8, 20);
        step!(g, a, b, c, d, 9, 0x21e1_cde6, 5);
        step!(g, d, a, b, c, 14, 0xc337_07d6, 9);
        step!(g, c, d, a, b, 3, 0xf4d5_0d87, 14);
        step!(g, b, c, d, a, 8, 0x455a_14ed, 20);
        step!(g, a, b, c, d, 13, 0xa9e3_e905, 5);
        step!(g, d, a, b, c, 2, 0xfcef_a3f8, 9);
        step!(g, c, d, a, b, 7, 0x676f_02d9, 14);
        step!(g, b, c, d, a, 12, 0x8d2a_4c8a, 20);

        // Round 3, H. Rotations 4, 11, 16, 23.
        step!(h_, a, b, c, d, 5, 0xfffa_3942, 4);
        step!(h_, d, a, b, c, 8, 0x8771_f681, 11);
        step!(h_, c, d, a, b, 11, 0x6d9d_6122, 16);
        step!(h_, b, c, d, a, 14, 0xfde5_380c, 23);
        step!(h_, a, b, c, d, 1, 0xa4be_ea44, 4);
        step!(h_, d, a, b, c, 4, 0x4bde_cfa9, 11);
        step!(h_, c, d, a, b, 7, 0xf6bb_4b60, 16);
        step!(h_, b, c, d, a, 10, 0xbebf_bc70, 23);
        step!(h_, a, b, c, d, 13, 0x289b_7ec6, 4);
        step!(h_, d, a, b, c, 0, 0xeaa1_27fa, 11);
        step!(h_, c, d, a, b, 3, 0xd4ef_3085, 16);
        step!(h_, b, c, d, a, 6, 0x0488_1d05, 23);
        step!(h_, a, b, c, d, 9, 0xd9d4_d039, 4);
        step!(h_, d, a, b, c, 12, 0xe6db_99e5, 11);
        step!(h_, c, d, a, b, 15, 0x1fa2_7cf8, 16);
        step!(h_, b, c, d, a, 2, 0xc4ac_5665, 23);

        // Round 4, K. Rotations 6, 10, 15, 21.
        step!(k, a, b, c, d, 0, 0xf429_2244, 6);
        step!(k, d, a, b, c, 7, 0x432a_ff97, 10);
        step!(k, c, d, a, b, 14, 0xab94_23a7, 15);
        step!(k, b, c, d, a, 5, 0xfc93_a039, 21);
        step!(k, a, b, c, d, 12, 0x655b_59c3, 6);
        step!(k, d, a, b, c, 3, 0x8f0c_cc92, 10);
        step!(k, c, d, a, b, 10, 0xffef_f47d, 15);
        step!(k, b, c, d, a, 1, 0x8584_5dd1, 21);
        step!(k, a, b, c, d, 8, 0x6fa8_7e4f, 6);
        step!(k, d, a, b, c, 15, 0xfe2c_e6e0, 10);
        step!(k, c, d, a, b, 6, 0xa301_4314, 15);
        step!(k, b, c, d, a, 13, 0x4e08_11a1, 21);
        step!(k, a, b, c, d, 4, 0xf753_7e82, 6);
        step!(k, d, a, b, c, 11, 0xbd3a_f235, 10);
        step!(k, c, d, a, b, 2, 0x2ad7_d2bb, 15);
        step!(k, b, c, d, a, 9, 0xeb86_d391, 21);

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }
}

impl fmt::Display for Md5Digest {
    /// Writes `MD5` without inspecting the digest state. Constant time with
    /// respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MD5")
    }
}

impl TryDigest for Md5Digest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let Self { h, buf } = self;
        buf.update(input, |block| Md5Digest::compress(h, block));
        Ok(())
    }

    /// Writes the 16-byte digest to the start of `output` and resets.
    ///
    /// # Panics
    ///
    /// Panics if `output` is shorter than 16 bytes, before changing any
    /// state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        assert!(
            output.len() >= DIGEST_LENGTH,
            "output buffer shorter than the 16-byte MD5 digest"
        );
        {
            let Self { h, buf } = self;
            // The MD5 length field is the bit length as a little-endian u64.
            let bit_len = buf.byte_count() << 3;
            buf.finish(&bit_len.to_le_bytes(), |block| {
                Md5Digest::compress(h, block)
            });
            for (i, &word) in h.iter().enumerate() {
                output[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
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

    fn md5_hex(input: &[u8]) -> String {
        let mut d = Md5Digest::new();
        d.update(input);
        let mut out = [0u8; 16];
        d.do_final(&mut out);
        let mut s = String::with_capacity(32);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // The test suite from RFC 1321, appendix A.5.
    #[test]
    fn rfc1321_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"a"), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(b"message digest"),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            md5_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            md5_hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
        assert_eq!(
            md5_hex(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn accessors() {
        let d = Md5Digest::new();
        assert_eq!(format!("{d}"), "MD5");
        assert_eq!(d.digest_size(), 16);
        assert_eq!(d.byte_length(), 64);
    }

    #[test]
    fn do_final_leaves_reset() {
        let mut d = Md5Digest::new();
        d.update(b"abc");
        let mut out = [0u8; 16];
        d.do_final(&mut out);
        d.do_final(&mut out); // the empty-message digest, so it was reset
        let mut s = String::new();
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        assert_eq!(s, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut a = Md5Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 16];
        a.do_final(&mut oa);

        let mut b = Md5Digest::new();
        b.update(&msg[..1]);
        b.update(&msg[1..64]);
        b.update(&msg[64..130]);
        b.update(&msg[130..]);
        let mut ob = [0u8; 16];
        b.do_final(&mut ob);

        assert_eq!(oa, ob);
    }
}
