//! MD4 message digest (RFC 1320), ported from Bouncy Castle's `MD4Digest`.
//!
//! MD4 is cryptographically broken; it is kept only for legacy
//! interoperability.

use core::convert::Infallible;

use tc_digest::TryDigest;

use crate::md_buffer::MdBuffer;

const DIGEST_LENGTH: usize = 16;
const BYTE_LENGTH: usize = 64;

// The initial chaining value (IV).
const IV: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// The MD4 digest (RFC 1320), producing a 16-byte hash.
///
/// MD4 is cryptographically broken, for collisions and preimages alike, and
/// kept only for interoperability with legacy data; do not use it for new
/// designs.
///
/// Constant time: the compression uses only additions, rotations and bitwise
/// operations, and the running time depends only on the message length.
///
/// `do_final` panics if the output buffer is shorter than 16 bytes.
#[derive(Clone)]
pub struct Md4Digest {
    /// The four chaining registers H1..H4.
    h: [u32; 4],
    /// The shared 64-byte block buffer, replacing Bouncy Castle's
    /// `GeneralDigest` base class.
    buf: MdBuffer<64>,
}

impl Default for Md4Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Md4Digest {
    /// Creates a fresh MD4 digest. Constant time.
    pub const fn new() -> Self {
        Md4Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }

    /// Compresses one 64-byte block into the registers `h` (Bouncy Castle
    /// `ProcessBlock`). Constant time.
    ///
    /// `h` is passed explicitly rather than through `&mut self`, so the
    /// `MdBuffer` closure can borrow `h` while `buf` is borrowed as well.
    fn compress(h: &mut [u32; 4], block: &[u8; 64]) {
        // MD4 is little-endian: read the block as 16 little-endian words.
        let mut x = [0u32; 16];
        for (word, chunk) in x.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes(chunk.try_into().expect("4-byte chunk"));
        }

        // The auxiliary functions F, G and H.
        fn f(u: u32, v: u32, w: u32) -> u32 {
            (u & v) | (!u & w)
        }
        fn g(u: u32, v: u32, w: u32) -> u32 {
            (u & v) | (u & w) | (v & w)
        }
        fn hh(u: u32, v: u32, w: u32) -> u32 {
            u ^ v ^ w
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];

        // Each step: t = rotl(t + phi(...) + X[k] (+ constant), s), all wrapping.
        macro_rules! r1 {
            ($t:ident, $p:ident, $q:ident, $r:ident, $k:expr, $s:expr) => {
                $t = $t
                    .wrapping_add(f($p, $q, $r))
                    .wrapping_add(x[$k])
                    .rotate_left($s);
            };
        }
        macro_rules! r2 {
            ($t:ident, $p:ident, $q:ident, $r:ident, $k:expr, $s:expr) => {
                $t = $t
                    .wrapping_add(g($p, $q, $r))
                    .wrapping_add(x[$k])
                    .wrapping_add(0x5a82_7999)
                    .rotate_left($s);
            };
        }
        macro_rules! r3 {
            ($t:ident, $p:ident, $q:ident, $r:ident, $k:expr, $s:expr) => {
                $t = $t
                    .wrapping_add(hh($p, $q, $r))
                    .wrapping_add(x[$k])
                    .wrapping_add(0x6ed9_eba1)
                    .rotate_left($s);
            };
        }

        // Round 1, F. Rotations S11=3 S12=7 S13=11 S14=19.
        r1!(a, b, c, d, 0, 3);
        r1!(d, a, b, c, 1, 7);
        r1!(c, d, a, b, 2, 11);
        r1!(b, c, d, a, 3, 19);
        r1!(a, b, c, d, 4, 3);
        r1!(d, a, b, c, 5, 7);
        r1!(c, d, a, b, 6, 11);
        r1!(b, c, d, a, 7, 19);
        r1!(a, b, c, d, 8, 3);
        r1!(d, a, b, c, 9, 7);
        r1!(c, d, a, b, 10, 11);
        r1!(b, c, d, a, 11, 19);
        r1!(a, b, c, d, 12, 3);
        r1!(d, a, b, c, 13, 7);
        r1!(c, d, a, b, 14, 11);
        r1!(b, c, d, a, 15, 19);

        // Round 2, G, adding 0x5a827999. Rotations S21=3 S22=5 S23=9 S24=13.
        r2!(a, b, c, d, 0, 3);
        r2!(d, a, b, c, 4, 5);
        r2!(c, d, a, b, 8, 9);
        r2!(b, c, d, a, 12, 13);
        r2!(a, b, c, d, 1, 3);
        r2!(d, a, b, c, 5, 5);
        r2!(c, d, a, b, 9, 9);
        r2!(b, c, d, a, 13, 13);
        r2!(a, b, c, d, 2, 3);
        r2!(d, a, b, c, 6, 5);
        r2!(c, d, a, b, 10, 9);
        r2!(b, c, d, a, 14, 13);
        r2!(a, b, c, d, 3, 3);
        r2!(d, a, b, c, 7, 5);
        r2!(c, d, a, b, 11, 9);
        r2!(b, c, d, a, 15, 13);

        // Round 3, H, adding 0x6ed9eba1. Rotations S31=3 S32=9 S33=11 S34=15.
        r3!(a, b, c, d, 0, 3);
        r3!(d, a, b, c, 8, 9);
        r3!(c, d, a, b, 4, 11);
        r3!(b, c, d, a, 12, 15);
        r3!(a, b, c, d, 2, 3);
        r3!(d, a, b, c, 10, 9);
        r3!(c, d, a, b, 6, 11);
        r3!(b, c, d, a, 14, 15);
        r3!(a, b, c, d, 1, 3);
        r3!(d, a, b, c, 9, 9);
        r3!(c, d, a, b, 5, 11);
        r3!(b, c, d, a, 13, 15);
        r3!(a, b, c, d, 3, 3);
        r3!(d, a, b, c, 11, 9);
        r3!(c, d, a, b, 7, 11);
        r3!(b, c, d, a, 15, 15);

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }
}

impl TryDigest for Md4Digest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "MD4"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        // Split borrow: the closure borrows `h` while `buf.update` borrows `buf`.
        let Self { h, buf } = self;
        buf.update(input, |block| Md4Digest::compress(h, block));
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
            "output buffer shorter than the 16-byte MD4 digest"
        );
        {
            let Self { h, buf } = self;
            // The MD4 length field is the bit length as a little-endian u64.
            let bit_len = buf.byte_count() << 3;
            buf.finish(&bit_len.to_le_bytes(), |block| {
                Md4Digest::compress(h, block)
            });
            // Output the four registers in little-endian order.
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

    fn md4_hex(input: &[u8]) -> String {
        let mut d = Md4Digest::new();
        d.update(input);
        let mut out = [0u8; 16];
        d.do_final(&mut out);
        let mut s = String::with_capacity(32);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // The test suite from RFC 1320, appendix A.5.
    #[test]
    fn rfc1320_vectors() {
        assert_eq!(md4_hex(b""), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(md4_hex(b"a"), "bde52cb31de33e46245e05fbdbd6fb24");
        assert_eq!(md4_hex(b"abc"), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(
            md4_hex(b"message digest"),
            "d9130a8164549fe818874806e1c7014b"
        );
        assert_eq!(
            md4_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "d79e1c308aa5bbcdeea8ed63df412da9"
        );
        assert_eq!(
            md4_hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "043f8582f241db351ce627e153e7f0e4"
        );
        assert_eq!(
            md4_hex(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            "e33b4ddc9c38f2199c3e7b164fcc0536"
        );
    }

    #[test]
    fn accessors() {
        let d = Md4Digest::new();
        assert_eq!(d.algorithm_name(), "MD4");
        assert_eq!(d.digest_size(), 16);
        assert_eq!(d.byte_length(), 64);
    }

    #[test]
    fn do_final_leaves_reset() {
        let mut d = Md4Digest::new();
        d.update(b"abc");
        let mut out = [0u8; 16];
        d.do_final(&mut out);
        // Finalizing again yields the empty-message digest, so it was reset.
        d.do_final(&mut out);
        let mut s = String::new();
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        assert_eq!(s, "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn chunked_matches_whole() {
        // A message spanning several blocks, fed whole and in pieces.
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut a = Md4Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 16];
        a.do_final(&mut oa);

        let mut b = Md4Digest::new();
        b.update(&msg[..1]);
        b.update(&msg[1..64]);
        b.update(&msg[64..130]);
        b.update(&msg[130..]);
        let mut ob = [0u8; 16];
        b.do_final(&mut ob);

        assert_eq!(oa, ob);
    }
}
