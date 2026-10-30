//! RIPEMD-160 message digest, ported from Bouncy Castle's
//! `RipeMD160Digest`.

use core::{convert::Infallible, fmt};

use tc_digest::TryDigest;
use tc_zeroize::Zeroize;

use crate::functions::{f1, f2, f3, f4, f5};
use crate::md_buffer::MdBuffer;

const DIGEST_LENGTH: usize = 20;
const BYTE_LENGTH: usize = 64;

const IV: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// The RIPEMD-160 digest, producing a 20-byte hash.
///
/// Constant time: the compression uses only additions, rotations and bitwise
/// operations, and the running time depends only on the message length.
///
/// Dropping or resetting the digest, which `do_final` also does, wipes its
/// chaining state and buffered input with volatile writes. Copies the
/// compression leaves in registers or on the stack, such as the message words
/// it reads, and copies a move leaves behind are not wiped.
///
/// `do_final` panics if the output buffer is shorter than 20 bytes.
#[derive(Clone)]
pub struct RipeMd160Digest {
    /// The five chaining registers.
    h: [u32; 5],
    /// The shared 64-byte block buffer.
    buf: MdBuffer<64>,
}

impl Default for RipeMd160Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl RipeMd160Digest {
    /// Creates a fresh RIPEMD-160 digest. Constant time.
    pub const fn new() -> Self {
        RipeMd160Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }

    /// Compresses one 64-byte block into the registers `h` (Bouncy Castle
    /// `ProcessBlock`), running two parallel lines of five rounds. The steps
    /// are unrolled as in Bouncy Castle. Constant time.
    fn compress(h: &mut [u32; 5], block: &[u8; 64]) {
        // RIPEMD is little-endian: read the block as 16 little-endian words.
        let mut x = [0u32; 16];
        for (word, chunk) in x.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes(chunk.try_into().expect("4-byte chunk"));
        }

        // Each step: a = rotl(a + f(b, c, d) + X[k] + constant, s) + e, then
        // c = rotl(c, 10), all wrapping.
        macro_rules! step {
            (
                $f:ident, $a:ident, $b:ident, $c:ident, $d:ident, $e:ident,
                $k:expr, $con:expr, $s:expr
            ) => {
                $a = $a
                    .wrapping_add($f($b, $c, $d))
                    .wrapping_add(x[$k])
                    .wrapping_add($con)
                    .rotate_left($s)
                    .wrapping_add($e);
                $c = $c.rotate_left(10);
            };
        }

        let [mut a, mut b, mut c, mut d, mut e] = *h;
        let [mut aa, mut bb, mut cc, mut dd, mut ee] = *h;

        // Round 1, left line, f1.
        step!(f1, a, b, c, d, e, 0, 0, 11);
        step!(f1, e, a, b, c, d, 1, 0, 14);
        step!(f1, d, e, a, b, c, 2, 0, 15);
        step!(f1, c, d, e, a, b, 3, 0, 12);
        step!(f1, b, c, d, e, a, 4, 0, 5);
        step!(f1, a, b, c, d, e, 5, 0, 8);
        step!(f1, e, a, b, c, d, 6, 0, 7);
        step!(f1, d, e, a, b, c, 7, 0, 9);
        step!(f1, c, d, e, a, b, 8, 0, 11);
        step!(f1, b, c, d, e, a, 9, 0, 13);
        step!(f1, a, b, c, d, e, 10, 0, 14);
        step!(f1, e, a, b, c, d, 11, 0, 15);
        step!(f1, d, e, a, b, c, 12, 0, 6);
        step!(f1, c, d, e, a, b, 13, 0, 7);
        step!(f1, b, c, d, e, a, 14, 0, 9);
        step!(f1, a, b, c, d, e, 15, 0, 8);

        // Round 1, right line, f5.
        step!(f5, aa, bb, cc, dd, ee, 5, 0x50a2_8be6, 8);
        step!(f5, ee, aa, bb, cc, dd, 14, 0x50a2_8be6, 9);
        step!(f5, dd, ee, aa, bb, cc, 7, 0x50a2_8be6, 9);
        step!(f5, cc, dd, ee, aa, bb, 0, 0x50a2_8be6, 11);
        step!(f5, bb, cc, dd, ee, aa, 9, 0x50a2_8be6, 13);
        step!(f5, aa, bb, cc, dd, ee, 2, 0x50a2_8be6, 15);
        step!(f5, ee, aa, bb, cc, dd, 11, 0x50a2_8be6, 15);
        step!(f5, dd, ee, aa, bb, cc, 4, 0x50a2_8be6, 5);
        step!(f5, cc, dd, ee, aa, bb, 13, 0x50a2_8be6, 7);
        step!(f5, bb, cc, dd, ee, aa, 6, 0x50a2_8be6, 7);
        step!(f5, aa, bb, cc, dd, ee, 15, 0x50a2_8be6, 8);
        step!(f5, ee, aa, bb, cc, dd, 8, 0x50a2_8be6, 11);
        step!(f5, dd, ee, aa, bb, cc, 1, 0x50a2_8be6, 14);
        step!(f5, cc, dd, ee, aa, bb, 10, 0x50a2_8be6, 14);
        step!(f5, bb, cc, dd, ee, aa, 3, 0x50a2_8be6, 12);
        step!(f5, aa, bb, cc, dd, ee, 12, 0x50a2_8be6, 6);

        // Round 2, left line, f2.
        step!(f2, e, a, b, c, d, 7, 0x5a82_7999, 7);
        step!(f2, d, e, a, b, c, 4, 0x5a82_7999, 6);
        step!(f2, c, d, e, a, b, 13, 0x5a82_7999, 8);
        step!(f2, b, c, d, e, a, 1, 0x5a82_7999, 13);
        step!(f2, a, b, c, d, e, 10, 0x5a82_7999, 11);
        step!(f2, e, a, b, c, d, 6, 0x5a82_7999, 9);
        step!(f2, d, e, a, b, c, 15, 0x5a82_7999, 7);
        step!(f2, c, d, e, a, b, 3, 0x5a82_7999, 15);
        step!(f2, b, c, d, e, a, 12, 0x5a82_7999, 7);
        step!(f2, a, b, c, d, e, 0, 0x5a82_7999, 12);
        step!(f2, e, a, b, c, d, 9, 0x5a82_7999, 15);
        step!(f2, d, e, a, b, c, 5, 0x5a82_7999, 9);
        step!(f2, c, d, e, a, b, 2, 0x5a82_7999, 11);
        step!(f2, b, c, d, e, a, 14, 0x5a82_7999, 7);
        step!(f2, a, b, c, d, e, 11, 0x5a82_7999, 13);
        step!(f2, e, a, b, c, d, 8, 0x5a82_7999, 12);

        // Round 2, right line, f4.
        step!(f4, ee, aa, bb, cc, dd, 6, 0x5c4d_d124, 9);
        step!(f4, dd, ee, aa, bb, cc, 11, 0x5c4d_d124, 13);
        step!(f4, cc, dd, ee, aa, bb, 3, 0x5c4d_d124, 15);
        step!(f4, bb, cc, dd, ee, aa, 7, 0x5c4d_d124, 7);
        step!(f4, aa, bb, cc, dd, ee, 0, 0x5c4d_d124, 12);
        step!(f4, ee, aa, bb, cc, dd, 13, 0x5c4d_d124, 8);
        step!(f4, dd, ee, aa, bb, cc, 5, 0x5c4d_d124, 9);
        step!(f4, cc, dd, ee, aa, bb, 10, 0x5c4d_d124, 11);
        step!(f4, bb, cc, dd, ee, aa, 14, 0x5c4d_d124, 7);
        step!(f4, aa, bb, cc, dd, ee, 15, 0x5c4d_d124, 7);
        step!(f4, ee, aa, bb, cc, dd, 8, 0x5c4d_d124, 12);
        step!(f4, dd, ee, aa, bb, cc, 12, 0x5c4d_d124, 7);
        step!(f4, cc, dd, ee, aa, bb, 4, 0x5c4d_d124, 6);
        step!(f4, bb, cc, dd, ee, aa, 9, 0x5c4d_d124, 15);
        step!(f4, aa, bb, cc, dd, ee, 1, 0x5c4d_d124, 13);
        step!(f4, ee, aa, bb, cc, dd, 2, 0x5c4d_d124, 11);

        // Round 3, left line, f3.
        step!(f3, d, e, a, b, c, 3, 0x6ed9_eba1, 11);
        step!(f3, c, d, e, a, b, 10, 0x6ed9_eba1, 13);
        step!(f3, b, c, d, e, a, 14, 0x6ed9_eba1, 6);
        step!(f3, a, b, c, d, e, 4, 0x6ed9_eba1, 7);
        step!(f3, e, a, b, c, d, 9, 0x6ed9_eba1, 14);
        step!(f3, d, e, a, b, c, 15, 0x6ed9_eba1, 9);
        step!(f3, c, d, e, a, b, 8, 0x6ed9_eba1, 13);
        step!(f3, b, c, d, e, a, 1, 0x6ed9_eba1, 15);
        step!(f3, a, b, c, d, e, 2, 0x6ed9_eba1, 14);
        step!(f3, e, a, b, c, d, 7, 0x6ed9_eba1, 8);
        step!(f3, d, e, a, b, c, 0, 0x6ed9_eba1, 13);
        step!(f3, c, d, e, a, b, 6, 0x6ed9_eba1, 6);
        step!(f3, b, c, d, e, a, 13, 0x6ed9_eba1, 5);
        step!(f3, a, b, c, d, e, 11, 0x6ed9_eba1, 12);
        step!(f3, e, a, b, c, d, 5, 0x6ed9_eba1, 7);
        step!(f3, d, e, a, b, c, 12, 0x6ed9_eba1, 5);

        // Round 3, right line, f3.
        step!(f3, dd, ee, aa, bb, cc, 15, 0x6d70_3ef3, 9);
        step!(f3, cc, dd, ee, aa, bb, 5, 0x6d70_3ef3, 7);
        step!(f3, bb, cc, dd, ee, aa, 1, 0x6d70_3ef3, 15);
        step!(f3, aa, bb, cc, dd, ee, 3, 0x6d70_3ef3, 11);
        step!(f3, ee, aa, bb, cc, dd, 7, 0x6d70_3ef3, 8);
        step!(f3, dd, ee, aa, bb, cc, 14, 0x6d70_3ef3, 6);
        step!(f3, cc, dd, ee, aa, bb, 6, 0x6d70_3ef3, 6);
        step!(f3, bb, cc, dd, ee, aa, 9, 0x6d70_3ef3, 14);
        step!(f3, aa, bb, cc, dd, ee, 11, 0x6d70_3ef3, 12);
        step!(f3, ee, aa, bb, cc, dd, 8, 0x6d70_3ef3, 13);
        step!(f3, dd, ee, aa, bb, cc, 12, 0x6d70_3ef3, 5);
        step!(f3, cc, dd, ee, aa, bb, 2, 0x6d70_3ef3, 14);
        step!(f3, bb, cc, dd, ee, aa, 10, 0x6d70_3ef3, 13);
        step!(f3, aa, bb, cc, dd, ee, 0, 0x6d70_3ef3, 13);
        step!(f3, ee, aa, bb, cc, dd, 4, 0x6d70_3ef3, 7);
        step!(f3, dd, ee, aa, bb, cc, 13, 0x6d70_3ef3, 5);

        // Round 4, left line, f4.
        step!(f4, c, d, e, a, b, 1, 0x8f1b_bcdc, 11);
        step!(f4, b, c, d, e, a, 9, 0x8f1b_bcdc, 12);
        step!(f4, a, b, c, d, e, 11, 0x8f1b_bcdc, 14);
        step!(f4, e, a, b, c, d, 10, 0x8f1b_bcdc, 15);
        step!(f4, d, e, a, b, c, 0, 0x8f1b_bcdc, 14);
        step!(f4, c, d, e, a, b, 8, 0x8f1b_bcdc, 15);
        step!(f4, b, c, d, e, a, 12, 0x8f1b_bcdc, 9);
        step!(f4, a, b, c, d, e, 4, 0x8f1b_bcdc, 8);
        step!(f4, e, a, b, c, d, 13, 0x8f1b_bcdc, 9);
        step!(f4, d, e, a, b, c, 3, 0x8f1b_bcdc, 14);
        step!(f4, c, d, e, a, b, 7, 0x8f1b_bcdc, 5);
        step!(f4, b, c, d, e, a, 15, 0x8f1b_bcdc, 6);
        step!(f4, a, b, c, d, e, 14, 0x8f1b_bcdc, 8);
        step!(f4, e, a, b, c, d, 5, 0x8f1b_bcdc, 6);
        step!(f4, d, e, a, b, c, 6, 0x8f1b_bcdc, 5);
        step!(f4, c, d, e, a, b, 2, 0x8f1b_bcdc, 12);

        // Round 4, right line, f2.
        step!(f2, cc, dd, ee, aa, bb, 8, 0x7a6d_76e9, 15);
        step!(f2, bb, cc, dd, ee, aa, 6, 0x7a6d_76e9, 5);
        step!(f2, aa, bb, cc, dd, ee, 4, 0x7a6d_76e9, 8);
        step!(f2, ee, aa, bb, cc, dd, 1, 0x7a6d_76e9, 11);
        step!(f2, dd, ee, aa, bb, cc, 3, 0x7a6d_76e9, 14);
        step!(f2, cc, dd, ee, aa, bb, 11, 0x7a6d_76e9, 14);
        step!(f2, bb, cc, dd, ee, aa, 15, 0x7a6d_76e9, 6);
        step!(f2, aa, bb, cc, dd, ee, 0, 0x7a6d_76e9, 14);
        step!(f2, ee, aa, bb, cc, dd, 5, 0x7a6d_76e9, 6);
        step!(f2, dd, ee, aa, bb, cc, 12, 0x7a6d_76e9, 9);
        step!(f2, cc, dd, ee, aa, bb, 2, 0x7a6d_76e9, 12);
        step!(f2, bb, cc, dd, ee, aa, 13, 0x7a6d_76e9, 9);
        step!(f2, aa, bb, cc, dd, ee, 9, 0x7a6d_76e9, 12);
        step!(f2, ee, aa, bb, cc, dd, 7, 0x7a6d_76e9, 5);
        step!(f2, dd, ee, aa, bb, cc, 10, 0x7a6d_76e9, 15);
        step!(f2, cc, dd, ee, aa, bb, 14, 0x7a6d_76e9, 8);

        // Round 5, left line, f5.
        step!(f5, b, c, d, e, a, 4, 0xa953_fd4e, 9);
        step!(f5, a, b, c, d, e, 0, 0xa953_fd4e, 15);
        step!(f5, e, a, b, c, d, 5, 0xa953_fd4e, 5);
        step!(f5, d, e, a, b, c, 9, 0xa953_fd4e, 11);
        step!(f5, c, d, e, a, b, 7, 0xa953_fd4e, 6);
        step!(f5, b, c, d, e, a, 12, 0xa953_fd4e, 8);
        step!(f5, a, b, c, d, e, 2, 0xa953_fd4e, 13);
        step!(f5, e, a, b, c, d, 10, 0xa953_fd4e, 12);
        step!(f5, d, e, a, b, c, 14, 0xa953_fd4e, 5);
        step!(f5, c, d, e, a, b, 1, 0xa953_fd4e, 12);
        step!(f5, b, c, d, e, a, 3, 0xa953_fd4e, 13);
        step!(f5, a, b, c, d, e, 8, 0xa953_fd4e, 14);
        step!(f5, e, a, b, c, d, 11, 0xa953_fd4e, 11);
        step!(f5, d, e, a, b, c, 6, 0xa953_fd4e, 8);
        step!(f5, c, d, e, a, b, 15, 0xa953_fd4e, 5);
        step!(f5, b, c, d, e, a, 13, 0xa953_fd4e, 6);

        // Round 5, right line, f1.
        step!(f1, bb, cc, dd, ee, aa, 12, 0, 8);
        step!(f1, aa, bb, cc, dd, ee, 15, 0, 5);
        step!(f1, ee, aa, bb, cc, dd, 10, 0, 12);
        step!(f1, dd, ee, aa, bb, cc, 4, 0, 9);
        step!(f1, cc, dd, ee, aa, bb, 1, 0, 12);
        step!(f1, bb, cc, dd, ee, aa, 5, 0, 5);
        step!(f1, aa, bb, cc, dd, ee, 8, 0, 14);
        step!(f1, ee, aa, bb, cc, dd, 7, 0, 6);
        step!(f1, dd, ee, aa, bb, cc, 6, 0, 8);
        step!(f1, cc, dd, ee, aa, bb, 2, 0, 13);
        step!(f1, bb, cc, dd, ee, aa, 13, 0, 6);
        step!(f1, aa, bb, cc, dd, ee, 14, 0, 5);
        step!(f1, ee, aa, bb, cc, dd, 0, 0, 15);
        step!(f1, dd, ee, aa, bb, cc, 3, 0, 13);
        step!(f1, cc, dd, ee, aa, bb, 9, 0, 11);
        step!(f1, bb, cc, dd, ee, aa, 11, 0, 11);

        // Combine the two lines into the new chaining value.
        let t = h[1].wrapping_add(c).wrapping_add(dd);
        h[1] = h[2].wrapping_add(d).wrapping_add(ee);
        h[2] = h[3].wrapping_add(e).wrapping_add(aa);
        h[3] = h[4].wrapping_add(a).wrapping_add(bb);
        h[4] = h[0].wrapping_add(b).wrapping_add(cc);
        h[0] = t;
    }
}

impl Drop for RipeMd160Digest {
    /// Wipes the chaining registers; the block buffer wipes itself.
    /// Constant time.
    fn drop(&mut self) {
        self.h.zeroize();
    }
}

impl fmt::Display for RipeMd160Digest {
    /// Writes `RIPEMD160` without inspecting the digest state. Constant time
    /// with respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RIPEMD160")
    }
}

impl TryDigest for RipeMd160Digest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let Self { h, buf } = self;
        buf.update(input, |block| Self::compress(h, block));
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
            "output buffer shorter than the 20-byte RIPEMD-160 digest"
        );
        {
            let Self { h, buf } = self;
            // The RIPEMD length field is the bit length as a little-endian u64.
            let bit_len = buf.byte_count() << 3;
            buf.finish(&bit_len.to_le_bytes(), |block| Self::compress(h, block));
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
