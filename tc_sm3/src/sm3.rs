//! SM3 message digest (GB/T 32905-2016), ported from Bouncy Castle's
//! `SM3Digest`.

use core::{convert::Infallible, fmt};

use tc_digest::TryDigest;
use tc_zeroize::Zeroize;

use crate::md_buffer::MdBuffer;

const DIGEST_LENGTH: usize = 32;
const BYTE_LENGTH: usize = 64;

// The initial value IV of GB/T 32905-2016.
const IV: [u32; 8] = [
    0x7380_166f,
    0x4914_b2b9,
    0x1724_42d7,
    0xda8a_0600,
    0xa96f_30bc,
    0x1631_38aa,
    0xe38d_ee4d,
    0xb0fb_0e4e,
];

/// The permutation P0 of the compression function. Constant time.
#[inline(always)]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

/// The permutation P1 of the message expansion. Constant time.
#[inline(always)]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

/// Compresses one 64-byte big-endian block into the eight chaining registers
/// `v` (Bouncy Castle `ProcessBlock`). Constant time: the message expansion
/// and the 64 rounds use only additions, rotations and bitwise operations, and
/// the round number alone chooses the boolean functions and the constant.
fn compress(v: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 68];
    for (word, chunk) in w[..16].iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(chunk.try_into().expect("4-byte chunk"));
    }
    for j in 16..68 {
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
            ^ w[j - 13].rotate_left(7)
            ^ w[j - 6];
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *v;

    for j in 0..64 {
        let (ff, gg, t) = if j < 16 {
            (a ^ b ^ c, e ^ f ^ g, 0x79cc_4519u32.rotate_left(j as u32))
        } else {
            (
                (a & b) | (a & c) | (b & c),
                (e & f) | ((!e) & g),
                0x7a87_9d8au32.rotate_left((j % 32) as u32),
            )
        };

        let a12 = a.rotate_left(12);
        let ss1 = a12.wrapping_add(e).wrapping_add(t).rotate_left(7);
        let ss2 = ss1 ^ a12;
        let tt1 = ff
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(w[j] ^ w[j + 4]);
        let tt2 = gg.wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j]);

        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    v[0] ^= a;
    v[1] ^= b;
    v[2] ^= c;
    v[3] ^= d;
    v[4] ^= e;
    v[5] ^= f;
    v[6] ^= g;
    v[7] ^= h;
}

/// The SM3 digest (GB/T 32905-2016), producing a 32-byte hash.
///
/// Constant time: the compression uses only additions, rotations and bitwise
/// operations, and the running time depends only on the message length.
///
/// Dropping or resetting the digest, which `do_final` also does, wipes its
/// chaining state and buffered input with volatile writes. Copies the
/// compression leaves in registers or on the stack, such as the expanded
/// message words, and copies a move leaves behind are not wiped.
///
/// `do_final` panics if the output buffer is shorter than 32 bytes.
#[derive(Clone)]
pub struct Sm3Digest {
    /// The eight chaining registers V.
    v: [u32; 8],
    /// The shared 64-byte block buffer.
    buf: MdBuffer<64>,
}

impl Default for Sm3Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Sm3Digest {
    /// Creates a fresh SM3 digest. Constant time.
    pub const fn new() -> Self {
        Sm3Digest {
            v: IV,
            buf: MdBuffer::new(),
        }
    }
}

impl Drop for Sm3Digest {
    /// Wipes the chaining registers; the block buffer wipes itself.
    /// Constant time.
    fn drop(&mut self) {
        self.v.zeroize();
    }
}

impl fmt::Display for Sm3Digest {
    /// Writes `SM3` without inspecting the digest state. Constant time with
    /// respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SM3")
    }
}

impl TryDigest for Sm3Digest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let Self { v, buf } = self;
        buf.update(input, |block| compress(v, block));
        Ok(())
    }

    /// Writes the 32-byte digest to the start of `output` and resets.
    ///
    /// # Panics
    ///
    /// Panics if `output` is shorter than 32 bytes, before changing any state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        assert!(
            output.len() >= DIGEST_LENGTH,
            "output buffer shorter than the 32-byte SM3 digest"
        );
        {
            let Self { v, buf } = self;
            // The SM3 length field is the bit length as a big-endian u64.
            let bit_len = buf.byte_count() << 3;
            buf.finish(&bit_len.to_be_bytes(), |block| compress(v, block));
            for (i, &word) in v.iter().enumerate() {
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
