//! SHA-512/t message digest (FIPS 180-4), ported from Bouncy Castle's
//! `Sha512tDigest`.
//!
//! SHA-512/t is SHA-512 with its output truncated to `t` bits and a distinct
//! initial hash value for each `t`, so SHA-512/256 is not merely truncated
//! SHA-512. The IV is the SHA-512 digest of the ASCII name `"SHA-512/t"`,
//! computed from the SHA-512 IV with every word XORed with `0xa5a5...a5`.

use core::convert::Infallible;

use tc_digest::TryDigest;

use crate::md_buffer::MdBuffer;
use crate::sha512_core::{IV as SHA512_IV, compress};

const BYTE_LENGTH: usize = 128;
const A5: u64 = 0xa5a5_a5a5_a5a5_a5a5;
const NAME_PREFIX: &[u8] = b"SHA-512/";
/// The length of the longest name, `"SHA-512/504"`.
const NAME_CAPACITY: usize = NAME_PREFIX.len() + 3;

/// The SHA-512/t digest (FIPS 180-4), producing a `t / 8`-byte hash.
///
/// `t` is a multiple of 8 from 8 to 504 other than 384, which is SHA-384's
/// length. SHA-512/224 and SHA-512/256 are the lengths FIPS 180-4 approves.
///
/// Constant time: the compression uses only additions, rotations, shifts and
/// bitwise operations, and the running time depends only on the message
/// length and `t`.
///
/// `do_final` panics if the output buffer is shorter than `t / 8` bytes.
#[derive(Clone)]
pub struct Sha512tDigest {
    /// The eight 64-bit chaining registers.
    h: [u64; 8],
    /// The shared 128-byte block buffer.
    buf: MdBuffer<128>,
    /// The IV derived from `t`, restored on reset.
    iv: [u64; 8],
    /// The output length in bytes, `t / 8`.
    digest_len: usize,
    /// The ASCII algorithm name, such as `"SHA-512/256"`, in the first
    /// `name_len` bytes.
    name: [u8; NAME_CAPACITY],
    name_len: usize,
}

impl Sha512tDigest {
    /// Creates a SHA-512/`bit_length` digest. Constant time: deriving the IV
    /// depends only on `bit_length`.
    ///
    /// # Panics
    ///
    /// Panics if `bit_length` is zero, not a multiple of 8, 512 or more, or 384
    /// (use [`Sha384Digest`](crate::Sha384Digest) instead). Bouncy Castle
    /// throws `ArgumentException` for the same values, except that it accepts
    /// zero.
    pub fn new(bit_length: usize) -> Self {
        assert!(bit_length != 0, "SHA-512/t: bit length must be positive");
        assert!(
            bit_length < 512,
            "SHA-512/t: bit length must be less than 512"
        );
        assert!(
            bit_length % 8 == 0,
            "SHA-512/t: bit length must be a multiple of 8"
        );
        assert!(
            bit_length != 384,
            "SHA-512/t: bit length cannot be 384, use SHA-384 instead"
        );

        let (name, name_len) = format_name(bit_length);
        let iv = generate_iv(&name[..name_len]);
        Sha512tDigest {
            h: iv,
            buf: MdBuffer::new(),
            iv,
            digest_len: bit_length / 8,
            name,
            name_len,
        }
    }
}

/// Formats the ASCII name `"SHA-512/<t>"` for `t` in `8..=504`, returning the
/// buffer and the name's length. Constant time.
fn format_name(bit_length: usize) -> ([u8; NAME_CAPACITY], usize) {
    let mut digits = [0u8; 3];
    let mut n = bit_length;
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }

    let mut name = [0u8; NAME_CAPACITY];
    let len = NAME_PREFIX.len() + digits.len() - i;
    name[..NAME_PREFIX.len()].copy_from_slice(NAME_PREFIX);
    name[NAME_PREFIX.len()..len].copy_from_slice(&digits[i..]);
    (name, len)
}

/// Derives the SHA-512/t IV (Bouncy Castle `tIvGenerate`): SHA-512 over the
/// ASCII `name`, starting from the SHA-512 IV XORed with `0xa5` bytes.
/// Constant time.
fn generate_iv(name: &[u8]) -> [u64; 8] {
    let mut h = SHA512_IV;
    for x in &mut h {
        *x ^= A5;
    }

    let mut buf = MdBuffer::<128>::new();
    buf.update(name, |b| compress(&mut h, b));
    let bit_len = (buf.byte_count() as u128) << 3;
    buf.finish(&bit_len.to_be_bytes(), |b| compress(&mut h, b));
    h
}

impl TryDigest for Sha512tDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).expect("the name is ASCII")
    }

    /// Returns `t / 8`, the output length chosen at construction.
    fn digest_size(&self) -> usize {
        self.digest_len
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let Self { h, buf, .. } = self;
        buf.update(input, |block| compress(h, block));
        Ok(())
    }

    /// Writes the `t / 8`-byte digest to the start of `output` and resets.
    ///
    /// # Panics
    ///
    /// Panics if `output` is shorter than `t / 8` bytes, before changing any
    /// state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.digest_len;
        assert!(
            output.len() >= len,
            "output buffer shorter than the SHA-512/t digest"
        );
        {
            let Self { h, buf, .. } = self;
            let bit_len = (buf.byte_count() as u128) << 3;
            buf.finish(&bit_len.to_be_bytes(), |block| compress(h, block));
            // Serialize all 64 bytes, then truncate to t / 8, which may end
            // partway through a word.
            let mut full = [0u8; 64];
            for (chunk, &word) in full.chunks_exact_mut(8).zip(h.iter()) {
                chunk.copy_from_slice(&word.to_be_bytes());
            }
            output[..len].copy_from_slice(&full[..len]);
        }
        self.try_reset()?;
        Ok(len)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.h = self.iv;
        self.buf = MdBuffer::new();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String};

    use super::*;
    use tc_digest::Digest;

    fn hex(d: &mut Sha512tDigest, input: &[u8]) -> String {
        d.update(input);
        let mut out = [0u8; 64];
        let n = d.do_final(&mut out);
        let mut s = String::with_capacity(n * 2);
        for &b in &out[..n] {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // NIST's SHA-512/224 and SHA-512/256 example vectors.
    #[test]
    fn sha512_224_vectors() {
        let mut d = Sha512tDigest::new(224);
        assert_eq!(d.algorithm_name(), "SHA-512/224");
        assert_eq!(d.digest_size(), 28);
        assert_eq!(
            hex(&mut d, b""),
            "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
        );
        assert_eq!(
            hex(&mut d, b"abc"),
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
        );
    }

    #[test]
    fn sha512_256_vectors() {
        let mut d = Sha512tDigest::new(256);
        assert_eq!(d.algorithm_name(), "SHA-512/256");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(
            hex(&mut d, b""),
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
        );
        assert_eq!(
            hex(&mut d, b"abc"),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
        );
    }

    // FIPS 180-4, sections 5.3.6.1 and 5.3.6.2, list the derived IVs.
    #[test]
    fn derived_ivs_match_fips_180_4() {
        assert_eq!(
            Sha512tDigest::new(224).iv,
            [
                0x8c3d_37c8_1954_4da2,
                0x73e1_9966_89dc_d4d6,
                0x1dfa_b7ae_32ff_9c82,
                0x679d_d514_582f_9fcf,
                0x0f6d_2b69_7bd4_4da8,
                0x77e3_6f73_04c4_8942,
                0x3f9d_85a8_6a1d_36c8,
                0x1112_e6ad_91d6_92a1,
            ]
        );
        assert_eq!(
            Sha512tDigest::new(256).iv,
            [
                0x2231_2194_fc2b_f72c,
                0x9f55_5fa3_c84c_64c2,
                0x2393_b86b_6f53_b151,
                0x9638_7719_5940_eabd,
                0x9628_3ee2_a88e_ffe3,
                0xbe5e_1e25_5386_3992,
                0x2b01_99fc_2c85_b8aa,
                0x0eb7_2ddc_81c5_2ca2,
            ]
        );
    }

    #[test]
    fn names_cover_one_to_three_digit_lengths() {
        assert_eq!(Sha512tDigest::new(8).algorithm_name(), "SHA-512/8");
        assert_eq!(Sha512tDigest::new(80).algorithm_name(), "SHA-512/80");
        assert_eq!(Sha512tDigest::new(504).algorithm_name(), "SHA-512/504");
        assert_eq!(Sha512tDigest::new(504).digest_size(), 63);
    }

    #[test]
    #[should_panic(expected = "must be positive")]
    fn rejects_zero() {
        let _ = Sha512tDigest::new(0);
    }

    #[test]
    #[should_panic(expected = "cannot be 384")]
    fn rejects_384() {
        let _ = Sha512tDigest::new(384);
    }

    #[test]
    #[should_panic(expected = "less than 512")]
    fn rejects_512() {
        let _ = Sha512tDigest::new(512);
    }

    #[test]
    #[should_panic(expected = "multiple of 8")]
    fn rejects_non_multiple_of_8() {
        let _ = Sha512tDigest::new(100);
    }
}
