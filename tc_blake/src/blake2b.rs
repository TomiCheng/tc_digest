//! BLAKE2b message digest, ported from Bouncy Castle's `Blake2bDigest`.
//!
//! The portable compression function is always available. On x86 and x86-64,
//! AVX2 is detected at run time through `tc_runtime`, without needing `std`,
//! and used when present; other targets use the portable path.

use core::convert::Infallible;

use tc_digest::TryDigest;
use tc_zeroize::Zeroize;

const BLOCK_LENGTH: usize = 128;
const DEFAULT_DIGEST_LENGTH: usize = 64;
const ROUNDS: usize = 12;

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; ROUNDS] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// The G function on four state words. Constant time.
#[inline(always)]
fn mix(state: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    let mut va = state[a];
    let mut vb = state[b];
    let mut vc = state[c];
    let mut vd = state[d];

    va = va.wrapping_add(vb).wrapping_add(x);
    vd = (vd ^ va).rotate_right(32);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_right(24);
    va = va.wrapping_add(vb).wrapping_add(y);
    vd = (vd ^ va).rotate_right(16);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_right(63);

    state[a] = va;
    state[b] = vb;
    state[c] = vc;
    state[d] = vd;
}

/// Compresses one block in plain Rust. Constant time: the message words are
/// picked by the public SIGMA permutation.
fn compress_portable(
    chain: &mut [u64; 8],
    counter_low: u64,
    counter_high: u64,
    final_flag: u64,
    block: &[u8; BLOCK_LENGTH],
) {
    let mut message = [0u64; 16];
    for (word, bytes) in message.iter_mut().zip(block.chunks_exact(8)) {
        *word = u64::from_le_bytes(bytes.try_into().unwrap());
    }

    let mut state = [0u64; 16];
    state[..8].copy_from_slice(chain);
    state[8..].copy_from_slice(&IV);
    state[12] ^= counter_low;
    state[13] ^= counter_high;
    state[14] ^= final_flag;

    for permutation in SIGMA {
        mix(
            &mut state,
            0,
            4,
            8,
            12,
            message[permutation[0]],
            message[permutation[1]],
        );
        mix(
            &mut state,
            1,
            5,
            9,
            13,
            message[permutation[2]],
            message[permutation[3]],
        );
        mix(
            &mut state,
            2,
            6,
            10,
            14,
            message[permutation[4]],
            message[permutation[5]],
        );
        mix(
            &mut state,
            3,
            7,
            11,
            15,
            message[permutation[6]],
            message[permutation[7]],
        );
        mix(
            &mut state,
            0,
            5,
            10,
            15,
            message[permutation[8]],
            message[permutation[9]],
        );
        mix(
            &mut state,
            1,
            6,
            11,
            12,
            message[permutation[10]],
            message[permutation[11]],
        );
        mix(
            &mut state,
            2,
            7,
            8,
            13,
            message[permutation[12]],
            message[permutation[13]],
        );
        mix(
            &mut state,
            3,
            4,
            9,
            14,
            message[permutation[14]],
            message[permutation[15]],
        );
    }

    for i in 0..8 {
        chain[i] ^= state[i] ^ state[i + 8];
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod avx2 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    use super::{BLOCK_LENGTH, IV, SIGMA};

    // Rust 1.85 still treats these intrinsics as unsafe inside target_feature
    // functions; newer compilers consider the block unnecessary.
    /// Four words in one vector, the first in the lowest lane. Constant time.
    #[allow(unused_unsafe)]
    #[target_feature(enable = "avx2")]
    unsafe fn set4(a: u64, b: u64, c: u64, d: u64) -> __m256i {
        // SAFETY: the function itself requires AVX2.
        unsafe { _mm256_set_epi64x(d as i64, c as i64, b as i64, a as i64) }
    }

    /// Rotates every lane right by `RIGHT` bits. Constant time.
    #[allow(unused_unsafe)]
    #[target_feature(enable = "avx2")]
    unsafe fn rotate_right<const RIGHT: i32, const LEFT: i32>(value: __m256i) -> __m256i {
        // SAFETY: the function itself requires AVX2.
        unsafe {
            _mm256_or_si256(
                _mm256_srli_epi64::<RIGHT>(value),
                _mm256_slli_epi64::<LEFT>(value),
            )
        }
    }

    /// The G function on four columns or diagonals at once. Constant time.
    #[target_feature(enable = "avx2")]
    unsafe fn mix(
        a: &mut __m256i,
        b: &mut __m256i,
        c: &mut __m256i,
        d: &mut __m256i,
        x: __m256i,
        y: __m256i,
    ) {
        // SAFETY: the function itself requires AVX2 and all values are vector
        // registers without additional memory requirements.
        unsafe {
            *a = _mm256_add_epi64(_mm256_add_epi64(*a, *b), x);
            *d = _mm256_shuffle_epi32::<0xb1>(_mm256_xor_si256(*d, *a));
            *c = _mm256_add_epi64(*c, *d);
            *b = rotate_right::<24, 40>(_mm256_xor_si256(*b, *c));
            *a = _mm256_add_epi64(_mm256_add_epi64(*a, *b), y);
            *d = rotate_right::<16, 48>(_mm256_xor_si256(*d, *a));
            *c = _mm256_add_epi64(*c, *d);
            *b = rotate_right::<63, 1>(_mm256_xor_si256(*b, *c));
        }
    }

    /// Compresses one block with four parallel G functions in each AVX2 vector.
    /// Constant time.
    ///
    /// # Safety
    ///
    /// The caller must establish that the current CPU and OS support AVX2.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn compress(
        chain: &mut [u64; 8],
        counter_low: u64,
        counter_high: u64,
        final_flag: u64,
        block: &[u8; BLOCK_LENGTH],
    ) {
        // SAFETY: this entire block is guarded by the function's AVX2 target
        // feature, and all pointers refer to properly sized local arrays.
        unsafe {
            let mut message = [0u64; 16];
            for (word, bytes) in message.iter_mut().zip(block.chunks_exact(8)) {
                *word = u64::from_le_bytes(bytes.try_into().unwrap());
            }

            let original_low = set4(chain[0], chain[1], chain[2], chain[3]);
            let original_high = set4(chain[4], chain[5], chain[6], chain[7]);
            let mut row1 = original_low;
            let mut row2 = original_high;
            let mut row3 = set4(IV[0], IV[1], IV[2], IV[3]);
            let mut row4 = set4(
                IV[4] ^ counter_low,
                IV[5] ^ counter_high,
                IV[6] ^ final_flag,
                IV[7],
            );

            for permutation in SIGMA {
                let x = set4(
                    message[permutation[0]],
                    message[permutation[2]],
                    message[permutation[4]],
                    message[permutation[6]],
                );
                let y = set4(
                    message[permutation[1]],
                    message[permutation[3]],
                    message[permutation[5]],
                    message[permutation[7]],
                );
                mix(&mut row1, &mut row2, &mut row3, &mut row4, x, y);

                row2 = _mm256_permute4x64_epi64::<0x39>(row2);
                row3 = _mm256_permute4x64_epi64::<0x4e>(row3);
                row4 = _mm256_permute4x64_epi64::<0x93>(row4);

                let x = set4(
                    message[permutation[8]],
                    message[permutation[10]],
                    message[permutation[12]],
                    message[permutation[14]],
                );
                let y = set4(
                    message[permutation[9]],
                    message[permutation[11]],
                    message[permutation[13]],
                    message[permutation[15]],
                );
                mix(&mut row1, &mut row2, &mut row3, &mut row4, x, y);

                row2 = _mm256_permute4x64_epi64::<0x93>(row2);
                row3 = _mm256_permute4x64_epi64::<0x4e>(row3);
                row4 = _mm256_permute4x64_epi64::<0x39>(row4);
            }

            let low = _mm256_xor_si256(original_low, _mm256_xor_si256(row1, row3));
            let high = _mm256_xor_si256(original_high, _mm256_xor_si256(row2, row4));
            _mm256_storeu_si256(chain.as_mut_ptr().cast(), low);
            _mm256_storeu_si256(chain.as_mut_ptr().add(4).cast(), high);
        }
    }
}

/// Compresses one block with AVX2 when the CPU has it, in plain Rust otherwise.
/// Constant time: the CPU, not the data, picks the path.
#[allow(unsafe_code)]
#[inline]
fn compress(
    chain: &mut [u64; 8],
    counter_low: u64,
    counter_high: u64,
    final_flag: u64,
    block: &[u8; BLOCK_LENGTH],
) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if tc_runtime::intrinsics::x86::Avx2::detect().is_some() {
        // SAFETY: the detected token proves the current CPU and OS support
        // AVX2.
        unsafe {
            avx2::compress(chain, counter_low, counter_high, final_flag, block);
        }
        return;
    }

    compress_portable(chain, counter_low, counter_high, final_flag, block);
}

/// The BLAKE2b message digest with optional key, salt, and personalization.
/// Constant time.
#[derive(Clone)]
pub struct Blake2bDigest {
    chain: [u64; 8],
    buffer: [u8; BLOCK_LENGTH],
    buffer_position: usize,
    counter_low: u64,
    counter_high: u64,
    final_flag: u64,
    digest_length: usize,
    key: [u8; 64],
    key_length: usize,
    salt: [u8; 16],
    personalization: [u8; 16],
}

impl Default for Blake2bDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2bDigest {
    /// Creates an unkeyed BLAKE2b-512 digest. Constant time.
    pub fn new() -> Self {
        Self::with_parameters(None, DEFAULT_DIGEST_LENGTH, None, None)
    }

    /// Creates an unkeyed BLAKE2b digest with an output size from 8 to 512 bits.
    /// Constant time.
    pub fn with_digest_size(digest_bits: usize) -> Self {
        assert!(
            (8..=512).contains(&digest_bits) && digest_bits % 8 == 0,
            "BLAKE2b digest bit length must be a multiple of 8 and not greater than 512"
        );
        Self::with_parameters(None, digest_bits / 8, None, None)
    }

    /// Creates keyed BLAKE2b-512. An empty key selects unkeyed hashing.
    /// Constant time with respect to the key; its length is public.
    pub fn with_key(key: &[u8]) -> Self {
        Self::with_parameters(Some(key), DEFAULT_DIGEST_LENGTH, None, None)
    }

    /// Creates BLAKE2b with its full sequential-mode parameter set. Constant time
    /// with respect to the key, salt and personalization; their lengths are public.
    ///
    /// `digest_length` is measured in bytes (1..=64), `key` may contain at
    /// most 64 bytes, and salt/personalization must each contain exactly 16
    /// bytes when present.
    pub fn with_parameters(
        key: Option<&[u8]>,
        digest_length: usize,
        salt: Option<&[u8]>,
        personalization: Option<&[u8]>,
    ) -> Self {
        assert!(
            (1..=64).contains(&digest_length),
            "BLAKE2b digest length must be between 1 and 64 bytes"
        );
        let key = key.unwrap_or_default();
        assert!(key.len() <= 64, "BLAKE2b keys must not exceed 64 bytes");
        if let Some(salt) = salt {
            assert_eq!(salt.len(), 16, "BLAKE2b salt must be exactly 16 bytes");
        }
        if let Some(personalization) = personalization {
            assert_eq!(
                personalization.len(),
                16,
                "BLAKE2b personalization must be exactly 16 bytes"
            );
        }

        let mut digest = Blake2bDigest {
            chain: [0; 8],
            buffer: [0; BLOCK_LENGTH],
            buffer_position: 0,
            counter_low: 0,
            counter_high: 0,
            final_flag: 0,
            digest_length,
            key: [0; 64],
            key_length: key.len(),
            salt: [0; 16],
            personalization: [0; 16],
        };
        digest.key[..key.len()].copy_from_slice(key);
        if let Some(salt) = salt {
            digest.salt.copy_from_slice(salt);
        }
        if let Some(personalization) = personalization {
            digest.personalization.copy_from_slice(personalization);
        }
        digest.reset_state();
        digest
    }

    /// Restarts from the parameter block, with the key as the first block when
    /// there is one. Constant time.
    fn reset_state(&mut self) {
        self.chain = IV;
        self.chain[0] ^= self.digest_length as u64 | ((self.key_length as u64) << 8) | 0x0101_0000;
        self.chain[4] ^= u64::from_le_bytes(self.salt[..8].try_into().expect("8-byte salt"));
        self.chain[5] ^= u64::from_le_bytes(self.salt[8..].try_into().expect("8-byte salt"));
        self.chain[6] ^= u64::from_le_bytes(
            self.personalization[..8]
                .try_into()
                .expect("8-byte personalization"),
        );
        self.chain[7] ^= u64::from_le_bytes(
            self.personalization[8..]
                .try_into()
                .expect("8-byte personalization"),
        );

        self.buffer = [0; BLOCK_LENGTH];
        self.buffer_position = 0;
        self.counter_low = 0;
        self.counter_high = 0;
        self.final_flag = 0;
        if self.key_length != 0 {
            self.buffer[..self.key_length].copy_from_slice(&self.key[..self.key_length]);
            self.buffer_position = BLOCK_LENGTH;
        }
    }

    /// Adds `increment` bytes to the block counter. Constant time with respect
    /// to the message; the count is public.
    fn increment_counter(&mut self, increment: usize) {
        let previous = self.counter_low;
        self.counter_low = self.counter_low.wrapping_add(increment as u64);
        if self.counter_low < previous {
            self.counter_high = self.counter_high.wrapping_add(1);
        }
    }

    /// Compresses the buffered block. Constant time.
    fn compress_buffer(&mut self) {
        compress(
            &mut self.chain,
            self.counter_low,
            self.counter_high,
            self.final_flag,
            &self.buffer,
        );
    }

    /// Wipes the retained key and the current input buffer. Constant time.
    pub fn clear_key(&mut self) {
        self.key.zeroize();
        self.key_length = 0;
        self.buffer.zeroize();
    }

    /// Clears the retained salt. Call [`reset`](tc_digest::Digest::reset)
    /// before starting a new computation with the cleared parameter. Constant time.
    pub fn clear_salt(&mut self) {
        self.salt.zeroize();
    }
}

impl TryDigest for Blake2bDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.digest_length
    }

    fn byte_length(&self) -> usize {
        BLOCK_LENGTH
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if input.is_empty() {
            return Ok(());
        }

        if self.buffer_position != 0 {
            let remaining = BLOCK_LENGTH - self.buffer_position;
            if input.len() > remaining {
                self.buffer[self.buffer_position..].copy_from_slice(&input[..remaining]);
                self.increment_counter(BLOCK_LENGTH);
                self.compress_buffer();
                self.buffer_position = 0;
                input = &input[remaining..];
            } else {
                self.buffer[self.buffer_position..self.buffer_position + input.len()]
                    .copy_from_slice(input);
                self.buffer_position += input.len();
                return Ok(());
            }
        }

        while input.len() > BLOCK_LENGTH {
            let block: &[u8; BLOCK_LENGTH] = input[..BLOCK_LENGTH]
                .try_into()
                .expect("128-byte BLAKE2b block");
            self.increment_counter(BLOCK_LENGTH);
            compress(
                &mut self.chain,
                self.counter_low,
                self.counter_high,
                self.final_flag,
                block,
            );
            input = &input[BLOCK_LENGTH..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_position = input.len();
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.digest_length;
        assert!(
            output.len() >= len,
            "output buffer shorter than the {len}-byte digest"
        );
        self.final_flag = u64::MAX;
        self.increment_counter(self.buffer_position);
        self.buffer[self.buffer_position..].fill(0);
        self.compress_buffer();

        for (word, output) in self
            .chain
            .iter()
            .zip(output[..self.digest_length].chunks_mut(8))
        {
            let bytes = word.to_le_bytes();
            output.copy_from_slice(&bytes[..output.len()]);
        }

        let digest_length = self.digest_length;
        self.reset_state();
        Ok(digest_length)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.reset_state();
        Ok(())
    }
}

impl Drop for Blake2bDigest {
    /// Wipes the chaining value, the buffer, the counters, the key, the salt
    /// and the personalization. Constant time.
    fn drop(&mut self) {
        self.chain.zeroize();
        self.buffer.zeroize();
        self.buffer_position.zeroize();
        self.counter_low.zeroize();
        self.counter_high.zeroize();
        self.key.zeroize();
        self.key_length.zeroize();
        self.salt.zeroize();
        self.personalization.zeroize();
    }
}

impl core::fmt::Display for Blake2bDigest {
    /// Writes `BLAKE2b` without inspecting the state. Constant time with respect
    /// to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BLAKE2b")
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        format,
        string::{String, ToString},
        vec::Vec,
    };

    use super::*;
    use tc_digest::Digest;

    fn hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push_str(&format!("{byte:02x}"));
        }
        encoded
    }

    fn digest_hex(digest: &mut Blake2bDigest, input: &[u8]) -> String {
        digest.update(input);
        let mut output = [0u8; 64];
        let size = digest.do_final(&mut output);
        hex(&output[..size])
    }

    #[test]
    fn rfc_and_bc_unkeyed_vectors() {
        let vectors: &[(&[u8], &str)] = &[
            (
                b"",
                "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
            ),
            (
                b"abc",
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
            ),
            (
                b"The quick brown fox jumps over the lazy dog",
                "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
            ),
        ];
        for &(message, expected) in vectors {
            assert_eq!(digest_hex(&mut Blake2bDigest::new(), message), expected);
        }
    }

    #[test]
    fn bc_keyed_vectors() {
        let key: Vec<u8> = (0..64).collect();
        let vectors: &[(&[u8], &str)] = &[
            (
                b"",
                "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
            ),
            (
                &[0x00],
                "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd",
            ),
            (
                &[0x00, 0x01],
                "da2cfbe2d8409a0f38026113884f84b50156371ae304c4430173d08a99d9fb1b983164a3770706d537f49e0c916d9f32b95cc37a95b99d857436f0232c88a965",
            ),
        ];
        let mut digest = Blake2bDigest::with_key(&key);
        for &(message, expected) in vectors {
            assert_eq!(digest_hex(&mut digest, message), expected);
        }
    }

    #[test]
    fn parameters_output_length_clone_chunking_and_reset() {
        let key: Vec<u8> = (0..64).collect();
        let salt: Vec<u8> = (0..16).collect();
        let personalization: Vec<u8> = (16..32).collect();
        let message: Vec<u8> = (0..78).collect();
        let mut digest =
            Blake2bDigest::with_parameters(Some(&key), 16, Some(&salt), Some(&personalization));
        assert_eq!(digest.to_string(), "BLAKE2b");
        assert_eq!(digest.digest_size(), 16);
        assert_eq!(digest.byte_length(), 128);
        digest.update(&message);

        let mut cloned = digest.clone();
        let mut expected = [0u8; 16];
        let mut cloned_output = [0u8; 16];
        digest.do_final(&mut expected);
        cloned.do_final(&mut cloned_output);
        assert_eq!(expected, cloned_output);
        assert_eq!(hex(&expected), "b6d48ed5771b17414c4e08bd8d8a3bc4");

        let mut chunked =
            Blake2bDigest::with_parameters(Some(&key), 16, Some(&salt), Some(&personalization));
        for chunk in message.chunks(7) {
            chunked.update(chunk);
        }
        let mut actual = [0u8; 16];
        chunked.do_final(&mut actual);
        assert_eq!(actual, expected);

        let mut reset_output = [0u8; 16];
        chunked.update(&message);
        chunked.reset();
        chunked.update(&message);
        chunked.do_final(&mut reset_output);
        assert_eq!(reset_output, expected);
    }

    #[test]
    fn every_output_size_and_block_boundaries() {
        let message: Vec<u8> = (0..=255).collect();
        for bytes in 1..=64 {
            let mut a = Blake2bDigest::with_digest_size(bytes * 8);
            let mut b = Blake2bDigest::with_parameters(None, bytes, None, None);
            a.update(&message);
            for chunk in message.chunks(127) {
                b.update(chunk);
            }
            let mut left = [0u8; 64];
            let mut right = [0u8; 64];
            assert_eq!(a.do_final(&mut left), bytes);
            assert_eq!(b.do_final(&mut right), bytes);
            assert_eq!(&left[..bytes], &right[..bytes]);
        }

        for length in [0, 1, 127, 128, 129, 255, 256] {
            let input = &message[..length];
            let expected = digest_hex(&mut Blake2bDigest::new(), input);
            let mut bytewise = Blake2bDigest::new();
            for byte in input {
                bytewise.update(core::slice::from_ref(byte));
            }
            assert_eq!(digest_hex(&mut bytewise, b""), expected);
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[allow(unsafe_code)]
    #[test]
    fn avx2_matches_portable() {
        if tc_runtime::intrinsics::x86::Avx2::detect().is_none() {
            return;
        }

        for case in 0..32u64 {
            let block = core::array::from_fn(|i| (i as u8).wrapping_mul(17) ^ case as u8);
            let chain = core::array::from_fn(|i| IV[i] ^ case.wrapping_mul((i + 1) as u64));
            for &(counter_low, counter_high, final_flag) in
                &[(0, 0, 0), (127, 0, u64::MAX), (u64::MAX - 3, case, 0)]
            {
                let mut portable = chain;
                let mut accelerated = chain;
                compress_portable(&mut portable, counter_low, counter_high, final_flag, &block);
                // SAFETY: guarded by runtime AVX2 detection above.
                unsafe {
                    avx2::compress(
                        &mut accelerated,
                        counter_low,
                        counter_high,
                        final_flag,
                        &block,
                    );
                }
                assert_eq!(accelerated, portable, "case {case}");
            }
        }
    }
}
