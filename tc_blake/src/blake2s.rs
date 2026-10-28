//! BLAKE2s message digest, ported from Bouncy Castle's `Blake2sDigest`.
//!
//! The portable compression function is always available. On x86 and x86-64,
//! SSE2 is detected at run time through `tc_runtime`, without needing `std`,
//! and used when present; other targets use the portable path.

use core::convert::Infallible;

use tc_digest::TryDigest;
use tc_zeroize::Zeroize;

const BLOCK_LENGTH: usize = 64;
const DEFAULT_DIGEST_LENGTH: usize = 32;
const ROUNDS: usize = 10;

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
];

/// The G function on four state words. Constant time.
#[inline(always)]
fn mix(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    let mut va = state[a];
    let mut vb = state[b];
    let mut vc = state[c];
    let mut vd = state[d];

    va = va.wrapping_add(vb).wrapping_add(x);
    vd = (vd ^ va).rotate_right(16);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_right(12);
    va = va.wrapping_add(vb).wrapping_add(y);
    vd = (vd ^ va).rotate_right(8);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_right(7);

    state[a] = va;
    state[b] = vb;
    state[c] = vc;
    state[d] = vd;
}

/// Compresses one block in plain Rust. Constant time: the message words are
/// picked by the public SIGMA permutation.
fn compress_portable(
    chain: &mut [u32; 8],
    counter_low: u32,
    counter_high: u32,
    final_flag: u32,
    block: &[u8; BLOCK_LENGTH],
) {
    let mut message = [0u32; 16];
    for (word, bytes) in message.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().unwrap());
    }

    let mut state = [0u32; 16];
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
mod sse2 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    use super::{BLOCK_LENGTH, IV, SIGMA};

    // Rust 1.85 still treats these intrinsics as unsafe inside target_feature
    // functions; newer compilers consider the block unnecessary.
    /// Four words in one vector, the first in the lowest lane. Constant time.
    #[allow(unused_unsafe)]
    #[target_feature(enable = "sse2")]
    unsafe fn set4(a: u32, b: u32, c: u32, d: u32) -> __m128i {
        // SAFETY: the function itself requires SSE2.
        unsafe { _mm_set_epi32(d as i32, c as i32, b as i32, a as i32) }
    }

    /// Rotates every lane right by `RIGHT` bits. Constant time.
    #[allow(unused_unsafe)]
    #[target_feature(enable = "sse2")]
    unsafe fn rotate_right<const RIGHT: i32, const LEFT: i32>(value: __m128i) -> __m128i {
        // SAFETY: the function itself requires SSE2.
        unsafe {
            _mm_or_si128(
                _mm_srli_epi32::<RIGHT>(value),
                _mm_slli_epi32::<LEFT>(value),
            )
        }
    }

    /// The G function on four columns or diagonals at once. Constant time.
    #[target_feature(enable = "sse2")]
    unsafe fn mix(
        a: &mut __m128i,
        b: &mut __m128i,
        c: &mut __m128i,
        d: &mut __m128i,
        x: __m128i,
        y: __m128i,
    ) {
        // SAFETY: the function itself requires SSE2 and operates only on
        // vector registers.
        unsafe {
            *a = _mm_add_epi32(_mm_add_epi32(*a, *b), x);
            *d = rotate_right::<16, 16>(_mm_xor_si128(*d, *a));
            *c = _mm_add_epi32(*c, *d);
            *b = rotate_right::<12, 20>(_mm_xor_si128(*b, *c));
            *a = _mm_add_epi32(_mm_add_epi32(*a, *b), y);
            *d = rotate_right::<8, 24>(_mm_xor_si128(*d, *a));
            *c = _mm_add_epi32(*c, *d);
            *b = rotate_right::<7, 25>(_mm_xor_si128(*b, *c));
        }
    }

    /// Compresses one block with four parallel G functions in each SSE2 vector.
    /// Constant time.
    ///
    /// # Safety
    ///
    /// The caller must establish that the current CPU and OS support SSE2.
    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn compress(
        chain: &mut [u32; 8],
        counter_low: u32,
        counter_high: u32,
        final_flag: u32,
        block: &[u8; BLOCK_LENGTH],
    ) {
        // SAFETY: this block is guarded by the function's SSE2 target feature,
        // and all pointers refer to properly sized local arrays.
        unsafe {
            let mut message = [0u32; 16];
            for (word, bytes) in message.iter_mut().zip(block.chunks_exact(4)) {
                *word = u32::from_le_bytes(bytes.try_into().unwrap());
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

                row2 = _mm_shuffle_epi32::<0x39>(row2);
                row3 = _mm_shuffle_epi32::<0x4e>(row3);
                row4 = _mm_shuffle_epi32::<0x93>(row4);

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

                row2 = _mm_shuffle_epi32::<0x93>(row2);
                row3 = _mm_shuffle_epi32::<0x4e>(row3);
                row4 = _mm_shuffle_epi32::<0x39>(row4);
            }

            let low = _mm_xor_si128(original_low, _mm_xor_si128(row1, row3));
            let high = _mm_xor_si128(original_high, _mm_xor_si128(row2, row4));
            _mm_storeu_si128(chain.as_mut_ptr().cast(), low);
            _mm_storeu_si128(chain.as_mut_ptr().add(4).cast(), high);
        }
    }
}

/// Compresses one block with SSE2 when the CPU has it, in plain Rust otherwise.
/// Constant time: the CPU, not the data, picks the path.
#[allow(unsafe_code)]
#[inline]
fn compress(
    chain: &mut [u32; 8],
    counter_low: u32,
    counter_high: u32,
    final_flag: u32,
    block: &[u8; BLOCK_LENGTH],
) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if tc_runtime::intrinsics::x86::Sse2::detect().is_some() {
        // SAFETY: the detected token proves the current CPU and OS support
        // SSE2.
        unsafe {
            sse2::compress(chain, counter_low, counter_high, final_flag, block);
        }
        return;
    }

    compress_portable(chain, counter_low, counter_high, final_flag, block);
}

/// The BLAKE2s message digest with optional key, salt, and personalization.
/// Constant time.
#[derive(Clone)]
pub struct Blake2sDigest {
    chain: [u32; 8],
    buffer: [u8; BLOCK_LENGTH],
    buffer_position: usize,
    counter_low: u32,
    counter_high: u32,
    final_flag: u32,
    digest_length: usize,
    key: [u8; 32],
    key_length: usize,
    salt: [u8; 8],
    personalization: [u8; 8],
    // Tree and XOF parameters; sequential mode is fanout 1, depth 1 and zeros.
    fanout: u8,
    depth: u8,
    leaf_length: u32,
    node_offset: u64,
    node_depth: u8,
    inner_length: u8,
}

impl Default for Blake2sDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2sDigest {
    /// Creates an unkeyed BLAKE2s-256 digest. Constant time.
    pub fn new() -> Self {
        Self::with_parameters(None, DEFAULT_DIGEST_LENGTH, None, None)
    }

    /// Creates an unkeyed BLAKE2s digest with an output size from 8 to 256 bits.
    /// Constant time.
    pub fn with_digest_size(digest_bits: usize) -> Self {
        assert!(
            (8..=256).contains(&digest_bits) && digest_bits % 8 == 0,
            "BLAKE2s digest bit length must be a multiple of 8 and not greater than 256"
        );
        Self::with_parameters(None, digest_bits / 8, None, None)
    }

    /// Creates keyed BLAKE2s-256. An empty key selects unkeyed hashing.
    /// Constant time with respect to the key; its length is public.
    pub fn with_key(key: &[u8]) -> Self {
        Self::with_parameters(Some(key), DEFAULT_DIGEST_LENGTH, None, None)
    }

    /// Creates BLAKE2s with its full sequential-mode parameter set. Constant time
    /// with respect to the key, salt and personalization; their lengths are public.
    ///
    /// `digest_length` is measured in bytes (1..=32), `key` may contain at
    /// most 32 bytes, and salt/personalization must each contain exactly 8
    /// bytes when present.
    pub fn with_parameters(
        key: Option<&[u8]>,
        digest_length: usize,
        salt: Option<&[u8]>,
        personalization: Option<&[u8]>,
    ) -> Self {
        assert!(
            (1..=32).contains(&digest_length),
            "BLAKE2s digest length must be between 1 and 32 bytes"
        );
        let key = key.unwrap_or_default();
        assert!(key.len() <= 32, "BLAKE2s keys must not exceed 32 bytes");
        if let Some(salt) = salt {
            assert_eq!(salt.len(), 8, "BLAKE2s salt must be exactly 8 bytes");
        }
        if let Some(personalization) = personalization {
            assert_eq!(
                personalization.len(),
                8,
                "BLAKE2s personalization must be exactly 8 bytes"
            );
        }

        let mut digest = Blake2sDigest {
            chain: [0; 8],
            buffer: [0; BLOCK_LENGTH],
            buffer_position: 0,
            counter_low: 0,
            counter_high: 0,
            final_flag: 0,
            digest_length,
            key: [0; 32],
            key_length: key.len(),
            salt: [0; 8],
            personalization: [0; 8],
            fanout: 1,
            depth: 1,
            leaf_length: 0,
            node_offset: 0,
            node_depth: 0,
            inner_length: 0,
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

    /// The BLAKE2xs root hash: sequential parameters, with the XOF output length
    /// in the high 32 bits of `node_offset`. Constant time with respect to the
    /// key, salt and personalization; their lengths are public.
    pub(crate) fn xof_root(
        digest_length: usize,
        key: Option<&[u8]>,
        salt: Option<&[u8]>,
        personalization: Option<&[u8]>,
        node_offset: u64,
    ) -> Self {
        let key = key.unwrap_or_default();
        let mut digest = Blake2sDigest {
            chain: [0; 8],
            buffer: [0; BLOCK_LENGTH],
            buffer_position: 0,
            counter_low: 0,
            counter_high: 0,
            final_flag: 0,
            digest_length,
            key: [0; 32],
            key_length: key.len(),
            salt: [0; 8],
            personalization: [0; 8],
            fanout: 1,
            depth: 1,
            leaf_length: 0,
            node_offset,
            node_depth: 0,
            inner_length: 0,
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

    /// A BLAKE2xs output node: fanout and depth 0, leaf and inner length
    /// `inner_length`, `node_offset` holding the XOF length high and the block
    /// index low, and no key, salt or personalization. Constant time.
    pub(crate) fn xof_node(digest_length: usize, inner_length: u8, node_offset: u64) -> Self {
        let mut digest = Blake2sDigest {
            chain: [0; 8],
            buffer: [0; BLOCK_LENGTH],
            buffer_position: 0,
            counter_low: 0,
            counter_high: 0,
            final_flag: 0,
            digest_length,
            key: [0; 32],
            key_length: 0,
            salt: [0; 8],
            personalization: [0; 8],
            fanout: 0,
            depth: 0,
            leaf_length: inner_length as u32,
            node_offset,
            node_depth: 0,
            inner_length,
        };
        digest.reset_state();
        digest
    }

    /// Restarts from the parameter block, with the key as the first block when
    /// there is one. Constant time.
    fn reset_state(&mut self) {
        self.chain = IV;
        // The whole BLAKE2s parameter block; sequential mode is fanout 1,
        // depth 1 and zeros.
        self.chain[0] ^= self.digest_length as u32
            | ((self.key_length as u32) << 8)
            | ((self.fanout as u32) << 16)
            | ((self.depth as u32) << 24);
        self.chain[1] ^= self.leaf_length;
        self.chain[2] ^= self.node_offset as u32;
        self.chain[3] ^= ((self.node_offset >> 32) as u32)
            | ((self.node_depth as u32) << 16)
            | ((self.inner_length as u32) << 24);
        self.chain[4] ^= u32::from_le_bytes(self.salt[..4].try_into().expect("4-byte salt"));
        self.chain[5] ^= u32::from_le_bytes(self.salt[4..].try_into().expect("4-byte salt"));
        self.chain[6] ^= u32::from_le_bytes(
            self.personalization[..4]
                .try_into()
                .expect("4-byte personalization"),
        );
        self.chain[7] ^= u32::from_le_bytes(
            self.personalization[4..]
                .try_into()
                .expect("4-byte personalization"),
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
        let increment = increment as u32;
        let previous = self.counter_low;
        self.counter_low = self.counter_low.wrapping_add(increment);
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

impl TryDigest for Blake2sDigest {
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
                .expect("64-byte BLAKE2s block");
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
        self.final_flag = u32::MAX;
        self.increment_counter(self.buffer_position);
        self.buffer[self.buffer_position..].fill(0);
        self.compress_buffer();

        for (word, output) in self
            .chain
            .iter()
            .zip(output[..self.digest_length].chunks_mut(4))
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

impl Drop for Blake2sDigest {
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

impl core::fmt::Display for Blake2sDigest {
    /// Writes `BLAKE2s` without inspecting the state. Constant time with respect
    /// to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BLAKE2s")
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

    fn digest_hex(digest: &mut Blake2sDigest, input: &[u8]) -> String {
        digest.update(input);
        let mut output = [0u8; 32];
        let size = digest.do_final(&mut output);
        hex(&output[..size])
    }

    #[test]
    fn rfc_and_bc_unkeyed_vectors() {
        let vectors: &[(&[u8], &str)] = &[
            (
                b"",
                "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
            ),
            (
                b"abc",
                "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
            ),
            (
                b"The quick brown fox jumps over the lazy dog",
                "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812",
            ),
        ];
        for &(message, expected) in vectors {
            assert_eq!(digest_hex(&mut Blake2sDigest::new(), message), expected);
        }
    }

    #[test]
    fn bc_keyed_vectors() {
        let key: Vec<u8> = (0..32).collect();
        let vectors: &[(&[u8], &str)] = &[
            (
                b"",
                "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
            ),
            (
                &[0x00],
                "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1",
            ),
            (
                &[0x00, 0x01],
                "6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803",
            ),
        ];
        let mut digest = Blake2sDigest::with_key(&key);
        for &(message, expected) in vectors {
            assert_eq!(digest_hex(&mut digest, message), expected);
        }
    }

    fn self_test_sequence(length: usize, seed: u32) -> Vec<u8> {
        let mut a = 0xdead_4badu32.wrapping_mul(seed);
        let mut b = 1u32;
        let mut output = Vec::with_capacity(length);
        for _ in 0..length {
            let t = a.wrapping_add(b);
            a = b;
            b = t;
            output.push((t >> 24) as u8);
        }
        output
    }

    #[test]
    fn rfc_self_test() {
        let mut test_digest = Blake2sDigest::new();
        let mut intermediate = [0u8; 32];

        for output_length in [16, 20, 28, 32] {
            for input_length in [0, 3, 64, 65, 255, 1024] {
                let input = self_test_sequence(input_length, input_length as u32);

                let mut unkeyed = Blake2sDigest::with_digest_size(output_length * 8);
                unkeyed.update(&input);
                unkeyed.do_final(&mut intermediate);
                test_digest.update(&intermediate[..output_length]);

                let key = self_test_sequence(output_length, output_length as u32);
                let mut keyed =
                    Blake2sDigest::with_parameters(Some(&key), output_length, None, None);
                keyed.update(&input);
                keyed.do_final(&mut intermediate);
                test_digest.update(&intermediate[..output_length]);
            }
        }

        assert_eq!(
            digest_hex(&mut test_digest, b""),
            "6a411f08ce25adcdfb02aba641451cec53c598b24f4fc787fbdc88797f4c1dfe"
        );
    }

    #[test]
    fn parameters_output_length_clone_chunking_and_reset() {
        let key: Vec<u8> = (0..32).collect();
        let salt: Vec<u8> = (0..8).collect();
        let personalization: Vec<u8> = (8..16).collect();
        let message: Vec<u8> = (0..78).collect();
        let mut digest =
            Blake2sDigest::with_parameters(Some(&key), 16, Some(&salt), Some(&personalization));
        assert_eq!(digest.to_string(), "BLAKE2s");
        assert_eq!(digest.digest_size(), 16);
        assert_eq!(digest.byte_length(), 64);
        digest.update(&message);

        let mut cloned = digest.clone();
        let mut expected = [0u8; 16];
        let mut cloned_output = [0u8; 16];
        digest.do_final(&mut expected);
        cloned.do_final(&mut cloned_output);
        assert_eq!(expected, cloned_output);

        let mut chunked =
            Blake2sDigest::with_parameters(Some(&key), 16, Some(&salt), Some(&personalization));
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
        for bytes in 1..=32 {
            let mut a = Blake2sDigest::with_digest_size(bytes * 8);
            let mut b = Blake2sDigest::with_parameters(None, bytes, None, None);
            a.update(&message);
            for chunk in message.chunks(63) {
                b.update(chunk);
            }
            let mut left = [0u8; 32];
            let mut right = [0u8; 32];
            assert_eq!(a.do_final(&mut left), bytes);
            assert_eq!(b.do_final(&mut right), bytes);
            assert_eq!(&left[..bytes], &right[..bytes]);
        }

        for length in [0, 1, 63, 64, 65, 127, 128, 255, 256] {
            let input = &message[..length];
            let expected = digest_hex(&mut Blake2sDigest::new(), input);
            let mut bytewise = Blake2sDigest::new();
            for byte in input {
                bytewise.update(core::slice::from_ref(byte));
            }
            assert_eq!(digest_hex(&mut bytewise, b""), expected);
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[allow(unsafe_code)]
    #[test]
    fn sse2_matches_portable() {
        if tc_runtime::intrinsics::x86::Sse2::detect().is_none() {
            return;
        }

        for case in 0..32u32 {
            let block = core::array::from_fn(|i| (i as u8).wrapping_mul(17) ^ case as u8);
            let chain = core::array::from_fn(|i| IV[i] ^ case.wrapping_mul((i + 1) as u32));
            for &(counter_low, counter_high, final_flag) in
                &[(0, 0, 0), (63, 0, u32::MAX), (u32::MAX - 3, case, 0)]
            {
                let mut portable = chain;
                let mut accelerated = chain;
                compress_portable(&mut portable, counter_low, counter_high, final_flag, &block);
                // SAFETY: guarded by runtime SSE2 detection above.
                unsafe {
                    sse2::compress(
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
