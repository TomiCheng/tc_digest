//! The Haraka v2 rounds on AES-NI, after Bouncy Castle's `Haraka256_X86` and
//! `Haraka512_X86`.
//!
//! Every function here executes AES-NI or SSE2 instructions. The two entry
//! points, `hash256` and `hash512`, take the `tc_runtime` tokens that prove
//! the CPU has both and are therefore safe to call; the rest are `unsafe`
//! target-feature functions reached only through them.
//!
//! Rust 1.85 still treats the register-only intrinsics as unsafe inside
//! target-feature functions, while newer compilers consider an `unsafe` block
//! around them unnecessary; blocks that hold nothing else allow
//! `unused_unsafe`.

#[cfg(target_arch = "x86")]
use core::arch::x86::{
    __m128i, _mm_aesenc_si128, _mm_loadu_si128, _mm_storel_epi64, _mm_storeu_si128,
    _mm_unpackhi_epi32, _mm_unpackhi_epi64, _mm_unpacklo_epi32, _mm_xor_si128,
};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_aesenc_si128, _mm_loadu_si128, _mm_storel_epi64, _mm_storeu_si128,
    _mm_unpackhi_epi32, _mm_unpackhi_epi64, _mm_unpacklo_epi32, _mm_xor_si128,
};

use tc_runtime::intrinsics::x86::{Aes, Sse2};

use super::{Block, DIGEST_LENGTH, ROUND_CONSTANTS};

/// Loads 16 bytes into a vector, the first byte in the lowest lane (Bouncy
/// Castle `Load128`). Constant time.
///
/// # Safety
///
/// The CPU must support SSE2.
///
/// # Panics
///
/// Panics if `bytes` is not 16 bytes long, which the constant ranges of the
/// callers rule out.
#[allow(unsafe_code)]
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn load128(bytes: &[u8]) -> __m128i {
    let bytes: &Block = bytes.try_into().expect("16-byte lane");
    // SAFETY: `bytes` is 16 readable bytes, `_mm_loadu_si128` reads exactly
    // those without an alignment requirement, and the caller guarantees SSE2.
    unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) }
}

/// Stores a vector into 16 bytes, the lowest lane first (Bouncy Castle
/// `Store128`). Constant time.
///
/// # Safety
///
/// The CPU must support SSE2.
///
/// # Panics
///
/// Panics if `bytes` is not 16 bytes long, which the constant ranges of the
/// callers rule out.
#[allow(unsafe_code)]
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn store128(bytes: &mut [u8], value: __m128i) {
    let bytes: &mut Block = bytes.try_into().expect("16-byte lane");
    // SAFETY: `bytes` is 16 writable bytes, `_mm_storeu_si128` writes exactly
    // those without an alignment requirement, and the caller guarantees SSE2.
    unsafe { _mm_storeu_si128(bytes.as_mut_ptr().cast(), value) }
}

/// Stores the low 64 bits of a vector into 8 bytes (Bouncy Castle `Store64`).
/// Constant time.
///
/// # Safety
///
/// The CPU must support SSE2.
///
/// # Panics
///
/// Panics if `bytes` is not 8 bytes long, which the constant ranges of the
/// callers rule out.
#[allow(unsafe_code)]
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn store64(bytes: &mut [u8], value: __m128i) {
    let bytes: &mut [u8; 8] = bytes.try_into().expect("8-byte half lane");
    // SAFETY: `bytes` is 8 writable bytes, `_mm_storel_epi64` writes only the
    // low 8 bytes of the vector there without an alignment requirement, and
    // the caller guarantees SSE2.
    unsafe { _mm_storel_epi64(bytes.as_mut_ptr().cast(), value) }
}

/// One AES encryption round on `state` with round constant `index` (`AESENC`,
/// `Aes.Encrypt` in Bouncy Castle). Constant time: the instruction makes no
/// table lookups or branches on the data, and `index` is the public round
/// number.
///
/// # Safety
///
/// The CPU must support AES-NI and SSE2.
#[allow(unsafe_code)]
#[inline]
#[target_feature(enable = "aes,sse2")]
unsafe fn aes_round(state: __m128i, index: usize) -> __m128i {
    // SAFETY: the caller guarantees AES-NI and SSE2, all that `load128` and
    // `_mm_aesenc_si128` need.
    unsafe { _mm_aesenc_si128(state, load128(&ROUND_CONSTANTS[index])) }
}

/// Two AES rounds on every lane, all lanes through the first before any takes
/// the second, with the round constants from `first` on (Bouncy Castle
/// `ImplAes`). Constant time.
///
/// # Safety
///
/// The CPU must support AES-NI and SSE2.
#[allow(unsafe_code)]
#[inline]
#[target_feature(enable = "aes,sse2")]
unsafe fn two_aes_rounds<const L: usize>(state: &mut [__m128i; L], first: usize) {
    for (lane, value) in state.iter_mut().enumerate() {
        // SAFETY: the caller guarantees AES-NI and SSE2.
        *value = unsafe { aes_round(*value, first + lane) };
    }
    for (lane, value) in state.iter_mut().enumerate() {
        // SAFETY: the caller guarantees AES-NI and SSE2.
        *value = unsafe { aes_round(*value, first + L + lane) };
    }
}

/// Interleaves the 32-bit words of the two lanes (Bouncy Castle
/// `Haraka256_X86.ImplMix`). Constant time.
///
/// # Safety
///
/// The CPU must support SSE2.
#[allow(unsafe_code, unused_unsafe)]
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn mix256(state: &mut [__m128i; 2]) {
    let [s0, s1] = *state;
    // SAFETY: the caller guarantees SSE2; the operands are registers.
    *state = unsafe { [_mm_unpacklo_epi32(s0, s1), _mm_unpackhi_epi32(s0, s1)] };
}

/// Permutes the 32-bit words of the four lanes (Bouncy Castle
/// `Haraka512_X86.ImplMix`). Constant time.
///
/// # Safety
///
/// The CPU must support SSE2.
#[allow(unsafe_code, unused_unsafe)]
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn mix512(state: &mut [__m128i; 4]) {
    let [s0, s1, s2, s3] = *state;
    // SAFETY: the caller guarantees SSE2; the operands are registers.
    *state = unsafe {
        let u0 = _mm_unpacklo_epi32(s0, s1);
        let u1 = _mm_unpackhi_epi32(s0, s1);
        let u2 = _mm_unpacklo_epi32(s2, s3);
        let u3 = _mm_unpackhi_epi32(s2, s3);
        [
            _mm_unpackhi_epi32(u1, u3),
            _mm_unpacklo_epi32(u2, u0),
            _mm_unpackhi_epi32(u2, u0),
            _mm_unpacklo_epi32(u1, u3),
        ]
    };
}

/// The five rounds of the Haraka-256 permutation, each two AES rounds per
/// lane and `mix256` (Bouncy Castle `Haraka256_X86.ImplRounds`).
/// Constant time.
///
/// # Safety
///
/// The CPU must support AES-NI and SSE2.
#[allow(unsafe_code)]
#[inline]
#[target_feature(enable = "aes,sse2")]
unsafe fn permute256(state: &mut [__m128i; 2]) {
    for round in 0..5 {
        // SAFETY: the caller guarantees AES-NI and SSE2.
        unsafe {
            two_aes_rounds(state, 4 * round);
            mix256(state);
        }
    }
}

/// The five rounds of the Haraka-512 permutation, each two AES rounds per
/// lane and `mix512` (Bouncy Castle `Haraka512_X86.ImplRounds`).
/// Constant time.
///
/// # Safety
///
/// The CPU must support AES-NI and SSE2.
#[allow(unsafe_code)]
#[inline]
#[target_feature(enable = "aes,sse2")]
unsafe fn permute512(state: &mut [__m128i; 4]) {
    for round in 0..5 {
        // SAFETY: the caller guarantees AES-NI and SSE2.
        unsafe {
            two_aes_rounds(state, 8 * round);
            mix512(state);
        }
    }
}

/// Haraka-256/256 of `input` into `output`: the permutation with the input
/// XORed back in (Bouncy Castle `Haraka256_X86.Hash`). Constant time.
///
/// # Safety
///
/// The CPU must support AES-NI and SSE2.
#[allow(unsafe_code)]
#[target_feature(enable = "aes,sse2")]
unsafe fn hash256_unchecked(input: &[u8; 32], output: &mut [u8; DIGEST_LENGTH]) {
    // SAFETY: the caller guarantees AES-NI and SSE2. Memory is reached only
    // through `load128` and `store128`, which check their lengths.
    unsafe {
        let mut state = [load128(&input[..16]), load128(&input[16..])];
        permute256(&mut state);
        let s0 = _mm_xor_si128(state[0], load128(&input[..16]));
        let s1 = _mm_xor_si128(state[1], load128(&input[16..]));
        store128(&mut output[..16], s0);
        store128(&mut output[16..], s1);
    }
}

/// Haraka-512/256 of `input` into `output`: the permutation with the input
/// XORed back in, then the upper halves of the first two lanes and the lower
/// halves of the last two (Bouncy Castle `Haraka512_X86.Hash`).
/// Constant time.
///
/// # Safety
///
/// The CPU must support AES-NI and SSE2.
#[allow(unsafe_code)]
#[target_feature(enable = "aes,sse2")]
unsafe fn hash512_unchecked(input: &[u8; 64], output: &mut [u8; DIGEST_LENGTH]) {
    // SAFETY: the caller guarantees AES-NI and SSE2. Memory is reached only
    // through `load128` and `store64`, which check their lengths.
    unsafe {
        let mut state = [
            load128(&input[..16]),
            load128(&input[16..32]),
            load128(&input[32..48]),
            load128(&input[48..]),
        ];
        permute512(&mut state);
        let s0 = _mm_xor_si128(state[0], load128(&input[..16]));
        let s1 = _mm_xor_si128(state[1], load128(&input[16..32]));
        let s2 = _mm_xor_si128(state[2], load128(&input[32..48]));
        let s3 = _mm_xor_si128(state[3], load128(&input[48..]));
        store64(&mut output[..8], _mm_unpackhi_epi64(s0, s0));
        store64(&mut output[8..16], _mm_unpackhi_epi64(s1, s1));
        store64(&mut output[16..24], s2);
        store64(&mut output[24..], s3);
    }
}

/// Haraka-256/256 of `input` into `output` on AES-NI. Constant time: the AES
/// rounds run on `AESENC`, which makes no table lookups or branches on the
/// data. The tokens prove that the CPU has AES-NI and SSE2.
#[allow(unsafe_code)]
pub(crate) fn hash256(input: &[u8; 32], output: &mut [u8; DIGEST_LENGTH], _aes: Aes, _sse2: Sse2) {
    // SAFETY: `tc_runtime` hands out the `Aes` and `Sse2` tokens only after
    // detecting AES-NI and SSE2 on this CPU, all that `hash256_unchecked`
    // requires.
    unsafe { hash256_unchecked(input, output) }
}

/// Haraka-512/256 of `input` into `output` on AES-NI. Constant time: the AES
/// rounds run on `AESENC`, which makes no table lookups or branches on the
/// data. The tokens prove that the CPU has AES-NI and SSE2.
#[allow(unsafe_code)]
pub(crate) fn hash512(input: &[u8; 64], output: &mut [u8; DIGEST_LENGTH], _aes: Aes, _sse2: Sse2) {
    // SAFETY: `tc_runtime` hands out the `Aes` and `Sse2` tokens only after
    // detecting AES-NI and SSE2 on this CPU, all that `hash512_unchecked`
    // requires.
    unsafe { hash512_unchecked(input, output) }
}
