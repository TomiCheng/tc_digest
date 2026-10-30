//! The Haraka v2 rounds in plain Rust: Bouncy Castle's `HarakaBase.AesEnc`
//! with its steps, and the `Haraka256256` and `Haraka512256` functions of
//! `Haraka256Digest` and `Haraka512Digest`.
//!
//! The S-box is a table indexed by bytes of the state, so these rounds are
//! variable time; the AES-NI rounds are the alternative on x86.

use super::{Block, DIGEST_LENGTH, ROUND_CONSTANTS};

// The AES S-box. Bouncy Castle `HarakaBase.S` is a 16 x 16 table indexed by
// the high and the low nibble; flattened, the byte itself is the index.
#[rustfmt::skip]
const S: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Substitutes `x` through the AES S-box (Bouncy Castle `SBox`).
/// Variable time: the table index is a byte of the state, so which cache
/// lines are read depends on the input.
#[inline(always)]
fn s_box(x: u8) -> u8 {
    S[usize::from(x)]
}

/// Substitutes every byte of `s` through the S-box (Bouncy Castle
/// `SubBytes`). Variable time, through `s_box`.
#[inline(always)]
fn sub_bytes(s: Block) -> Block {
    s.map(s_box)
}

/// Rotates row `r` of the column-major state left by `r` bytes (Bouncy Castle
/// `ShiftRows`). Constant time: a fixed byte permutation.
#[inline(always)]
#[rustfmt::skip]
fn shift_rows(s: Block) -> Block {
    [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11],
    ]
}

/// Multiplies `p` by x in GF(2^8) modulo the AES polynomial
/// `x^8 + x^4 + x^3 + x + 1` (Bouncy Castle `MulX`). Constant time: the
/// reduction multiplies the top bit by the constant instead of branching on
/// it.
#[inline(always)]
fn mul_x(p: u8) -> u8 {
    ((p & 0x7f) << 1) ^ ((p >> 7) * 0x1b)
}

/// Multiplies every column of `s` by the AES MixColumns matrix (Bouncy
/// Castle `MixColumns`). Constant time.
#[inline(always)]
fn mix_columns(s: Block) -> Block {
    let mut output = [0u8; 16];
    for (out, column) in output.chunks_exact_mut(4).zip(s.chunks_exact(4)) {
        let (a, b, c, d) = (column[0], column[1], column[2], column[3]);
        out[0] = mul_x(a) ^ mul_x(b) ^ b ^ c ^ d;
        out[1] = a ^ mul_x(b) ^ mul_x(c) ^ c ^ d;
        out[2] = a ^ b ^ mul_x(c) ^ mul_x(d) ^ d;
        out[3] = mul_x(a) ^ a ^ b ^ c ^ mul_x(d);
    }
    output
}

/// One AES encryption round on `s` with round key `rk`: `SubBytes`,
/// `ShiftRows`, `MixColumns` and `AddRoundKey`, the operation of the x86
/// `AESENC` instruction (Bouncy Castle `AesEnc`). Variable time, through
/// `sub_bytes`.
#[inline]
fn aes_enc(s: Block, rk: &Block) -> Block {
    let mut s = mix_columns(shift_rows(sub_bytes(s)));
    for (byte, key) in s.iter_mut().zip(rk) {
        *byte ^= key;
    }
    s
}

/// Interleaves the 32-bit words of the two lanes (Bouncy Castle `Mix256`):
/// the first output lane takes words 0 and 1 of both lanes alternately, the
/// second words 2 and 3. Constant time: a fixed byte permutation.
fn mix256(s1: &[Block; 2]) -> [Block; 2] {
    let mut s2 = [[0u8; 16]; 2];
    s2[0][0..4].copy_from_slice(&s1[0][0..4]);
    s2[0][4..8].copy_from_slice(&s1[1][0..4]);
    s2[0][8..12].copy_from_slice(&s1[0][4..8]);
    s2[0][12..16].copy_from_slice(&s1[1][4..8]);

    s2[1][0..4].copy_from_slice(&s1[0][8..12]);
    s2[1][4..8].copy_from_slice(&s1[1][8..12]);
    s2[1][8..12].copy_from_slice(&s1[0][12..16]);
    s2[1][12..16].copy_from_slice(&s1[1][12..16]);
    s2
}

/// Permutes the 32-bit words of the four lanes (Bouncy Castle `Mix512`).
/// Constant time: a fixed byte permutation.
fn mix512(s1: &[Block; 4]) -> [Block; 4] {
    let mut s2 = [[0u8; 16]; 4];
    s2[0][0..4].copy_from_slice(&s1[0][12..16]);
    s2[0][4..8].copy_from_slice(&s1[2][12..16]);
    s2[0][8..12].copy_from_slice(&s1[1][12..16]);
    s2[0][12..16].copy_from_slice(&s1[3][12..16]);

    s2[1][0..4].copy_from_slice(&s1[2][0..4]);
    s2[1][4..8].copy_from_slice(&s1[0][0..4]);
    s2[1][8..12].copy_from_slice(&s1[3][0..4]);
    s2[1][12..16].copy_from_slice(&s1[1][0..4]);

    s2[2][0..4].copy_from_slice(&s1[2][4..8]);
    s2[2][4..8].copy_from_slice(&s1[0][4..8]);
    s2[2][8..12].copy_from_slice(&s1[3][4..8]);
    s2[2][12..16].copy_from_slice(&s1[1][4..8]);

    s2[3][0..4].copy_from_slice(&s1[0][8..12]);
    s2[3][4..8].copy_from_slice(&s1[2][8..12]);
    s2[3][8..12].copy_from_slice(&s1[1][8..12]);
    s2[3][12..16].copy_from_slice(&s1[3][8..12]);
    s2
}

/// Haraka-256/256 of `msg` into `output` (Bouncy Castle `Haraka256256`): five
/// rounds of two AES rounds per lane and `mix256`, then `msg` XORed back in.
/// Variable time, through `sub_bytes`.
pub(crate) fn hash256(msg: &[u8; 32], output: &mut [u8; DIGEST_LENGTH]) {
    let mut s: [Block; 2] = [[0; 16]; 2];
    for (lane, bytes) in s.iter_mut().zip(msg.chunks_exact(16)) {
        lane.copy_from_slice(bytes);
    }

    for rc in ROUND_CONSTANTS[..20].chunks_exact(4) {
        s[0] = aes_enc(s[0], &rc[0]);
        s[1] = aes_enc(s[1], &rc[1]);
        s[0] = aes_enc(s[0], &rc[2]);
        s[1] = aes_enc(s[1], &rc[3]);
        s = mix256(&s);
    }

    for ((out, state), input) in output.iter_mut().zip(s.as_flattened()).zip(msg) {
        *out = state ^ input;
    }
}

/// Haraka-512/256 of `msg` into `output` (Bouncy Castle `Haraka512256`): five
/// rounds of two AES rounds per lane and `mix512`, then `msg` XORed back in
/// and the 32 bytes of the digest taken from the middle of the lanes.
/// Variable time, through `sub_bytes`.
pub(crate) fn hash512(msg: &[u8; 64], output: &mut [u8; DIGEST_LENGTH]) {
    let mut s: [Block; 4] = [[0; 16]; 4];
    for (lane, bytes) in s.iter_mut().zip(msg.chunks_exact(16)) {
        lane.copy_from_slice(bytes);
    }

    for rc in ROUND_CONSTANTS.chunks_exact(8) {
        for (lane, key) in s.iter_mut().zip(&rc[..4]) {
            *lane = aes_enc(*lane, key);
        }
        for (lane, key) in s.iter_mut().zip(&rc[4..]) {
            *lane = aes_enc(*lane, key);
        }
        s = mix512(&s);
    }

    for (state, input) in s.as_flattened_mut().iter_mut().zip(msg) {
        *state ^= input;
    }
    output[..8].copy_from_slice(&s[0][8..]);
    output[8..16].copy_from_slice(&s[1][8..]);
    output[16..24].copy_from_slice(&s[2][..8]);
    output[24..].copy_from_slice(&s[3][..8]);
}
