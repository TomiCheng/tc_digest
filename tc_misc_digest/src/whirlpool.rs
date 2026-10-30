//! Whirlpool message digest (ISO/IEC 10118-3), ported from Bouncy Castle's
//! `WhirlpoolDigest`.
//!
//! Whirlpool runs a dedicated 512-bit block cipher W in the Miyaguchi–Preneel
//! mode: each 64-byte block `m` updates the state `h` to `h ^ W_h(m) ^ m`. W
//! runs ten rounds on an 8×8-byte state, each a substitution through one
//! S-box, a cyclic shift of the columns, a mix of the rows by a circulant
//! matrix and a round key; its key schedule runs the same rounds with round
//! constants in place of the key. As in Bouncy Castle, the substitution, shift
//! and mix go through eight tables of words built from the S-box, here at
//! compile time. The length field is 256 bits.

use core::{convert::Infallible, fmt};

use tc_digest::TryDigest;
use tc_zeroize::Zeroize;

use crate::md_buffer::MdBuffer;

const DIGEST_LENGTH: usize = 64;
const BYTE_LENGTH: usize = 64;
const ROUNDS: usize = 10;

// The width of the length field in bytes.
const LENGTH_FIELD: usize = 32;

/// The Whirlpool S-box, from which every table derives.
#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
    0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
    0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
    0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
    0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
    0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
    0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
    0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
    0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
    0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
    0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
    0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
    0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
    0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
    0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
    0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86,
];

/// The tables C0 to C7 of Bouncy Castle: entry `i` of `C[t]` is the S-box
/// output of `i` times the circulant row `(1, 1, 4, 1, 8, 5, 2, 9)` rotated
/// right by `t` bytes, so one lookup per byte applies the substitution and the
/// row mix.
static C: [[u64; 256]; 8] = generate_tables();

/// The round constants; `RC[0]` is unused, as in Bouncy Castle's `_rc`.
const RC: [u64; ROUNDS + 1] = generate_round_constants(&generate_tables());

/// Multiplies `input` by x in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1
/// (Bouncy Castle `MulX` with its polynomial `0x011d`, whose x^8 term only
/// cancels the bit shifted out of the byte). Constant time: a mask, not a
/// branch, applies the reduction.
const fn mul_x(input: u8) -> u8 {
    (input << 1) ^ ((input >> 7).wrapping_neg() & 0x1d)
}

/// Builds the tables C0 to C7 from the S-box, as Bouncy Castle's static
/// constructor does; `u64::from_be_bytes` packs the bytes as its
/// `PackIntoUInt64`. Constant time: the S-box index is the loop counter.
const fn generate_tables() -> [[u64; 256]; 8] {
    let mut c = [[0u64; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let v1 = SBOX[i];
        let v2 = mul_x(v1);
        let v4 = mul_x(v2);
        let v5 = v4 ^ v1;
        let v8 = mul_x(v4);
        let v9 = v8 ^ v1;

        c[0][i] = u64::from_be_bytes([v1, v1, v4, v1, v8, v5, v2, v9]);
        c[1][i] = u64::from_be_bytes([v9, v1, v1, v4, v1, v8, v5, v2]);
        c[2][i] = u64::from_be_bytes([v2, v9, v1, v1, v4, v1, v8, v5]);
        c[3][i] = u64::from_be_bytes([v5, v2, v9, v1, v1, v4, v1, v8]);
        c[4][i] = u64::from_be_bytes([v8, v5, v2, v9, v1, v1, v4, v1]);
        c[5][i] = u64::from_be_bytes([v1, v8, v5, v2, v9, v1, v1, v4]);
        c[6][i] = u64::from_be_bytes([v4, v1, v8, v5, v2, v9, v1, v1]);
        c[7][i] = u64::from_be_bytes([v1, v4, v1, v8, v5, v2, v9, v1]);
        i += 1;
    }
    c
}

/// Builds the round constants from the tables `c`, as Bouncy Castle's
/// constructor does: byte `j` of constant `r` is the S-box output of
/// `8 (r - 1) + j`, taken from the table that holds it at that byte.
/// Constant time: the table indices are loop counters.
const fn generate_round_constants(c: &[[u64; 256]; 8]) -> [u64; ROUNDS + 1] {
    let mut rc = [0u64; ROUNDS + 1];
    let mut r = 1;
    while r <= ROUNDS {
        let i = 8 * (r - 1);
        let mut j = 0;
        while j < 8 {
            rc[r] ^= c[j][i + j] & (0xff00_0000_0000_0000 >> (8 * j));
            j += 1;
        }
        r += 1;
    }
    rc
}

/// Applies the substitution, the column shift and the row mix of one round to
/// `input` through the tables (the lookups Bouncy Castle's `ProcessBlock`
/// writes out for both the round key and the cipher state). Variable time: the
/// table indices are bytes of `input`, so the memory access pattern depends on
/// the message and the chaining state.
#[inline(always)]
fn transform(input: &[u64; 8]) -> [u64; 8] {
    let mut output = [0u64; 8];
    for (i, word) in output.iter_mut().enumerate() {
        *word = C[0][(input[i] >> 56) as usize & 0xff]
            ^ C[1][(input[(i + 7) & 7] >> 48) as usize & 0xff]
            ^ C[2][(input[(i + 6) & 7] >> 40) as usize & 0xff]
            ^ C[3][(input[(i + 5) & 7] >> 32) as usize & 0xff]
            ^ C[4][(input[(i + 4) & 7] >> 24) as usize & 0xff]
            ^ C[5][(input[(i + 3) & 7] >> 16) as usize & 0xff]
            ^ C[6][(input[(i + 2) & 7] >> 8) as usize & 0xff]
            ^ C[7][input[(i + 1) & 7] as usize & 0xff];
    }
    output
}

/// Compresses one 64-byte block of big-endian words into the state `hash` as
/// `hash ^ W_hash(block) ^ block` (Bouncy Castle `ProcessBlock`).
/// Variable time, through `transform`.
fn compress(hash: &mut [u64; 8], block: &[u8; 64]) {
    let mut message = [0u64; 8];
    for (word, chunk) in message.iter_mut().zip(block.chunks_exact(8)) {
        *word = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
    }

    // The first round key K^0 is the chaining state.
    let mut key = *hash;
    let mut state = [0u64; 8];
    for ((s, m), k) in state.iter_mut().zip(message).zip(key) {
        *s = m ^ k;
    }

    for &rc in &RC[1..] {
        key = transform(&key);
        key[0] ^= rc;
        let transformed = transform(&state);
        for ((s, t), k) in state.iter_mut().zip(transformed).zip(key) {
            *s = t ^ k;
        }
    }

    // The Miyaguchi–Preneel feed-forward.
    for ((h, s), m) in hash.iter_mut().zip(state).zip(message) {
        *h ^= s ^ m;
    }
}

/// The 256-bit big-endian bit length of a message of `byte_count` bytes.
/// Bouncy Castle counts bits in 256 bits; the byte count here wraps at 2^64
/// bytes. Constant time.
fn length_field(byte_count: u64) -> [u8; LENGTH_FIELD] {
    let mut field = [0u8; LENGTH_FIELD];
    field[LENGTH_FIELD - 16..].copy_from_slice(&(u128::from(byte_count) << 3).to_be_bytes());
    field
}

/// The Whirlpool digest (ISO/IEC 10118-3, Bouncy Castle `WhirlpoolDigest`),
/// producing a 64-byte hash.
///
/// Variable time: every round indexes the tables with bytes of the cipher
/// state and the round key, which can leak the message through cache timing.
/// Hash only public data with it, or accept that leak in the threat model.
///
/// Dropping or resetting the digest, which `do_final` also does, wipes its
/// chaining state and buffered input with volatile writes. Copies the
/// compression leaves in registers or on the stack, such as the round keys
/// and cipher states, and copies a move leaves behind are not wiped.
///
/// `do_final` panics if the output buffer is shorter than 64 bytes.
#[derive(Clone)]
pub struct WhirlpoolDigest {
    /// The chaining state, eight words that start at zero.
    hash: [u64; 8],
    /// The shared 64-byte block buffer.
    buf: MdBuffer<64>,
}

impl Default for WhirlpoolDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl WhirlpoolDigest {
    /// Creates a fresh Whirlpool digest. Constant time.
    pub const fn new() -> Self {
        WhirlpoolDigest {
            hash: [0; 8],
            buf: MdBuffer::new(),
        }
    }
}

impl Drop for WhirlpoolDigest {
    /// Wipes the chaining state; the block buffer wipes itself.
    /// Constant time.
    fn drop(&mut self) {
        self.hash.zeroize();
    }
}

impl fmt::Display for WhirlpoolDigest {
    /// Writes `Whirlpool` without inspecting the digest state. Constant time
    /// with respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Whirlpool")
    }
}

impl TryDigest for WhirlpoolDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let Self { hash, buf } = self;
        buf.update(input, |block| compress(hash, block));
        Ok(())
    }

    /// Writes the 64-byte digest to the start of `output` and resets.
    ///
    /// # Panics
    ///
    /// Panics if `output` is shorter than 64 bytes, before changing any state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        assert!(
            output.len() >= DIGEST_LENGTH,
            "output buffer shorter than the 64-byte Whirlpool digest"
        );
        {
            let Self { hash, buf } = self;
            let length = length_field(buf.byte_count());
            buf.finish(&length, |block| compress(hash, block));
            for (chunk, word) in output.chunks_exact_mut(8).zip(hash.iter()) {
                chunk.copy_from_slice(&word.to_be_bytes());
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
