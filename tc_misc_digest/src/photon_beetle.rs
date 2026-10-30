//! PHOTON-Beetle-Hash, ported from Bouncy Castle's `PhotonBeetleDigest`.
//!
//! The hash is a sponge on the PHOTON-256 permutation: twelve AES-like rounds
//! of AddConstant, SubCells (a 4-bit S-box), ShiftRows and MixColumnSerial (an
//! MDS matrix over GF(2^4)) on an 8×8 matrix of nibbles. The first 16 bytes of
//! the message fill the state directly, the rest is absorbed 4 bytes per
//! permutation, and two 16-byte squeezes give the 32-byte digest.

use core::{convert::Infallible, fmt};

use tc_digest::TryDigest;
use tc_zeroize::Zeroize;

const DIGEST_LENGTH: usize = 32;
const STATE_BYTES: usize = 32;
// The first block fills the state directly; it is also the buffer size.
const INITIAL_RATE: usize = 16;
// The absorption rate after the first block.
const RATE: usize = 4;
const SQUEEZE_RATE: usize = 16;
// The domain constant goes into the top three bits of the last state byte.
const LAST_THREE_BITS_OFFSET: u32 = 5;
const ROUNDS: usize = 12;
// The side of the nibble matrix.
const D: usize = 8;

// The round constants, eight per round, added to column 0.
#[rustfmt::skip]
const RC: [u8; ROUNDS * D] = [
     1,  0,  2,  6, 14, 15, 13,  9,
     3,  2,  0,  4, 12, 13, 15, 11,
     7,  6,  4,  0,  8,  9, 11, 15,
    14, 15, 13,  9,  1,  0,  2,  6,
    13, 12, 14, 10,  2,  3,  1,  5,
    11, 10,  8, 12,  4,  5,  7,  3,
     6,  7,  5,  1,  9,  8, 10, 14,
    12, 13, 15, 11,  3,  2,  0,  4,
     9,  8, 10, 14,  6,  7,  5,  1,
     2,  3,  1,  5, 13, 12, 14, 10,
     5,  4,  6,  2, 10, 11,  9, 13,
    10, 11,  9, 13,  5,  4,  6,  2,
];

// The MDS matrix of MixColumnSerial over GF(2^4).
#[rustfmt::skip]
const MIX_COL_MATRIX: [[u8; D]; D] = [
    [ 2,  4,  2, 11,  2,  8,  5,  6],
    [12,  9,  8, 13,  7,  7,  5,  2],
    [ 4,  4, 13, 13,  9,  4, 13,  9],
    [ 1,  6,  5,  1, 12, 13, 15, 14],
    [15, 12,  9, 13, 14,  5, 14, 13],
    [ 9, 14,  5, 15,  4, 12,  9,  6],
    [12,  2,  2, 10,  3,  1,  1, 14],
    [15,  1, 13, 10,  5, 10,  2,  3],
];

// The 4-bit S-box of SubCells.
const SBOX: [u8; 16] = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2];

/// The PHOTON-256 permutation on the 32-byte state (Bouncy Castle
/// `PHOTON_Permutation`). Nibble `i` of the matrix, row by row, is the low
/// half of byte `i / 2` for even `i` and the high half for odd `i`.
///
/// Variable time: SubCells indexes the S-box with nibbles of the state, so the
/// memory access pattern depends on the message. MixColumnSerial multiplies
/// in GF(2^4) with integer multiplications, masks and XORs, without tables.
fn photon_permutation(state: &mut [u8; STATE_BYTES]) {
    let mut s = [[0u8; D]; D];
    for i in 0..D * D {
        s[i >> 3][i & 7] = (state[i >> 1] >> (4 * (i & 1))) & 0x0f;
    }

    for round in 0..ROUNDS {
        // AddConstant.
        for (row, &rc) in s.iter_mut().zip(&RC[round * D..(round + 1) * D]) {
            row[0] ^= rc;
        }

        // SubCells.
        for row in s.iter_mut() {
            for cell in row.iter_mut() {
                *cell = SBOX[usize::from(*cell)];
            }
        }

        // ShiftRows: row i rotates left by i cells.
        for (i, row) in s.iter_mut().enumerate().skip(1) {
            row.rotate_left(i);
        }

        // MixColumnSerial, one column at a time; the products are reduced
        // modulo x^4 + x + 1.
        for j in 0..D {
            let mut column = [0u8; D];
            for (out, matrix_row) in column.iter_mut().zip(&MIX_COL_MATRIX) {
                let mut sum = 0u32;
                for (&x, row) in matrix_row.iter().zip(&s) {
                    let x = u32::from(x);
                    let b = u32::from(row[j]);
                    sum ^= x * (b & 1);
                    sum ^= x * (b & 2);
                    sum ^= x * (b & 4);
                    sum ^= x * (b & 8);
                }

                let t0 = sum >> 4;
                sum = (sum & 15) ^ t0 ^ (t0 << 1);

                let t1 = sum >> 4;
                sum = (sum & 15) ^ t1 ^ (t1 << 1);

                *out = sum as u8;
            }
            for (row, &value) in s.iter_mut().zip(&column) {
                row[j] = value;
            }
        }
    }

    for i in (0..D * D).step_by(2) {
        state[i >> 1] = (s[i >> 3][i & 7] & 0x0f) | ((s[i >> 3][(i + 1) & 7] & 0x0f) << 4);
    }
}

/// Absorbs one full 16-byte buffer (Bouncy Castle `ProcessBuffer`): the first
/// block of the message fills the state, every later one goes in 4 bytes per
/// permutation. Variable time, through `photon_permutation`.
fn process_buffer(state: &mut [u8; STATE_BYTES], phase: &mut u8, block: &[u8]) {
    if *phase == 0 {
        state[..INITIAL_RATE].copy_from_slice(&block[..INITIAL_RATE]);
        *phase = 1;
    } else {
        for chunk in block[..INITIAL_RATE].chunks_exact(RATE) {
            photon_permutation(state);
            xor_into(state, chunk);
        }
        *phase = 2;
    }
}

/// XORs `bytes` into the start of the state (Bouncy Castle `Bytes.XorTo`).
/// Constant time.
fn xor_into(state: &mut [u8; STATE_BYTES], bytes: &[u8]) {
    for (s, &x) in state.iter_mut().zip(bytes) {
        *s ^= x;
    }
}

/// The PHOTON-Beetle-Hash digest (Bouncy Castle `PhotonBeetleDigest`), a NIST
/// lightweight cryptography finalist producing a 32-byte hash.
///
/// Variable time: the permutation indexes a 4-bit S-box with nibbles of the
/// state, which can leak the message through cache timing. The table is only
/// 16 bytes, but it may straddle two cache lines, and loads at secret indices
/// are not guaranteed to take the same time. Hash only public data with it,
/// or accept that leak in the threat model.
///
/// Dropping or resetting the digest, which `do_final` also does, wipes its
/// state, buffered input, buffer position and absorption phase with volatile
/// writes. Copies the permutation leaves in registers or on the stack, such
/// as the nibble matrix, and copies a move leaves behind are not wiped.
///
/// `do_final` panics if the output buffer is shorter than 32 bytes.
#[derive(Clone)]
pub struct PhotonBeetleDigest {
    /// The 32-byte PHOTON-256 state.
    state: [u8; STATE_BYTES],
    /// The partial 16-byte block not yet absorbed.
    buffer: [u8; INITIAL_RATE],
    /// The number of bytes in `buffer`, always below 16 between calls.
    buffer_position: usize,
    /// 0 before any block, 1 after the first 16-byte block, 2 after a block
    /// absorbed 4 bytes at a time.
    phase: u8,
}

impl Default for PhotonBeetleDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl PhotonBeetleDigest {
    /// Creates a fresh PHOTON-Beetle-Hash digest. Constant time.
    pub const fn new() -> Self {
        PhotonBeetleDigest {
            state: [0; STATE_BYTES],
            buffer: [0; INITIAL_RATE],
            buffer_position: 0,
            phase: 0,
        }
    }

    /// Absorbs the buffered bytes with the ozs padding and adds the domain
    /// constant (Bouncy Castle `FinishAbsorbing`). Variable time, through
    /// `photon_permutation`; the branches depend only on the message length.
    fn finish_absorbing(&mut self) {
        let position = self.buffer_position;
        if self.phase == 0 {
            if position != 0 {
                self.state[..position].copy_from_slice(&self.buffer[..position]);
                // ozs padding.
                self.state[position] ^= 0x01;
            }

            self.state[STATE_BYTES - 1] ^= 1 << LAST_THREE_BITS_OFFSET;
        } else if self.phase == 1 && position == 0 {
            self.state[STATE_BYTES - 1] ^= 2 << LAST_THREE_BITS_OFFSET;
        } else {
            let mut chunks = self.buffer[..position].chunks_exact(RATE);
            for chunk in &mut chunks {
                photon_permutation(&mut self.state);
                xor_into(&mut self.state, chunk);
            }

            let remainder = chunks.remainder();
            if !remainder.is_empty() {
                photon_permutation(&mut self.state);
                xor_into(&mut self.state, remainder);
                // ozs padding.
                self.state[remainder.len()] ^= 0x01;
                self.state[STATE_BYTES - 1] ^= 2 << LAST_THREE_BITS_OFFSET;
            } else {
                self.state[STATE_BYTES - 1] ^= 1 << LAST_THREE_BITS_OFFSET;
            }
        }
    }
}

impl Drop for PhotonBeetleDigest {
    /// Wipes the state, the buffered bytes, the buffer position and the
    /// phase. Constant time.
    fn drop(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.buffer_position.zeroize();
        self.phase.zeroize();
    }
}

impl fmt::Display for PhotonBeetleDigest {
    /// Writes `Photon-Beetle Hash` without inspecting the digest state.
    /// Constant time with respect to the message; output timing depends on
    /// the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Photon-Beetle Hash")
    }
}

impl TryDigest for PhotonBeetleDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    // Bouncy Castle leaves `GetByteLength` unimplemented; this reports the
    // absorption rate after the first block.
    fn byte_length(&self) -> usize {
        RATE
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        let available = INITIAL_RATE - self.buffer_position;
        if input.len() < available {
            self.buffer[self.buffer_position..self.buffer_position + input.len()]
                .copy_from_slice(input);
            self.buffer_position += input.len();
            return Ok(());
        }

        if self.buffer_position > 0 {
            let (head, rest) = input.split_at(available);
            self.buffer[self.buffer_position..].copy_from_slice(head);
            process_buffer(&mut self.state, &mut self.phase, &self.buffer);
            input = rest;
        }

        while input.len() >= INITIAL_RATE {
            let (block, rest) = input.split_at(INITIAL_RATE);
            process_buffer(&mut self.state, &mut self.phase, block);
            input = rest;
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_position = input.len();
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
            "output buffer shorter than the 32-byte PHOTON-Beetle-Hash digest"
        );
        self.finish_absorbing();

        photon_permutation(&mut self.state);
        output[..SQUEEZE_RATE].copy_from_slice(&self.state[..SQUEEZE_RATE]);
        photon_permutation(&mut self.state);
        output[SQUEEZE_RATE..DIGEST_LENGTH]
            .copy_from_slice(&self.state[..DIGEST_LENGTH - SQUEEZE_RATE]);

        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    // A fresh digest replaces this one, which the drop wipes.
    fn try_reset(&mut self) -> Result<(), Self::Error> {
        *self = Self::new();
        Ok(())
    }
}
