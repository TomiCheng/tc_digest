//! Xoodyak Hash, ported from Bouncy Castle's `XoodyakDigest`.
//!
//! Xoodyak runs the Cyclist mode on the 384-bit Xoodoo permutation. In hash
//! mode it absorbs the message in 16-byte blocks, one permutation each, and
//! squeezes two 16-byte blocks for the fixed 32-byte digest.

use core::{convert::Infallible, fmt};

use tc_digest::TryDigest;
use tc_zeroize::Zeroize;

const DIGEST_LENGTH: usize = 32;
// The Xoodoo state, b' in the specification.
const STATE_BYTES: usize = 48;
// The absorption rate R_absorb of hash mode, also the block buffer size.
const RATE: usize = 16;
// The bytes of one squeeze, half the digest.
const TAG_LENGTH: usize = 16;

// The Xoodoo round constants, one per round.
const RC: [u32; 12] = [
    0x0000_0058,
    0x0000_0038,
    0x0000_03c0,
    0x0000_00d0,
    0x0000_0120,
    0x0000_0014,
    0x0000_0060,
    0x0000_002c,
    0x0000_0380,
    0x0000_00f0,
    0x0000_01a0,
    0x0000_0012,
];

/// The twelve-round Xoodoo permutation on the state, read as twelve
/// little-endian words (Bouncy Castle `Up`; hash mode adds no up color).
/// Constant time: theta, rho, iota and chi use only XOR, AND, NOT and fixed
/// rotations, and the round count is fixed.
fn up(state: &mut [u8; STATE_BYTES]) {
    let mut words = [0u32; 12];
    for (word, chunk) in words.iter_mut().zip(state.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().expect("4-byte chunk"));
    }
    let [
        mut a0,
        mut a1,
        mut a2,
        mut a3,
        mut a4,
        mut a5,
        mut a6,
        mut a7,
        mut a8,
        mut a9,
        mut a10,
        mut a11,
    ] = words;

    for rc in RC {
        // Theta: column parity mixer.
        let p0 = a0 ^ a4 ^ a8;
        let p1 = a1 ^ a5 ^ a9;
        let p2 = a2 ^ a6 ^ a10;
        let p3 = a3 ^ a7 ^ a11;

        let e0 = p3.rotate_left(5) ^ p3.rotate_left(14);
        let e1 = p0.rotate_left(5) ^ p0.rotate_left(14);
        let e2 = p1.rotate_left(5) ^ p1.rotate_left(14);
        let e3 = p2.rotate_left(5) ^ p2.rotate_left(14);

        a0 ^= e0;
        a4 ^= e0;
        a8 ^= e0;

        a1 ^= e1;
        a5 ^= e1;
        a9 ^= e1;

        a2 ^= e2;
        a6 ^= e2;
        a10 ^= e2;

        a3 ^= e3;
        a7 ^= e3;
        a11 ^= e3;

        // Rho-west: plane shift.
        let mut b0 = a0;
        let b1 = a1;
        let b2 = a2;
        let b3 = a3;

        let b4 = a7;
        let b5 = a4;
        let b6 = a5;
        let b7 = a6;

        let mut b8 = a8.rotate_left(11);
        let mut b9 = a9.rotate_left(11);
        let mut b10 = a10.rotate_left(11);
        let mut b11 = a11.rotate_left(11);

        // Iota: round constant.
        b0 ^= rc;

        // Chi: nonlinear layer.
        a0 = b0 ^ (!b4 & b8);
        a1 = b1 ^ (!b5 & b9);
        a2 = b2 ^ (!b6 & b10);
        a3 = b3 ^ (!b7 & b11);

        a4 = b4 ^ (!b8 & b0);
        a5 = b5 ^ (!b9 & b1);
        a6 = b6 ^ (!b10 & b2);
        a7 = b7 ^ (!b11 & b3);

        b8 ^= !b0 & b4;
        b9 ^= !b1 & b5;
        b10 ^= !b2 & b6;
        b11 ^= !b3 & b7;

        // Rho-east: plane shift.
        a4 = a4.rotate_left(1);
        a5 = a5.rotate_left(1);
        a6 = a6.rotate_left(1);
        a7 = a7.rotate_left(1);

        a8 = b10.rotate_left(8);
        a9 = b11.rotate_left(8);
        a10 = b8.rotate_left(8);
        a11 = b9.rotate_left(8);
    }

    let words = [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11];
    for (chunk, word) in state.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
}

/// XORs `block`, at most 16 bytes, into the start of the state followed by
/// the padding byte 0x01 (Bouncy Castle `Down`). Constant time: the bytes
/// touched depend only on the length of `block`.
fn down(state: &mut [u8; STATE_BYTES], block: &[u8]) {
    for (s, &x) in state.iter_mut().zip(block) {
        *s ^= x;
    }
    state[block.len()] ^= 0x01;
}

/// The Xoodyak Hash digest (Bouncy Castle `XoodyakDigest`), producing a
/// 32-byte hash.
///
/// Constant time: the Xoodoo permutation uses only XOR, AND, NOT and fixed
/// rotations, and the running time depends only on the message length.
///
/// Dropping or resetting the digest, which `do_final` also does, wipes its
/// state, buffered input, buffer position and absorbed-block flag with
/// volatile writes. Copies the permutation leaves in registers or on the
/// stack, such as the state words, and copies a move leaves behind are not
/// wiped.
///
/// `do_final` panics if the output buffer is shorter than 32 bytes.
#[derive(Clone)]
pub struct XoodyakDigest {
    /// The 48-byte Xoodoo state.
    state: [u8; STATE_BYTES],
    /// The partial block not yet absorbed.
    buffer: [u8; RATE],
    /// The number of bytes in `buffer`, always below 16 between calls.
    buffer_position: usize,
    /// Whether a full block has been absorbed; without one, `do_final`
    /// absorbs an empty block for the empty message.
    updated: bool,
}

impl Default for XoodyakDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl XoodyakDigest {
    /// Creates a fresh Xoodyak Hash digest. Constant time.
    pub const fn new() -> Self {
        let mut state = [0u8; STATE_BYTES];
        // The hash-mode color of the first absorbed block, set ahead of time
        // as Bouncy Castle's `Reset` does.
        state[STATE_BYTES - 1] = 0x01;
        XoodyakDigest {
            state,
            buffer: [0; RATE],
            buffer_position: 0,
            updated: false,
        }
    }
}

impl Drop for XoodyakDigest {
    /// Wipes the state, the buffered bytes, the buffer position and the
    /// absorbed-block flag. Constant time.
    fn drop(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.buffer_position.zeroize();
        self.updated.zeroize();
    }
}

impl fmt::Display for XoodyakDigest {
    /// Writes `Xoodyak Hash` without inspecting the digest state.
    /// Constant time with respect to the message; output timing depends on
    /// the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Xoodyak Hash")
    }
}

impl TryDigest for XoodyakDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        RATE
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        let available = RATE - self.buffer_position;
        if input.len() < available {
            self.buffer[self.buffer_position..self.buffer_position + input.len()]
                .copy_from_slice(input);
            self.buffer_position += input.len();
            return Ok(());
        }

        if self.buffer_position > 0 {
            let (head, rest) = input.split_at(available);
            self.buffer[self.buffer_position..].copy_from_slice(head);
            input = rest;

            down(&mut self.state, &self.buffer);
            up(&mut self.state);
            self.updated = true;
        }

        while input.len() >= RATE {
            let (block, rest) = input.split_at(RATE);
            down(&mut self.state, block);
            up(&mut self.state);
            self.updated = true;
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
            "output buffer shorter than the 32-byte Xoodyak Hash digest"
        );
        // The last, possibly empty, block; a message of whole blocks has none.
        if self.buffer_position > 0 || !self.updated {
            down(&mut self.state, &self.buffer[..self.buffer_position]);
            up(&mut self.state);
        }

        output[..TAG_LENGTH].copy_from_slice(&self.state[..TAG_LENGTH]);

        // The second squeeze: Down of the empty string, then Up.
        self.state[0] ^= 0x01;
        up(&mut self.state);

        output[TAG_LENGTH..DIGEST_LENGTH].copy_from_slice(&self.state[..TAG_LENGTH]);

        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    // A fresh digest replaces this one, which the drop wipes.
    fn try_reset(&mut self) -> Result<(), Self::Error> {
        *self = Self::new();
        Ok(())
    }
}
