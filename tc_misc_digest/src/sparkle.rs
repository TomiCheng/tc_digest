//! ESCH-256 and ESCH-384, ported from Bouncy Castle's `SparkleDigest`.
//!
//! ESCH is the hash of the SPARKLE family, a NIST lightweight cryptography
//! finalist: a sponge with a 16-byte rate on the SPARKLE-384 permutation for
//! ESCH-256 and on SPARKLE-512 for ESCH-384. Each message block enters the
//! state through the linear map `ELL`. The permutations, which Bouncy Castle
//! shares with its SCHWAEMM engine, live in this module.

use core::{convert::Infallible, fmt};

use tc_digest::TryDigest;
use tc_zeroize::Zeroize;

const RATE_BYTES: usize = 16;
const RATE_WORDS: usize = 4;
// The larger state, SPARKLE-512; ESCH-256 uses the first twelve words.
const MAX_STATE_WORDS: usize = 16;

// The round constants of SPARKLE, the fractional digits of e.
const RCON: [u32; 8] = [
    0xb7e1_5162,
    0xbf71_5880,
    0x38b4_da56,
    0x324e_7738,
    0xbb11_85eb,
    0x4f7c_7b57,
    0xcfbf_a1c8,
    0xc2b3_293d,
];

/// Selects the ESCH variant (Bouncy Castle `SparkleDigest.SparkleParameters`).
/// Both variants are constant time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SparkleParameters {
    /// ESCH-256: a 32-byte digest on the 384-bit SPARKLE permutation.
    Esch256,
    /// ESCH-384: a 48-byte digest on the 512-bit SPARKLE permutation.
    Esch384,
}

impl SparkleParameters {
    /// The digest length in bytes. Constant time.
    const fn digest_bytes(self) -> usize {
        match self {
            Self::Esch256 => 32,
            Self::Esch384 => 48,
        }
    }

    /// The state length in 32-bit words. Constant time.
    const fn state_words(self) -> usize {
        match self {
            Self::Esch256 => 12,
            Self::Esch384 => 16,
        }
    }

    /// The steps of the slim permutation, run after each message block and
    /// between squeezes. Constant time.
    const fn steps_slim(self) -> usize {
        match self {
            Self::Esch256 => 7,
            Self::Esch384 => 8,
        }
    }

    /// The steps of the big permutation, run after the last block.
    /// Constant time.
    const fn steps_big(self) -> usize {
        match self {
            Self::Esch256 => 11,
            Self::Esch384 => 12,
        }
    }
}

/// The ESCH-256 or ESCH-384 digest (Bouncy Castle `SparkleDigest`), producing
/// a 32- or 48-byte hash.
///
/// Constant time: the SPARKLE permutations use only additions, XORs and fixed
/// rotations, and the running time depends only on the message length and
/// the variant.
///
/// Dropping or resetting the digest, which `do_final` also does, wipes its
/// state, buffered input and buffer position with volatile writes; resetting
/// keeps the variant. Copies the permutation leaves in registers or on the
/// stack, and copies a move leaves behind are not wiped.
///
/// `do_final` panics if the output buffer is shorter than the digest, 32
/// bytes for ESCH-256 and 48 bytes for ESCH-384.
#[derive(Clone)]
pub struct SparkleDigest {
    /// The selected variant.
    parameters: SparkleParameters,
    /// The SPARKLE state; ESCH-256 uses the first twelve words.
    state: [u32; MAX_STATE_WORDS],
    /// The last block, held back until more input or `do_final` shows whether
    /// it ends the message.
    buffer: [u8; RATE_BYTES],
    /// The number of bytes in `buffer`, 0 to 16.
    buffer_position: usize,
}

impl SparkleDigest {
    /// Creates a fresh ESCH digest of the selected variant. Constant time.
    pub const fn new(parameters: SparkleParameters) -> Self {
        SparkleDigest {
            parameters,
            state: [0; MAX_STATE_WORDS],
            buffer: [0; RATE_BYTES],
            buffer_position: 0,
        }
    }
}

/// Runs `steps` steps of SPARKLE-384 for ESCH-256 or SPARKLE-512 for ESCH-384
/// on the state (Bouncy Castle `SparkleEngine.SparkleOpt`). Constant time.
fn sparkle_opt(parameters: SparkleParameters, state: &mut [u32; MAX_STATE_WORDS], steps: usize) {
    match parameters {
        SparkleParameters::Esch256 => sparkle_opt12(
            state
                .first_chunk_mut()
                .expect("the state holds twelve words"),
            steps,
        ),
        SparkleParameters::Esch384 => sparkle_opt16(state, steps),
    }
}

/// Mixes one 16-byte block into the state through `ELL` and runs `steps`
/// steps of the permutation (Bouncy Castle `ProcessBlock`). Constant time.
fn process_block(
    parameters: SparkleParameters,
    state: &mut [u32; MAX_STATE_WORDS],
    block: &[u8],
    steps: usize,
) {
    let t0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
    let t1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
    let t2 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
    let t3 = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);

    // Addition of a buffer block to the state.
    let tx = ell(t0 ^ t2);
    let ty = ell(t1 ^ t3);
    state[0] ^= t0 ^ ty;
    state[1] ^= t1 ^ tx;
    state[2] ^= t2 ^ ty;
    state[3] ^= t3 ^ tx;
    state[4] ^= ty;
    state[5] ^= tx;
    if parameters == SparkleParameters::Esch384 {
        state[6] ^= ty;
        state[7] ^= tx;
    }

    sparkle_opt(parameters, state, steps);
}

/// Writes the four rate words of the state, little-endian, to the first 16
/// bytes of `output` (Bouncy Castle `Pack.UInt32_To_LE`). Constant time.
fn store_rate(state: &[u32; MAX_STATE_WORDS], output: &mut [u8]) {
    for (chunk, word) in output[..RATE_BYTES]
        .chunks_exact_mut(4)
        .zip(&state[..RATE_WORDS])
    {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
}

/// The linear map `ELL`: a 16-bit rotation XORed with the low half (Bouncy
/// Castle `ELL`). Constant time.
#[inline(always)]
fn ell(x: u32) -> u32 {
    x.rotate_right(16) ^ (x & 0xffff)
}

/// The Alzette ARX-box on the branch `(s00, s01)` with the round constant
/// `rc` (Bouncy Castle `ArxBox`). Constant time.
#[inline(always)]
fn arx_box(rc: u32, s00: &mut u32, s01: &mut u32) {
    *s00 = s00.wrapping_add(s01.rotate_right(31));
    *s01 ^= s00.rotate_right(24);
    *s00 ^= rc;
    *s00 = s00.wrapping_add(s01.rotate_right(17));
    *s01 ^= s00.rotate_right(17);
    *s00 ^= rc;
    *s00 = s00.wrapping_add(*s01);
    *s01 ^= s00.rotate_right(31);
    *s00 ^= rc;
    *s00 = s00.wrapping_add(s01.rotate_right(24));
    *s01 ^= s00.rotate_right(16);
    *s00 ^= rc;
}

/// `steps` steps of SPARKLE-384 on six branches (Bouncy Castle
/// `SparkleOpt12`). Constant time: the step counter alone selects the round
/// constant.
fn sparkle_opt12(state: &mut [u32; 12], steps: usize) {
    let [
        mut s00,
        mut s01,
        mut s02,
        mut s03,
        mut s04,
        mut s05,
        mut s06,
        mut s07,
        mut s08,
        mut s09,
        mut s10,
        mut s11,
    ] = *state;

    for step in 0..steps {
        // Add round constant.
        s01 ^= RCON[step & 7];
        s03 ^= step as u32;

        // ARXBOX layer.
        arx_box(RCON[0], &mut s00, &mut s01);
        arx_box(RCON[1], &mut s02, &mut s03);
        arx_box(RCON[2], &mut s04, &mut s05);
        arx_box(RCON[3], &mut s06, &mut s07);
        arx_box(RCON[4], &mut s08, &mut s09);
        arx_box(RCON[5], &mut s10, &mut s11);

        // Linear layer.
        let t024 = ell(s00 ^ s02 ^ s04);
        let t135 = ell(s01 ^ s03 ^ s05);

        let u00 = s00 ^ s06;
        let u01 = s01 ^ s07;
        let u02 = s02 ^ s08;
        let u03 = s03 ^ s09;
        let u04 = s04 ^ s10;
        let u05 = s05 ^ s11;

        s06 = s00;
        s07 = s01;
        s08 = s02;
        s09 = s03;
        s10 = s04;
        s11 = s05;

        s00 = u02 ^ t135;
        s01 = u03 ^ t024;
        s02 = u04 ^ t135;
        s03 = u05 ^ t024;
        s04 = u00 ^ t135;
        s05 = u01 ^ t024;
    }

    *state = [s00, s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11];
}

/// `steps` steps of SPARKLE-512 on eight branches, two steps per pass so the
/// halves trade places instead of being copied (the portable path of Bouncy
/// Castle `SparkleOpt16`; its SSE2 path is not ported). `steps` must be even.
/// Constant time: the step counter alone selects the round constant.
fn sparkle_opt16(state: &mut [u32; 16], steps: usize) {
    debug_assert!(steps & 1 == 0, "SPARKLE-512 runs an even number of steps");

    let [
        mut s00,
        mut s01,
        mut s02,
        mut s03,
        mut s04,
        mut s05,
        mut s06,
        mut s07,
        mut s08,
        mut s09,
        mut s10,
        mut s11,
        mut s12,
        mut s13,
        mut s14,
        mut s15,
    ] = *state;

    let mut step = 0;
    while step < steps {
        // Step 1: add round constant.
        s01 ^= RCON[step & 7];
        s03 ^= step as u32;
        step += 1;

        // ARXBOX layer.
        arx_box(RCON[0], &mut s00, &mut s01);
        arx_box(RCON[1], &mut s02, &mut s03);
        arx_box(RCON[2], &mut s04, &mut s05);
        arx_box(RCON[3], &mut s06, &mut s07);
        arx_box(RCON[4], &mut s08, &mut s09);
        arx_box(RCON[5], &mut s10, &mut s11);
        arx_box(RCON[6], &mut s12, &mut s13);
        arx_box(RCON[7], &mut s14, &mut s15);

        // Linear layer.
        let t0246 = ell(s00 ^ s02 ^ s04 ^ s06);
        let t1357 = ell(s01 ^ s03 ^ s05 ^ s07);

        let u08 = s08;
        let u09 = s09;

        s08 = s02 ^ s10 ^ t1357;
        s09 = s03 ^ s11 ^ t0246;
        s10 = s04 ^ s12 ^ t1357;
        s11 = s05 ^ s13 ^ t0246;
        s12 = s06 ^ s14 ^ t1357;
        s13 = s07 ^ s15 ^ t0246;
        s14 = s00 ^ u08 ^ t1357;
        s15 = s01 ^ u09 ^ t0246;

        // Step 2: add round constant.
        s09 ^= RCON[step & 7];
        s11 ^= step as u32;
        step += 1;

        // ARXBOX layer.
        arx_box(RCON[0], &mut s08, &mut s09);
        arx_box(RCON[1], &mut s10, &mut s11);
        arx_box(RCON[2], &mut s12, &mut s13);
        arx_box(RCON[3], &mut s14, &mut s15);
        arx_box(RCON[4], &mut s00, &mut s01);
        arx_box(RCON[5], &mut s02, &mut s03);
        arx_box(RCON[6], &mut s04, &mut s05);
        arx_box(RCON[7], &mut s06, &mut s07);

        // Linear layer.
        let t8ace = ell(s08 ^ s10 ^ s12 ^ s14);
        let t9bdf = ell(s09 ^ s11 ^ s13 ^ s15);

        let u00 = s00;
        let u01 = s01;

        s00 = s02 ^ s10 ^ t9bdf;
        s01 = s03 ^ s11 ^ t8ace;
        s02 = s04 ^ s12 ^ t9bdf;
        s03 = s05 ^ s13 ^ t8ace;
        s04 = s06 ^ s14 ^ t9bdf;
        s05 = s07 ^ s15 ^ t8ace;
        s06 = u00 ^ s08 ^ t9bdf;
        s07 = u01 ^ s09 ^ t8ace;
    }

    *state = [
        s00, s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11, s12, s13, s14, s15,
    ];
}

impl Drop for SparkleDigest {
    /// Wipes the state, the buffered bytes and the buffer position.
    /// Constant time.
    fn drop(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.buffer_position.zeroize();
    }
}

impl fmt::Display for SparkleDigest {
    /// Writes `ESCH-256` or `ESCH-384` without inspecting the digest state.
    /// Constant time with respect to the message; output timing depends on
    /// the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.parameters {
            SparkleParameters::Esch256 => "ESCH-256",
            SparkleParameters::Esch384 => "ESCH-384",
        })
    }
}

impl TryDigest for SparkleDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.parameters.digest_bytes()
    }

    fn byte_length(&self) -> usize {
        RATE_BYTES
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        let available = RATE_BYTES - self.buffer_position;
        if input.len() <= available {
            self.buffer[self.buffer_position..self.buffer_position + input.len()]
                .copy_from_slice(input);
            self.buffer_position += input.len();
            return Ok(());
        }

        let steps = self.parameters.steps_slim();
        if self.buffer_position > 0 {
            let (head, rest) = input.split_at(available);
            self.buffer[self.buffer_position..].copy_from_slice(head);
            input = rest;

            process_block(self.parameters, &mut self.state, &self.buffer, steps);
        }

        // The last block stays buffered, even when full.
        while input.len() > RATE_BYTES {
            let (block, rest) = input.split_at(RATE_BYTES);
            process_block(self.parameters, &mut self.state, block, steps);
            input = rest;
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_position = input.len();
        Ok(())
    }

    /// Writes the 32- or 48-byte digest to the start of `output` and resets,
    /// keeping the variant.
    ///
    /// # Panics
    ///
    /// Panics if `output` is shorter than the digest, before changing any
    /// state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let digest_bytes = self.parameters.digest_bytes();
        assert!(
            output.len() >= digest_bytes,
            "output buffer shorter than the {digest_bytes}-byte ESCH digest"
        );
        let parameters = self.parameters;
        let state_words = parameters.state_words();

        // Addition of the constant M1 for a padded last block, M2 for a full
        // one.
        if self.buffer_position < RATE_BYTES {
            self.state[(state_words >> 1) - 1] ^= 1 << 24;

            // Padding.
            self.buffer[self.buffer_position] = 0x80;
            self.buffer[self.buffer_position + 1..].fill(0);
        } else {
            self.state[(state_words >> 1) - 1] ^= 1 << 25;
        }

        // Addition of the last block, padding included.
        process_block(
            parameters,
            &mut self.state,
            &self.buffer,
            parameters.steps_big(),
        );

        store_rate(&self.state, output);
        for squeezed in output[RATE_BYTES..digest_bytes].chunks_exact_mut(RATE_BYTES) {
            sparkle_opt(parameters, &mut self.state, parameters.steps_slim());
            store_rate(&self.state, squeezed);
        }

        self.try_reset()?;
        Ok(digest_bytes)
    }

    // A fresh digest of the same variant replaces this one, which the drop
    // wipes.
    fn try_reset(&mut self) -> Result<(), Self::Error> {
        *self = Self::new(self.parameters);
        Ok(())
    }
}
