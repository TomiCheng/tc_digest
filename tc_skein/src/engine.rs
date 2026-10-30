//! Skein's Unique Block Iteration (UBI) chaining over Threefish, ported from
//! Bouncy Castle's `SkeinEngine`.

use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_threefish::{ThreefishParamsRef, ThreefishPortableEngine};
use tc_zeroize::Zeroize;

use crate::{InitError, SkeinParams, SkeinParamsRef};

const MAX_WORDS: usize = 16;
const MAX_BLOCK_BYTES: usize = MAX_WORDS * 8;

// The UBI block types of Skein 1.3 (Bouncy Castle `SkeinParameters`).
const TYPE_KEY: u64 = 0;
const TYPE_CONFIG: u64 = 4;
const TYPE_PERSONALISATION: u64 = 8;
const TYPE_PUBLIC_KEY: u64 = 12;
const TYPE_KEY_IDENTIFIER: u64 = 16;
const TYPE_NONCE: u64 = 20;
const TYPE_MESSAGE: u64 = 48;
const TYPE_OUTPUT: u64 = 63;

const T1_FIRST: u64 = 1 << 62;
const T1_FINAL: u64 = 1 << 63;

/// The chaining values after the configuration block of the usual unkeyed
/// variants, from Appendix C of the Skein 1.3 submission (Bouncy Castle
/// `InitialStates`): state size and output size in bits, then the words.
const INITIAL_STATES: [(usize, usize, &[u64]); 9] = [
    (
        256,
        128,
        &[
            0xe111_1906_964d_7260,
            0x883d_aaa7_7c8d_811c,
            0x1008_0df4_9196_0f7a,
            0xccf7_dde5_b45b_c1c2,
        ],
    ),
    (
        256,
        160,
        &[
            0x1420_2314_7282_5e98,
            0x2ac4_e9a2_5a77_e590,
            0xd47a_5856_8838_d63e,
            0x2dd2_e496_8586_ab7d,
        ],
    ),
    (
        256,
        224,
        &[
            0xc609_8a8c_9ae5_ea0b,
            0x876d_5686_08c5_191c,
            0x99cb_88d7_d7f5_3884,
            0x384b_ddb1_aedd_b5de,
        ],
    ),
    (
        256,
        256,
        &[
            0xfc9d_a860_d048_b449,
            0x2fca_6647_9fa7_d833,
            0xb33b_c389_6656_840f,
            0x6a54_e920_fde8_da69,
        ],
    ),
    (
        512,
        128,
        &[
            0xa8bc_7bf3_6fbf_9f52,
            0x1e98_72ce_bd1a_f0aa,
            0x309b_1790_b321_90d3,
            0xbcfb_b854_3f94_805c,
            0x0da6_1bcd_6e31_b11b,
            0x1a18_ebea_d46a_32e3,
            0xa2cc_5b18_ce84_aa82,
            0x6982_ab28_9d46_982d,
        ],
    ),
    (
        512,
        160,
        &[
            0x28b8_1a2a_e013_bd91,
            0xc2f1_1668_b5bd_f78f,
            0x1760_d8f3_f6a5_6f12,
            0x4fb7_4758_8239_904f,
            0x21ed_e07f_7eaf_5056,
            0xd908_922e_63ed_70b8,
            0xb8ec_76ff_eccb_52fa,
            0x01a4_7bb8_a3f2_7a6e,
        ],
    ),
    (
        512,
        224,
        &[
            0xccd0_6162_4867_7224,
            0xcba6_5cf3_a923_39ef,
            0x8ccd_69d6_52ff_4b64,
            0x398a_ed7b_3ab8_90b4,
            0x0f59_d1b1_457d_2bd0,
            0x6776_fe65_75d4_eb3d,
            0x99fb_c70e_9974_13e9,
            0x9e2c_fccf_e1c4_1ef7,
        ],
    ),
    (
        512,
        384,
        &[
            0xa3f6_c6bf_3a75_ef5f,
            0xb0fe_f9cc_fd84_faa4,
            0x9d77_dd66_3d77_0cfe,
            0xd798_cbf3_b468_fdda,
            0x1bc4_a666_8a0e_4465,
            0x7ed7_d434_e580_7407,
            0x548f_c1ac_d4ec_44d6,
            0x266e_1754_6aa1_8ff8,
        ],
    ),
    (
        512,
        512,
        &[
            0x4903_adff_749c_51ce,
            0x0d95_de39_9746_df03,
            0x8fd1_9341_27c7_9bce,
            0x9a25_5629_ff35_2cb1,
            0x5db6_2599_df6c_a7b0,
            0xeabe_394c_a9d5_c3f4,
            0x9911_12c7_1a75_b523,
            0xae18_a40b_660f_cc33,
        ],
    ),
];

/// The UBI tweak (Bouncy Castle `UbiTweak`): the 96-bit byte position in
/// bits 0 to 95, the block type in bits 120 to 125, and the first and final
/// flags in bits 126 and 127.
#[derive(Clone, Copy)]
struct UbiTweak([u64; 2]);

impl UbiTweak {
    /// The tweak of the first block of a UBI of `block_type`. Constant time.
    const fn new(block_type: u64) -> Self {
        UbiTweak([0, T1_FIRST | (block_type << 56)])
    }

    /// Advances the position by `advance` bytes, modulo 2^96 (Bouncy Castle
    /// `AdvancePosition`). Constant time.
    fn advance_position(&mut self, advance: usize) {
        let position = u128::from(self.0[0]) | (u128::from(self.0[1] & 0xffff_ffff) << 64);
        let position = position.wrapping_add(advance as u128);
        self.0[0] = position as u64;
        self.0[1] = (self.0[1] & 0xffff_ffff_0000_0000) | ((position >> 64) as u64 & 0xffff_ffff);
    }

    /// Returns the tweak as 16 little-endian bytes. Constant time.
    fn to_bytes(self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&self.0[0].to_le_bytes());
        bytes[8..].copy_from_slice(&self.0[1].to_le_bytes());
        bytes
    }
}

/// Encrypts `block` with Threefish of `WORDS` words under the key `chain` and
/// `tweak`, and XORs the block back in: one UBI step (Bouncy Castle UBI
/// `ProcessBlock`). Constant time: Threefish uses only additions, rotations
/// and XORs.
fn process_threefish<const WORDS: usize>(
    chain: &[u64; MAX_WORDS],
    tweak: UbiTweak,
    block: &[u8; MAX_BLOCK_BYTES],
) -> [u64; MAX_WORDS] {
    let mut key = [0u8; MAX_BLOCK_BYTES];
    for (bytes, word) in key.chunks_exact_mut(8).zip(&chain[..WORDS]) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    let tweak = tweak.to_bytes();
    let mut cipher = ThreefishPortableEngine::<WORDS>::new();
    cipher
        .init(
            CipherDirection::Encrypt,
            &ThreefishParamsRef::with_tweak(&key[..WORDS * 8], &tweak),
        )
        .expect("Skein passes a full Threefish key and tweak");
    let mut encrypted = [0u8; MAX_BLOCK_BYTES];
    cipher
        .process_block(&block[..WORDS * 8], &mut encrypted[..WORDS * 8])
        .expect("Skein passes a full Threefish block");

    let mut output = [0u64; MAX_WORDS];
    for ((word, e), m) in output[..WORDS]
        .iter_mut()
        .zip(encrypted.chunks_exact(8))
        .zip(block.chunks_exact(8))
    {
        let e = u64::from_le_bytes(e.try_into().expect("8-byte chunk"));
        let m = u64::from_le_bytes(m.try_into().expect("8-byte chunk"));
        *word = e ^ m;
    }
    output
}

/// Runs one UBI step with the Threefish variant of `words` words.
/// Constant time.
fn process_block(
    words: usize,
    chain: &[u64; MAX_WORDS],
    tweak: UbiTweak,
    block: &[u8; MAX_BLOCK_BYTES],
) -> [u64; MAX_WORDS] {
    match words {
        4 => process_threefish::<4>(chain, tweak, block),
        8 => process_threefish::<8>(chain, tweak, block),
        16 => process_threefish::<16>(chain, tweak, block),
        _ => unreachable!("Skein validates its state size"),
    }
}

/// The 32-byte configuration block (Bouncy Castle `Configuration`): the
/// schema `SHA3`, version 1, the output length in bits and no tree hashing.
/// Constant time.
fn config_block(output_size_bits: u64) -> [u8; 32] {
    let mut config = [0u8; 32];
    config[..4].copy_from_slice(b"SHA3");
    config[4..6].copy_from_slice(&1u16.to_le_bytes());
    config[8..16].copy_from_slice(&output_size_bits.to_le_bytes());
    config
}

/// The Skein 1.3 engine (Bouncy Castle `SkeinEngine`): Unique Block Iteration
/// over Threefish with a 256-, 512- or 1024-bit state and any whole number of
/// output bytes, optionally keyed and personalised through [`SkeinParams`].
///
/// [`SkeinDigest`](crate::SkeinDigest) wraps it with the `tc_digest` traits;
/// the engine serves callers that build on Skein directly, such as a Skein
/// MAC.
///
/// Constant time: Threefish uses only additions, rotations and XORs, and the
/// running time depends only on the lengths of the message, the parameters
/// and the output.
///
/// Dropping the engine wipes its chaining value, its state after the key and
/// parameters, and its buffered block with volatile writes. Copies the
/// compression leaves in registers or on the stack, such as the Threefish key
/// bytes, and copies a move leaves behind are not wiped.
#[derive(Clone)]
pub struct SkeinEngine {
    /// The Threefish words per block: 4, 8 or 16.
    words: usize,
    /// The output length in bytes.
    output_size: usize,
    /// The chaining value; the first `words` entries are in use.
    chain: [u64; MAX_WORDS],
    /// The chaining value after the key, configuration and pre-message
    /// parameters, which a reset restores.
    initial_state: [u64; MAX_WORDS],
    /// The UBI block buffer.
    block: [u8; MAX_BLOCK_BYTES],
    /// The bytes buffered in `block`.
    offset: usize,
    /// The tweak of the current UBI block.
    tweak: UbiTweak,
}

impl SkeinEngine {
    /// The 256-bit state size, in bits.
    pub const SKEIN_256: usize = 256;
    /// The 512-bit state size, in bits.
    pub const SKEIN_512: usize = 512;
    /// The 1024-bit state size, in bits.
    pub const SKEIN_1024: usize = 1024;

    /// Creates an unkeyed engine with a `state_size_bits` of 256, 512 or 1024
    /// and an output of `output_size_bits`, a positive multiple of 8.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics on any other state size or output size, as Bouncy Castle
    /// throws an `ArgumentException`.
    pub fn new(state_size_bits: usize, output_size_bits: usize) -> Self {
        assert!(
            matches!(state_size_bits, 256 | 512 | 1024),
            "Skein state size must be 256, 512 or 1024 bits"
        );
        assert!(
            output_size_bits > 0 && output_size_bits % 8 == 0,
            "Skein output size must be a positive multiple of 8 bits"
        );
        let mut engine = SkeinEngine {
            words: state_size_bits / 64,
            output_size: output_size_bits / 8,
            chain: [0; MAX_WORDS],
            initial_state: [0; MAX_WORDS],
            block: [0; MAX_BLOCK_BYTES],
            offset: 0,
            tweak: UbiTweak::new(TYPE_MESSAGE),
        };
        engine.process_parameters(&SkeinParamsRef::new());
        engine
    }

    /// Applies `params` and starts a new message (Bouncy Castle `Init`); empty
    /// parameters return the engine to the plain digest. Constant time with
    /// respect to the parameter contents; their lengths are public.
    ///
    /// Returns [`InitError::KeyTooShort`] for a key shorter than 16 bytes,
    /// leaving the engine unchanged.
    pub fn init<P: SkeinParams + ?Sized>(&mut self, params: &P) -> Result<(), InitError> {
        if params.key().is_some_and(|key| key.len() < 16) {
            return Err(InitError::KeyTooShort);
        }
        self.process_parameters(params);
        Ok(())
    }

    /// Returns the state and block size in bytes. Constant time.
    pub const fn block_size(&self) -> usize {
        self.words * 8
    }

    /// Returns the output size in bytes. Constant time.
    pub const fn output_size(&self) -> usize {
        self.output_size
    }

    /// Absorbs message bytes. Constant time with respect to their contents.
    pub fn update(&mut self, input: &[u8]) {
        self.ubi_update(input);
    }

    /// Finishes the message, writes the output to the start of `output`,
    /// returns its length and starts a new message under the same parameters
    /// (Bouncy Castle `DoFinal`). Constant time with respect to the message
    /// and the parameters.
    ///
    /// # Panics
    ///
    /// Panics if `output` is shorter than the output size, before changing
    /// any state.
    pub fn do_final(&mut self, output: &mut [u8]) -> usize {
        assert!(
            output.len() >= self.output_size,
            "output buffer shorter than the Skein output"
        );
        self.ubi_final();

        // The output transform: one UBI of type output per block, each keyed
        // with the final chaining value and fed the block counter.
        let block_size = self.block_size();
        for (counter, chunk) in output[..self.output_size]
            .chunks_mut(block_size)
            .enumerate()
        {
            let mut block = [0u8; MAX_BLOCK_BYTES];
            block[..8].copy_from_slice(&(counter as u64).to_le_bytes());
            let mut tweak = UbiTweak::new(TYPE_OUTPUT);
            tweak.advance_position(8);
            tweak.0[1] |= T1_FINAL;
            let words = process_block(self.words, &self.chain, tweak, &block);
            for (bytes, word) in chunk.chunks_mut(8).zip(&words) {
                bytes.copy_from_slice(&word.to_le_bytes()[..bytes.len()]);
            }
        }

        self.reset();
        self.output_size
    }

    /// Discards the message and starts a new one under the same parameters
    /// (Bouncy Castle `Reset`). Constant time.
    pub fn reset(&mut self) {
        self.chain = self.initial_state;
        self.ubi_init(TYPE_MESSAGE);
    }

    /// Computes the state after the key, the configuration and the
    /// pre-message parameters, in type order (Bouncy Castle
    /// `CreateInitialState`), and starts the message UBI. Constant time with
    /// respect to the parameter contents.
    fn process_parameters<P: SkeinParams + ?Sized>(&mut self, params: &P) {
        let words = self.words;
        let precomputed = INITIAL_STATES
            .iter()
            .find(|(state, output, _)| *state == words * 64 && *output == self.output_size * 8);
        self.chain = [0; MAX_WORDS];
        match (params.key(), precomputed) {
            (None, Some((_, _, state))) => self.chain[..words].copy_from_slice(state),
            (key, _) => {
                if let Some(key) = key {
                    self.process_ubi(TYPE_KEY, key);
                }
                self.process_ubi(TYPE_CONFIG, &config_block(self.output_size as u64 * 8));
            }
        }
        for (block_type, value) in [
            (TYPE_PERSONALISATION, params.personalisation()),
            (TYPE_PUBLIC_KEY, params.public_key()),
            (TYPE_KEY_IDENTIFIER, params.key_identifier()),
            (TYPE_NONCE, params.nonce()),
        ] {
            if let Some(value) = value {
                self.process_ubi(block_type, value);
            }
        }
        self.initial_state = self.chain;
        self.ubi_init(TYPE_MESSAGE);
    }

    /// Runs a complete UBI of `block_type` over `value` into the chaining
    /// value (Bouncy Castle `UbiComplete`). Constant time with respect to the
    /// contents of `value`.
    fn process_ubi(&mut self, block_type: u64, value: &[u8]) {
        self.ubi_init(block_type);
        self.ubi_update(value);
        self.ubi_final();
    }

    /// Starts a UBI of `block_type` (Bouncy Castle UBI `Reset`).
    /// Constant time.
    fn ubi_init(&mut self, block_type: u64) {
        self.tweak = UbiTweak::new(block_type);
        self.offset = 0;
    }

    /// Absorbs `input`, keeping the last block buffered so that it can carry
    /// the final flag (Bouncy Castle UBI `Update`). Constant time with
    /// respect to the contents of `input`.
    fn ubi_update(&mut self, mut input: &[u8]) {
        let block_size = self.block_size();
        while !input.is_empty() {
            if self.offset == block_size {
                self.chain = process_block(self.words, &self.chain, self.tweak, &self.block);
                self.tweak.0[1] &= !T1_FIRST;
                self.offset = 0;
            }
            let take = input.len().min(block_size - self.offset);
            self.block[self.offset..self.offset + take].copy_from_slice(&input[..take]);
            self.offset += take;
            self.tweak.advance_position(take);
            input = &input[take..];
        }
    }

    /// Pads the buffered block with zeros and processes it as the final
    /// block (Bouncy Castle UBI `DoFinal`). Constant time.
    fn ubi_final(&mut self) {
        self.block[self.offset..].fill(0);
        self.tweak.0[1] |= T1_FINAL;
        self.chain = process_block(self.words, &self.chain, self.tweak, &self.block);
    }
}

impl Drop for SkeinEngine {
    /// Wipes the chaining value, the state after the parameters and the
    /// buffered block. Constant time.
    fn drop(&mut self) {
        self.chain.zeroize();
        self.initial_state.zeroize();
        self.block.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_precomputed_initial_states_match_the_configuration_block() {
        for (state, output, words) in INITIAL_STATES {
            let mut engine = SkeinEngine::new(state, output);
            engine.chain = [0; MAX_WORDS];
            engine.process_ubi(TYPE_CONFIG, &config_block(output as u64));
            assert_eq!(&engine.chain[..state / 64], words, "Skein-{state}-{output}");
        }
    }

    #[test]
    fn the_position_carries_into_the_high_word_and_wraps_at_96_bits() {
        let mut tweak = UbiTweak::new(TYPE_MESSAGE);
        tweak.0[0] = u64::MAX;
        tweak.advance_position(2);
        assert_eq!(tweak.0, [1, T1_FIRST | (TYPE_MESSAGE << 56) | 1]);

        tweak.0[0] = u64::MAX;
        tweak.0[1] |= 0xffff_ffff;
        tweak.advance_position(1);
        assert_eq!(tweak.0, [0, T1_FIRST | (TYPE_MESSAGE << 56)]);
    }
}
