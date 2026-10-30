//! GOST R 34.11-94 message digest (RFC 5831), ported from Bouncy Castle's
//! `Gost3411Digest`.

use core::{convert::Infallible, fmt};

use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_digest::TryDigest;
use tc_gost28147::{Gost28147Engine, Gost28147ParamsRef, s_box};
use tc_zeroize::Zeroize;

const DIGEST_LENGTH: usize = 32;
const BYTE_LENGTH: usize = 32;

/// The constant C3 of the key generation, the only nonzero one of C2 to C4.
const C3: [u8; 32] = [
    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
    0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff,
];

/// The GOST R 34.11-94 digest (RFC 5831), producing a 32-byte hash.
///
/// [`new`](Self::new) uses the CryptoPro D-A S-box of RFC 4357, as Bouncy
/// Castle's `Gost3411Digest` does; [`with_s_box`](Self::with_s_box) takes any
/// other, such as `tc_gost28147::s_box::D_TEST`, the test parameters of
/// RFC 5831's examples. GOST R 34.11-94 has been withdrawn in favour of
/// GOST R 34.11-2012; use it to interoperate with existing data.
///
/// Variable time: each step encrypts the chaining state with GOST 28147-89,
/// whose rounds index the S-box with nibbles derived from the message and the
/// state, which can leak the message through cache timing. Hash only public
/// data with it.
///
/// Dropping or resetting the digest, which `do_final` also does, wipes its
/// state, checksum, buffered block and length with volatile writes, and
/// dropping it also wipes the S-box. Each GOST 28147-89 engine the step
/// creates wipes its own key on drop. Copies the step leaves in registers or
/// on the stack, such as the derived keys, and copies a move leaves behind
/// are not wiped.
///
/// `do_final` panics if the output buffer is shorter than 32 bytes.
#[derive(Clone)]
pub struct Gost3411Digest {
    /// The chaining value H.
    state: [u8; 32],
    /// The running sum Σ of the message blocks, modulo 2^256.
    checksum: [u8; 32],
    /// The block being filled.
    block: [u8; 32],
    /// The number of bytes filled in `block`, in `0..32`.
    block_offset: usize,
    /// The message length in bytes.
    byte_count: u64,
    /// The GOST 28147-89 S-box.
    s_box: [u8; 128],
}

impl Default for Gost3411Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Gost3411Digest {
    /// Creates a digest with the CryptoPro D-A S-box, matching Bouncy Castle.
    /// Constant time.
    pub const fn new() -> Self {
        Self::with_s_box(s_box::D_A)
    }

    /// Creates a digest with a caller-selected GOST 28147-89 S-box.
    /// Constant time: the table is copied without being inspected.
    pub const fn with_s_box(s_box: [u8; 128]) -> Self {
        Self {
            state: [0; 32],
            checksum: [0; 32],
            block: [0; 32],
            block_offset: 0,
            byte_count: 0,
            s_box,
        }
    }

    /// Adds `block` to the checksum modulo 2^256. Constant time.
    fn sum_block(&mut self, block: &[u8; 32]) {
        let mut carry = 0u16;
        for (sum, input) in self.checksum.iter_mut().zip(block) {
            carry += *sum as u16 + *input as u16;
            *sum = carry as u8;
            carry >>= 8;
        }
    }

    /// Encrypts one 8-byte block with GOST 28147-89 under `key`.
    /// Variable time: the cipher indexes its S-box with secret nibbles.
    fn encrypt(&self, key: &[u8; 32], input: &[u8], output: &mut [u8]) {
        let mut cipher = Gost28147Engine::new();
        let params = Gost28147ParamsRef::with_s_box(key, &self.s_box);
        cipher
            .init(CipherDirection::Encrypt, &params)
            .expect("GOST R 34.11-94 always supplies a 32-byte key and a 128-byte S-box");
        cipher
            .process_block(input, output)
            .expect("GOST R 34.11-94 always supplies 8-byte blocks");
    }

    /// The step function: derives four keys from the state and `message`,
    /// encrypts the four words of the state, and mixes the result with the
    /// shuffle transformation. Variable time: it runs GOST 28147-89.
    fn process_block(&mut self, message: &[u8; 32]) {
        let mut u = self.state;
        let mut v = *message;
        let mut w = [0u8; 32];
        let mut s = [0u8; 32];

        xor_into(&u, &v, &mut w);
        let key = permute(&w);
        self.encrypt(&key, &self.state[..8], &mut s[..8]);

        for round in 1..4 {
            transform_a(&mut u);
            if round == 2 {
                for (value, constant) in u.iter_mut().zip(C3) {
                    *value ^= constant;
                }
            }
            transform_a(&mut v);
            transform_a(&mut v);
            xor_into(&u, &v, &mut w);
            let key = permute(&w);
            self.encrypt(
                &key,
                &self.state[round * 8..round * 8 + 8],
                &mut s[round * 8..round * 8 + 8],
            );
        }

        for _ in 0..12 {
            transform_fw(&mut s);
        }
        for (value, message) in s.iter_mut().zip(message) {
            *value ^= *message;
        }
        transform_fw(&mut s);
        for (value, state) in s.iter_mut().zip(self.state) {
            *value ^= state;
        }
        for _ in 0..61 {
            transform_fw(&mut s);
        }
        self.state = s;
    }

    /// Adds a message block to the checksum and runs the step function on it.
    /// Variable time: it runs GOST 28147-89.
    fn process_message_block(&mut self, block: &[u8; 32]) {
        self.sum_block(block);
        self.process_block(block);
    }

    /// Buffers one byte, processing the block once it is full.
    /// Variable time: a full block runs GOST 28147-89.
    fn process_byte(&mut self, byte: u8) {
        self.block[self.block_offset] = byte;
        self.block_offset += 1;
        self.byte_count = self.byte_count.wrapping_add(1);
        if self.block_offset == BYTE_LENGTH {
            let block = self.block;
            self.process_message_block(&block);
            self.block_offset = 0;
        }
    }

    /// Wipes the state, checksum, buffered block and length, keeping the
    /// S-box. Constant time.
    fn wipe_message(&mut self) {
        self.state.zeroize();
        self.checksum.zeroize();
        self.block.zeroize();
        self.block_offset.zeroize();
        self.byte_count.zeroize();
    }
}

/// Writes `left ^ right` to `output`. Constant time.
fn xor_into(left: &[u8; 32], right: &[u8; 32], output: &mut [u8; 32]) {
    for ((output, left), right) in output.iter_mut().zip(left).zip(right) {
        *output = *left ^ *right;
    }
}

/// The byte permutation P that turns a mixed value into a cipher key.
/// Constant time: the indices are fixed.
fn permute(input: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut offset = 0;
    for column in 0..8 {
        for row in 0..4 {
            output[offset] = input[row * 8 + column];
            offset += 1;
        }
    }
    output
}

/// The transformation A: shifts the four 64-bit words and appends the XOR of
/// the first two. Constant time.
fn transform_a(value: &mut [u8; 32]) {
    let mut tail = [0u8; 8];
    for i in 0..8 {
        tail[i] = value[i] ^ value[i + 8];
    }
    value.copy_within(8..32, 0);
    value[24..].copy_from_slice(&tail);
}

/// One round of the shuffle transformation ψ on sixteen 16-bit words.
/// Constant time.
fn transform_fw(value: &mut [u8; 32]) {
    let mut words = [0u16; 16];
    for (index, word) in words.iter_mut().enumerate() {
        *word = u16::from_le_bytes([value[index * 2], value[index * 2 + 1]]);
    }
    let feedback = words[0] ^ words[1] ^ words[2] ^ words[3] ^ words[12] ^ words[15];
    words.copy_within(1..16, 0);
    words[15] = feedback;
    for (index, word) in words.iter().enumerate() {
        value[index * 2..index * 2 + 2].copy_from_slice(&word.to_le_bytes());
    }
}

impl Drop for Gost3411Digest {
    /// Wipes the state, checksum, buffered block, length and S-box.
    /// Constant time.
    fn drop(&mut self) {
        self.wipe_message();
        self.s_box.zeroize();
    }
}

impl fmt::Display for Gost3411Digest {
    /// Writes `Gost3411` without inspecting the digest state. Constant time
    /// with respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Gost3411")
    }
}

impl TryDigest for Gost3411Digest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        while self.block_offset != 0 && !input.is_empty() {
            self.process_byte(input[0]);
            input = &input[1..];
        }
        while input.len() >= BYTE_LENGTH {
            let block: &[u8; 32] = input[..BYTE_LENGTH].try_into().unwrap();
            self.process_message_block(block);
            self.byte_count = self.byte_count.wrapping_add(BYTE_LENGTH as u64);
            input = &input[BYTE_LENGTH..];
        }
        for &byte in input {
            self.process_byte(byte);
        }
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
            "output buffer shorter than the 32-byte GOST R 34.11-94 digest"
        );

        let bit_count = self.byte_count.wrapping_mul(8);
        if self.block_offset != 0 {
            self.block[self.block_offset..].fill(0);
            let block = self.block;
            self.process_message_block(&block);
        }
        let mut length = [0u8; 32];
        length[..8].copy_from_slice(&bit_count.to_le_bytes());
        self.process_block(&length);
        let checksum = self.checksum;
        self.process_block(&checksum);

        output[..DIGEST_LENGTH].copy_from_slice(&self.state);
        self.wipe_message();
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.wipe_message();
        Ok(())
    }
}
