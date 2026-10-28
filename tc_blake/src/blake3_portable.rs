//! Portable BLAKE3 hash / XOF, ported from Bouncy Castle's `Blake3Digest`.
//!
//! BLAKE3 is a tree hash: the message is split into 1024-byte chunks, each chunk
//! compressed in 64-byte blocks (a BLAKE2s-like 7-round mix, but with rotate-right
//! and a fixed permutation), and chunk chaining values merged pairwise up a binary
//! tree (the `stack`). The root node is flagged `ROOT`, after which the digest
//! becomes an extendable-output function ([`TryXof`]). Supports the unkeyed,
//! keyed-hash, and derive-key modes.

use core::convert::Infallible;

use tc_digest::{Digest, TryDigest, TryXof};
use tc_zeroize::Zeroize;

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;
const ROUNDS: usize = 7;

// A 64-bit chunk counter merges at most 54 subtrees before the root, so the
// stack never holds more chaining values.
const MAX_DEPTH: usize = 54;

// Flags.
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const KEYED_HASH: u32 = 16;
const DERIVE_CONTEXT: u32 = 32;
const DERIVE_KEY: u32 = 64;

// Indices into the state V.
const COUNT0: usize = 12;
const COUNT1: usize = 13;
const DATALEN: usize = 14;
const FLAGS: usize = 15;

const SIGMA: [u8; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

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

/// The portable BLAKE3 hash / extendable-output function, one 64-byte block at
/// a time. Constant time.
#[derive(Clone)]
pub struct Blake3PortableDigest {
    /// The 64-byte input buffer while absorbing, the output block while squeezing.
    buffer: [u8; BLOCK_LEN],
    /// The key words, the IV when unkeyed.
    k: [u32; 8],
    /// The current chaining value.
    chaining: [u32; 8],
    /// The 16-word state.
    v: [u32; 16],
    /// The 16 message words.
    m: [u32; 16],
    /// The chaining values of the subtrees still to be merged.
    stack: [[u32; 8]; MAX_DEPTH],
    /// How many entries of `stack` are in use.
    stack_len: usize,
    /// The default output length in bytes.
    digest_len: usize,
    /// Whether output has started.
    outputting: bool,
    /// The mode: 0, `KEYED_HASH`, `DERIVE_CONTEXT` or `DERIVE_KEY`.
    mode: u32,
    /// The flags and data length of the root node, for every output block.
    output_mode: u32,
    output_data_len: u32,
    /// The chunk counter, or the output block counter while squeezing.
    counter: u64,
    /// Bytes of the current chunk already compressed.
    curr_bytes: usize,
    /// The next position in `buffer`.
    pos: usize,
}

impl Default for Blake3PortableDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3PortableDigest {
    /// Creates an unkeyed BLAKE3 with the default 32-byte digest. Constant time.
    pub fn new() -> Self {
        Self::with_digest_size(256)
    }

    /// Creates an unkeyed BLAKE3 with a default output size in bits.
    /// Constant time.
    pub fn with_digest_size(digest_bits: usize) -> Self {
        Self::init(digest_bits / 8, 0, IV)
    }

    /// Creates a keyed BLAKE3 (keyed-hash mode) with a 32-byte key.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not exactly 32 bytes.
    pub fn with_key(digest_bits: usize, key: &[u8]) -> Self {
        assert_eq!(key.len(), 32, "BLAKE3 key must be exactly 32 bytes");
        let mut k = [0u32; 8];
        load_words_le(key, &mut k);
        Self::init(digest_bits / 8, KEYED_HASH, k)
    }

    /// Creates a BLAKE3 in derive-key mode from a context string. Constant
    /// time with respect to the contents of `context`; its length is public.
    pub fn with_derive_key(digest_bits: usize, context: &[u8]) -> Self {
        let mut k = [0u32; 8];
        load_words_le(&derive_context_key(context), &mut k);
        Self::init(digest_bits / 8, DERIVE_KEY, k)
    }

    /// A fresh digest with the key words `k` in `mode`. Constant time.
    fn init(digest_len: usize, mode: u32, k: [u32; 8]) -> Self {
        Blake3PortableDigest {
            buffer: [0; BLOCK_LEN],
            k,
            chaining: [0; 8],
            v: [0; 16],
            m: [0; 16],
            stack: [[0; 8]; MAX_DEPTH],
            stack_len: 0,
            digest_len,
            outputting: false,
            mode,
            output_mode: 0,
            output_data_len: 0,
            counter: 0,
            curr_bytes: 0,
            pos: 0,
        }
    }

    // ---- Compression ----

    /// The G function; the message words are picked by the public
    /// permutation `idx`. Constant time.
    fn mix_g(&mut self, idx: &[u8; 16], msg_idx: usize, a: usize, b: usize, c: usize, d: usize) {
        let m0 = self.m[idx[msg_idx * 2] as usize];
        let m1 = self.m[idx[msg_idx * 2 + 1] as usize];
        self.v[a] = self.v[a].wrapping_add(self.v[b]).wrapping_add(m0);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(16);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(12);
        self.v[a] = self.v[a].wrapping_add(self.v[b]).wrapping_add(m1);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(8);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(7);
    }

    /// One round: G on the columns, then on the diagonals. Constant time.
    fn perform_round(&mut self, idx: &[u8; 16]) {
        self.mix_g(idx, 0, 0, 4, 8, 12);
        self.mix_g(idx, 1, 1, 5, 9, 13);
        self.mix_g(idx, 2, 2, 6, 10, 14);
        self.mix_g(idx, 3, 3, 7, 11, 15);
        self.mix_g(idx, 4, 0, 5, 10, 15);
        self.mix_g(idx, 5, 1, 6, 11, 12);
        self.mix_g(idx, 6, 2, 7, 8, 13);
        self.mix_g(idx, 7, 3, 4, 9, 14);
    }

    /// The seven rounds and the output of the compression. Constant time.
    fn compress(&mut self) {
        let mut idx: [u8; 16] = core::array::from_fn(|i| i as u8);
        for _ in 0..ROUNDS - 1 {
            self.perform_round(&idx);
            for b in &mut idx {
                *b = SIGMA[*b as usize];
            }
        }
        self.perform_round(&idx);
        self.adjust_chaining();
    }

    /// Takes the compression output: the next chaining value while absorbing,
    /// a whole output block while squeezing. Constant time.
    fn adjust_chaining(&mut self) {
        if self.outputting {
            for i in 0..8 {
                self.v[i] ^= self.v[i + 8];
                self.v[i + 8] ^= self.chaining[i];
            }
            for (i, word) in self.v.iter().enumerate() {
                self.buffer[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            self.pos = 0;
        } else {
            for i in 0..8 {
                self.chaining[i] = self.v[i] ^ self.v[i + 8];
            }
        }
    }

    // ---- Blocks and the tree ----

    /// Sets up the state for a chunk block of `data_len` bytes. Constant time
    /// with respect to the message; lengths and positions are public.
    fn init_chunk_block(&mut self, data_len: usize, final_block: bool) {
        let src = if self.curr_bytes == 0 {
            &self.k
        } else {
            &self.chaining
        };
        self.v[..8].copy_from_slice(src);
        self.v[8..12].copy_from_slice(&IV[..4]);
        self.v[COUNT0] = self.counter as u32;
        self.v[COUNT1] = (self.counter >> 32) as u32;
        self.v[DATALEN] = data_len as u32;
        self.v[FLAGS] = self.mode
            + if self.curr_bytes == 0 { CHUNK_START } else { 0 }
            + if final_block { CHUNK_END } else { 0 };

        self.curr_bytes += data_len;
        if self.curr_bytes >= CHUNK_LEN {
            self.counter += 1;
            self.curr_bytes = 0;
            self.v[FLAGS] |= CHUNK_END;
        }

        if final_block && self.stack_len == 0 {
            self.set_root();
        }
    }

    /// Sets up the state for a parent node. Constant time.
    fn init_parent_block(&mut self) {
        self.v[..8].copy_from_slice(&self.k);
        self.v[8..12].copy_from_slice(&IV[..4]);
        self.v[COUNT0] = 0;
        self.v[COUNT1] = 0;
        self.v[DATALEN] = BLOCK_LEN as u32;
        self.v[FLAGS] = self.mode | PARENT;
    }

    /// Flags the node being set up as the root and switches to output.
    /// Constant time.
    fn set_root(&mut self) {
        self.v[FLAGS] |= ROOT;
        self.output_mode = self.v[FLAGS];
        self.output_data_len = self.v[DATALEN];
        self.counter = 0;
        self.outputting = true;
        let (head, _) = self.v.split_at(8);
        self.chaining.copy_from_slice(head);
    }

    /// Loads a block as little-endian message words. Constant time.
    fn init_m(&mut self, block: &[u8; BLOCK_LEN]) {
        for i in 0..16 {
            self.m[i] = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
    }

    /// Compresses a block that is not the last of the message. Constant time.
    fn compress_block(&mut self, block: &[u8; BLOCK_LEN]) {
        self.init_chunk_block(BLOCK_LEN, false);
        self.init_m(block);
        self.compress();
        if self.curr_bytes == 0 {
            self.adjust_stack();
        }
    }

    /// Merges the finished chunk into the stack, once for each trailing zero
    /// bit of the chunk count. Constant time with respect to the message; the
    /// count is public.
    fn adjust_stack(&mut self) {
        let mut count = self.counter;
        while count > 0 {
            if count & 1 == 1 {
                break;
            }
            let left = self.pop().expect("stack not empty when merging");
            self.m[..8].copy_from_slice(&left);
            self.m[8..16].copy_from_slice(&self.chaining);
            self.init_parent_block();
            self.compress();
            count >>= 1;
        }
        self.push();
    }

    /// Pushes the chaining value on the stack. Constant time.
    fn push(&mut self) {
        self.stack[self.stack_len] = self.chaining;
        self.stack_len += 1;
    }

    /// Pops the most recent stacked chaining value. Constant time.
    fn pop(&mut self) -> Option<[u32; 8]> {
        self.stack_len = self.stack_len.checked_sub(1)?;
        Some(self.stack[self.stack_len])
    }

    /// Compresses the last block, `data_len` bytes, and merges the stack up to
    /// the root. Constant time with respect to the message; lengths are public.
    fn compress_final_block(&mut self, data_len: usize) {
        self.init_chunk_block(data_len, true);
        let block = self.buffer;
        self.init_m(&block);
        self.compress();
        self.process_stack();
    }

    /// Merges every stacked chaining value, the last merge being the root.
    /// Constant time with respect to the message; the stack depth is public.
    fn process_stack(&mut self) {
        while let Some(left) = self.pop() {
            self.m[..8].copy_from_slice(&left);
            self.m[8..16].copy_from_slice(&self.chaining);
            self.init_parent_block();
            if self.stack_len == 0 {
                self.set_root();
            }
            self.compress();
        }
    }

    /// Computes the next 64-byte output block from the root. Constant time.
    fn next_output_block(&mut self) {
        self.counter += 1;
        self.v[..8].copy_from_slice(&self.chaining);
        self.v[8..12].copy_from_slice(&IV[..4]);
        self.v[COUNT0] = self.counter as u32;
        self.v[COUNT1] = (self.counter >> 32) as u32;
        self.v[DATALEN] = self.output_data_len;
        self.v[FLAGS] = self.output_mode;
        self.compress();
    }

    /// Absorbs `input`, keeping the last block for finalization. Constant time
    /// with respect to the message; its length is public.
    fn update_bytes(&mut self, mut input: &[u8]) {
        assert!(!self.outputting, "BLAKE3: cannot absorb while outputting");
        if input.is_empty() {
            return;
        }

        if self.pos != 0 {
            let remaining = BLOCK_LEN - self.pos;
            if input.len() <= remaining {
                self.buffer[self.pos..self.pos + input.len()].copy_from_slice(input);
                self.pos += input.len();
                return;
            }
            self.buffer[self.pos..].copy_from_slice(&input[..remaining]);
            let block = self.buffer;
            self.compress_block(&block);
            self.pos = 0;
            self.buffer = [0; BLOCK_LEN];
            input = &input[remaining..];
        }

        // Compress every whole block but the last, which finalization needs.
        while input.len() > BLOCK_LEN {
            let block: &[u8; BLOCK_LEN] = input[..BLOCK_LEN].try_into().unwrap();
            self.compress_block(block);
            input = &input[BLOCK_LEN..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.pos = input.len();
    }

    /// Writes the next `output.len()` output bytes, finishing the message on
    /// the first read. Constant time with respect to the message; lengths are
    /// public.
    fn output_bytes(&mut self, output: &mut [u8]) {
        if !self.outputting {
            self.compress_final_block(self.pos);
        }
        let mut out_pos = 0;
        let mut left = output.len();

        if self.pos < BLOCK_LEN {
            let n = left.min(BLOCK_LEN - self.pos);
            output[out_pos..out_pos + n].copy_from_slice(&self.buffer[self.pos..self.pos + n]);
            self.pos += n;
            out_pos += n;
            left -= n;
        }

        while left > 0 {
            self.next_output_block();
            let n = left.min(BLOCK_LEN);
            output[out_pos..out_pos + n].copy_from_slice(&self.buffer[..n]);
            self.pos += n;
            out_pos += n;
            left -= n;
        }
    }
}

impl TryDigest for Blake3PortableDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.digest_len
    }

    fn byte_length(&self) -> usize {
        BLOCK_LEN
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.update_bytes(input);
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.digest_len;
        assert!(
            output.len() >= len,
            "output buffer shorter than the {len}-byte digest"
        );
        self.try_output_final(&mut output[..len])
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.chaining.zeroize();
        self.v.zeroize();
        self.m.zeroize();
        self.stack[..self.stack_len].zeroize();
        self.stack_len = 0;
        self.buffer.zeroize();
        self.counter = 0;
        self.curr_bytes = 0;
        self.pos = 0;
        self.outputting = false;
        Ok(())
    }
}

impl TryXof for Blake3PortableDigest {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.output_bytes(output);
        Ok(output.len())
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let written = self.try_output(output)?;
        self.try_reset()?;
        Ok(written)
    }
}

impl Drop for Blake3PortableDigest {
    /// Wipes the key words, the chaining values, the state, the message words
    /// and the buffer. Constant time.
    fn drop(&mut self) {
        self.k.zeroize();
        self.chaining.zeroize();
        self.v.zeroize();
        self.m.zeroize();
        self.stack.zeroize();
        self.buffer.zeroize();
    }
}

/// Hashes `context` in derive-context mode; the first 32 bytes are the key of
/// derive-key mode. Constant time with respect to the contents of `context`;
/// its length is public.
pub(crate) fn derive_context_key(context: &[u8]) -> [u8; 32] {
    let mut ctx = Blake3PortableDigest::init(32, DERIVE_CONTEXT, IV);
    ctx.update(context);
    let mut key = [0u8; 32];
    ctx.do_final(&mut key);
    key
}

/// Reads little-endian `u32` words from `bytes` into `words`. Constant time.
fn load_words_le(bytes: &[u8], words: &mut [u32]) {
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap());
    }
}

impl core::fmt::Display for Blake3PortableDigest {
    /// Writes `BLAKE3` without inspecting the state. Constant time with respect
    /// to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BLAKE3")
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec, vec::Vec};

    use super::*;
    use tc_digest::Xof;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn blake3_hex(input: &[u8], out_len: usize) -> String {
        let mut d = Blake3PortableDigest::new();
        d.update(input);
        let mut out = vec![0u8; out_len];
        d.output_final(&mut out);
        hex(&out)
    }

    // The official empty-message vector, 32 and 64 bytes; the second also
    // checks the next XOF block.
    #[test]
    fn empty_vector_and_xof() {
        assert_eq!(
            blake3_hex(b"", 32),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            blake3_hex(b"", 64),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262\
             e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a"
        );
    }

    #[test]
    fn accessors() {
        let d = Blake3PortableDigest::new();
        assert_eq!(alloc::string::ToString::to_string(&d), "BLAKE3");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 64);
    }

    // Several chunks (3000 bytes, over two of 1024) fed in pieces or at once
    // give the same hash, through the stack merges.
    #[test]
    fn multi_chunk_chunked_matches_whole() {
        let msg: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
        let whole = blake3_hex(&msg, 32);

        let mut d = Blake3PortableDigest::new();
        for c in msg.chunks(7) {
            d.update(c);
        }
        let mut out = [0u8; 32];
        d.output_final(&mut out);
        assert_eq!(hex(&out), whole);
    }

    #[test]
    fn xof_streamed_matches_single() {
        let mut a = Blake3PortableDigest::new();
        a.update(b"the quick brown fox");
        let mut whole = [0u8; 200];
        a.output(&mut whole);

        let mut b = Blake3PortableDigest::new();
        b.update(b"the quick brown fox");
        let mut streamed = [0u8; 200];
        let (mut off, sizes) = (0usize, [1usize, 63, 64, 65, 7]);
        for s in sizes {
            b.output(&mut streamed[off..off + s]);
            off += s;
        }
        b.output(&mut streamed[off..]);
        assert_eq!(whole, streamed);
    }
}
