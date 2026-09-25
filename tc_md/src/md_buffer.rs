//! Shared block accumulator for Merkle–Damgård digests, generic over block size.
//!
//! This replaces Bouncy Castle's abstract `GeneralDigest` (64-byte block) and
//! `LongDigest` (128-byte block) base classes; a const generic collapses both
//! into one [`MdBuffer<N>`]. Each digest embeds an `MdBuffer<N>` and passes its
//! compression step as a closure over its own chaining registers, so this type
//! never touches algorithm state, only block bookkeeping and padding placement.
//!
//! Length-field encodings differ across families (SHA is big-endian, MD4 and
//! MD5 little-endian; 64 or 128 bits wide), so [`finish`](MdBuffer::finish)
//! does not encode the length itself: the caller passes the encoded bytes.

/// A block accumulator for `N`-byte Merkle–Damgård blocks.
///
/// `N` is the compression block size in bytes: 64 for MD4, MD5, SHA-1 and
/// SHA-256, 128 for SHA-384 and SHA-512.
#[derive(Clone)]
pub(crate) struct MdBuffer<const N: usize> {
    /// The partially filled current block.
    block: [u8; N],
    /// The number of bytes filled in `block`, in `0..N`.
    offset: usize,
    /// The total message length absorbed so far, padding excluded, from which
    /// the caller computes the length field.
    byte_count: u64,
}

impl<const N: usize> MdBuffer<N> {
    /// Creates an empty buffer. Constant time.
    pub(crate) const fn new() -> Self {
        MdBuffer {
            block: [0; N],
            offset: 0,
            byte_count: 0,
        }
    }

    /// Returns the number of message bytes absorbed so far. Constant time.
    pub(crate) fn byte_count(&self) -> u64 {
        self.byte_count
    }

    /// Absorbs `input`, passing each completed `N`-byte block to `compress`.
    ///
    /// Whole blocks go to `compress` straight from `input` without a copy into
    /// the buffer. Constant time: the work depends only on the input length and
    /// the bytes already buffered, never on the message contents.
    pub(crate) fn update(&mut self, mut input: &[u8], mut compress: impl FnMut(&[u8; N])) {
        self.byte_count = self.byte_count.wrapping_add(input.len() as u64);

        // Top up a partially filled block first.
        if self.offset != 0 {
            let take = (N - self.offset).min(input.len());
            self.block[self.offset..self.offset + take].copy_from_slice(&input[..take]);
            self.offset += take;
            input = &input[take..];
            if self.offset == N {
                compress(&self.block);
                self.offset = 0;
            }
        }

        // Pass whole blocks straight through.
        while input.len() >= N {
            let (block, rest) = input.split_at(N);
            compress(block.try_into().expect("split_at(N) yields N bytes"));
            input = rest;
        }

        // Keep the remainder for the next call.
        if !input.is_empty() {
            self.block[..input.len()].copy_from_slice(input);
            self.offset = input.len();
        }
    }

    /// Pads the message and passes the final one or two blocks to `compress`.
    ///
    /// Appends `0x80`, then zeros up to the position that leaves exactly
    /// `length_field.len()` bytes in the block, then `length_field`, which the
    /// caller has already encoded in its family's width and byte order.
    /// `length_field` must be shorter than `N`.
    ///
    /// The buffer is not reset; the caller resets it after writing the digest,
    /// as Bouncy Castle's `DoFinal` does. Constant time: the padding depends
    /// only on the message length.
    pub(crate) fn finish(&mut self, length_field: &[u8], mut compress: impl FnMut(&[u8; N])) {
        debug_assert!(
            length_field.len() < N,
            "length field must fit within a block"
        );

        // `push` compresses and wraps to a fresh block whenever one fills, so
        // padding that does not fit the current block spills into the next.
        self.push(0x80, &mut compress);
        while self.offset != N - length_field.len() {
            self.push(0, &mut compress);
        }
        for &byte in length_field {
            self.push(byte, &mut compress);
        }
        // The length field completed a block, so it has been compressed and
        // `offset` is back at zero.
    }

    /// Appends one padding byte, compressing when the block fills. Unlike
    /// `update`, it leaves `byte_count` unchanged. Constant time.
    fn push(&mut self, byte: u8, compress: &mut impl FnMut(&[u8; N])) {
        self.block[self.offset] = byte;
        self.offset += 1;
        if self.offset == N {
            compress(&self.block);
            self.offset = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// Collects every 64-byte block passed to `compress`, finishing with a
    /// SHA-style big-endian 64-bit length.
    fn collect64(feed: &[&[u8]]) -> Vec<[u8; 64]> {
        let mut buf = MdBuffer::<64>::new();
        let mut blocks: Vec<[u8; 64]> = Vec::new();
        for chunk in feed {
            buf.update(chunk, |b| blocks.push(*b));
        }
        let bit_len = buf.byte_count() << 3;
        buf.finish(&bit_len.to_be_bytes(), |b| blocks.push(*b));
        blocks
    }

    #[test]
    fn an_empty_message_pads_to_one_block() {
        let blocks = collect64(&[b""]);
        assert_eq!(blocks.len(), 1);
        let b = blocks[0];
        assert_eq!(b[0], 0x80);
        assert!(b[1..].iter().all(|&x| x == 0)); // length zero
    }

    #[test]
    fn padding_follows_the_message_and_the_length_ends_the_block() {
        let blocks = collect64(&[b"abc"]);
        assert_eq!(blocks.len(), 1);
        let b = blocks[0];
        assert_eq!(&b[..3], b"abc");
        assert_eq!(b[3], 0x80);
        assert!(b[4..56].iter().all(|&x| x == 0));
        // 24 bits = 0x18, big-endian in the last 8 bytes.
        assert_eq!(&b[56..64], &[0, 0, 0, 0, 0, 0, 0, 0x18]);
    }

    #[test]
    fn padding_spills_into_a_second_block_when_the_length_does_not_fit() {
        let msg = [0x61u8; 56];
        let blocks = collect64(&[&msg]);
        assert_eq!(blocks.len(), 2);
        assert_eq!(&blocks[0][..56], &msg[..]);
        assert_eq!(blocks[0][56], 0x80);
        assert!(blocks[0][57..].iter().all(|&x| x == 0));
        assert!(blocks[1][..56].iter().all(|&x| x == 0));
        // 56 * 8 = 448 = 0x01C0
        assert_eq!(&blocks[1][56..64], &[0, 0, 0, 0, 0, 0, 0x01, 0xC0]);
    }

    #[test]
    fn chunked_input_produces_the_same_blocks_as_whole_input() {
        let msg: Vec<u8> = (0..130).map(|i| i as u8).collect();
        let whole = collect64(&[&msg]);
        let chunked = collect64(&[&msg[..1], &msg[1..64], &msg[64..70], &msg[70..]]);
        assert_eq!(whole, chunked);
        // 130 = 2 * 64 + 2: two message blocks and one padding block.
        assert_eq!(whole.len(), 3);
    }

    /// The const generic also holds for 128-byte blocks with a SHA-512-style
    /// 16-byte big-endian length.
    #[test]
    fn a_128_byte_block_pads_an_empty_message_to_one_block() {
        let mut buf = MdBuffer::<128>::new();
        let mut blocks: Vec<[u8; 128]> = Vec::new();
        let bit_len = (buf.byte_count() as u128) << 3;
        buf.finish(&bit_len.to_be_bytes(), |b| blocks.push(*b));
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0][0], 0x80);
        assert!(blocks[0][1..].iter().all(|&x| x == 0)); // zero 128-bit length
    }
}
