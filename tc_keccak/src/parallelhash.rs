//! ParallelHash of NIST SP 800-185, ported from Bouncy Castle's
//! `ParallelHash`.
//!
//! ParallelHash splits the message into `B`-byte blocks, hashes each block with
//! a plain SHAKE into a chaining value of twice the security strength, and
//! absorbs those values into an outer cSHAKE with the function name
//! `"ParallelHash"`, after `left_encode(B)`. Before the first output it absorbs
//! `right_encode(n) || right_encode(L)`, with `n` the number of blocks and `L`
//! the output length in bits, or 0 for an extendable output.
//!
//! The blocks are independent, which is what would let a caller hash them in
//! parallel; this port runs them in sequence, as Bouncy Castle does, feeding
//! each block to the compressor as it arrives instead of buffering it.

use core::convert::Infallible;
use core::fmt;

use tc_digest::{Digest, TryDigest, TryXof, Xof};
use tc_zeroize::Zeroize;

use crate::cshake::CShakeDigest;
use crate::xof_utils::{left_encode, right_encode};

const N_PARALLEL_HASH: &[u8] = b"ParallelHash";

/// ParallelHash128 or ParallelHash256 of SP 800-185. Constant time.
#[derive(Clone)]
pub struct ParallelHash {
    // The outer cSHAKE, function name "ParallelHash" and the caller's
    // customization.
    cshake: CShakeDigest,
    // The per-block compressor, a plain SHAKE.
    compressor: CShakeDigest,
    // The default output length in bytes.
    output_length: usize,
    // The block size B in bytes.
    block_size: usize,
    // The length of a chaining value, 32 or 64 bytes.
    compressor_len: usize,
    // The bytes of the current block fed to the compressor.
    in_block: usize,
    // The number of blocks absorbed.
    n_count: u64,
    // Whether nothing has been read yet, so the closing encodings are still to come.
    first_output: bool,
}

impl ParallelHash {
    /// ParallelHash with a `bit_length` security strength, 128 or 256, the
    /// customization `s`, `b`-byte blocks and twice the strength of output.
    /// Constant time with respect to the contents of `s`.
    ///
    /// # Panics
    ///
    /// Panics for any other strength or for `b` of 0, as Bouncy Castle throws.
    pub fn new(bit_length: usize, s: &[u8], b: usize) -> Self {
        Self::with_output_size(bit_length, s, b, bit_length * 2)
    }

    /// ParallelHash with a `bit_length` security strength, 128 or 256, the
    /// customization `s`, `b`-byte blocks and `output_size_bits` bits of
    /// output, rounded up to whole bytes. Constant time with respect to the
    /// contents of `s`.
    ///
    /// # Panics
    ///
    /// Panics for any other strength or for `b` of 0, as Bouncy Castle throws.
    pub fn with_output_size(
        bit_length: usize,
        s: &[u8],
        b: usize,
        output_size_bits: usize,
    ) -> Self {
        assert!(b > 0, "ParallelHash: block size must be greater than 0");
        let mut h = ParallelHash {
            cshake: CShakeDigest::new(bit_length, N_PARALLEL_HASH, s),
            compressor: CShakeDigest::new(bit_length, b"", b""),
            output_length: output_size_bits.div_ceil(8),
            block_size: b,
            compressor_len: bit_length * 2 / 8,
            in_block: 0,
            n_count: 0,
            first_output: true,
        };
        h.init();
        h
    }

    /// Resets both cSHAKEs, since the compressor may hold half a block, and
    /// absorbs `left_encode(B)`. Constant time.
    fn init(&mut self) {
        self.cshake.reset();
        self.compressor.reset();
        self.cshake
            .update(left_encode(self.block_size as u64).as_slice());
        self.n_count = 0;
        self.in_block = 0;
        self.first_output = true;
    }

    /// Finishes a block: squeezes its chaining value from the compressor, which
    /// `output_final` resets, into the outer cSHAKE. Constant time.
    fn finish_block(&mut self) {
        let clen = self.compressor_len;
        let mut cb = [0u8; 64];
        self.compressor.output_final(&mut cb[..clen]);
        self.cshake.update(&cb[..clen]);
        self.n_count += 1;
        self.in_block = 0;
    }

    /// Before the first output, finishes any partial block and absorbs
    /// `right_encode(n) || right_encode(L)`. Constant time.
    fn wrap_up(&mut self, output_bits: u64) {
        if self.in_block != 0 {
            self.finish_block();
        }
        self.cshake.update(right_encode(self.n_count).as_slice());
        self.cshake.update(right_encode(output_bits).as_slice());
        self.first_output = false;
    }
}

impl fmt::Display for ParallelHash {
    /// Writes `ParallelHash` and the security strength, such as
    /// `ParallelHash128`, without inspecting the state. Constant time with
    /// respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ParallelHash{}", self.cshake.bit_length())
    }
}

impl Drop for ParallelHash {
    /// Wipes the counts the message length sets; both cSHAKEs wipe themselves.
    /// Constant time.
    fn drop(&mut self) {
        self.in_block.zeroize();
        self.n_count.zeroize();
    }
}

impl TryDigest for ParallelHash {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.output_length
    }

    fn byte_length(&self) -> usize {
        self.cshake.byte_length()
    }

    // Feeds the compressor as the input arrives, finishing a block at each B
    // bytes; SHAKE gives the same value however its input is split.
    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        while !input.is_empty() {
            let take = (self.block_size - self.in_block).min(input.len());
            self.compressor.update(&input[..take]);
            self.in_block += take;
            input = &input[take..];
            if self.in_block == self.block_size {
                self.finish_block();
            }
        }
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.output_length;
        assert!(
            output.len() >= len,
            "output buffer shorter than the {len}-byte digest"
        );
        self.try_output_final(&mut output[..len])
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.init();
        Ok(())
    }
}

impl TryXof for ParallelHash {
    // An extendable output, right_encode(0).
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if self.first_output {
            self.wrap_up(0);
        }
        self.cshake.try_output(output)
    }

    // A fixed-length output, right_encode of the configured length in bits.
    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if self.first_output {
            self.wrap_up(self.output_length as u64 * 8);
        }
        self.cshake.try_output(output)?;
        self.try_reset()?;
        Ok(output.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        let d: Vec<char> = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        d.chunks(2)
            .map(|p| (p[0].to_digit(16).unwrap() as u8) << 4 | p[1].to_digit(16).unwrap() as u8)
            .collect()
    }

    // The two messages of NIST's samples.
    fn data24() -> Vec<u8> {
        unhex("000102030405060710111213141516172021222324252627")
    }
    fn data72() -> Vec<u8> {
        unhex(
            "000102030405060708090a0b101112131415161718191a1b\
             202122232425262728292a2b303132333435363738393a3b\
             404142434445464748494a4b505152535455565758595a5b",
        )
    }

    fn ph_final(bits: usize, s: &[u8], b: usize, msg: &[u8]) -> Vec<u8> {
        let mut h = ParallelHash::new(bits, s, b);
        h.update(msg);
        let mut out = vec![0u8; h.digest_size()];
        h.do_final(&mut out);
        out
    }

    #[test]
    fn accessors() {
        let h = ParallelHash::new(128, b"", 8);
        assert_eq!(h.digest_size(), 32);
        assert_eq!(alloc::format!("{h}"), "ParallelHash128");
        assert_eq!(h.byte_length(), 168);

        let h = ParallelHash::new(256, b"", 8);
        assert_eq!(h.digest_size(), 64);
        assert_eq!(h.byte_length(), 136);
    }

    // NIST's SP 800-185 ParallelHash samples, with fixed-length outputs.
    #[test]
    fn nist_samples_fixed() {
        assert_eq!(
            ph_final(128, b"", 8, &data24()),
            unhex("ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5")
        );
        assert_eq!(
            ph_final(128, b"Parallel Data", 8, &data24()),
            unhex("fc484dcb3f84dceedc353438151bee58157d6efed0445a81f165e495795b7206")
        );
        assert_eq!(
            ph_final(128, b"Parallel Data", 12, &data72()),
            unhex("f7fd5312896c6685c828af7e2adb97e393e7f8d54e3c2ea4b95e5aca3796e8fc")
        );
        assert_eq!(
            ph_final(256, b"", 8, &data24()),
            unhex(
                "bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c45110553\
                 1b7f2a3e0ce055c02805e7c2de1fb746af97a1dd01f43b824e31b87612410429"
            )
        );
        assert_eq!(
            ph_final(256, b"Parallel Data", 8, &data24()),
            unhex(
                "cdf15289b54f6212b4bc270528b49526006dd9b54e2b6add1ef6900dda3963bb\
                 33a72491f236969ca8afaea29c682d47a393c065b38e29fae651a2091c833110"
            )
        );
        assert_eq!(
            ph_final(256, b"Parallel Data", 12, &data72()),
            unhex(
                "69d0fcb764ea055dd09334bc6021cb7e4b61348dff375da262671cdec3effa8d\
                 1b4568a6cce16b1cad946ddde27f6ce2b8dee4cd1b24851ebf00eb90d43813e9"
            )
        );
    }

    // An extendable output, right_encode(0), differs from a fixed one.
    #[test]
    fn xof_mode() {
        let mut h = ParallelHash::new(128, b"Parallel Data", 12);
        h.update(&data72());
        let mut o = [0u8; 32];
        h.output(&mut o);
        assert_ne!(
            o.to_vec(),
            unhex("f7fd5312896c6685c828af7e2adb97e393e7f8d54e3c2ea4b95e5aca3796e8fc")
        );
        assert_eq!(
            o.to_vec(),
            unhex("0127ad9772ab904691987fcc4a24888f341fa0db2145e872d4efd255376602f0")
        );

        let mut h = ParallelHash::new(256, b"Parallel Data", 12);
        h.update(&data72());
        let mut o = [0u8; 64];
        h.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex(
                "6b3e790b330c889a204c2fbc728d809f19367328d852f4002dc829f73afd6bce\
                 fb7fe5b607b13a801c0be5c1170bdb794e339458fdb0e62a6af3d42558970249"
            )
        );
    }

    // An empty message, a large B of 62 and an odd customization, Bouncy Castle's ImplTestEmpty.
    #[test]
    fn empty_message_large_block() {
        let s = b"Ny0LL2tUmt<+kuN5:Z7pZ_7]R; l/i:%pWbo4}";
        let mut h = ParallelHash::new(256, s, 62);
        h.update(b"");
        let mut o = [0u8; 2];
        h.output(&mut o);
        assert_eq!(o.to_vec(), unhex("13c4"));
    }

    // Input split across block boundaries gives the digest of the whole.
    #[test]
    fn chunked_matches_whole() {
        let msg = data72();
        let whole = ph_final(128, b"Parallel Data", 12, &msg);

        let mut h = ParallelHash::new(128, b"Parallel Data", 12);
        for chunk in [
            &msg[..5],
            &msg[5..12],
            &msg[12..13],
            &msg[13..48],
            &msg[48..],
        ] {
            h.update(chunk);
        }
        let mut out = vec![0u8; h.digest_size()];
        h.do_final(&mut out);
        assert_eq!(out, whole);
    }

    // do_final resets, so the same input gives the same digest again.
    #[test]
    fn do_final_resets() {
        let a = ph_final(128, b"", 8, &data24());
        let b = ph_final(128, b"", 8, &data24());
        assert_eq!(a, b);
    }

    // Reset discards a half-fed block instead of leaving it in the compressor.
    #[test]
    fn reset_discards_a_partial_block() {
        let mut h = ParallelHash::new(128, b"Parallel Data", 12);
        h.update(&data72()[..17]);
        h.reset();
        h.update(&data72());
        let mut out = vec![0u8; h.digest_size()];
        h.do_final(&mut out);
        assert_eq!(out, ph_final(128, b"Parallel Data", 12, &data72()));
    }
}
