//! BLAKE3 hash / XOF on the BLAKE3 team's `blake3` crate.
//!
//! Same constructors, output and panics as [`crate::Blake3PortableDigest`];
//! the `blake3` crate picks SSE2, SSE4.1, AVX2 or AVX-512 at run time without
//! needing `std`, and hashes several chunks in parallel.

use core::convert::Infallible;

use ::blake3::hazmat::HasherExt;
use ::blake3::{Hasher, OutputReader};
use tc_digest::{TryDigest, TryXof};
use zeroize::Zeroize;

use crate::blake3_portable::derive_context_key;

const BLOCK_LEN: usize = 64;
const KEY_LEN: usize = 32;

/// The BLAKE3 hash / extendable-output function on the `blake3` crate.
/// Constant time, as the `blake3` crate is.
#[derive(Clone)]
pub struct Blake3UpstreamDigest {
    hasher: Hasher,
    /// Created on the first read; `None` while absorbing.
    reader: Option<OutputReader>,
    digest_len: usize,
}

impl Default for Blake3UpstreamDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3UpstreamDigest {
    /// Creates an unkeyed BLAKE3 with the default 32-byte digest. Constant time.
    pub fn new() -> Self {
        Self::with_digest_size(256)
    }

    /// Creates an unkeyed BLAKE3 with a default output size in bits.
    /// Constant time.
    pub fn with_digest_size(digest_bits: usize) -> Self {
        Self::build(Hasher::new(), digest_bits)
    }

    /// Creates a keyed BLAKE3 (keyed-hash mode) with a 32-byte key.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not exactly 32 bytes.
    pub fn with_key(digest_bits: usize, key: &[u8]) -> Self {
        assert_eq!(key.len(), KEY_LEN, "BLAKE3 key must be exactly 32 bytes");
        Self::build(Hasher::new_keyed(key.try_into().unwrap()), digest_bits)
    }

    /// Creates a BLAKE3 in derive-key mode from a context string. Constant
    /// time with respect to the contents of `context`; its length is public.
    pub fn with_derive_key(digest_bits: usize, context: &[u8]) -> Self {
        // `blake3` takes the context only as &str, so the portable digest hashes
        // any bytes into the context key, which the hazmat constructor takes;
        // both compute the same value.
        let context_key = derive_context_key(context);
        Self::build(Hasher::new_from_context_key(&context_key), digest_bits)
    }

    /// Wraps `hasher` with a default output of `digest_bits`. Constant time.
    fn build(hasher: Hasher, digest_bits: usize) -> Self {
        Self {
            hasher,
            reader: None,
            digest_len: digest_bits / 8,
        }
    }
}

impl TryDigest for Blake3UpstreamDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.digest_len
    }

    fn byte_length(&self) -> usize {
        BLOCK_LEN
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        assert!(
            self.reader.is_none(),
            "BLAKE3: cannot absorb while outputting"
        );
        self.hasher.update(input);
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
        self.hasher.reset();
        self.reader.zeroize();
        Ok(())
    }
}

impl TryXof for Blake3UpstreamDigest {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.reader
            .get_or_insert_with(|| self.hasher.finalize_xof())
            .fill(output);
        Ok(output.len())
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let written = self.try_output(output)?;
        self.try_reset()?;
        Ok(written)
    }
}

impl Drop for Blake3UpstreamDigest {
    /// Wipes the hasher and the output reader through the `zeroize` crate.
    /// Constant time.
    fn drop(&mut self) {
        self.hasher.zeroize();
        self.reader.zeroize();
    }
}

impl core::fmt::Display for Blake3UpstreamDigest {
    /// Writes `BLAKE3` without inspecting the state. Constant time with respect
    /// to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BLAKE3")
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::{vec, vec::Vec};

    use super::*;
    use crate::Blake3PortableDigest;
    use tc_digest::{Digest, Xof};

    const KEY: &[u8; 32] = b"whats the Elvish word for friend";
    // A context that is not UTF-8, which `blake3::Hasher::new_derive_key` cannot take.
    const CONTEXT: &[u8] = b"\xff tc_blake upstream context \xfe";
    const LENGTHS: [usize; 14] = [
        0, 1, 63, 64, 65, 1023, 1024, 1025, 2047, 2048, 2049, 3072, 8193, 31745,
    ];

    fn message(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn output_of<D: Xof>(mut digest: D, input: &[u8], chunk: usize, out_len: usize) -> Vec<u8> {
        for part in input.chunks(chunk.max(1)) {
            digest.update(part);
        }
        let mut out = vec![0u8; out_len];
        digest.output_final(&mut out);
        out
    }

    #[test]
    fn every_mode_matches_the_portable_digest_across_chunk_boundaries() {
        for len in LENGTHS {
            let input = message(len);
            for chunk in [len, 7, 1000] {
                assert_eq!(
                    output_of(Blake3UpstreamDigest::new(), &input, chunk, 131),
                    output_of(Blake3PortableDigest::new(), &input, chunk, 131),
                    "unkeyed len {len} chunk {chunk}"
                );
                assert_eq!(
                    output_of(Blake3UpstreamDigest::with_key(256, KEY), &input, chunk, 131),
                    output_of(Blake3PortableDigest::with_key(256, KEY), &input, chunk, 131),
                    "keyed len {len} chunk {chunk}"
                );
                assert_eq!(
                    output_of(
                        Blake3UpstreamDigest::with_derive_key(256, CONTEXT),
                        &input,
                        chunk,
                        131
                    ),
                    output_of(
                        Blake3PortableDigest::with_derive_key(256, CONTEXT),
                        &input,
                        chunk,
                        131
                    ),
                    "derive-key len {len} chunk {chunk}"
                );
            }
        }
    }

    #[test]
    fn streamed_output_clone_and_reset_behave_like_the_portable_digest() {
        let input = message(3000);
        let mut upstream = Blake3UpstreamDigest::with_key(256, KEY);
        let mut portable = Blake3PortableDigest::with_key(256, KEY);
        upstream.update(&input[..1500]);
        portable.update(&input[..1500]);
        let mut upstream_clone = upstream.clone();
        upstream.update(&input[1500..]);
        portable.update(&input[1500..]);
        upstream_clone.update(&input[1500..]);

        let (mut a, mut b, mut c) = ([0u8; 200], [0u8; 200], [0u8; 200]);
        let mut offset = 0;
        for size in [1usize, 63, 64, 65, 7] {
            upstream.output(&mut a[offset..offset + size]);
            portable.output(&mut b[offset..offset + size]);
            offset += size;
        }
        upstream.output(&mut a[offset..]);
        portable.output(&mut b[offset..]);
        upstream_clone.output(&mut c);
        assert_eq!(a, b);
        assert_eq!(a, c);

        upstream.reset();
        portable.reset();
        let mut upstream_digest = [0u8; 32];
        let mut portable_digest = [0u8; 32];
        upstream.update(&input);
        portable.update(&input);
        upstream.do_final(&mut upstream_digest);
        portable.do_final(&mut portable_digest);
        assert_eq!(upstream_digest, portable_digest);
    }

    #[test]
    fn name_and_sizes_match_the_portable_digest() {
        let upstream = Blake3UpstreamDigest::with_digest_size(512);
        let portable = Blake3PortableDigest::with_digest_size(512);
        assert_eq!(upstream.to_string(), portable.to_string());
        assert_eq!(upstream.digest_size(), portable.digest_size());
        assert_eq!(upstream.byte_length(), portable.byte_length());
    }

    #[test]
    #[should_panic(expected = "BLAKE3: cannot absorb while outputting")]
    fn absorbing_after_output_panics_like_the_portable_digest() {
        let mut digest = Blake3UpstreamDigest::new();
        digest.output(&mut [0u8; 8]);
        digest.update(b"late");
    }
}
