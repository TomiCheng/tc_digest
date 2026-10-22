//! The encodings of NIST SP 800-185 §2.3, `left_encode`, `right_encode` and
//! `encode_string`, ported from Bouncy Castle's `XofUtils`. They underlie
//! cSHAKE, TupleHash, ParallelHash and KMAC. Lengths are in bits unless a name
//! says otherwise.

use tc_digest::Digest;

/// An encoding in a fixed array: a `u64` takes at most eight bytes, plus one
/// for its length.
pub(crate) struct Encoded {
    bytes: [u8; 9],
    len: usize,
}

impl Encoded {
    /// The encoded bytes. Constant time.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

// The number of big-endian bytes of `value`, at least one.
fn byte_count(value: u64) -> usize {
    (64 - value.leading_zeros() as usize).div_ceil(8).max(1)
}

/// `left_encode(x)`: the byte length `n` of `x`, at least one, then `x` big
/// endian. Constant time: `value` is always a public length, and the running
/// time depends only on its byte length.
pub(crate) fn left_encode(value: u64) -> Encoded {
    let n = byte_count(value);
    let mut bytes = [0; 9];
    bytes[0] = n as u8;
    bytes[1..=n].copy_from_slice(&value.to_be_bytes()[8 - n..]);
    Encoded { bytes, len: n + 1 }
}

/// `right_encode(x)`: `x` big endian, then its byte length `n`, at least one.
/// Constant time: `value` is always a public length, and the running time
/// depends only on its byte length.
pub(crate) fn right_encode(value: u64) -> Encoded {
    let n = byte_count(value);
    let mut bytes = [0; 9];
    bytes[..n].copy_from_slice(&value.to_be_bytes()[8 - n..]);
    bytes[n] = n as u8;
    Encoded { bytes, len: n + 1 }
}

/// Absorbs `encode_string(s)`, `left_encode(bitlen(s)) || s`, as two updates
/// instead of joining them; the empty string is `left_encode(0)`.
/// Constant time with respect to the contents of `s`.
pub(crate) fn absorb_encoded_string(digest: &mut impl Digest, s: &[u8]) {
    digest.update(left_encode(s.len() as u64 * 8).as_slice());
    digest.update(s);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn left_encode_examples() {
        assert_eq!(left_encode(0).as_slice(), [1, 0]);
        assert_eq!(left_encode(168).as_slice(), [1, 168]);
        assert_eq!(left_encode(256).as_slice(), [2, 1, 0]);
        assert_eq!(left_encode(65536).as_slice(), [3, 1, 0, 0]);
        assert_eq!(
            left_encode(u64::MAX).as_slice(),
            [8, 255, 255, 255, 255, 255, 255, 255, 255]
        );
    }

    #[test]
    fn right_encode_examples() {
        assert_eq!(right_encode(0).as_slice(), [0, 1]);
        assert_eq!(right_encode(256).as_slice(), [1, 0, 2]);
        assert_eq!(right_encode(65536).as_slice(), [1, 0, 0, 3]);
        assert_eq!(
            right_encode(u64::MAX).as_slice(),
            [255, 255, 255, 255, 255, 255, 255, 255, 8]
        );
    }
}
