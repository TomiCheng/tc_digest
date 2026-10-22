//! TupleHash of NIST SP 800-185, ported from Bouncy Castle's `TupleHash`.
//!
//! TupleHash hashes an ordered tuple of byte strings unambiguously: each call
//! to [`update`](tc_digest::Digest::update) is one element, absorbed with its
//! length as `encode_string`, so `(a, b)` and `(ab,)` differ. It is cSHAKE
//! with the function name `"TupleHash"`; before the first output it absorbs
//! `right_encode(L)`, with `L` the output length in bits for a fixed-length
//! output or 0 for an extendable one, so the two never coincide.

use core::convert::Infallible;
use core::fmt;

use tc_digest::{Digest, TryDigest, TryXof};

use crate::cshake::CShakeDigest;
use crate::xof_utils::{absorb_encoded_string, right_encode};

const N_TUPLE_HASH: &[u8] = b"TupleHash";

/// TupleHash128 or TupleHash256 of SP 800-185. Constant time with respect to
/// the elements; the running time depends on their number and lengths.
#[derive(Clone)]
pub struct TupleHash {
    cshake: CShakeDigest,
    // The default output length in bytes.
    output_length: usize,
    // Whether nothing has been read yet, so right_encode(L) is still to come.
    first_output: bool,
}

impl TupleHash {
    /// TupleHash with a `bit_length` security strength, 128 or 256, the
    /// customization `s` and twice the strength of output: 32 bytes for 128,
    /// 64 for 256. Constant time with respect to the contents of `s`.
    ///
    /// # Panics
    ///
    /// Panics for any other strength, as Bouncy Castle throws.
    pub fn new(bit_length: usize, s: &[u8]) -> Self {
        Self::with_output_size(bit_length, s, bit_length * 2)
    }

    /// TupleHash with a `bit_length` security strength, 128 or 256, the
    /// customization `s` and `output_size_bits` bits of output, rounded up to
    /// whole bytes. Constant time with respect to the contents of `s`.
    ///
    /// # Panics
    ///
    /// Panics for any other strength, as Bouncy Castle throws.
    pub fn with_output_size(bit_length: usize, s: &[u8], output_size_bits: usize) -> Self {
        TupleHash {
            cshake: CShakeDigest::new(bit_length, N_TUPLE_HASH, s),
            output_length: output_size_bits.div_ceil(8),
            first_output: true,
        }
    }

    /// Absorbs `right_encode(L)` before the first output: `L` is the output
    /// length in bits for a fixed-length output, 0 for an extendable one.
    /// Constant time.
    fn wrap_up(&mut self, output_bytes: usize) {
        self.cshake
            .update(right_encode(output_bytes as u64 * 8).as_slice());
        self.first_output = false;
    }
}

impl fmt::Display for TupleHash {
    /// Writes `TupleHash` and the security strength, such as `TupleHash128`,
    /// without inspecting the state. Constant time with respect to the
    /// message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TupleHash{}", self.cshake.bit_length())
    }
}

impl TryDigest for TupleHash {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.output_length
    }

    fn byte_length(&self) -> usize {
        self.cshake.byte_length()
    }

    // Each update is one element of the tuple.
    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        absorb_encoded_string(&mut self.cshake, input);
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
        self.cshake.try_reset()?;
        self.first_output = true;
        Ok(())
    }
}

impl TryXof for TupleHash {
    // An extendable output, right_encode(0).
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if self.first_output {
            self.wrap_up(0);
        }
        self.cshake.try_output(output)
    }

    // A fixed-length output, right_encode of its length in bits.
    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if self.first_output {
            self.wrap_up(output.len());
        }
        self.cshake.try_output(output)?;
        self.try_reset()?;
        Ok(output.len())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use tc_digest::{Digest, Xof};

    fn unhex(s: &str) -> Vec<u8> {
        let d: Vec<char> = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        d.chunks(2)
            .map(|p| (p[0].to_digit(16).unwrap() as u8) << 4 | p[1].to_digit(16).unwrap() as u8)
            .collect()
    }

    fn tuple_final(bits: usize, s: &[u8], elems: &[&[u8]]) -> Vec<u8> {
        let mut t = TupleHash::new(bits, s);
        for e in elems {
            t.update(e);
        }
        let mut out = vec![0u8; t.digest_size()];
        t.do_final(&mut out);
        out
    }

    #[test]
    fn accessors() {
        let t = TupleHash::new(128, b"");
        assert_eq!(t.digest_size(), 32);
        assert_eq!(alloc::format!("{t}"), "TupleHash128");
        assert_eq!(t.byte_length(), 168);

        let t = TupleHash::new(256, b"");
        assert_eq!(t.digest_size(), 64);
        assert_eq!(t.byte_length(), 136);
    }

    // NIST's SP 800-185 TupleHash samples.
    #[test]
    fn nist_samples_128() {
        let e1: &[u8] = &unhex("000102");
        let e2: &[u8] = &unhex("101112131415");
        let e3: &[u8] = &unhex("202122232425262728");

        // #1: no customization, the tuple (e1, e2).
        assert_eq!(
            tuple_final(128, b"", &[e1, e2]),
            unhex("c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1")
        );
        // #2: customized as "My Tuple App", the tuple (e1, e2).
        assert_eq!(
            tuple_final(128, b"My Tuple App", &[e1, e2]),
            unhex("75cdb20ff4db1154e841d758e24160c54bae86eb8c13e7f5f40eb35588e96dfb")
        );
        // #3: customized, the tuple (e1, e2, e3).
        assert_eq!(
            tuple_final(128, b"My Tuple App", &[e1, e2, e3]),
            unhex("e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84")
        );
    }

    #[test]
    fn nist_samples_256() {
        let e1: &[u8] = &unhex("000102");
        let e2: &[u8] = &unhex("101112131415");
        let e3: &[u8] = &unhex("202122232425262728");

        assert_eq!(
            tuple_final(256, b"", &[e1, e2]),
            unhex(
                "cfb7058caca5e668f81a12a20a2195ce97a925f1dba3e7449a56f82201ec6073\
                 11ac2696b1ab5ea2352df1423bde7bd4bb78c9aed1a853c78672f9eb23bbe194"
            )
        );
        assert_eq!(
            tuple_final(256, b"My Tuple App", &[e1, e2]),
            unhex(
                "147c2191d5ed7efd98dbd96d7ab5a11692576f5fe2a5065f3e33de6bba9f3aa1\
                 c4e9a068a289c61c95aab30aee1e410b0b607de3620e24a4e3bf9852a1d4367e"
            )
        );
        assert_eq!(
            tuple_final(256, b"My Tuple App", &[e1, e2, e3]),
            unhex(
                "45000be63f9b6bfd89f54717670f69a9bc763591a4f05c50d68891a744bcc6e7\
                 d6d5b5e82c018da999ed35b0bb49c9678e526abd8e85c13ed254021db9e790ce"
            )
        );
    }

    // An extendable output, right_encode(0), differs from a fixed one, right_encode(L).
    #[test]
    fn xof_mode_differs_from_fixed() {
        let e1: &[u8] = &unhex("000102");
        let e2: &[u8] = &unhex("101112131415");
        let e3: &[u8] = &unhex("202122232425262728");

        // TupleHash128 as an XOF.
        let mut t = TupleHash::new(128, b"My Tuple App");
        t.update(e1);
        t.update(e2);
        t.update(e3);
        let mut o = [0u8; 32];
        t.output(&mut o);
        assert_ne!(
            o.to_vec(),
            unhex("e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84")
        );
        assert_eq!(
            o.to_vec(),
            unhex("900fe16cad098d28e74d632ed852f99daab7f7df4d99e775657885b4bf76d6f8")
        );

        // TupleHash256 as an XOF.
        let mut t = TupleHash::new(256, b"My Tuple App");
        t.update(e1);
        t.update(e2);
        t.update(e3);
        let mut o = [0u8; 64];
        t.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex(
                "0c59b11464f2336c34663ed51b2b950bec743610856f36c28d1d088d8a244628\
                 4dd09830a6a178dc752376199fae935d86cfdee5913d4922dfd369b66a53c897"
            )
        );
    }

    // do_final resets, so the same tuple gives the same digest again.
    #[test]
    fn do_final_resets() {
        let e1: &[u8] = &unhex("000102");
        let e2: &[u8] = &unhex("101112131415");
        let first = tuple_final(128, b"My Tuple App", &[e1, e2]);
        let second = tuple_final(128, b"My Tuple App", &[e1, e2]);
        assert_eq!(first, second);
    }

    // Element boundaries count: (a, b) is not (ab,).
    #[test]
    fn tuple_boundaries_matter() {
        let ab = tuple_final(128, b"", &[b"ab"]);
        let a_b = tuple_final(128, b"", &[b"a", b"b"]);
        assert_ne!(ab, a_b);
    }
}
