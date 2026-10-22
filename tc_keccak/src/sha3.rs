//! SHA-3 of FIPS 202, ported from Bouncy Castle's `Sha3Digest`: the Keccak
//! sponge with the domain pad `0x06`, at the four standardized output sizes.

use core::convert::Infallible;
use core::fmt;

use tc_digest::TryDigest;

use crate::keccak::KeccakDigest;

/// SHA3-224, SHA3-256, SHA3-384 or SHA3-512 of FIPS 202. Constant time.
#[derive(Clone)]
pub struct Sha3Digest {
    sponge: KeccakDigest,
}

impl Default for Sha3Digest {
    /// SHA3-256, as Bouncy Castle's default constructor. Constant time.
    fn default() -> Self {
        Self::new(256)
    }
}

impl Sha3Digest {
    /// SHA3 with `bit_length` bits of output: 224, 256, 384 or 512.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics for any other length, as Bouncy Castle throws.
    pub fn new(bit_length: usize) -> Self {
        assert!(
            matches!(bit_length, 224 | 256 | 384 | 512),
            "SHA-3: bit length must be one of 224, 256, 384, 512"
        );

        Sha3Digest {
            sponge: KeccakDigest::with_domain(bit_length, 0x06),
        }
    }
}

impl fmt::Display for Sha3Digest {
    /// Writes `SHA3-` and the output length in bits, such as `SHA3-256`,
    /// without inspecting the state. Constant time with respect to the
    /// message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SHA3-{}", self.sponge.digest_size() * 8)
    }
}

impl TryDigest for Sha3Digest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.sponge.digest_size()
    }

    fn byte_length(&self) -> usize {
        self.sponge.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.sponge.try_update(input)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.sponge.try_do_final(output)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.sponge.try_reset()
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec, vec::Vec};

    use super::*;
    use tc_digest::Digest;

    fn hex(bit_length: usize, input: &[u8]) -> String {
        let mut digest = Sha3Digest::new(bit_length);
        digest.update(input);

        let mut output = vec![0u8; digest.digest_size()];
        digest.do_final(&mut output);

        let mut encoded = String::with_capacity(output.len() * 2);
        for byte in output {
            encoded.push_str(&format!("{byte:02x}"));
        }
        encoded
    }

    /// FIPS 202 known-answer tests for every standardized output size.
    #[test]
    fn empty_message_vectors() {
        assert_eq!(
            hex(224, b""),
            "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
        );
        assert_eq!(
            hex(256, b""),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex(384, b""),
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a\
             c3713831264adb47fb6bd1e058d5f004"
        );
        assert_eq!(
            hex(512, b""),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
    }

    #[test]
    fn abc_vectors() {
        assert_eq!(
            hex(224, b"abc"),
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
        );
        assert_eq!(
            hex(256, b"abc"),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            hex(384, b"abc"),
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2\
             98d88cea927ac7f539f1edf228376d25"
        );
        assert_eq!(
            hex(512, b"abc"),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
    }

    #[test]
    fn accessors_and_default() {
        let digest = Sha3Digest::default();
        assert_eq!(digest.digest_size(), 32);
        assert_eq!(digest.byte_length(), 136);

        let expected = [
            (224, 28, 144),
            (256, 32, 136),
            (384, 48, 104),
            (512, 64, 72),
        ];
        for (bits, digest_size, byte_length) in expected {
            let digest = Sha3Digest::new(bits);
            assert_eq!(digest.digest_size(), digest_size);
            assert_eq!(digest.byte_length(), byte_length);
            assert_eq!(format!("{digest}"), format!("SHA3-{bits}"));
        }
    }

    #[test]
    fn chunked_matches_whole_for_all_sizes() {
        let message: Vec<u8> = (0..400).map(|i| i as u8).collect();

        for bits in [224, 256, 384, 512] {
            let mut whole = Sha3Digest::new(bits);
            whole.update(&message);
            let mut expected = vec![0u8; whole.digest_size()];
            whole.do_final(&mut expected);

            let rate = Sha3Digest::new(bits).byte_length();
            let mut chunked = Sha3Digest::new(bits);
            chunked.update(&message[..rate - 1]);
            chunked.update(&message[rate - 1..rate]);
            chunked.update(&message[rate..]);
            let mut actual = vec![0u8; chunked.digest_size()];
            chunked.do_final(&mut actual);

            assert_eq!(actual, expected, "SHA3-{bits}");
        }
    }

    #[test]
    fn clone_and_final_reset() {
        let mut original = Sha3Digest::new(256);
        original.update(b"prefix");
        let mut cloned = original.clone();

        original.update(b"-suffix");
        cloned.update(b"-suffix");
        let mut original_output = [0u8; 32];
        let mut cloned_output = [0u8; 32];
        original.do_final(&mut original_output);
        cloned.do_final(&mut cloned_output);
        assert_eq!(original_output, cloned_output);

        original.do_final(&mut original_output);
        assert_eq!(
            original_output,
            [
                0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
                0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
                0x80, 0xf8, 0x43, 0x4a,
            ]
        );
    }

    #[test]
    #[should_panic(expected = "SHA-3: bit length must be one of 224, 256, 384, 512")]
    fn rejects_non_standard_size() {
        let _ = Sha3Digest::new(128);
    }
}
