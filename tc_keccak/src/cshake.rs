//! cSHAKE of NIST SP 800-185, ported from Bouncy Castle's `CShakeDigest`.
//!
//! cSHAKE parameterizes SHAKE with a function-name string `N`, reserved for
//! NIST, and a customization string `S`. With both empty it is exactly SHAKE;
//! otherwise the sponge first absorbs
//! `bytepad(encode_string(N) || encode_string(S), rate)` and uses the domain
//! pad `0x04`.

use core::convert::Infallible;
use core::fmt;

use tc_digest::{Digest, TryDigest, TryXof};

use crate::keccak::KeccakDigest;
use crate::xof_utils::{absorb_encoded_string, left_encode};

/// cSHAKE128 or cSHAKE256 of SP 800-185. Constant time; building it takes time
/// that depends on the lengths of `N` and `S`.
#[derive(Clone)]
pub struct CShakeDigest {
    sponge: KeccakDigest,
    // The sponge after the bytepad prefix, restored on reset; with N and S
    // both empty, an empty SHAKE.
    initial: KeccakDigest,
    // The security strength in bits, 128 or 256, which sets the name and the
    // default output length.
    bit_length: usize,
}

impl CShakeDigest {
    /// cSHAKE with a `bit_length` security strength, 128 or 256, the function
    /// name `n` and the customization `s`. Leave `n` empty unless a NIST
    /// standard defines it; with both empty this is SHAKE. Constant time with
    /// respect to the contents of `n` and `s`; it takes time that depends on
    /// their lengths.
    ///
    /// # Panics
    ///
    /// Panics for any other strength, as Bouncy Castle throws.
    pub fn new(bit_length: usize, n: &[u8], s: &[u8]) -> Self {
        assert!(
            matches!(bit_length, 128 | 256),
            "cSHAKE: bit length must be 128 or 256"
        );

        let initial = if n.is_empty() && s.is_empty() {
            KeccakDigest::with_domain(bit_length, 0x1f)
        } else {
            // SP 800-185's bytepad(encode_string(N) || encode_string(S), rate).
            let mut sponge = KeccakDigest::with_domain(bit_length, 0x04);
            let rate_bytes = sponge.byte_length() as u64;
            sponge.update(left_encode(rate_bytes).as_slice());
            absorb_encoded_string(&mut sponge, n);
            absorb_encoded_string(&mut sponge, s);
            sponge.pad_to_block();
            sponge
        };
        CShakeDigest {
            sponge: initial.clone(),
            initial,
            bit_length,
        }
    }

    /// The security strength in bits, 128 or 256, for the names of the
    /// functions built on cSHAKE. Constant time.
    pub(crate) fn bit_length(&self) -> usize {
        self.bit_length
    }
}

impl fmt::Display for CShakeDigest {
    /// Writes `CSHAKE` and the security strength, such as `CSHAKE128`, as
    /// Bouncy Castle names it, without inspecting the state. Constant time with
    /// respect to the message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CSHAKE{}", self.bit_length)
    }
}

impl TryDigest for CShakeDigest {
    type Error = Infallible;

    // Twice the security strength in bytes, as SHAKE.
    fn digest_size(&self) -> usize {
        self.bit_length / 4
    }

    fn byte_length(&self) -> usize {
        self.sponge.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.sponge.try_update(input)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.digest_size();
        assert!(
            output.len() >= len,
            "output buffer shorter than the {len}-byte digest"
        );
        self.try_output_final(&mut output[..len])
    }

    // The saved prefix replaces the sponge, which the drop wipes.
    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.sponge = self.initial.clone();
        Ok(())
    }
}

impl TryXof for CShakeDigest {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.sponge.xof_output(output);
        Ok(output.len())
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let written = self.try_output(output)?;
        self.try_reset()?;
        Ok(written)
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

    #[test]
    fn accessors() {
        let d = CShakeDigest::new(128, b"", b"Email Signature");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 168);
        assert_eq!(alloc::format!("{d}"), "CSHAKE128");

        let d = CShakeDigest::new(256, b"", b"Email Signature");
        assert_eq!(d.digest_size(), 64);
        assert_eq!(d.byte_length(), 136);
        assert_eq!(alloc::format!("{d}"), "CSHAKE256");
    }

    // NIST's SP 800-185 cSHAKE samples #1 to #4: N empty, S "Email Signature".
    #[test]
    fn nist_samples() {
        // cSHAKE128 of a 4-byte message.
        let mut d = CShakeDigest::new(128, b"", b"Email Signature");
        d.update(&unhex("00010203"));
        let mut o = [0u8; 32];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex("c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5")
        );

        // cSHAKE128 of a 1600-bit message, 0x00 to 0xc7.
        let msg: Vec<u8> = (0u16..200).map(|i| i as u8).collect();
        let mut d = CShakeDigest::new(128, b"", b"Email Signature");
        d.update(&msg);
        let mut o = [0u8; 32];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex("c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b")
        );

        // cSHAKE256 of a 4-byte message.
        let mut d = CShakeDigest::new(256, b"", b"Email Signature");
        d.update(&unhex("00010203"));
        let mut o = [0u8; 64];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex(
                "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd1\
                 64020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c"
            )
        );

        // cSHAKE256 of the 1600-bit message.
        let mut d = CShakeDigest::new(256, b"", b"Email Signature");
        d.update(&msg);
        let mut o = [0u8; 64];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex(
                "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac864302730917\
                 27f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb"
            )
        );
    }

    // Bouncy Castle's checkZeroPadZ: a long S makes bytepad span several
    // blocks, once with a non-empty N.
    #[test]
    fn zero_pad_z() {
        let mut d = CShakeDigest::new(256, b"", &[0u8; 265]);
        let mut o = [0u8; 20];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex("6e393540387004f087c4180db008acf6825190cf")
        );

        let mut d = CShakeDigest::new(128, b"", &[0u8; 329]);
        let mut o = [0u8; 20];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex("309bd7c285fcf8b839c9686b2cc00bd578947bee")
        );

        let mut d = CShakeDigest::new(128, &[0u8; 29], &[0u8; 300]);
        let mut o = [0u8; 20];
        d.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex("ff6aafd83b8d22fc3e2e9b9948b581967ed9c5e7")
        );
    }

    // With N and S both empty, cSHAKE is SHAKE.
    #[test]
    fn empty_customization_equals_shake() {
        use crate::shake::ShakeDigest;
        let msg = unhex("eeaabeef");
        for bits in [128usize, 256] {
            let mut r = ShakeDigest::new(bits);
            r.update(&msg);
            let mut ro = [0u8; 32];
            r.output_final(&mut ro);

            let mut c = CShakeDigest::new(bits, b"", b"");
            c.update(&msg);
            let mut co = [0u8; 32];
            c.output_final(&mut co);
            assert_eq!(ro, co, "cSHAKE{bits}(empty) must equal SHAKE{bits}");
        }
    }

    // Bouncy Castle's doFinalTest: output continues the stream without
    // resetting, output_final finishes and resets.
    #[test]
    fn output_vs_output_final_reset() {
        let first = unhex("c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5");
        let mut d = CShakeDigest::new(128, b"", b"Email Signature");
        d.update(&unhex("00010203"));
        let mut o = [0u8; 32];
        d.output(&mut o);
        assert_eq!(o.to_vec(), first);
        // The next read continues the stream, so it differs.
        d.output(&mut o);
        assert_ne!(o.to_vec(), first);

        // After output_final the same input gives the first output again.
        d.output_final(&mut o);
        d.update(&unhex("00010203"));
        d.output_final(&mut o);
        assert_eq!(o.to_vec(), first);
    }

    #[test]
    fn long_block() {
        let data: Vec<u8> = (0u32..200).map(|i| i as u8).collect();
        let mut d = CShakeDigest::new(256, b"", &[0u8; 200]);
        d.update(&data);
        let mut o = vec![0u8; 32];
        d.output_final(&mut o);
        assert_eq!(
            o,
            unhex("4a899b5be460d85a9789215bc17f88b8f8ac049bd3b519f561e7b5d3870dafa3")
        );
    }
}
