//! MD2 message digest (RFC 1319), ported from Bouncy Castle's `MD2Digest`.

use core::convert::Infallible;

use tc_digest::TryDigest;

const DIGEST_LENGTH: usize = 16;
const BYTE_LENGTH: usize = 16;

/// The MD2 digest (RFC 1319), producing a 16-byte hash.
///
/// MD2 is cryptographically broken and kept only for interoperability with
/// legacy data; do not use it for new designs.
///
/// Variable time: the compression indexes the S-box with message-derived
/// bytes, which can leak the message through cache timing. Hash only public
/// data with it.
///
/// `do_final` panics if the output buffer is shorter than 16 bytes.
#[derive(Clone)]
pub struct Md2Digest {
    /// The 48-byte state buffer X.
    x: [u8; 48],
    /// The 16-byte message block M being filled.
    m: [u8; 16],
    /// The number of bytes filled in `m`, in `0..16`.
    m_off: usize,
    /// The 16-byte checksum C.
    c: [u8; 16],
}

impl Default for Md2Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Md2Digest {
    /// Creates a fresh MD2 digest. Constant time.
    pub const fn new() -> Self {
        Md2Digest {
            x: [0; 48],
            m: [0; 16],
            m_off: 0,
            c: [0; 16],
        }
    }

    /// Absorbs one byte (Bouncy Castle `Update`), processing and emptying the
    /// block once 16 bytes are buffered. Variable time.
    fn process_byte(&mut self, input: u8) {
        self.m[self.m_off] = input;
        self.m_off += 1;
        if self.m_off == 16 {
            let m = self.m;
            self.process_checksum(m);
            self.process_block(m);
            self.m_off = 0;
        }
    }

    /// Updates the checksum C (Bouncy Castle `ProcessChecksum`). `m` is taken
    /// by value to avoid borrowing `self` twice. Variable time: the S-box index
    /// depends on the message.
    fn process_checksum(&mut self, m: [u8; 16]) {
        let mut l = self.c[15];
        for (&message, checksum) in m.iter().zip(&mut self.c) {
            *checksum ^= S[(message ^ l) as usize];
            l = *checksum;
        }
    }

    /// Compresses one block into X (Bouncy Castle `ProcessBlock`). `m` is
    /// either M or C, so it is taken by value. Variable time: the S-box index
    /// depends on the state.
    fn process_block(&mut self, m: [u8; 16]) {
        for (i, &message) in m.iter().enumerate() {
            self.x[i + 16] = message;
            self.x[i + 32] = message ^ self.x[i];
        }
        // 18 rounds of diffusion; `t` is a u8, so the mod-256 reduction is free.
        let mut t: u8 = 0;
        for j in 0..18u8 {
            for k in 0..48 {
                self.x[k] ^= S[t as usize];
                t = self.x[k];
            }
            t = t.wrapping_add(j);
        }
    }
}

impl TryDigest for Md2Digest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "MD2"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        // Byte by byte. Bouncy Castle copies whole 16-byte blocks as a fast
        // path; the result is identical.
        for &b in input {
            self.process_byte(b);
        }
        Ok(())
    }

    fn try_update_byte(&mut self, input: u8) -> Result<(), Self::Error> {
        self.process_byte(input);
        Ok(())
    }

    /// Writes the 16-byte digest to the start of `output` and resets.
    ///
    /// # Panics
    ///
    /// Panics if `output` is shorter than 16 bytes, before changing any state.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        assert!(
            output.len() >= DIGEST_LENGTH,
            "output buffer shorter than the 16-byte MD2 digest"
        );

        // Pad with n bytes of value n, where n is the number of bytes missing.
        let padding = (16 - self.m_off) as u8;
        for i in self.m_off..16 {
            self.m[i] = padding;
        }
        // Checksum the last block, compress it, then compress the checksum.
        let m = self.m;
        self.process_checksum(m);
        self.process_block(m);
        let c = self.c; // read after process_checksum so it covers the last block
        self.process_block(c);

        output[..DIGEST_LENGTH].copy_from_slice(&self.x[..DIGEST_LENGTH]);

        *self = Self::new();
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        *self = Self::new();
        Ok(())
    }
}

/// The 256-byte S-box, a permutation built from the digits of pi (RFC 1319).
/// Rows match Bouncy Castle's `MD2Digest.S`.
#[rustfmt::skip]
static S: [u8; 256] = [
    41, 46, 67, 201, 162, 216, 124,
    1, 61, 54, 84, 161, 236, 240,
    6, 19, 98, 167, 5, 243, 192,
    199, 115, 140, 152, 147, 43, 217,
    188, 76, 130, 202, 30, 155, 87,
    60, 253, 212, 224, 22, 103, 66,
    111, 24, 138, 23, 229, 18, 190,
    78, 196, 214, 218, 158, 222, 73,
    160, 251, 245, 142, 187, 47, 238,
    122, 169, 104, 121, 145, 21, 178,
    7, 63, 148, 194, 16, 137, 11,
    34, 95, 33, 128, 127, 93, 154,
    90, 144, 50, 39, 53, 62, 204,
    231, 191, 247, 151, 3, 255, 25,
    48, 179, 72, 165, 181, 209, 215,
    94, 146, 42, 172, 86, 170, 198,
    79, 184, 56, 210, 150, 164, 125,
    182, 118, 252, 107, 226, 156, 116,
    4, 241, 69, 157, 112, 89, 100,
    113, 135, 32, 134, 91, 207, 101,
    230, 45, 168, 2, 27, 96, 37,
    173, 174, 176, 185, 246, 28, 70,
    97, 105, 52, 64, 126, 15, 85,
    71, 163, 35, 221, 81, 175, 58,
    195, 92, 249, 206, 186, 197, 234,
    38, 44, 83, 13, 110, 133, 40,
    132, 9, 211, 223, 205, 244, 65,
    129, 77, 82, 106, 220, 55, 200,
    108, 193, 171, 250, 36, 225, 123,
    8, 12, 189, 177, 74, 120, 136,
    149, 139, 227, 99, 232, 109, 233,
    203, 213, 254, 59, 0, 29, 57,
    242, 239, 183, 14, 102, 88, 208,
    228, 166, 119, 114, 248, 235, 117,
    75, 10, 49, 68, 80, 180, 143,
    237, 31, 26, 219, 153, 141, 51,
    159, 17, 131, 20,
];

#[cfg(test)]
mod tests {
    use alloc::{format, string::String};

    use super::*;
    use tc_digest::Digest;

    /// Formats a 16-byte digest as lowercase hex.
    fn hex16(out: [u8; 16]) -> String {
        let mut s = String::with_capacity(32);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn md2_hex(input: &[u8]) -> String {
        let mut d = Md2Digest::new();
        d.update(input);
        let mut out = [0u8; 16];
        d.do_final(&mut out);
        hex16(out)
    }

    // The test suite from RFC 1319, appendix A.5.
    #[test]
    fn rfc1319_vectors() {
        assert_eq!(md2_hex(b""), "8350e5a3e24c153df2275c9f80692773");
        assert_eq!(md2_hex(b"a"), "32ec01ec4a6dac72c0ab96fb34c0b5d1");
        assert_eq!(md2_hex(b"abc"), "da853b0d3f88d99b30283a69e6ded6bb");
        assert_eq!(
            md2_hex(b"message digest"),
            "ab4f496bfb2a530b219ff33031fe06b0"
        );
        assert_eq!(
            md2_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "4e8ddff3650292ab5a4108c3aa47940b"
        );
    }

    #[test]
    fn accessors() {
        let d = Md2Digest::new();
        assert_eq!(d.algorithm_name(), "MD2");
        assert_eq!(d.digest_size(), 16);
        assert_eq!(d.byte_length(), 16);
    }

    #[test]
    fn do_final_leaves_reset() {
        let mut d = Md2Digest::new();
        d.update(b"abc");
        let mut out = [0u8; 16];
        d.do_final(&mut out);
        // Finalizing again yields the empty-message digest, so it was reset.
        d.do_final(&mut out);
        assert_eq!(hex16(out), "8350e5a3e24c153df2275c9f80692773");
    }

    #[test]
    fn byte_by_byte_matches_bulk() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let mut a = Md2Digest::new();
        a.update(msg);
        let mut oa = [0u8; 16];
        a.do_final(&mut oa);

        let mut b = Md2Digest::new();
        for &byte in msg {
            b.update_byte(byte);
        }
        let mut ob = [0u8; 16];
        b.do_final(&mut ob);

        assert_eq!(oa, ob);
    }
}
