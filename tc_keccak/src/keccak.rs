//! The Keccak-f\[1600\] permutation and the sponge every digest here is built
//! on, ported from Bouncy Castle's `KeccakDigest`.
//!
//! A sponge XORs its input into a 1600-bit state, 25 `u64` lanes, one rate of
//! bytes at a time with a permutation between blocks (absorbing), then reads
//! its output back the same way (squeezing). [`KeccakDigest`] is raw Keccak,
//! the version submitted to the SHA-3 competition, with the domain pad `0x01`;
//! SHA-3, SHAKE and cSHAKE reuse the same sponge with their own pads.

use core::convert::Infallible;
use core::fmt;

use tc_digest::TryDigest;
use tc_zeroize::Zeroize;

/// The 24 round constants of the ι step.
#[rustfmt::skip]
const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// The Keccak-f\[1600\] permutation: 24 rounds of θ, ρ, π, χ and ι over 25
/// lanes, as Bouncy Castle's `KeccakPermutation`. Constant time: only XOR,
/// AND, OR, NOT and fixed rotations.
///
/// It uses lane complementing, XKCP's "bebigokimisa": the lanes Abe, Abi, Ago,
/// Aki, Ami and Asa are complemented on entry, χ is written with the ANDs and
/// ORs that keep that pattern, which cuts its NOTs from 25 to 5 a round, and
/// the six lanes are complemented again on exit.
pub(crate) fn keccak_f1600(a: &mut [u64; 25]) {
    let (mut a00, mut a01, mut a02, mut a03, mut a04) = (a[0], !a[1], !a[2], a[3], a[4]);
    let (mut a05, mut a06, mut a07, mut a08, mut a09) = (a[5], a[6], a[7], !a[8], a[9]);
    let (mut a10, mut a11, mut a12, mut a13, mut a14) = (a[10], a[11], !a[12], a[13], a[14]);
    let (mut a15, mut a16, mut a17, mut a18, mut a19) = (a[15], a[16], !a[17], a[18], a[19]);
    let (mut a20, mut a21, mut a22, mut a23, mut a24) = (!a[20], a[21], a[22], a[23], a[24]);

    for &rc in RC.iter() {
        // θ: the column parities, each fed back into the neighbouring columns.
        let ca = a00 ^ a05 ^ a10 ^ a15 ^ a20;
        let ce = a01 ^ a06 ^ a11 ^ a16 ^ a21;
        let ci = a02 ^ a07 ^ a12 ^ a17 ^ a22;
        let co = a03 ^ a08 ^ a13 ^ a18 ^ a23;
        let cu = a04 ^ a09 ^ a14 ^ a19 ^ a24;
        let da = cu ^ ce.rotate_left(1);
        let de = ca ^ ci.rotate_left(1);
        let di = ce ^ co.rotate_left(1);
        let d_o = ci ^ cu.rotate_left(1);
        let du = co ^ ca.rotate_left(1);

        // ρ and π: each lane rotated by its fixed offset into its new position.
        let bba = a00 ^ da;
        let bbe = (a06 ^ de).rotate_left(44);
        let bbi = (a12 ^ di).rotate_left(43);
        let bbo = (a18 ^ d_o).rotate_left(21);
        let bbu = (a24 ^ du).rotate_left(14);
        let bga = (a03 ^ d_o).rotate_left(28);
        let bge = (a09 ^ du).rotate_left(20);
        let bgi = (a10 ^ da).rotate_left(3);
        let bgo = (a16 ^ de).rotate_left(45);
        let bgu = (a22 ^ di).rotate_left(61);
        let bka = (a01 ^ de).rotate_left(1);
        let bke = (a07 ^ di).rotate_left(6);
        let bki = (a13 ^ d_o).rotate_left(25);
        let bko = (a19 ^ du).rotate_left(8);
        let bku = (a20 ^ da).rotate_left(18);
        let bma = (a04 ^ du).rotate_left(27);
        let bme = (a05 ^ da).rotate_left(36);
        let bmi = (a11 ^ de).rotate_left(10);
        let bmo = (a17 ^ di).rotate_left(15);
        let bmu = (a23 ^ d_o).rotate_left(56);
        let bsa = (a02 ^ di).rotate_left(62);
        let bse = (a08 ^ d_o).rotate_left(55);
        let bsi = (a14 ^ du).rotate_left(39);
        let bso = (a15 ^ da).rotate_left(41);
        let bsu = (a21 ^ de).rotate_left(2);

        // χ, with ι on the first lane, in the complemented form.
        a00 = bba ^ (bbe | bbi) ^ rc;
        a01 = bbe ^ (!bbi | bbo);
        a02 = bbi ^ (bbo & bbu);
        a03 = bbo ^ (bbu | bba);
        a04 = bbu ^ (bba & bbe);

        a05 = bga ^ (bge | bgi);
        a06 = bge ^ (bgi & bgo);
        a07 = bgi ^ (bgo | !bgu);
        a08 = bgo ^ (bgu | bga);
        a09 = bgu ^ (bga & bge);

        a10 = bka ^ (bke | bki);
        a11 = bke ^ (bki & bko);
        a12 = bki ^ (!bko & bku);
        a13 = !bko ^ (bku | bka);
        a14 = bku ^ (bka & bke);

        a15 = bma ^ (bme & bmi);
        a16 = bme ^ (bmi | bmo);
        a17 = bmi ^ (!bmo | bmu);
        a18 = !bmo ^ (bmu & bma);
        a19 = bmu ^ (bma | bme);

        a20 = bsa ^ (!bse & bsi);
        a21 = !bse ^ (bsi | bso);
        a22 = bsi ^ (bso & bsu);
        a23 = bso ^ (bsu | bsa);
        a24 = bsu ^ (bsa & bse);
    }

    *a = [
        a00, !a01, !a02, a03, a04, a05, a06, a07, !a08, a09, a10, a11, !a12, a13, a14, a15, a16,
        !a17, a18, a19, !a20, a21, a22, a23, a24,
    ];
}

/// Raw Keccak, the SHA-3 competition version with the domain pad `0x01`, as
/// Bouncy Castle's `KeccakDigest`. Constant time.
///
/// This is the sponge the other digests in the crate are built on, each with
/// its own domain pad.
#[derive(Clone)]
pub struct KeccakDigest {
    // The 1600-bit state as 25 lanes.
    state: [u64; 25],
    // The bytes absorbed or squeezed per permutation: (1600 - 2 x output bits) / 8.
    rate_bytes: usize,
    // The position within the current block, while absorbing or squeezing.
    pos: usize,
    // The fixed output length in bytes.
    out_len: usize,
    // The domain separation bits padded on before the final permutation.
    domain: u8,
    // Whether the sponge is squeezing; it absorbs no more until reset.
    squeezing: bool,
}

impl KeccakDigest {
    /// Raw Keccak with `bit_length` bits of output: 128, 224, 256, 288, 384 or
    /// 512. Constant time.
    ///
    /// # Panics
    ///
    /// Panics for any other length, as Bouncy Castle throws.
    pub fn new(bit_length: usize) -> Self {
        Self::with_domain(bit_length, 0x01)
    }

    /// A sponge with `bit_length` bits of output and the domain pad `domain`,
    /// for SHA-3 (`0x06`), SHAKE (`0x1f`) and cSHAKE (`0x04`). Constant time.
    pub(crate) fn with_domain(bit_length: usize, domain: u8) -> Self {
        assert!(
            matches!(bit_length, 128 | 224 | 256 | 288 | 384 | 512),
            "Keccak: bit length must be one of 128, 224, 256, 288, 384, 512"
        );
        let rate = 1600 - (bit_length << 1);
        KeccakDigest {
            state: [0; 25],
            rate_bytes: rate / 8,
            pos: 0,
            out_len: bit_length / 8,
            domain,
            squeezing: false,
        }
    }

    /// XORs `input` into the state, permuting at each full block. On a lane
    /// boundary it takes a whole eight-byte little-endian lane, and goes byte by
    /// byte only off one; every rate is a multiple of eight, so a lane never
    /// crosses a block. Constant time: the work depends only on the input
    /// length and the position.
    fn absorb(&mut self, input: &[u8]) {
        let mut i = 0;
        while i < input.len() {
            if self.pos % 8 == 0 && input.len() - i >= 8 {
                let lane = u64::from_le_bytes(input[i..i + 8].try_into().expect("an 8-byte lane"));
                self.state[self.pos / 8] ^= lane;
                self.pos += 8;
                i += 8;
            } else {
                self.state[self.pos / 8] ^= (input[i] as u64) << ((self.pos % 8) * 8);
                self.pos += 1;
                i += 1;
            }
            if self.pos == self.rate_bytes {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    /// Pads with pad10*1, the domain bits at the position and the closing bit
    /// at the end of the block, permutes and starts squeezing. Constant time.
    fn pad_and_switch(&mut self) {
        self.state[self.pos / 8] ^= (self.domain as u64) << ((self.pos % 8) * 8);
        let last = self.rate_bytes - 1;
        self.state[last / 8] ^= 0x80u64 << ((last % 8) * 8);
        keccak_f1600(&mut self.state);
        self.pos = 0;
        self.squeezing = true;
    }

    /// Reads `output` from the state, permuting before each new block; the
    /// position carries over, so successive calls continue one output stream.
    /// Like absorbing, it reads whole lanes on lane boundaries. Constant time:
    /// the work depends only on the output length and the position.
    fn squeeze(&mut self, output: &mut [u8]) {
        let mut i = 0;
        while i < output.len() {
            if self.pos == self.rate_bytes {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            if self.pos % 8 == 0 && output.len() - i >= 8 {
                output[i..i + 8].copy_from_slice(&self.state[self.pos / 8].to_le_bytes());
                self.pos += 8;
                i += 8;
            } else {
                output[i] = (self.state[self.pos / 8] >> ((self.pos % 8) * 8)) as u8;
                self.pos += 1;
                i += 1;
            }
        }
    }

    /// The zero padding of SP 800-185's `bytepad`, up to the next block
    /// boundary. XORing zeros changes nothing, so it only permutes when the
    /// position is inside a block; on a boundary absorbing has already
    /// permuted. Constant time.
    pub(crate) fn pad_to_block(&mut self) {
        if self.pos != 0 {
            keccak_f1600(&mut self.state);
            self.pos = 0;
        }
    }

    /// Squeezes `output` as an extendable-output function: the first call pads
    /// and switches to squeezing, later calls continue the stream. It does not
    /// reset. Constant time.
    pub(crate) fn xof_output(&mut self, output: &mut [u8]) {
        if !self.squeezing {
            self.pad_and_switch();
        }
        self.squeeze(output);
    }
}

impl fmt::Display for KeccakDigest {
    /// Writes `Keccak-` and the output length in bits, such as `Keccak-256`,
    /// without inspecting the state. Constant time with respect to the
    /// message; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keccak-{}", self.out_len * 8)
    }
}

impl TryDigest for KeccakDigest {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.out_len
    }

    fn byte_length(&self) -> usize {
        self.rate_bytes
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        assert!(!self.squeezing, "Keccak: attempt to absorb while squeezing");
        self.absorb(input);
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.out_len;
        assert!(
            output.len() >= len,
            "output buffer shorter than the {len}-byte digest"
        );
        self.pad_and_switch();
        self.squeeze(&mut output[..len]);
        self.try_reset()?;
        Ok(len)
    }

    // A fresh digest replaces this one, which the drop wipes.
    fn try_reset(&mut self) -> Result<(), Self::Error> {
        *self = Self::with_domain(self.out_len * 8, self.domain);
        Ok(())
    }
}

impl Drop for KeccakDigest {
    /// Wipes the state and the position; every digest that holds a sponge is
    /// wiped through here. Constant time.
    fn drop(&mut self) {
        self.state.zeroize();
        self.pos.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec::Vec};

    use super::*;
    use tc_digest::Digest;

    fn hex(bit_length: usize, input: &[u8]) -> String {
        let mut d = KeccakDigest::new(bit_length);
        d.update(input);
        let mut out = alloc::vec![0u8; bit_length / 8];
        d.do_final(&mut out);
        let mut s = String::with_capacity(bit_length / 4);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // Raw Keccak, not SHA-3.
    #[test]
    fn keccak256_vectors() {
        assert_eq!(
            hex(256, b""),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex(256, b"abc"),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        assert_eq!(
            hex(256, b"The quick brown fox jumps over the lazy dog"),
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
        );
    }

    #[test]
    fn keccak512_empty() {
        assert_eq!(
            hex(512, b""),
            "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304\
             c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"
        );
    }

    #[test]
    fn accessors_and_reset() {
        let mut d = KeccakDigest::new(256);
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 136); // a 1088-bit rate
        d.update(b"abc");
        let mut o = [0u8; 32];
        d.do_final(&mut o);
        // do_final reset the digest, so this is the empty message.
        d.do_final(&mut o);
        let s: String = o.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            s,
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..400).map(|i| i as u8).collect();
        let mut a = KeccakDigest::new(256);
        a.update(&msg);
        let mut oa = [0u8; 32];
        a.do_final(&mut oa);
        let mut b = KeccakDigest::new(256);
        b.update(&msg[..100]);
        b.update(&msg[100..136]);
        b.update(&msg[136..]);
        let mut ob = [0u8; 32];
        b.do_final(&mut ob);
        assert_eq!(oa, ob);
    }

    #[test]
    fn display_names_the_output_length() {
        assert_eq!(format!("{}", KeccakDigest::new(256)), "Keccak-256");
        assert_eq!(format!("{}", KeccakDigest::new(288)), "Keccak-288");
    }
}
