//! The Ascon-p permutation shared by every digest here.

const ROUND_CONSTANTS: [u64; 12] = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
];

/// One round: constant addition, the bitsliced 5-bit S-box and the linear
/// layer. Constant time: XOR, AND, NOT and fixed rotations only.
#[inline(always)]
fn round(state: &mut [u64; 5], constant: u64) {
    let [x0, x1, x2, x3, x4] = *state;
    let sx = x2 ^ constant;

    let t0 = x0 ^ x1 ^ sx ^ x3 ^ (x1 & (x0 ^ sx ^ x4));
    let t1 = x0 ^ sx ^ x3 ^ x4 ^ ((x1 ^ sx) & (x1 ^ x3));
    let t2 = x1 ^ sx ^ x4 ^ (x3 & x4);
    let t3 = x0 ^ x1 ^ sx ^ ((!x0) & (x3 ^ x4));
    let t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);

    state[0] = t0 ^ t0.rotate_right(19) ^ t0.rotate_right(28);
    state[1] = t1 ^ t1.rotate_right(39) ^ t1.rotate_right(61);
    state[2] = !(t2 ^ t2.rotate_right(1) ^ t2.rotate_right(6));
    state[3] = t3 ^ t3.rotate_right(10) ^ t3.rotate_right(17);
    state[4] = t4 ^ t4.rotate_right(7) ^ t4.rotate_right(41);
}

/// Ascon-p\[12\], the full twelve rounds. Constant time.
pub(crate) fn p12(state: &mut [u64; 5]) {
    for constant in ROUND_CONSTANTS {
        round(state, constant);
    }
}

/// Ascon-p\[8\], the last eight rounds, for the Ascon v1.2 A variants.
/// Constant time.
#[cfg(feature = "legacy")]
pub(crate) fn p8(state: &mut [u64; 5]) {
    for &constant in &ROUND_CONSTANTS[4..] {
        round(state, constant);
    }
}
