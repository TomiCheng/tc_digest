//! The five boolean functions of the RIPEMD family. RIPEMD-128 and RIPEMD-256
//! use the first four, RIPEMD-160 and RIPEMD-320 all five; Bouncy Castle
//! repeats them in every digest class.

/// f1, `x ^ y ^ z`. Constant time.
#[inline(always)]
pub(crate) fn f1(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// f2, `(x & y) | (!x & z)`: y where x is set, else z. Constant time.
#[inline(always)]
pub(crate) fn f2(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

/// f3, `(x | !y) ^ z`. Constant time.
#[inline(always)]
pub(crate) fn f3(x: u32, y: u32, z: u32) -> u32 {
    (x | !y) ^ z
}

/// f4, `(x & z) | (y & !z)`: x where z is set, else y. Constant time.
#[inline(always)]
pub(crate) fn f4(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & !z)
}

/// f5, `x ^ (y | !z)`. Constant time.
#[inline(always)]
pub(crate) fn f5(x: u32, y: u32, z: u32) -> u32 {
    x ^ (y | !z)
}
