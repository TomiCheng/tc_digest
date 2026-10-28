//! The adapters of the `alloc` feature: NullDigest, Prehash and ShortenedDigest,
//! checked against a toy digest whose output is easy to predict.

#![cfg(feature = "alloc")]

use core::convert::Infallible;
use core::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use tc_digest::util::{NullDigest, Prehash, PrehashError, ShortenedDigest};
use tc_digest::{Digest, TryDigest};

/// An 8-byte toy digest: byte `i` of the output is the sum of the input bytes
/// at positions congruent to `i` modulo 8, plus `i`.
#[derive(Clone, Default)]
struct Lanes8 {
    sums: [u8; 8],
    count: usize,
}

impl fmt::Display for Lanes8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LANES-8")
    }
}

impl TryDigest for Lanes8 {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        8
    }

    fn byte_length(&self) -> usize {
        16
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Infallible> {
        for &byte in input {
            self.sums[self.count % 8] = self.sums[self.count % 8].wrapping_add(byte);
            self.count += 1;
        }
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Infallible> {
        for (i, (out, sum)) in output[..8].iter_mut().zip(self.sums).enumerate() {
            *out = sum.wrapping_add(i as u8);
        }
        *self = Self::default();
        Ok(8)
    }

    fn try_reset(&mut self) -> Result<(), Infallible> {
        *self = Self::default();
        Ok(())
    }
}

fn lanes8(input: &[u8]) -> [u8; 8] {
    let mut digest = Lanes8::default();
    digest.update(input);
    let mut out = [0; 8];
    digest.do_final(&mut out);
    out
}

#[test]
fn null_digest_writes_its_input_back_and_starts_over() {
    let mut null = NullDigest::new();
    assert_eq!(null.to_string(), "NULL");
    assert_eq!(null.byte_length(), 0);
    null.update(b"hello, ");
    null.update_byte(b'w');
    null.update(b"orld");
    assert_eq!(null.digest_size(), 12);

    let mut out = [0; 16];
    assert_eq!(null.do_final(&mut out), 12);
    assert_eq!(&out[..12], b"hello, world");
    assert_eq!(null.digest_size(), 0);
    assert_eq!(null.do_final(&mut []), 0);

    null.update(b"discarded");
    null.reset();
    assert_eq!(null.digest_size(), 0);
}

#[test]
fn null_digest_panics_on_a_short_buffer_and_keeps_its_input() {
    let mut null = NullDigest::new();
    null.update(b"abc");
    let result = catch_unwind(AssertUnwindSafe(|| null.do_final(&mut [0; 2])));
    assert!(result.is_err());
    let mut out = [0; 3];
    assert_eq!(null.do_final(&mut out), 3);
    assert_eq!(&out, b"abc");
}

#[test]
fn prehash_passes_one_digest_value_through() {
    let value = lanes8(b"message");
    let mut prehash = Prehash::for_digest(&Lanes8::default());
    assert_eq!(prehash.to_string(), "LANES-8");
    assert_eq!(prehash.digest_size(), 8);
    assert_eq!(prehash.byte_length(), 8);

    prehash.try_update(&value[..3]).unwrap();
    prehash.try_update(&value[3..]).unwrap();
    assert_eq!(prehash.len(), 8);
    let mut out = [0; 8];
    assert_eq!(prehash.try_do_final(&mut out), Ok(8));
    assert_eq!(out, value);
    assert!(prehash.is_empty());
}

#[test]
fn prehash_rejects_too_much_input_without_taking_any_of_it() {
    let mut prehash = Prehash::new("TEST", 4);
    prehash.try_update(&[1, 2]).unwrap();
    assert_eq!(
        prehash.try_update(&[3, 4, 5]),
        Err(PrehashError::InputTooLong {
            limit: 4,
            attempted: 5
        })
    );
    assert_eq!(prehash.len(), 2);
    prehash.try_update(&[3, 4]).unwrap();
    let mut out = [0; 4];
    assert_eq!(prehash.try_do_final(&mut out), Ok(4));
    assert_eq!(out, [1, 2, 3, 4]);
}

#[test]
fn prehash_finalized_at_the_wrong_length_fails_and_resets() {
    let mut prehash = Prehash::new("TEST", 4);
    prehash.try_update(&[1, 2]).unwrap();
    let mut out = [0; 4];
    assert_eq!(
        prehash.try_do_final(&mut out),
        Err(PrehashError::IncorrectLength {
            expected: 4,
            actual: 2
        })
    );
    assert!(prehash.is_empty());
    prehash.try_update(&[5, 6, 7, 8]).unwrap();
    assert_eq!(prehash.try_do_final(&mut out), Ok(4));
    assert_eq!(out, [5, 6, 7, 8]);
}

#[test]
fn prehash_panics_on_a_short_buffer_and_keeps_its_input() {
    let mut prehash = Prehash::new("TEST", 4);
    prehash.try_update(&[1, 2, 3, 4]).unwrap();
    let result = catch_unwind(AssertUnwindSafe(|| prehash.try_do_final(&mut [0; 3])));
    assert!(result.is_err());
    assert_eq!(prehash.len(), 4);
    let mut out = [0; 4];
    assert_eq!(prehash.try_do_final(&mut out), Ok(4));
    assert_eq!(out, [1, 2, 3, 4]);
}

#[test]
fn prehash_debug_shows_lengths_but_not_the_value() {
    let mut prehash = Prehash::new("TEST", 4);
    prehash.try_update(&[0xab, 0xcd]).unwrap();
    let debug = format!("{prehash:?}");
    assert!(debug.contains("digest_size: 4") && debug.contains("position: 2"));
    assert!(!debug.contains("171") && !debug.contains("205"));
}

#[test]
fn shortened_digest_is_the_prefix_of_its_base_and_named_after_it() {
    let mut short = ShortenedDigest::new(Lanes8::default(), 5);
    assert_eq!(short.to_string(), "LANES-8(40)");
    assert_eq!(short.digest_size(), 5);
    assert_eq!(short.byte_length(), 16);

    short.update(b"discarded");
    short.reset();
    for piece in b"a longer message".chunks(3) {
        short.update(piece);
    }
    let mut out = [0; 5];
    assert_eq!(short.do_final(&mut out), 5);
    assert_eq!(out, lanes8(b"a longer message")[..5]);
}

#[test]
fn shortened_digest_panics_on_a_short_buffer_and_keeps_the_base_state() {
    let mut short = ShortenedDigest::new(Lanes8::default(), 5);
    short.update(b"abc");
    let result = catch_unwind(AssertUnwindSafe(|| short.do_final(&mut [0; 4])));
    assert!(result.is_err());
    let mut out = [0; 5];
    short.do_final(&mut out);
    assert_eq!(out, lanes8(b"abc")[..5]);
}

#[test]
#[should_panic(expected = "length exceeds the base digest size")]
fn shortened_digest_rejects_a_length_over_the_base_size() {
    let _ = ShortenedDigest::new(Lanes8::default(), 9);
}

// The wipe itself cannot be observed without unsafe code; this guards that
// the adapters holding bytes run a destructor.
#[test]
fn the_adapters_holding_bytes_wipe_themselves_on_drop() {
    assert!(std::mem::needs_drop::<NullDigest>());
    assert!(std::mem::needs_drop::<Prehash>());
}
