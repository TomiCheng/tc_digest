#![cfg(feature = "haraka")]
//! Haraka-256/256 and Haraka-512/256: the examples of Appendix B of the
//! Haraka v2 paper (IACR ePrint 2016/098) and the Monte Carlo, offset-output
//! and error cases of Bouncy Castle's `Haraka256DigestTest` and
//! `Haraka512DigestTest`; the fixed-input contract, which stands in for the
//! shared digest contract because the error type is `HarakaError`; and the
//! accessors.
//!
//! These tests run on whichever path the CPU selects. A unit test inside the
//! crate checks the portable rounds against the same vectors and that the
//! AES-NI rounds agree with them.

mod common;

use std::fmt::Display;

use common::counting_message;
use tc_digest::TryDigest;
use tc_misc_digest::{Haraka256Digest, Haraka512Digest, HarakaError};

/// Everything the contract tests need from a Haraka digest.
trait Haraka: TryDigest<Error = HarakaError> + Clone + Display {}

impl<D: TryDigest<Error = HarakaError> + Clone + Display> Haraka for D {}

/// The 32-byte digest of the whole `input`, absorbed in one update.
fn digest_of<D: TryDigest<Error = HarakaError>>(digest: &mut D, input: &[u8]) -> [u8; 32] {
    digest.try_update(input).expect("the fixed input fits");
    let mut output = [0u8; 32];
    assert_eq!(digest.try_do_final(&mut output), Ok(32));
    output
}

/// The `N` bytes of `2 * N` hexadecimal digits.
fn from_hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), 2 * N);
    std::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
}

const APPENDIX_B_256: &str = "8027ccb87949774b78d0545fb72bf70c695c2a0923cbd47bba1159efbf2b2c1c";
const APPENDIX_B_512: &str = "be7f723b4e80a99813b292287f306f625a6d57331cae5f34dd9277b0945be2aa";

#[test]
fn haraka_256_matches_appendix_b_of_the_haraka_v2_paper() {
    assert_eq!(
        digest_of(&mut Haraka256Digest::new(), &counting_message(32)),
        from_hex(APPENDIX_B_256)
    );
}

#[test]
fn haraka_512_matches_appendix_b_of_the_haraka_v2_paper() {
    assert_eq!(
        digest_of(&mut Haraka512Digest::new(), &counting_message(64)),
        from_hex(APPENDIX_B_512)
    );
}

/// Bouncy Castle's `TestMonty`: 1000 digests, each of the previous digest.
#[test]
fn haraka_256_matches_the_bouncy_castle_monte_carlo_vectors() {
    for (start, expected) in [
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "e78599d7163ab58f1c90f0171c6fc4e852eb4b8cc29a4af63194fd9977c1de84",
        ),
        (
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "c4cebda63c00c4cd312f36ea92afd4b0f6048507c5b367326ef9d8fdd2d5c09a",
        ),
    ] {
        let mut digest = Haraka256Digest::new();
        let mut result: [u8; 32] = from_hex(start);
        for _ in 0..1000 {
            result = digest_of(&mut digest, &result);
        }
        assert_eq!(result, from_hex(expected));
    }
}

/// Bouncy Castle's `TestMonty`: 1000 digests, each copied over the lower half
/// of the 64-byte input after an odd step and over the upper half otherwise.
#[test]
fn haraka_512_matches_the_bouncy_castle_monte_carlo_vectors() {
    for (start, expected) in [
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\
             202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "ABE210FE673F3B28E70E5100C476D82F61A7E2BDB3D8423FB0A15E5DE3D3A4DE",
        ),
        (
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
             FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "5F5ECB52C61F5036C96BE555D2E18C520AB3ED093954700C283A322D14DBFE02",
        ),
    ] {
        let mut digest = Haraka512Digest::new();
        let mut input: [u8; 64] = from_hex(start);
        let mut result = [0u8; 32];
        for step in 0..1000 {
            result = digest_of(&mut digest, &input);
            let half = if step & 1 == 1 { 0 } else { 32 };
            input[half..half + 32].copy_from_slice(&result);
        }
        assert_eq!(result, from_hex(expected));
    }
}

/// Bouncy Castle's `TestOutput` writes the digest 4 bytes into a 36-byte
/// array; here the caller passes the array from that offset on.
#[test]
fn the_digest_lands_at_the_start_of_the_output_it_is_given() {
    for (mut digest, input, expected) in [
        (
            Box::new(Haraka256Digest::new()) as Box<dyn TryDigest<Error = HarakaError>>,
            counting_message(32),
            "000000008027ccb87949774b78d0545fb72bf70c695c2a0923cbd47bba1159efbf2b2c1c",
        ),
        (
            Box::new(Haraka512Digest::new()),
            counting_message(64),
            "00000000be7f723b4e80a99813b292287f306f625a6d57331cae5f34dd9277b0945be2aa",
        ),
    ] {
        digest.try_update(&input).unwrap();
        let mut output = [0u8; 36];
        assert_eq!(digest.try_do_final(&mut output[4..]), Ok(32));
        assert_eq!(output, from_hex::<36>(expected));
    }
}

/// Bouncy Castle's `TestInputTooLong` and the same overflow after partial and
/// complete inputs, each followed by finishing the original input.
fn check_overlong_updates_are_rejected<D: Haraka>(make: impl Fn() -> D) {
    let n = make().byte_length();
    let message = counting_message(n);
    let expected = digest_of(&mut make(), &message);
    let too_long = HarakaError::InputTooLong {
        limit: n,
        attempted: n + 1,
    };

    let mut digest = make();
    assert_eq!(digest.try_update(&counting_message(n + 1)), Err(too_long));
    assert_eq!(digest_of(&mut digest, &message), expected);

    let mut digest = make();
    digest.try_update(&message[..n - 1]).unwrap();
    assert_eq!(digest.try_update(&[0xaa, 0xbb]), Err(too_long));
    digest.try_update(&message[n - 1..]).unwrap();
    assert_eq!(digest.try_update_byte(0xaa), Err(too_long));
    assert_eq!(
        digest.try_update(&[0xaa; 7]),
        Err(HarakaError::InputTooLong {
            limit: n,
            attempted: n + 7,
        })
    );
    assert_eq!(digest.try_update(&[]), Ok(()));
    let mut output = [0u8; 32];
    assert_eq!(digest.try_do_final(&mut output), Ok(32));
    assert_eq!(output, expected, "{digest}");
}

#[test]
fn an_update_past_the_fixed_length_is_rejected_without_changing_state() {
    check_overlong_updates_are_rejected(Haraka256Digest::new);
    check_overlong_updates_are_rejected(Haraka512Digest::new);
}

/// Bouncy Castle's `TestInputTooShort` for every incomplete length, each
/// followed by finishing the input.
fn check_incomplete_inputs_are_rejected<D: Haraka>(make: impl Fn() -> D) {
    let n = make().byte_length();
    let message = counting_message(n);
    let expected = digest_of(&mut make(), &message);
    for len in 0..n {
        let mut digest = make();
        digest.try_update(&message[..len]).unwrap();
        let mut output = [0xee_u8; 32];
        assert_eq!(
            digest.try_do_final(&mut output),
            Err(HarakaError::IncorrectLength {
                expected: n,
                actual: len,
            })
        );
        assert_eq!(output, [0xee; 32], "{digest} wrote after {len} bytes");
        assert_eq!(digest_of(&mut digest, &message[len..]), expected);
    }
}

#[test]
fn finalizing_an_incomplete_input_is_rejected_without_changing_state() {
    check_incomplete_inputs_are_rejected(Haraka256Digest::new);
    check_incomplete_inputs_are_rejected(Haraka512Digest::new);
}

/// Bouncy Castle's `TestOutput` with a 31-byte buffer, and every other short
/// length, each followed by a successful finalization.
fn check_short_outputs_are_rejected<D: Haraka>(make: impl Fn() -> D) {
    let n = make().byte_length();
    let message = counting_message(n);
    let expected = digest_of(&mut make(), &message);
    let mut digest = make();
    digest.try_update(&message).unwrap();
    for len in 0..32 {
        let mut output = vec![0xee_u8; len];
        assert_eq!(
            digest.try_do_final(&mut output),
            Err(HarakaError::OutputTooShort {
                required: 32,
                actual: len,
            })
        );
        assert!(output.iter().all(|&b| b == 0xee), "{digest} wrote {len}");
    }
    let mut output = [0u8; 32];
    assert_eq!(digest.try_do_final(&mut output), Ok(32));
    assert_eq!(output, expected);
}

#[test]
fn a_short_output_buffer_is_rejected_without_changing_state() {
    check_short_outputs_are_rejected(Haraka256Digest::new);
    check_short_outputs_are_rejected(Haraka512Digest::new);
}

#[test]
fn an_incomplete_input_is_reported_before_a_short_output() {
    let mut digest = Haraka256Digest::new();
    digest.try_update(&[0; 31]).unwrap();
    assert_eq!(
        digest.try_do_final(&mut [0u8; 31]),
        Err(HarakaError::IncorrectLength {
            expected: 32,
            actual: 31,
        })
    );

    let mut digest = Haraka512Digest::new();
    digest.try_update(&[0; 63]).unwrap();
    assert_eq!(
        digest.try_do_final(&mut []),
        Err(HarakaError::IncorrectLength {
            expected: 64,
            actual: 63,
        })
    );
}

fn check_do_final_writes_32_bytes_and_resets<D: Haraka>(make: impl Fn() -> D) {
    let n = make().byte_length();
    let message = counting_message(n);
    let expected = digest_of(&mut make(), &message);
    let mut digest = make();

    digest.try_update(&message).unwrap();
    let mut output = [0xee_u8; 80];
    assert_eq!(digest.try_do_final(&mut output), Ok(digest.digest_size()));
    assert_eq!(output[..32], expected);
    assert!(output[32..].iter().all(|&b| b == 0xee));

    assert_eq!(
        digest.try_do_final(&mut output),
        Err(HarakaError::IncorrectLength {
            expected: n,
            actual: 0,
        }),
        "{digest} kept its input after do_final"
    );
    assert_eq!(digest_of(&mut digest, &message), expected);
}

#[test]
fn do_final_writes_32_bytes_and_resets() {
    check_do_final_writes_32_bytes_and_resets(Haraka256Digest::new);
    check_do_final_writes_32_bytes_and_resets(Haraka512Digest::new);
}

fn check_reset_discards_the_input<D: Haraka>(make: impl Fn() -> D) {
    let n = make().byte_length();
    let message = counting_message(n);
    let expected = digest_of(&mut make(), &message);
    for discarded in [1, n - 1, n] {
        let mut digest = make();
        digest.try_update(&vec![0x5a; discarded]).unwrap();
        assert_eq!(digest.try_reset(), Ok(()));
        assert_eq!(digest_of(&mut digest, &message), expected, "{digest}");
    }
}

#[test]
fn reset_discards_the_buffered_input() {
    check_reset_discards_the_input(Haraka256Digest::new);
    check_reset_discards_the_input(Haraka512Digest::new);
}

fn check_clones_continue_independently<D: Haraka>(make: impl Fn() -> D) {
    let n = make().byte_length();
    let first = counting_message(n);
    let second: Vec<u8> = first.iter().map(|b| !b).collect();

    let mut original = make();
    original.try_update(&first[..n / 2]).unwrap();
    let mut copy = original.clone();
    let mut copy_output = [0u8; 32];
    copy.try_update(&second[n / 2..]).unwrap();
    copy.try_do_final(&mut copy_output).unwrap();
    let mut original_output = [0u8; 32];
    original.try_update(&first[n / 2..]).unwrap();
    original.try_do_final(&mut original_output).unwrap();

    let mut spliced = first[..n / 2].to_vec();
    spliced.extend_from_slice(&second[n / 2..]);
    assert_eq!(copy_output, digest_of(&mut make(), &spliced));
    assert_eq!(original_output, digest_of(&mut make(), &first));
}

#[test]
fn clones_continue_independently() {
    check_clones_continue_independently(Haraka256Digest::new);
    check_clones_continue_independently(Haraka512Digest::new);
}

/// Every split into two and three updates, and byte-by-byte updates, give the
/// digest of the input absorbed at once.
fn check_splits<D: Haraka>(make: impl Fn() -> D) {
    let n = make().byte_length();
    let message = counting_message(n);
    let whole = digest_of(&mut make(), &message);

    for first in 0..=n {
        for second in first..=n {
            let mut digest = make();
            digest.try_update(&message[..first]).unwrap();
            digest.try_update(&message[first..second]).unwrap();
            assert_eq!(
                digest_of(&mut digest, &message[second..]),
                whole,
                "{digest} split at {first} and {second}"
            );
        }
    }

    let mut digest = make();
    for &byte in &message {
        digest.try_update_byte(byte).unwrap();
    }
    assert_eq!(digest_of(&mut digest, &[]), whole);
}

#[test]
fn splitting_the_input_across_updates_never_changes_the_digest() {
    check_splits(Haraka256Digest::new);
    check_splits(Haraka512Digest::new);
}

#[test]
fn the_errors_use_the_wording_of_bouncy_castle() {
    let cases = [
        (
            HarakaError::InputTooLong {
                limit: 32,
                attempted: 33,
            },
            "total input cannot be more than 32 bytes",
        ),
        (
            HarakaError::IncorrectLength {
                expected: 64,
                actual: 63,
            },
            "input must be exactly 64 bytes",
        ),
        (
            HarakaError::OutputTooShort {
                required: 32,
                actual: 31,
            },
            "output too short to receive digest",
        ),
    ];
    for (error, wording) in cases {
        let error: &dyn std::error::Error = &error;
        assert!(error.to_string().contains(wording), "{error}");
    }
}

#[test]
fn accessors_report_the_algorithm() {
    let digest = Haraka256Digest::new();
    assert_eq!(digest.to_string(), "Haraka-256");
    assert_eq!(digest.digest_size(), 32);
    assert_eq!(digest.byte_length(), 32);

    let digest = Haraka512Digest::new();
    assert_eq!(digest.to_string(), "Haraka-512");
    assert_eq!(digest.digest_size(), 32);
    assert_eq!(digest.byte_length(), 64);
}

#[test]
fn const_constructors_match_default() {
    const HARAKA_256: Haraka256Digest = Haraka256Digest::new();
    const HARAKA_512: Haraka512Digest = Haraka512Digest::new();

    let mut from_const = HARAKA_256;
    assert_eq!(
        digest_of(&mut from_const, &counting_message(32)),
        digest_of(&mut Haraka256Digest::default(), &counting_message(32))
    );
    let mut from_const = HARAKA_512;
    assert_eq!(
        digest_of(&mut from_const, &counting_message(64)),
        digest_of(&mut Haraka512Digest::default(), &counting_message(64))
    );
}

#[test]
fn the_digests_run_a_destructor() {
    // The wipe itself cannot be observed without unsafe code; this guards
    // against the destructor that performs it disappearing.
    assert!(std::mem::needs_drop::<Haraka256Digest>());
    assert!(std::mem::needs_drop::<Haraka512Digest>());
}
