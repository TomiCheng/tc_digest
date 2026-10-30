#![cfg(feature = "sparkle")]
//! ESCH-256 and ESCH-384 tests. The known answers are entries of Bouncy
//! Castle's `crypto/sparkle/LWC_HASH_KAT_256.txt` and `LWC_HASH_KAT_384.txt`,
//! the NIST lightweight cryptography KATs that `SparkleTest` reads, whose
//! message `Count = n + 1` is the `n` counting bytes `00 01 02 ...`: the
//! empty message, one byte, the lengths around one and two 16-byte blocks,
//! where a full last block takes the other domain constant, and the two
//! longest, 1023 and 1024 bytes.

mod common;

use common::{check_contract, counting_message, hex_digest};
use tc_digest::{Digest, TryDigest};
use tc_misc_digest::{SparkleDigest, SparkleParameters};

/// `(message length, digest)` pairs from `LWC_HASH_KAT_256.txt`.
const ESCH256_KAT: [(usize, &str); 10] = [
    (
        0,
        "c0e815d78b875dc768c6c8b3afa51987cd69e5c087d387368628a511cfad5730",
    ),
    (
        1,
        "d515fd9c2852d9d6f00c9cf01d858af467eedf21ff68cc14c005b3eff7a6ecd3",
    ),
    (
        15,
        "5753e34e3fc970881e1752b59c573e89448d08a93eae46da2a5d8ab04790a60c",
    ),
    (
        16,
        "acff841e2a526d83d6e94ab5564d6d64c98f5e8016bb1c2950386ed156c6c174",
    ),
    (
        17,
        "e6bf73941a7417fefd2dd5882ffcbfaea22b4c131ef155943fc817f61ad05b85",
    ),
    (
        31,
        "8f9fdd4c85aaf7775025300d8e60c1afe77524f51c5c7bd00b656d0fd07d26b1",
    ),
    (
        32,
        "78b905b2e2d4110b76ef8afd2495f58ad6ffd6b9727377f3e5dfceebf3031e24",
    ),
    (
        33,
        "dccfeadcdd16ab5859ee571a2a669edff5581e2093ba3b979b73a9d73d848b27",
    ),
    (
        1023,
        "966789b66e108391d521cd63bbc5129b745c0149a4cfa6017a3e6264a661196b",
    ),
    (
        1024,
        "2efd300525b3a4fe87933334e2c87affefb65b4f59bd72c2af3f7a69740d0d15",
    ),
];

/// `(message length, digest)` pairs from `LWC_HASH_KAT_384.txt`.
const ESCH384_KAT: [(usize, &str); 10] = [
    (
        0,
        "2981715e2263ebd0cb6e5c2c99d0776d5e691ee737fde05247895e75d02e7447fd6ab707e2ec8385a539777965e472ee",
    ),
    (
        1,
        "ca78366c86e82726c19ebd1dbbb1375cef93c570f856ce2ff5da0ca87140dacd65f3e1c5af5f84b3f6390b9ac1a2fa4d",
    ),
    (
        15,
        "c61174073ae9e1dff4698369fedb8ed785f4873eb0cbdc16ff0a23d2e7a985a165ec76daee03b9d14c91ac316a5b6c0f",
    ),
    (
        16,
        "0008f97d6bbb701d5e33fcc178efe3e3d5e77915d4a4daf6e1ae34cd28edb895a053e19d930b50f72837e1a8f5b1f450",
    ),
    (
        17,
        "4d5607783a26b83fd478c8eac31634dd3641adb61c6df964d6935e716d6826397c01aaec57f584e6fb293ec26b547ce8",
    ),
    (
        31,
        "a3b8f52af30ca05bbf9acda603278a05e369ad0670948137273be67019407a57e036098aa0070c7ea74d8cb2aa9b3c1e",
    ),
    (
        32,
        "55ba6e68b5ef92458c75e4888b25b31dc6212933b138c9623217af9aaff2a4691b81331de422387d12f170ef088e0ea1",
    ),
    (
        33,
        "ec526f22147a290b6fadcdbc74ea9c2205d68c86b8616e7da10179cd177670c5bac2b60828147649852fdeece04e2a6b",
    ),
    (
        1023,
        "ef172555d4606a35929c8add02db3fed0085151b048975e9b3e00422412f46d205197e7cdbb3a675b9c7fe7efdaf1134",
    ),
    (
        1024,
        "167488df37dd406c729328a451d79dca2ae1fa1fff03888c2ad86db507a92e46769cb07c7d31a18ecbf5a0b3e3f1f678",
    ),
];

const VARIANTS: [(SparkleParameters, &[(usize, &str)]); 2] = [
    (SparkleParameters::Esch256, &ESCH256_KAT),
    (SparkleParameters::Esch384, &ESCH384_KAT),
];

#[test]
fn esch_matches_the_lwc_kat_entries_bouncy_castle_tests() {
    for (parameters, kat) in VARIANTS {
        for &(len, expected) in kat {
            let mut digest = SparkleDigest::new(parameters);
            assert_eq!(
                hex_digest(&mut digest, &counting_message(len)),
                expected,
                "{digest} of {len} counting bytes"
            );
        }
    }
}

#[test]
fn one_digest_fed_in_seven_byte_pieces_matches_every_kat_entry_in_turn() {
    for (parameters, kat) in VARIANTS {
        let mut digest = SparkleDigest::new(parameters);
        for &(len, expected) in kat {
            for piece in counting_message(len).chunks(7) {
                digest.update(piece);
            }
            assert_eq!(
                hex_digest(&mut digest, b""),
                expected,
                "{digest} of {len} counting bytes in pieces"
            );
        }
    }
}

#[test]
fn both_variants_keep_the_digest_contract() {
    check_contract(|| SparkleDigest::new(SparkleParameters::Esch256));
    check_contract(|| SparkleDigest::new(SparkleParameters::Esch384));
}

#[test]
fn accessors_report_the_algorithm_of_each_variant() {
    let esch256 = SparkleDigest::new(SparkleParameters::Esch256);
    assert_eq!(esch256.to_string(), "ESCH-256");
    assert_eq!(esch256.digest_size(), 32);
    assert_eq!(esch256.byte_length(), 16);

    let esch384 = SparkleDigest::new(SparkleParameters::Esch384);
    assert_eq!(esch384.to_string(), "ESCH-384");
    assert_eq!(esch384.digest_size(), 48);
    assert_eq!(esch384.byte_length(), 16);
}

#[test]
fn reset_keeps_the_selected_variant() {
    let mut digest = SparkleDigest::new(SparkleParameters::Esch384);
    digest.update(b"discarded");
    digest.reset();
    assert_eq!(digest.digest_size(), 48);
    assert_eq!(hex_digest(&mut digest, b""), ESCH384_KAT[0].1);
}

#[test]
fn const_constructor_matches_the_runtime_constructor() {
    const ESCH256: SparkleDigest = SparkleDigest::new(SparkleParameters::Esch256);
    const ESCH384: SparkleDigest = SparkleDigest::new(SparkleParameters::Esch384);
    for (from_const, parameters) in [
        (ESCH256, SparkleParameters::Esch256),
        (ESCH384, SparkleParameters::Esch384),
    ] {
        let mut from_const = from_const;
        assert_eq!(
            hex_digest(&mut from_const, b"abc"),
            hex_digest(&mut SparkleDigest::new(parameters), b"abc")
        );
    }
}

#[test]
fn the_digest_runs_a_destructor() {
    // The wipe itself cannot be observed without unsafe code; this guards
    // against the destructor that performs it disappearing.
    assert!(std::mem::needs_drop::<SparkleDigest>());
}
