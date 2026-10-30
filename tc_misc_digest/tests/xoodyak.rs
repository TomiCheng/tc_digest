#![cfg(feature = "xoodyak")]
//! Xoodyak Hash tests. The known answers are entries of Bouncy Castle's
//! `crypto/xoodyak/LWC_HASH_KAT_256.txt`, the NIST lightweight cryptography
//! KAT that `XoodyakTest` reads, whose message `Count = n + 1` is the `n`
//! counting bytes `00 01 02 ...`: the empty message, one byte, the lengths
//! around one and two 16-byte blocks, and the two longest, 1023 and 1024
//! bytes.

mod common;

use common::{check_contract, counting_message, hex_digest};
use tc_digest::{Digest, TryDigest};
use tc_misc_digest::XoodyakDigest;

/// `(message length, digest)` pairs from `LWC_HASH_KAT_256.txt`.
const KAT: [(usize, &str); 10] = [
    (
        0,
        "ea152f2b47bce24efb66c479d4adf17bd324d806e85ff75ee369ee50dc8f8bd1",
    ),
    (
        1,
        "27921f8ddf392894460b70b3ed6c091e6421b7d2147dcd6031d7efebad3030cc",
    ),
    (
        15,
        "db4c9cfe9d385d8ca329e27aeb495a0816c1ab051a57c231a134082661d71bed",
    ),
    (
        16,
        "9ea695347cdddff9bc63ece30fe231441d581768fe223dd6bd7367094fd216b3",
    ),
    (
        17,
        "20593b39bb6d595019331601244411323f713085bb1a30218c972b96d9b7b7b3",
    ),
    (
        31,
        "b91e0c762169748d4e2b8d4972b63a4866caad1b5ebfb7f37deadeb4424df768",
    ),
    (
        32,
        "cebe4aff9eac2218017dda5f8207ba830e989187256539bd7d31ae5e94ff0c6e",
    ),
    (
        33,
        "249cfccd50d66e722e80e79002ce3b302b4ca067483ab9cdeb474dbf555b7633",
    ),
    (
        1023,
        "e9ebb4e428c6d7d7e161f5fd2b85543b648fa5f9b85897e3ba8c52a98d652e08",
    ),
    (
        1024,
        "fcc4d63932d98c30cab597e60b7cca475bd9fbf984838c5cb5615c949f814615",
    ),
];

#[test]
fn xoodyak_matches_the_lwc_kat_entries_bouncy_castle_tests() {
    for (len, expected) in KAT {
        assert_eq!(
            hex_digest(&mut XoodyakDigest::new(), &counting_message(len)),
            expected,
            "Xoodyak Hash of {len} counting bytes"
        );
    }
}

#[test]
fn one_digest_fed_in_seven_byte_pieces_matches_every_kat_entry_in_turn() {
    let mut digest = XoodyakDigest::new();
    for (len, expected) in KAT {
        for piece in counting_message(len).chunks(7) {
            digest.update(piece);
        }
        assert_eq!(
            hex_digest(&mut digest, b""),
            expected,
            "Xoodyak Hash of {len} counting bytes in pieces"
        );
    }
}

#[test]
fn xoodyak_keeps_the_digest_contract() {
    check_contract(XoodyakDigest::new);
}

#[test]
fn accessors_report_the_algorithm() {
    let digest = XoodyakDigest::new();
    assert_eq!(digest.to_string(), "Xoodyak Hash");
    assert_eq!(digest.digest_size(), 32);
    assert_eq!(digest.byte_length(), 16);
}

#[test]
fn const_constructor_matches_default() {
    const XOODYAK: XoodyakDigest = XoodyakDigest::new();
    let mut from_const = XOODYAK;
    assert_eq!(
        hex_digest(&mut from_const, b"abc"),
        hex_digest(&mut XoodyakDigest::default(), b"abc")
    );
}

#[test]
fn the_digest_runs_a_destructor() {
    // The wipe itself cannot be observed without unsafe code; this guards
    // against the destructor that performs it disappearing.
    assert!(std::mem::needs_drop::<XoodyakDigest>());
}
