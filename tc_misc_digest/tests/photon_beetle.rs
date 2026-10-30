#![cfg(feature = "photon-beetle")]
//! PHOTON-Beetle-Hash tests. The known answers are entries of Bouncy Castle's
//! `crypto/photonbeetle/LWC_HASH_KAT_256.txt`, the NIST lightweight
//! cryptography KAT that `PhotonBeetleTest` reads, whose message
//! `Count = n + 1` is the `n` counting bytes `00 01 02 ...`: the empty
//! message, a partial first block (1, 15), the first block alone (16), a
//! partial or whole 4-byte rate after it (17, 19, 20, 21, 31), a second
//! 16-byte block (32, 33, 36), and the two longest, 1023 and 1024 bytes.

mod common;

use common::{check_contract, counting_message, hex_digest};
use tc_digest::{Digest, TryDigest};
use tc_misc_digest::PhotonBeetleDigest;

/// `(message length, digest)` pairs from `LWC_HASH_KAT_256.txt`.
const KAT: [(usize, &str); 14] = [
    (
        0,
        "44a99882fea033566856a27e7f0c94dc84fac7e411b08b890a4a574e3db75d4a",
    ),
    (
        1,
        "f165ccd18640b9703e96f1bd9a4a4ee32dd4031e4680a1b9890891dcc63468a7",
    ),
    (
        15,
        "b26e2947b1ebf3d8d6116716cd89f7ee18683feb11cb6bf81f29c7364a1207ba",
    ),
    (
        16,
        "ab0d1eb0315df8af7f7ae0ac42eaf2f52fb0fdf0904e182dcc796b6cb8d7981a",
    ),
    (
        17,
        "5a281ad7eb81fb083d05ccd21b78c4bca938af26f20869da29c8f13b7389bc5f",
    ),
    (
        19,
        "441dd532063b8dda4f053eb4f37583120def0f2e62edbb900b9afc2564a01615",
    ),
    (
        20,
        "e6470f7fb66345b3db97774832ab07f26dd836b6cd3b28afa74f67404368f54f",
    ),
    (
        21,
        "a518eef8c72d9d1da6bee187716a9bbf1daff28eaab6b5e89f071259c219f4cf",
    ),
    (
        31,
        "eb955043643b385d88721af08baa6caac4b61870e6a30b2572ee4102e2a9973a",
    ),
    (
        32,
        "73609f6a67b96085829dfe8a3fe3ebc767f48a493640dd97461957ad995239e5",
    ),
    (
        33,
        "68a6c4b6a99849c6b0586d5f6fa1aaf9a39a0985936cb7ab74f130258f62ca4f",
    ),
    (
        36,
        "9164597b0fd4b6afdcf7450e5dcd1af3601d1936e7acc5af955632dbb1e1b52b",
    ),
    (
        1023,
        "bffec95dad96c38f7fded7908584055784a0239d5bf7991320539a350310c8eb",
    ),
    (
        1024,
        "f03a08651510da78d15de3f95c94e226af7a1fc11d77682b0b002c482bc410a9",
    ),
];

#[test]
fn photon_beetle_matches_the_lwc_kat_entries_bouncy_castle_tests() {
    for (len, expected) in KAT {
        assert_eq!(
            hex_digest(&mut PhotonBeetleDigest::new(), &counting_message(len)),
            expected,
            "PHOTON-Beetle-Hash of {len} counting bytes"
        );
    }
}

#[test]
fn one_digest_fed_in_seven_byte_pieces_matches_every_kat_entry_in_turn() {
    let mut digest = PhotonBeetleDigest::new();
    for (len, expected) in KAT {
        for piece in counting_message(len).chunks(7) {
            digest.update(piece);
        }
        assert_eq!(
            hex_digest(&mut digest, b""),
            expected,
            "PHOTON-Beetle-Hash of {len} counting bytes in pieces"
        );
    }
}

#[test]
fn photon_beetle_keeps_the_digest_contract() {
    check_contract(PhotonBeetleDigest::new);
}

/// The contract splits around the 4-byte `byte_length`, which stays inside
/// the first 16-byte block; this splits every message up to three buffers
/// and one byte at every point instead.
#[test]
fn splitting_across_the_16_byte_buffer_never_changes_the_digest() {
    for len in 0..=49 {
        let message = counting_message(len);
        let whole = hex_digest(&mut PhotonBeetleDigest::new(), &message);
        for split in 0..=len {
            let mut digest = PhotonBeetleDigest::new();
            digest.update(&message[..split]);
            assert_eq!(
                hex_digest(&mut digest, &message[split..]),
                whole,
                "{len} bytes split at {split}"
            );
        }
    }
}

#[test]
fn accessors_report_the_algorithm() {
    let digest = PhotonBeetleDigest::new();
    assert_eq!(digest.to_string(), "Photon-Beetle Hash");
    assert_eq!(digest.digest_size(), 32);
    assert_eq!(digest.byte_length(), 4);
}

#[test]
fn const_constructor_matches_default() {
    const PHOTON_BEETLE: PhotonBeetleDigest = PhotonBeetleDigest::new();
    let mut from_const = PHOTON_BEETLE;
    assert_eq!(
        hex_digest(&mut from_const, b"abc"),
        hex_digest(&mut PhotonBeetleDigest::default(), b"abc")
    );
}

#[test]
fn the_digest_runs_a_destructor() {
    // The wipe itself cannot be observed without unsafe code; this guards
    // against the destructor that performs it disappearing.
    assert!(std::mem::needs_drop::<PhotonBeetleDigest>());
}
