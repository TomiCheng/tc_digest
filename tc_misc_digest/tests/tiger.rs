#![cfg(feature = "tiger")]
//! Tiger tests: every vector of Bouncy Castle's `TigerDigestTest`, including
//! 64 KiB of counting bytes, and a million `'a'` bytes and messages on the
//! padding boundaries with expected digests computed by Bouncy Castle, since
//! OpenSSL has no Tiger; then the API contract every digest shares.

mod common;

use common::{check_contract, counting_message, hex_digest};
use tc_digest::{Digest, TryDigest};
use tc_misc_digest::TigerDigest;

#[test]
fn tiger_matches_bouncy_castle_on_its_test_vectors() {
    for (message, expected) in [
        (&b""[..], "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"),
        (b"abc", "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93"),
        (b"Tiger", "dd00230799f5009fec6debc838bb6a27df2b9d6f110c7937"),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
            "f71c8583902afb879edfe610f82c0d4786a3a534504486b5",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvw",
            "38f41d9d9a710a10c3727ac0deeaa270727d9f926ec10139",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789",
            "48ceeb6308b87d46e95d656112cdf18d97915f9765658957",
        ),
        (
            b"Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, \
              proceedings of Fast Software Encryption 3, Cambridge, 1996.",
            "631abdd103eb9a3d245b6dfd4d77b257fc7439501d1568dd",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-\
              ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
            "c54034e5b43eb8005848a7e0ae6aac76e4ff590ae715fd25",
        ),
    ] {
        assert_eq!(hex_digest(&mut TigerDigest::new(), message), expected);
    }
}

#[test]
fn tiger_matches_bouncy_castle_on_64_kib_of_counting_bytes() {
    assert_eq!(
        hex_digest(&mut TigerDigest::new(), &counting_message(65_536)),
        "fdf4f5b35139f48e710e421be5af411de1a8aac333f26204"
    );
}

#[test]
fn tiger_matches_bouncy_castle_on_a_million_a_bytes() {
    let mut digest = TigerDigest::new();
    for _ in 0..1000 {
        digest.update(&[b'a'; 1000]);
    }
    assert_eq!(
        hex_digest(&mut digest, b""),
        "6db0e2729cbead93d715c6a7d36302e9b3cee0d2bc314b41"
    );
}

/// Hashes the messages `0, 1, 2, ...` on the padding boundaries of 64-byte
/// blocks: the length field just fits (55, 111), just spills into another
/// block (56, 112), or the message fills whole blocks (64, 128).
#[test]
fn tiger_matches_bouncy_castle_on_padding_boundaries() {
    for (len, expected) in [
        (55, "2d48ee2bf85de234754becf3c6f5b0e62988b5bf24aea5bb"),
        (56, "0d17702ddca078ed1cc51b95df29ea1053ce97f69395c613"),
        (64, "212df89c57155270344accb19027b0b26b104fa0fbbe0fe4"),
        (111, "2b0fb04f100be9ad51b7d64c76651bab4b7d31d1d9195711"),
        (112, "b6495b6256ff464ec409a4098b622e8bdbb1003411854fd7"),
        (128, "34fa7c74ee67c1f92c0be1cfd4b2f46a14ffb999604925f6"),
    ] {
        assert_eq!(
            hex_digest(&mut TigerDigest::new(), &counting_message(len)),
            expected,
            "Tiger of a {len}-byte message"
        );
    }
}

#[test]
fn tiger_keeps_the_digest_contract() {
    check_contract(TigerDigest::new);
}

#[test]
fn accessors_report_the_algorithm() {
    let digest = TigerDigest::new();
    assert_eq!(digest.to_string(), "Tiger");
    assert_eq!(digest.digest_size(), 24);
    assert_eq!(digest.byte_length(), 64);
}

#[test]
fn const_constructor_matches_default() {
    const TIGER: TigerDigest = TigerDigest::new();
    let mut from_const = TIGER;
    assert_eq!(
        hex_digest(&mut from_const, b"abc"),
        hex_digest(&mut TigerDigest::default(), b"abc")
    );
}

#[test]
fn the_digest_runs_a_destructor() {
    // The wipe itself cannot be observed without unsafe code; this guards
    // against the destructor that performs it disappearing.
    assert!(std::mem::needs_drop::<TigerDigest>());
}
