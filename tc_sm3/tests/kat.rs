//! Known-answer tests: the two examples of GB/T 32905-2016 and the further
//! vectors of Bouncy Castle's `SM3DigestTest`, including 64 KiB of counting
//! bytes and a million `'a'` bytes, and messages on the padding boundaries
//! with expected digests computed by OpenSSL.

mod common;

use common::{counting_message, hex_digest};
use tc_digest::Digest;
use tc_sm3::Sm3Digest;

#[test]
fn sm3_matches_the_gb_t_32905_examples() {
    assert_eq!(
        hex_digest(&mut Sm3Digest::new(), b"abc"),
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    );
    assert_eq!(
        hex_digest(
            &mut Sm3Digest::new(),
            b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
        ),
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
    );
}

#[test]
fn sm3_matches_bouncy_castle_on_its_non_standard_vectors() {
    for (message, expected) in [
        (
            &b""[..],
            "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
        ),
        (
            b"a",
            "623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88",
        ),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595",
        ),
    ] {
        assert_eq!(hex_digest(&mut Sm3Digest::new(), message), expected);
    }
}

#[test]
fn sm3_matches_bouncy_castle_on_64_kib_of_counting_bytes() {
    assert_eq!(
        hex_digest(&mut Sm3Digest::new(), &counting_message(65_536)),
        "97049bdc8f0736bc7300eafa9980aeb9cf00f24f7ec3a8f1f8884954d7655c1d"
    );
}

#[test]
fn sm3_matches_bouncy_castle_on_a_million_a_bytes() {
    let mut digest = Sm3Digest::new();
    for _ in 0..1000 {
        digest.update(&[b'a'; 1000]);
    }
    assert_eq!(
        hex_digest(&mut digest, b""),
        "c8aaf89429554029e231941a2acc0ad61ff2a5acd8fadd25847a3a732b3b02c3"
    );
}

/// Hashes the messages `0, 1, 2, ...` on the padding boundaries of 64-byte
/// blocks: the length field just fits (55, 111), just spills into another
/// block (56, 112), or the message fills whole blocks (64, 128).
#[test]
fn sm3_matches_openssl_on_padding_boundaries() {
    for (len, expected) in [
        (
            55,
            "a79cf9dcee3404abf7f769698201647fd9d3ff61d629d0f58bb4b5579a427db8",
        ),
        (
            56,
            "62f7363b15f4de76dd925c493b9d6d00d4ba0ef2a1f334c1d0f13b293aeb40d1",
        ),
        (
            64,
            "93566f236d157aae078d1ddb5cebdbba1520b5142e22a8915564345ba2ae1d63",
        ),
        (
            111,
            "46ea8ff040518238fb6e34b688209bdcd18b31672c4ba28271045f8c8c312733",
        ),
        (
            112,
            "1c7b0125f4f56aa3e7104b10b25ce1c98e7668720f9a9e2eb21b6de36bbc62e7",
        ),
        (
            128,
            "a9e7985473ca09df1510d83b572f72375430756c4a661b00724afeb8b75dd0a5",
        ),
    ] {
        assert_eq!(
            hex_digest(&mut Sm3Digest::new(), &counting_message(len)),
            expected,
            "SM3 of a {len}-byte message"
        );
    }
}
