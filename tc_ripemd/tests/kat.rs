//! Known-answer tests: the test suite of the RIPEMD authors, which Bouncy
//! Castle's `RipeMD*DigestTest` carry, with one million `'a'` bytes, and
//! messages on the padding boundaries, whose expected digests Bouncy Castle
//! computed and, for RIPEMD-160, OpenSSL confirmed.

mod common;

use common::{NamedDigest, counting_message, hex_digest};
use tc_ripemd::{RipeMd128Digest, RipeMd160Digest, RipeMd256Digest, RipeMd320Digest};

/// The eight messages of the RIPEMD test suite.
const MESSAGES: [&[u8]; 8] = [
    b"",
    b"a",
    b"abc",
    b"message digest",
    b"abcdefghijklmnopqrstuvwxyz",
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
];

fn check_suite<D: NamedDigest>(make: impl Fn() -> D, expected: [&str; 8]) {
    for (message, expected) in MESSAGES.into_iter().zip(expected) {
        let mut digest = make();
        assert_eq!(
            hex_digest(&mut digest, message),
            expected,
            "{digest} of {:?}",
            String::from_utf8_lossy(message)
        );
    }
}

fn check_million_a<D: NamedDigest>(mut digest: D, expected: &str) {
    for _ in 0..1000 {
        digest.update(&[b'a'; 1000]);
    }
    assert_eq!(hex_digest(&mut digest, b""), expected, "{digest}");
}

/// Hashes the messages `0, 1, 2, ...` on the padding boundaries of 64-byte
/// blocks: the length field just fits (55, 111), just spills into another
/// block (56, 112), or the message fills whole blocks (64, 128).
fn check_boundaries<D: NamedDigest>(make: impl Fn() -> D, expected: [(usize, &str); 6]) {
    for (len, expected) in expected {
        let mut digest = make();
        assert_eq!(
            hex_digest(&mut digest, &counting_message(len)),
            expected,
            "{digest} of a {len}-byte message"
        );
    }
}

#[test]
fn ripemd128_matches_the_test_suite() {
    check_suite(
        RipeMd128Digest::new,
        [
            "cdf26213a150dc3ecb610f18f6b38b46",
            "86be7afa339d0fc7cfc785e72f578d33",
            "c14a12199c66e4ba84636b0f69144c77",
            "9e327b3d6e523062afc1132d7df9d1b8",
            "fd2aa607f71dc8f510714922b371834e",
            "a1aa0689d0fafa2ddc22e88b49133a06",
            "d1e959eb179c911faea4624c60c5c702",
            "3f45ef194732c2dbb2c4a2c769795fa3",
        ],
    );
}

#[test]
fn ripemd128_matches_the_million_a_vector() {
    check_million_a(RipeMd128Digest::new(), "4a7f5723f954eba1216c9d8f6320431f");
}

#[test]
fn ripemd128_matches_bouncy_castle_on_padding_boundaries() {
    check_boundaries(
        RipeMd128Digest::new,
        [
            (55, "37cec696967031ab2122155998a07f51"),
            (56, "320b7d4de17a731b9ba5cbb48956d605"),
            (64, "406c6ec2643ccef38f964864d12c9191"),
            (111, "2b5ae5d14dc053558a1702959367760b"),
            (112, "7a6a3a6553b2c3387bebe119e80cfb2b"),
            (128, "fbe1ac0eecf0aa2671a6f25733e9711b"),
        ],
    );
}

#[test]
fn ripemd160_matches_the_test_suite() {
    check_suite(
        RipeMd160Digest::new,
        [
            "9c1185a5c5e9fc54612808977ee8f548b2258d31",
            "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
            "5d0689ef49d2fae572b881b123a85ffa21595f36",
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
            "b0e20b6e3116640286ed3a87a5713079b21f5189",
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
        ],
    );
}

#[test]
fn ripemd160_matches_the_million_a_vector() {
    check_million_a(
        RipeMd160Digest::new(),
        "52783243c1697bdbe16d37f97f68f08325dc1528",
    );
}

#[test]
fn ripemd160_matches_bouncy_castle_and_openssl_on_padding_boundaries() {
    check_boundaries(
        RipeMd160Digest::new,
        [
            (55, "3c86963b3ff646a65ae42996e9664c747cc7e5e6"),
            (56, "ebdd79cfd4fd9949ef8089673d2620427f487cfb"),
            (64, "2581f5e9f957b44b0fa24d31996de47409dd1e0f"),
            (111, "9f72db053bc5370c786e34013fb8da5958000d5a"),
            (112, "c1bfa4009bfeaa30ada4d940fc40f97ffea3fc39"),
            (128, "7c4d36070c1e1176b2960a1b0dd2319d547cf8eb"),
        ],
    );
}

#[test]
fn ripemd256_matches_the_test_suite() {
    check_suite(
        RipeMd256Digest::new,
        [
            "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
            "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925",
            "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
            "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e",
            "649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133",
            "3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f",
            "5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8",
            "06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd",
        ],
    );
}

#[test]
fn ripemd256_matches_the_million_a_vector() {
    check_million_a(
        RipeMd256Digest::new(),
        "ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978",
    );
}

#[test]
fn ripemd256_matches_bouncy_castle_on_padding_boundaries() {
    check_boundaries(
        RipeMd256Digest::new,
        [
            (
                55,
                "a7e0d9bfb62fb1e4a88f127f0664ce655b363df17910783643a5f790eba43f1b",
            ),
            (
                56,
                "f961dba8c62fa522b19fb6a376d2e2d3071e8c71e899708e4763879a369a1186",
            ),
            (
                64,
                "f4fff1bbd2086bbe13a46a8f281cbcc725d882bb783a8b2fbade2ec969d4343d",
            ),
            (
                111,
                "e625994e6abecace3d83e27e2979bcf696c3bdd761a7eaf33754eb9023a7113a",
            ),
            (
                112,
                "7ab2db3a9f6448fe0e4f2cf9bb5ce8cdeef9ee52cb6a471286b6f89eb155c3bb",
            ),
            (
                128,
                "cdbb22e28ae05a82ca0e4aea774df5932443ce9a4c76d05b5171ff9fe4092fb1",
            ),
        ],
    );
}

#[test]
fn ripemd320_matches_the_test_suite() {
    check_suite(
        RipeMd320Digest::new,
        [
            "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8",
            "ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d",
            "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d",
            "3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197",
            "cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009",
            "d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac",
            "ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4",
            "557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42",
        ],
    );
}

#[test]
fn ripemd320_matches_the_million_a_vector() {
    check_million_a(
        RipeMd320Digest::new(),
        "bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66",
    );
}

#[test]
fn ripemd320_matches_bouncy_castle_on_padding_boundaries() {
    check_boundaries(
        RipeMd320Digest::new,
        [
            (
                55,
                "d5383387f99fef6732967302f2aff4b8f694b43235768e151bfda508d6170133ee44c4d1bf19d1ff",
            ),
            (
                56,
                "a092a11fb22676778c6720ba1539b3ef72f7e25b1e75aad307ce3d1a1fbc9962d95d1b6e8bd19148",
            ),
            (
                64,
                "8da29de9049df2855cf8f26594c03275b9a216cca012a8245818bb63b0ee6e4ab2dc069b393270cf",
            ),
            (
                111,
                "90278c79cf7129ec87620c6a1e1ceff81361b9ff7234f1202c3cf9903e3842a09a511e27639bf037",
            ),
            (
                112,
                "a67689a579055f4baec45289f5f7c2a8236196f241a84ef721a2b8fe3f7aabed17a50754a3791813",
            ),
            (
                128,
                "05e40364d0466b7c46755eb198f02bff8f4f1d584afc27b900654a528454cf692e2792cbab60cf8d",
            ),
        ],
    );
}
