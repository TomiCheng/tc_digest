//! Known-answer tests: GOST R 34.11-94 with Bouncy Castle's
//! `GOST3411DigestTest` vectors for the CryptoPro and test S-boxes, two of
//! which RFC 5831 section 7.3 prints, and Streebog with the examples of
//! RFC 6986 section 10.

mod common;

use common::hex_digest;
use tc_digest::Digest;
use tc_gost3411::{Gost3411_2012_256Digest, Gost3411_2012_512Digest, Gost3411Digest};
use tc_gost28147::s_box;

/// The messages of Bouncy Castle's `GOST3411DigestTest`.
const MESSAGES: [&str; 4] = [
    "",
    "This is message, length=32 bytes",
    "Suppose the original message has length = 50 bytes",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
];

/// Decodes a value printed in an RFC, where the most significant byte comes
/// first, into the byte order the digests read and write: reversed.
fn rfc_bytes(printed: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = printed
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    bytes.reverse();
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn gost3411_94_matches_bouncy_castle_with_the_cryptopro_s_box() {
    let expected = [
        "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0",
        "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb",
        "c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011",
        "73b70a39497de53a6e08c67b6d4db853540f03e9389299d9b0156ef7e85d0f61",
    ];
    for (message, expected) in MESSAGES.into_iter().zip(expected) {
        assert_eq!(
            hex_digest(&mut Gost3411Digest::new(), message.as_bytes()),
            expected,
            "{message:?}"
        );
    }
}

#[test]
fn gost3411_94_matches_bouncy_castle_and_rfc_5831_with_the_test_s_box() {
    // Bouncy Castle lists these under "S-box = D-Test"; RFC 5831 section 7.3
    // prints the second and third, as the numbers checked below.
    let expected = [
        "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d",
        "b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa",
        "471aba57a60a770d3a76130635c1fbea4ef14de51f78b4ae57dd893b62f55208",
        "95c1af627c356496d80274330b2cff6a10c67b5f597087202f94d06d2338cf8e",
    ];
    for (message, expected) in MESSAGES.into_iter().zip(expected) {
        assert_eq!(
            hex_digest(
                &mut Gost3411Digest::with_s_box(s_box::D_TEST),
                message.as_bytes()
            ),
            expected,
            "{message:?}"
        );
    }

    for (message, printed) in [
        (
            MESSAGES[1],
            "FAFF37A615A816691CFF3EF8B68CA247E09525F39F8119832EB81975D366C4B1",
        ),
        (
            MESSAGES[2],
            "0852F5623B89DD57AEB4781FE54DF14EEAFBC1350613763A0D770AA657BA1A47",
        ),
    ] {
        assert_eq!(
            hex_digest(
                &mut Gost3411Digest::with_s_box(s_box::D_TEST),
                message.as_bytes()
            ),
            hex(&rfc_bytes(printed))
        );
    }
}

#[test]
fn gost3411_94_matches_bouncy_castle_on_a_million_a_bytes() {
    let mut digest = Gost3411Digest::new();
    for _ in 0..1000 {
        digest.update(&[b'a'; 1000]);
    }
    assert_eq!(
        hex_digest(&mut digest, b""),
        "8693287aa62f9478f7cb312ec0866b6c4e4a0f11160441e8f4ffcd2715dd554f"
    );
}

/// RFC 6986 section 10.1, M1: the 63 ASCII digits `"0123...012"`.
const RFC_6986_M1: &str = concat!(
    "32313039383736353433323130393837",
    "36353433323130393837363534333231",
    "30393837363534333231303938373635",
    "343332313039383736353433323130",
);

/// RFC 6986 section 10.2, M2.
const RFC_6986_M2: &str = concat!(
    "fbe2e5f0eee3c820fbeafaebef20fffb",
    "f0e1e0f0f520e0ed20e8ece0ebe5f0f2",
    "f120fff0eeec20f120faf2fee5e2202c",
    "e8f6f3ede220e8e6eee1e8f0f2d1202c",
    "e8f0f2e5e220e5d1",
);

#[test]
fn streebog_512_matches_the_rfc_6986_examples() {
    for (message, printed) in [
        (
            RFC_6986_M1,
            concat!(
                "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00",
                "fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b",
            ),
        ),
        (
            RFC_6986_M2,
            concat!(
                "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f03",
                "7613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e",
            ),
        ),
    ] {
        assert_eq!(
            hex_digest(&mut Gost3411_2012_512Digest::new(), &rfc_bytes(message)),
            hex(&rfc_bytes(printed))
        );
    }
}

#[test]
fn streebog_256_matches_the_rfc_6986_examples() {
    for (message, printed) in [
        (
            RFC_6986_M1,
            "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d",
        ),
        (
            RFC_6986_M2,
            "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d",
        ),
    ] {
        assert_eq!(
            hex_digest(&mut Gost3411_2012_256Digest::new(), &rfc_bytes(message)),
            hex(&rfc_bytes(printed))
        );
    }
}

#[test]
fn rfc_6986_m1_is_the_ascii_digits() {
    assert_eq!(
        rfc_bytes(RFC_6986_M1),
        b"012345678901234567890123456789012345678901234567890123456789012"
    );
}
