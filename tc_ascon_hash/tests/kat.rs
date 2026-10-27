//! Known-answer tests for the fixed-output digests: Ascon-Hash256 against
//! ascon-c's NIST SP 800-232 KAT, and the Ascon v1.2 hashes and ISAP Hash
//! against Bouncy Castle's `LWC_HASH_KAT_256` files, 1025 messages each.

#![allow(deprecated)]

use tc_ascon_hash::AsconHash256;
#[cfg(feature = "legacy")]
use tc_ascon_hash::{AsconDigest, AsconParameters, IsapDigest};
use tc_digest::Digest;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(feature = "legacy")]
fn unhex(text: &str) -> Vec<u8> {
    let text = text.trim();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// The `(Msg, MD)` records of a KAT file.
#[cfg(feature = "legacy")]
fn records(data: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut message = None;
    for line in data.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("Msg =") {
            message = Some(unhex(value));
        } else if let Some(value) = line.strip_prefix("MD =") {
            out.push((message.take().expect("Msg before MD"), unhex(value)));
        }
    }
    out
}

/// Hashes each message at once and in 5-byte pieces with the same digest,
/// which `do_final` resets between messages.
#[cfg(feature = "legacy")]
fn check_file<D: Digest>(name: &str, digest: &mut D, data: &str) {
    let records = records(data);
    assert_eq!(records.len(), 1025, "{name}: records in the file");
    for (index, (message, expected)) in records.iter().enumerate() {
        let mut output = [0u8; 32];
        digest.update(message);
        digest.do_final(&mut output);
        assert_eq!(&output[..], &expected[..], "{name} #{}", index + 1);

        for piece in message.chunks(5) {
            digest.update(piece);
        }
        digest.do_final(&mut output);
        assert_eq!(
            &output[..],
            &expected[..],
            "{name} #{} in pieces",
            index + 1
        );
    }
}

#[test]
fn ascon_hash256_matches_selected_ascon_c_vectors() {
    // Messages 00, 01, ... of each length, around the rate and longer.
    let vectors = [
        (
            0,
            "0b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2",
        ),
        (
            1,
            "0728621035af3ed2bca03bf6fde900f9456f5330e4b5ee23e7f6a1e70291bc80",
        ),
        (
            2,
            "6115e7c9c4081c2797fc8fe1bc57a836afa1c5381e556dd583860ca2dfb48dd2",
        ),
        (
            7,
            "3e4d273ba69b3b9c53216107e88b75cdbeedbcbf8faf0219c3928ab62b116577",
        ),
        (
            8,
            "b88e497ae8e6fb641b87ef622eb8f2fca0ed95383f7ffebe167acf1099ba764f",
        ),
        (
            9,
            "94269c30e0296e1ec86655041841823efa1927f520fd58c8e9bce6197878c1a6",
        ),
        (
            15,
            "6421330df99c05eb715415ee17b455f2674f862ae3cc5badffe43a4a3ed273e1",
        ),
        (
            16,
            "3158c1940a2fbadbd68ab661777859b94a689e4efc375911467addd641835c38",
        ),
        (
            17,
            "f149e99dd0f429599bb89b8079bf3f4dca3f298efefcf9b1ea16fe84f9b8b6e2",
        ),
        (
            31,
            "b900cd3f06f1618b68c16665807206dbe273df40135361f449847d573903fabd",
        ),
        (
            32,
            "bd9d3d60a66b53868eab2a5c74539a518a1f60f01eb176c60e43dee81680b33e",
        ),
        (
            33,
            "a58665a2cb9530c502096a7957a76e428af4ad044b4da5c471f9da6f7b3e5868",
        ),
        (
            63,
            "5072896862f6b9cfe8ef76d80559e156254782a40ac5f64cbf7934ad1f624b30",
        ),
        (
            64,
            "a6f241bea5d16405812c06019d9f72d60132bd7c089c60549b2e56bb01c64f48",
        ),
        (
            65,
            "bff4fa006fe6feabb5ce9b219492d0d230f4d05f2bac42db7189f441b1e83b53",
        ),
        (
            126,
            "4666aff6ba886835281152b30fd26f7d8d15c260ed136677c6db21593a476a4e",
        ),
        (
            127,
            "d968938c7f7849403160e291ea54ad79c0caf1237c1375a0b553d5c8122f88b3",
        ),
        (
            128,
            "ce8c1047063527f52dddf77dfa8cff33cad07edd981aae3fe845958209c0ec1f",
        ),
        (
            255,
            "ada496e2c0ade829f37832a8ba34cf6059dffbb3beba88ca5ded3363914ea69a",
        ),
        (
            511,
            "65eb85cf958ab45421a39052dd13e61011dedec9b89c161bd7d1ace2a48a18a9",
        ),
        (
            1024,
            "48140032bb7df2e2b5c95d403c9ab69b4bc00453980bf85f15a84cae2b09a0e9",
        ),
    ];

    let mut digest = AsconHash256::new();
    for (length, expected) in vectors {
        let message: Vec<u8> = (0..length).map(|i| i as u8).collect();
        let mut output = [0u8; 32];
        digest.update(&message);
        digest.do_final(&mut output);
        assert_eq!(hex(&output), expected, "length {length}");

        for piece in message.chunks(5) {
            digest.update(piece);
        }
        digest.do_final(&mut output);
        assert_eq!(hex(&output), expected, "length {length} in pieces");
    }
}

#[cfg(feature = "legacy")]
#[test]
fn ascon_v1_2_hash_matches_bouncy_castle_kat() {
    check_file(
        "Ascon-Hash",
        &mut AsconDigest::new(AsconParameters::AsconHash),
        include_str!("data/ascon_hash_legacy_kat.txt"),
    );
}

#[cfg(feature = "legacy")]
#[test]
fn ascon_v1_2_hash_a_matches_bouncy_castle_kat() {
    check_file(
        "Ascon-HashA",
        &mut AsconDigest::new(AsconParameters::AsconHashA),
        include_str!("data/ascon_hasha_legacy_kat.txt"),
    );
}

// ISAP Hash is the Ascon v1.2 hash, so the same file checks it.
#[cfg(feature = "legacy")]
#[test]
fn isap_hash_matches_the_ascon_v1_2_hash_kat() {
    check_file(
        "ISAP Hash",
        &mut IsapDigest::new(),
        include_str!("data/ascon_hash_legacy_kat.txt"),
    );
}
