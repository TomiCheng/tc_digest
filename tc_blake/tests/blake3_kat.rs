//! Official BLAKE3 known-answer tests (BLAKE3-team/BLAKE3 `test_vectors.json`, via
//! bc-csharp `Blake3Test.cs`). Each vector gives the unkeyed hash, the keyed hash,
//! and the derive-key hash of the length-`n` input `i % 251`, as extended XOF
//! output.

mod blake3_vectors;

use blake3_vectors::TEST_VECTORS;
use tc_blake::{Blake3Digest, Blake3PortableDigest};
use tc_digest::Xof;

const KEY: &[u8] = b"whats the Elvish word for friend";
const CONTEXT: &[u8] = b"BLAKE3 2019-12-27 16:29:52 test vectors context";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn check<D: Xof>(name: &str, new: fn() -> D, keyed: fn(&[u8]) -> D, derived: fn(&[u8]) -> D) {
    for &(len, hash, keyed_hash, derived_hash) in TEST_VECTORS {
        let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        for (mode, mut digest, expected) in [
            ("hash", new(), hash),
            ("keyed", keyed(KEY), keyed_hash),
            ("derived", derived(CONTEXT), derived_hash),
        ] {
            let expected = unhex(expected);
            digest.update(&input);
            let mut out = vec![0u8; expected.len()];
            digest.output_final(&mut out);
            assert_eq!(out, expected, "{name} {mode} len {len}");
        }
    }
}

#[test]
fn official_vectors_hold_for_the_selected_backend() {
    check(
        "Blake3Digest",
        Blake3Digest::new,
        |key| Blake3Digest::with_key(256, key),
        |context| Blake3Digest::with_derive_key(256, context),
    );
}

#[test]
fn official_vectors_hold_for_the_portable_backend() {
    check(
        "Blake3PortableDigest",
        Blake3PortableDigest::new,
        |key| Blake3PortableDigest::with_key(256, key),
        |context| Blake3PortableDigest::with_derive_key(256, context),
    );
}

#[cfg(feature = "blake3")]
#[test]
fn official_vectors_hold_for_the_upstream_backend() {
    check(
        "Blake3UpstreamDigest",
        tc_blake::Blake3UpstreamDigest::new,
        |key| tc_blake::Blake3UpstreamDigest::with_key(256, key),
        |context| tc_blake::Blake3UpstreamDigest::with_derive_key(256, context),
    );
}
