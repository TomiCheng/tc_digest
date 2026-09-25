//! The API contract every digest shares: `do_final` writes exactly
//! `digest_size` bytes and resets, a short output buffer panics before any
//! state changes, clones continue independently, and how the message is split
//! into updates never changes the digest.

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};

use common::{NamedDigest, counting_message, hex_digest};
use tc_digest::Digest;
use tc_sha::{Sha1Digest, Sha224Digest, Sha256Digest, Sha384Digest, Sha512Digest, Sha512tDigest};

/// Runs every contract check on digests built by `make`.
fn check_contract<D: NamedDigest + Clone>(make: impl Fn() -> D) {
    do_final_writes_digest_size_bytes_and_resets(&make);
    a_short_output_panics_without_changing_state(&make);
    clones_continue_independently(&make);
    splitting_the_message_never_changes_the_digest(&make);
}

fn do_final_writes_digest_size_bytes_and_resets<D: Digest>(make: &impl Fn() -> D) {
    let empty = hex_digest(&mut make(), b"");
    let mut digest = make();
    let size = digest.digest_size();

    digest.update(b"abc");
    let mut output = [0xee_u8; 80];
    assert_eq!(digest.do_final(&mut output), size);
    assert!(output[size..].iter().all(|&b| b == 0xee));
    assert_eq!(hex_digest(&mut digest, b""), empty);

    digest.update(b"discarded");
    digest.reset();
    assert_eq!(hex_digest(&mut digest, b""), empty);
}

fn a_short_output_panics_without_changing_state<D: NamedDigest>(make: &impl Fn() -> D) {
    let expected = hex_digest(&mut make(), b"abc");
    let mut digest = make();
    digest.update(b"abc");

    let mut short = vec![0u8; digest.digest_size() - 1];
    let result = catch_unwind(AssertUnwindSafe(|| digest.do_final(&mut short)));
    assert!(result.is_err(), "{digest} accepted a short buffer");
    assert_eq!(hex_digest(&mut digest, b""), expected);
}

fn clones_continue_independently<D: Digest + Clone>(make: &impl Fn() -> D) {
    let mut original = make();
    original.update(b"ab");
    let mut copy = original.clone();
    assert_eq!(hex_digest(&mut copy, b"c"), hex_digest(&mut make(), b"abc"));
    assert_eq!(
        hex_digest(&mut original, b"d"),
        hex_digest(&mut make(), b"abd")
    );
}

/// For every message up to two blocks and one byte, splits around the block
/// edges and byte-by-byte updates give the digest of the whole message.
fn splitting_the_message_never_changes_the_digest<D: NamedDigest>(make: &impl Fn() -> D) {
    let block = make().byte_length();
    for len in 0..=2 * block + 1 {
        let message = counting_message(len);
        let whole = hex_digest(&mut make(), &message);

        let splits = [
            0,
            1,
            block - 1,
            block,
            block + 1,
            len / 2,
            len.saturating_sub(1),
            len,
        ];
        for split in splits.into_iter().filter(|&split| split <= len) {
            let mut digest = make();
            digest.update(&message[..split]);
            assert_eq!(
                hex_digest(&mut digest, &message[split..]),
                whole,
                "{digest} of {len} bytes split at {split}"
            );
        }

        let mut digest = make();
        for &byte in &message {
            digest.update_byte(byte);
        }
        assert_eq!(hex_digest(&mut digest, b""), whole);
    }
}

#[test]
fn sha1_keeps_the_digest_contract() {
    check_contract(Sha1Digest::new);
}

#[test]
fn sha224_keeps_the_digest_contract() {
    check_contract(Sha224Digest::new);
}

#[test]
fn sha256_keeps_the_digest_contract() {
    check_contract(Sha256Digest::new);
}

#[test]
fn sha384_keeps_the_digest_contract() {
    check_contract(Sha384Digest::new);
}

#[test]
fn sha512_keeps_the_digest_contract() {
    check_contract(Sha512Digest::new);
}

#[test]
fn sha512_t_keeps_the_digest_contract_at_every_tested_length() {
    // The shortest and longest outputs, and the two FIPS 180-4 approves.
    for t in [8, 224, 256, 504] {
        check_contract(|| Sha512tDigest::new(t));
    }
}

#[test]
fn accessors_report_each_algorithm() {
    for (digest, name, size, block) in [
        (&Sha1Digest::new() as &dyn NamedDigest, "SHA-1", 20, 64),
        (&Sha224Digest::new(), "SHA-224", 28, 64),
        (&Sha256Digest::new(), "SHA-256", 32, 64),
        (&Sha384Digest::new(), "SHA-384", 48, 128),
        (&Sha512Digest::new(), "SHA-512", 64, 128),
        (&Sha512tDigest::new(224), "SHA-512/224", 28, 128),
        (&Sha512tDigest::new(256), "SHA-512/256", 32, 128),
    ] {
        assert_eq!(digest.to_string(), name);
        assert_eq!(digest.digest_size(), size);
        assert_eq!(digest.byte_length(), block);
    }
}

#[test]
fn const_constructors_match_default() {
    const SHA1: Sha1Digest = Sha1Digest::new();
    const SHA224: Sha224Digest = Sha224Digest::new();
    const SHA256: Sha256Digest = Sha256Digest::new();
    const SHA384: Sha384Digest = Sha384Digest::new();
    const SHA512: Sha512Digest = Sha512Digest::new();
    for (mut from_const, mut from_default) in [
        (
            Box::new(SHA1) as Box<dyn Digest>,
            Box::new(Sha1Digest::default()) as Box<dyn Digest>,
        ),
        (Box::new(SHA224), Box::new(Sha224Digest::default())),
        (Box::new(SHA256), Box::new(Sha256Digest::default())),
        (Box::new(SHA384), Box::new(Sha384Digest::default())),
        (Box::new(SHA512), Box::new(Sha512Digest::default())),
    ] {
        assert_eq!(
            hex_digest(from_const.as_mut(), b"abc"),
            hex_digest(from_default.as_mut(), b"abc")
        );
    }
}

#[test]
fn digests_are_clone_send_and_sync() {
    fn assert_traits<T: Clone + Send + Sync>() {}
    assert_traits::<Sha1Digest>();
    assert_traits::<Sha224Digest>();
    assert_traits::<Sha256Digest>();
    assert_traits::<Sha384Digest>();
    assert_traits::<Sha512Digest>();
    assert_traits::<Sha512tDigest>();
}
