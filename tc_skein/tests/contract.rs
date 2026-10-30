//! The API contract every digest shares: `do_final` writes exactly
//! `digest_size` bytes and resets, a short output buffer panics before any
//! state changes, clones continue independently, and how the message is split
//! into updates never changes the digest.

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};

use common::{NamedDigest, counting_message, hex_digest};
use tc_digest::{Digest, TryDigest};
use tc_skein::{InitError, SkeinDigest, SkeinEngine, SkeinParams, SkeinParamsRef};

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
    let mut output = vec![0xee_u8; size + 16];
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

const KEY: [u8; 32] = [0x42; 32];

#[test]
fn every_state_size_keeps_the_digest_contract() {
    for (state, output) in [(256, 256), (512, 512), (1024, 1024), (256, 520), (512, 160)] {
        check_contract(|| SkeinDigest::new(state, output));
    }
}

#[test]
fn a_keyed_digest_keeps_the_digest_contract_and_its_key_across_resets() {
    check_contract(|| {
        let mut digest = SkeinDigest::new(512, 512);
        digest.init(&SkeinParamsRef::new().with_key(&KEY)).unwrap();
        digest
    });
}

#[test]
fn accessors_report_the_state_and_digest_sizes() {
    for (state, output) in [(256, 160), (512, 512), (1024, 2056)] {
        let digest = SkeinDigest::new(state, output);
        assert_eq!(digest.to_string(), format!("Skein-{state}-{output}"));
        assert_eq!(digest.digest_size(), output / 8);
        assert_eq!(digest.byte_length(), state / 8);
    }
    assert_eq!(SkeinDigest::SKEIN_256, 256);
    assert_eq!(SkeinDigest::SKEIN_512, 512);
    assert_eq!(SkeinDigest::SKEIN_1024, 1024);
}

#[test]
fn the_engine_and_the_digest_agree() {
    let message = counting_message(300);
    let mut engine = SkeinEngine::new(1024, 384);
    engine.init(&SkeinParamsRef::new().with_key(&KEY)).unwrap();
    engine.update(&message);
    let mut from_engine = [0u8; 48];
    assert_eq!(engine.do_final(&mut from_engine), 48);

    let mut digest = SkeinDigest::new(1024, 384);
    digest.init(&SkeinParamsRef::new().with_key(&KEY)).unwrap();
    digest.update(&message);
    let mut from_digest = [0u8; 48];
    digest.do_final(&mut from_digest);
    assert_eq!(from_engine, from_digest);
}

#[test]
fn empty_parameters_return_to_the_plain_digest() {
    let mut digest = SkeinDigest::new(512, 512);
    digest.init(&SkeinParamsRef::new().with_key(&KEY)).unwrap();
    digest.update(b"discarded");
    digest.init(&SkeinParamsRef::default()).unwrap();
    assert_eq!(
        hex_digest(&mut digest, b"abc"),
        hex_digest(&mut SkeinDigest::new(512, 512), b"abc")
    );
}

#[test]
fn a_short_key_is_rejected_and_leaves_the_digest_unchanged() {
    let mut digest = SkeinDigest::new(256, 256);
    digest.init(&SkeinParamsRef::new().with_key(&KEY)).unwrap();
    digest.update(b"ab");
    assert_eq!(
        digest.init(&SkeinParamsRef::new().with_key(&[0; 15])),
        Err(InitError::KeyTooShort)
    );

    let mut expected = SkeinDigest::new(256, 256);
    expected
        .init(&SkeinParamsRef::new().with_key(&KEY))
        .unwrap();
    assert_eq!(
        hex_digest(&mut digest, b"c"),
        hex_digest(&mut expected, b"abc")
    );
}

#[test]
fn unsupported_sizes_panic() {
    for (state, output) in [
        (128, 256),
        (384, 256),
        (2048, 256),
        (256, 0),
        (256, 12),
        (512, 257),
    ] {
        let result = catch_unwind(|| SkeinDigest::new(state, output));
        assert!(result.is_err(), "accepted Skein-{state}-{output}");
    }
}

#[test]
fn the_digest_runs_a_destructor() {
    // The wipe itself cannot be observed without unsafe code; this guards
    // against the destructor that performs it disappearing.
    assert!(std::mem::needs_drop::<SkeinEngine>());
    assert!(std::mem::needs_drop::<SkeinDigest>());
}

#[test]
fn a_caller_parameter_type_supplies_only_what_it_has() {
    struct KeyOnly([u8; 32]);
    impl SkeinParams for KeyOnly {
        fn key(&self) -> Option<&[u8]> {
            Some(&self.0)
        }
    }

    let mut custom = SkeinDigest::new(256, 256);
    custom.init(&KeyOnly(KEY)).unwrap();
    let mut borrowed = SkeinDigest::new(256, 256);
    borrowed
        .init(&SkeinParamsRef::new().with_key(&KEY))
        .unwrap();
    assert_eq!(
        hex_digest(&mut custom, b"abc"),
        hex_digest(&mut borrowed, b"abc")
    );
}

#[cfg(feature = "alloc")]
#[test]
fn owned_parameters_give_the_same_digest_as_borrowed_ones() {
    use tc_skein::SkeinParamsOwned;

    let personalisation = b"20261030 me@example.com app";
    let owned = SkeinParamsOwned::new()
        .with_key(KEY.to_vec())
        .with_personalisation(personalisation.to_vec())
        .with_public_key(vec![5; 33])
        .with_key_identifier(vec![6; 9])
        .with_nonce(vec![7; 16]);
    let borrowed = SkeinParamsRef::new()
        .with_key(&KEY)
        .with_personalisation(personalisation)
        .with_public_key(&[5; 33])
        .with_key_identifier(&[6; 9])
        .with_nonce(&[7; 16]);

    let mut from_owned = SkeinDigest::new(512, 512);
    from_owned.init(&owned).unwrap();
    let mut from_borrowed = SkeinDigest::new(512, 512);
    from_borrowed.init(&borrowed).unwrap();
    assert_eq!(
        hex_digest(&mut from_owned, b"abc"),
        hex_digest(&mut from_borrowed, b"abc")
    );
}
