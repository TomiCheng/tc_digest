//! Helpers shared by the integration tests.

// Each test file uses a different subset.
#![allow(dead_code)]

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use tc_digest::Digest;

/// Everything the tests need from a digest: the infallible API and the name
/// its `Display` implementation writes.
pub trait NamedDigest: Digest + fmt::Display {}

impl<D: Digest + fmt::Display + ?Sized> NamedDigest for D {}

/// Absorbs `message`, finalizes, and returns the digest as lowercase hex.
pub fn hex_digest<D: Digest + ?Sized>(digest: &mut D, message: &[u8]) -> String {
    digest.update(message);
    let mut output = [0u8; 64];
    let written = digest.do_final(&mut output);
    output[..written]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The message `0, 1, 2, ...` of `len` bytes, wrapping at 256.
pub fn counting_message(len: usize) -> Vec<u8> {
    (0..len).map(|i| i as u8).collect()
}

/// Runs every contract check on digests built by `make`.
pub fn check_contract<D: NamedDigest + Clone>(make: impl Fn() -> D) {
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
