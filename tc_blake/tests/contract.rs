//! Contract tests: how the input or the output is split never changes the
//! bytes, a short output buffer panics before any state changes, and every
//! digest wipes itself on drop.

use std::panic::{AssertUnwindSafe, catch_unwind};

#[cfg(feature = "blake3")]
use tc_blake::Blake3UpstreamDigest;
use tc_blake::{Blake2bDigest, Blake2sDigest, Blake2xsDigest, Blake3Digest, Blake3PortableDigest};
use tc_digest::{Digest, Xof};

fn message() -> Vec<u8> {
    (0..2500u32).map(|i| (i * 7 + 3) as u8).collect()
}

// Feeding one byte at a time always takes the byte path, the reference.
fn absorbing_in_chunks_matches_byte_by_byte<D: Digest>(name: &str, make: impl Fn() -> D) {
    let message = message();
    let mut reference = make();
    for byte in &message {
        reference.update(core::slice::from_ref(byte));
    }
    let mut want = vec![0; reference.digest_size()];
    reference.do_final(&mut want);

    for chunk in [1, 7, 63, 64, 65, 127, 128, 129, 1000, 1024, 1025] {
        let mut digest = make();
        for piece in message.chunks(chunk) {
            digest.update(piece);
        }
        let mut got = vec![0; digest.digest_size()];
        digest.do_final(&mut got);
        assert_eq!(got, want, "{name} in {chunk}-byte chunks");
    }
}

#[test]
fn absorbing_in_any_chunks_matches_absorbing_byte_by_byte() {
    absorbing_in_chunks_matches_byte_by_byte("BLAKE2b", Blake2bDigest::new);
    absorbing_in_chunks_matches_byte_by_byte("keyed BLAKE2b", || Blake2bDigest::with_key(&[7; 64]));
    absorbing_in_chunks_matches_byte_by_byte("BLAKE2s", Blake2sDigest::new);
    absorbing_in_chunks_matches_byte_by_byte("keyed BLAKE2s", || Blake2sDigest::with_key(&[7; 32]));
    absorbing_in_chunks_matches_byte_by_byte("BLAKE2xs", || Blake2xsDigest::with_digest_size(100));
    absorbing_in_chunks_matches_byte_by_byte("BLAKE3", Blake3Digest::new);
    absorbing_in_chunks_matches_byte_by_byte("portable BLAKE3", Blake3PortableDigest::new);
    #[cfg(feature = "blake3")]
    absorbing_in_chunks_matches_byte_by_byte("upstream BLAKE3", Blake3UpstreamDigest::new);
}

fn squeezing_in_chunks_matches_byte_by_byte<X: Xof>(name: &str, make: impl Fn() -> X) {
    let mut reference = make();
    reference.update(b"abc");
    let want: Vec<u8> = (0..300)
        .map(|_| {
            let mut byte = [0];
            reference.output(&mut byte);
            byte[0]
        })
        .collect();

    for chunk in [1, 7, 31, 32, 33, 63, 64, 65, 100] {
        let mut xof = make();
        xof.update(b"abc");
        let mut got = vec![0; want.len()];
        for piece in got.chunks_mut(chunk) {
            xof.output(piece);
        }
        assert_eq!(got, want, "{name} in {chunk}-byte chunks");
    }
}

#[test]
fn squeezing_in_any_chunks_matches_squeezing_byte_by_byte() {
    squeezing_in_chunks_matches_byte_by_byte("BLAKE2xs", || Blake2xsDigest::with_digest_size(300));
    squeezing_in_chunks_matches_byte_by_byte("BLAKE3", Blake3Digest::new);
    squeezing_in_chunks_matches_byte_by_byte("portable BLAKE3", Blake3PortableDigest::new);
    #[cfg(feature = "blake3")]
    squeezing_in_chunks_matches_byte_by_byte("upstream BLAKE3", Blake3UpstreamDigest::new);
}

fn short_output_panics_without_changing_state<D: Digest>(name: &str, make: impl Fn() -> D) {
    let mut expected = make();
    expected.update(b"abc");
    let mut want = vec![0; expected.digest_size()];
    expected.do_final(&mut want);

    let mut digest = make();
    digest.update(b"abc");
    let mut short = vec![0; digest.digest_size() - 1];
    let result = catch_unwind(AssertUnwindSafe(|| digest.do_final(&mut short)));
    assert!(result.is_err(), "{name} accepted a short buffer");

    let mut got = vec![0; digest.digest_size()];
    digest.do_final(&mut got);
    assert_eq!(got, want, "{name}");
}

#[test]
fn every_digest_checks_the_output_length_before_finishing() {
    short_output_panics_without_changing_state("BLAKE2b", Blake2bDigest::new);
    short_output_panics_without_changing_state("BLAKE2s", Blake2sDigest::new);
    short_output_panics_without_changing_state("BLAKE2xs", || Blake2xsDigest::with_digest_size(64));
    short_output_panics_without_changing_state("BLAKE3", Blake3Digest::new);
    short_output_panics_without_changing_state("portable BLAKE3", Blake3PortableDigest::new);
    #[cfg(feature = "blake3")]
    short_output_panics_without_changing_state("upstream BLAKE3", Blake3UpstreamDigest::new);
}

// The wipe itself cannot be observed without unsafe code; this guards that
// every digest runs a destructor.
#[test]
fn every_digest_wipes_itself_on_drop() {
    assert!(std::mem::needs_drop::<Blake2bDigest>());
    assert!(std::mem::needs_drop::<Blake2sDigest>());
    assert!(std::mem::needs_drop::<Blake2xsDigest>());
    assert!(std::mem::needs_drop::<Blake3Digest>());
    assert!(std::mem::needs_drop::<Blake3PortableDigest>());
    #[cfg(feature = "blake3")]
    assert!(std::mem::needs_drop::<Blake3UpstreamDigest>());
}
