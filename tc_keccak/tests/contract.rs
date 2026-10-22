//! Contract tests: how the input or the output is split never changes the
//! bytes, a short output buffer panics before any state changes, and every
//! digest wipes itself on drop.

use std::panic::{AssertUnwindSafe, catch_unwind};

use tc_digest::{Digest, TryDigest, Xof};
use tc_keccak::{CShakeDigest, KeccakDigest, ParallelHash, Sha3Digest, ShakeDigest, TupleHash};

// Feeding one byte at a time always takes the byte path, the reference.
#[test]
fn absorbing_in_any_chunks_matches_absorbing_byte_by_byte() {
    let message: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
    for bits in [224, 256, 384, 512] {
        let mut reference = Sha3Digest::new(bits);
        for byte in &message {
            reference.update(core::slice::from_ref(byte));
        }
        let mut want = vec![0; reference.digest_size()];
        reference.do_final(&mut want);

        for chunk in 1..=17 {
            let mut digest = Sha3Digest::new(bits);
            for piece in message.chunks(chunk) {
                digest.update(piece);
            }
            let mut got = vec![0; digest.digest_size()];
            digest.do_final(&mut got);
            assert_eq!(got, want, "SHA3-{bits} in {chunk}-byte chunks");
        }
    }
}

#[test]
fn squeezing_in_any_chunks_matches_squeezing_byte_by_byte() {
    for bits in [128, 256] {
        let mut reference = ShakeDigest::new(bits);
        reference.update(b"abc");
        let want: Vec<u8> = (0..600)
            .map(|_| {
                let mut byte = [0];
                reference.output(&mut byte);
                byte[0]
            })
            .collect();

        for chunk in 1..=17 {
            let mut shake = ShakeDigest::new(bits);
            shake.update(b"abc");
            let mut got = vec![0; want.len()];
            for piece in got.chunks_mut(chunk) {
                shake.output(piece);
            }
            assert_eq!(got, want, "SHAKE{bits} in {chunk}-byte chunks");
        }
    }
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
    short_output_panics_without_changing_state("Keccak-256", || KeccakDigest::new(256));
    short_output_panics_without_changing_state("SHA3-256", || Sha3Digest::new(256));
    short_output_panics_without_changing_state("SHAKE128", || ShakeDigest::new(128));
    short_output_panics_without_changing_state("cSHAKE128", || {
        CShakeDigest::new(128, b"", b"Email Signature")
    });
    short_output_panics_without_changing_state("TupleHash128", || TupleHash::new(128, b""));
    short_output_panics_without_changing_state("ParallelHash128", || {
        ParallelHash::new(128, b"", 8)
    });
}

// The wipe itself cannot be observed without unsafe code; this guards
// that every digest runs a destructor.
#[test]
fn every_digest_wipes_itself_on_drop() {
    assert!(std::mem::needs_drop::<KeccakDigest>());
    assert!(std::mem::needs_drop::<Sha3Digest>());
    assert!(std::mem::needs_drop::<ShakeDigest>());
    assert!(std::mem::needs_drop::<CShakeDigest>());
    assert!(std::mem::needs_drop::<TupleHash>());
    assert!(std::mem::needs_drop::<ParallelHash>());
}
