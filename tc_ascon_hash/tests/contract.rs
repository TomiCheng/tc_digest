//! Contract tests: how the input or the output is split never changes the
//! bytes, a short output buffer panics before any state changes, and every
//! digest wipes itself on drop.

#![allow(deprecated)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use tc_ascon_hash::{AsconCXof128, AsconHash256, AsconXof128};
#[cfg(feature = "legacy")]
use tc_ascon_hash::{AsconDigest, AsconParameters, AsconXof, AsconXofParameters, IsapDigest};
use tc_digest::{Digest, Xof};

fn message() -> Vec<u8> {
    (0..300u32).map(|i| (i * 7 + 3) as u8).collect()
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

    for chunk in 1..=17 {
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
    absorbing_in_chunks_matches_byte_by_byte("Ascon-Hash256", AsconHash256::new);
    absorbing_in_chunks_matches_byte_by_byte("Ascon-XOF128", AsconXof128::new);
    absorbing_in_chunks_matches_byte_by_byte("Ascon-CXOF128", || {
        AsconCXof128::with_customization(b"ctx")
    });
    #[cfg(feature = "legacy")]
    absorbing_in_chunks_matches_byte_by_byte("Ascon-Hash", || {
        AsconDigest::new(AsconParameters::AsconHash)
    });
    #[cfg(feature = "legacy")]
    absorbing_in_chunks_matches_byte_by_byte("Ascon-HashA", || {
        AsconDigest::new(AsconParameters::AsconHashA)
    });
    #[cfg(feature = "legacy")]
    absorbing_in_chunks_matches_byte_by_byte("Ascon-Xof", || {
        AsconXof::new(AsconXofParameters::AsconXof)
    });
    #[cfg(feature = "legacy")]
    absorbing_in_chunks_matches_byte_by_byte("Ascon-XofA", || {
        AsconXof::new(AsconXofParameters::AsconXofA)
    });
    #[cfg(feature = "legacy")]
    absorbing_in_chunks_matches_byte_by_byte("ISAP Hash", IsapDigest::new);
}

fn squeezing_in_chunks_matches_byte_by_byte<X: Xof>(name: &str, make: impl Fn() -> X) {
    let mut reference = make();
    reference.update(b"abc");
    let want: Vec<u8> = (0..200)
        .map(|_| {
            let mut byte = [0];
            reference.output(&mut byte);
            byte[0]
        })
        .collect();

    for chunk in 1..=17 {
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
    squeezing_in_chunks_matches_byte_by_byte("Ascon-XOF128", AsconXof128::new);
    squeezing_in_chunks_matches_byte_by_byte("Ascon-CXOF128", || {
        AsconCXof128::with_customization(b"ctx")
    });
    #[cfg(feature = "legacy")]
    squeezing_in_chunks_matches_byte_by_byte("Ascon-Xof", || {
        AsconXof::new(AsconXofParameters::AsconXof)
    });
    #[cfg(feature = "legacy")]
    squeezing_in_chunks_matches_byte_by_byte("Ascon-XofA", || {
        AsconXof::new(AsconXofParameters::AsconXofA)
    });
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
    short_output_panics_without_changing_state("Ascon-Hash256", AsconHash256::new);
    short_output_panics_without_changing_state("Ascon-XOF128", AsconXof128::new);
    short_output_panics_without_changing_state("Ascon-CXOF128", || {
        AsconCXof128::with_customization(b"ctx")
    });
    #[cfg(feature = "legacy")]
    short_output_panics_without_changing_state("Ascon-Hash", || {
        AsconDigest::new(AsconParameters::AsconHash)
    });
    #[cfg(feature = "legacy")]
    short_output_panics_without_changing_state("Ascon-Xof", || {
        AsconXof::new(AsconXofParameters::AsconXof)
    });
    #[cfg(feature = "legacy")]
    short_output_panics_without_changing_state("ISAP Hash", IsapDigest::new);
}

// The wipe itself cannot be observed without unsafe code; this guards that
// every digest runs a destructor.
#[test]
fn every_digest_wipes_itself_on_drop() {
    assert!(std::mem::needs_drop::<AsconHash256>());
    assert!(std::mem::needs_drop::<AsconXof128>());
    assert!(std::mem::needs_drop::<AsconCXof128>());
    #[cfg(feature = "legacy")]
    assert!(std::mem::needs_drop::<AsconDigest>());
    #[cfg(feature = "legacy")]
    assert!(std::mem::needs_drop::<AsconXof>());
    #[cfg(feature = "legacy")]
    assert!(std::mem::needs_drop::<IsapDigest>());
}
