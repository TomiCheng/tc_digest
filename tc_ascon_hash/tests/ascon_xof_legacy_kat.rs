//! Official Ascon v1.2 XOF known-answer tests (`AsconXof` / `AsconXofA`),
//! 1025 vectors each (Msg to a 32-byte MD).

#![cfg(feature = "legacy")]
#![allow(deprecated)]

use tc_ascon_hash::{AsconXof, AsconXofParameters};
use tc_digest::{Digest, Xof};

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn run_kat(data: &str, parameters: AsconXofParameters) {
    let (mut msg, mut md, mut count) = (None, None, 0usize);
    let mut checked = 0usize;

    for line in data.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Msg =") {
            msg = Some(unhex(v));
        } else if let Some(v) = line.strip_prefix("MD =") {
            md = Some(unhex(v));
        } else if let Some(v) = line.strip_prefix("Count =") {
            count = v.trim().parse().unwrap();
        }

        if let (Some(m), Some(expected)) = (&msg, &md) {
            // One absorb, one read.
            let mut x = AsconXof::new(parameters);
            x.update(m);
            let mut out = vec![0u8; expected.len()];
            x.output_final(&mut out);
            assert_eq!(&out, expected, "{parameters:?} Count {count}: single-shot");

            // Absorbing and reading in pieces off the rate gives the same bytes.
            let mut x = AsconXof::new(parameters);
            for chunk in m.chunks(3) {
                x.update(chunk);
            }
            let mut out = vec![0u8; expected.len()];
            let mut off = 0;
            for step in [1usize, 7, 8, 9] {
                if off >= out.len() {
                    break;
                }
                let end = (off + step).min(out.len());
                x.output(&mut out[off..end]);
                off = end;
            }
            if off < out.len() {
                let len = out.len();
                x.output(&mut out[off..len]);
            }
            assert_eq!(&out, expected, "{parameters:?} Count {count}: streamed");

            checked += 1;
            (msg, md) = (None, None);
        }
    }

    assert_eq!(
        checked, 1025,
        "expected 1025 KAT vectors for {parameters:?}"
    );
}

#[test]
fn official_ascon_xof_kat() {
    run_kat(
        include_str!("data/ascon_xof_legacy_kat.txt"),
        AsconXofParameters::AsconXof,
    );
}

#[test]
fn official_ascon_xofa_kat() {
    run_kat(
        include_str!("data/ascon_xofa_legacy_kat.txt"),
        AsconXofParameters::AsconXofA,
    );
}
