//! Official Ascon-CXOF128 known-answer tests (NIST SP 800-232 / ascon-c
//! `LWC_CXOF_KAT_128_512.txt`, 1089 vectors). Each record gives a message `Msg`,
//! a customization string `Z`, and the 64-byte output `MD`.

use tc_ascon_hash::AsconCXof128;
use tc_digest::{Digest, Xof};

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn official_cxof128_kat_vectors() {
    let data = include_str!("data/ascon_cxof128_kat.txt");

    let (mut msg, mut z, mut md, mut count) = (None, None, None, 0usize);
    let mut checked = 0usize;

    for line in data.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Msg =") {
            msg = Some(unhex(v));
        } else if let Some(v) = line.strip_prefix("Z =") {
            z = Some(unhex(v));
        } else if let Some(v) = line.strip_prefix("MD =") {
            md = Some(unhex(v));
        } else if let Some(v) = line.strip_prefix("Count =") {
            count = v.trim().parse().unwrap();
        }

        if let (Some(m), Some(zz), Some(expected)) = (&msg, &z, &md) {
            // One absorb, one read.
            let mut x = AsconCXof128::with_customization(zz);
            x.update(m);
            let mut out = vec![0u8; expected.len()];
            x.output_final(&mut out);
            assert_eq!(&out, expected, "Count {count}: single-shot");

            // Absorbing and reading in pieces gives the same bytes.
            let mut x = AsconCXof128::with_customization(zz);
            for chunk in m.chunks(3) {
                x.update(chunk);
            }
            let mut out = vec![0u8; expected.len()];
            let mut off = 0;
            for step in [1usize, 7, 8, 9, 39] {
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
            assert_eq!(&out, expected, "Count {count}: streamed");

            checked += 1;
            (msg, z, md) = (None, None, None);
        }
    }

    assert_eq!(checked, 1089, "expected 1089 KAT vectors");
}
