//! BLAKE3 end-to-end throughput benchmarks.
//!
//! Run the portable backend:
//! `cargo bench -p tc_blake --bench blake3`
//!
//! Run the portable and `blake3`-crate backends side by side:
//! `cargo bench -p tc_blake --bench blake3 --features blake3`

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tc_blake::Blake3PortableDigest;
#[cfg(feature = "blake3")]
use tc_blake::Blake3UpstreamDigest;
use tc_digest::Digest;

const INPUT_SIZES: [usize; 5] = [64, 1024, 4096, 64 * 1024, 1024 * 1024];

fn input(size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(17))
        .collect()
}

fn bench_backend<D: Digest>(c: &mut Criterion, name: &str, mut digest: D) {
    let mut group = c.benchmark_group(format!("blake3/unkeyed/{name}"));

    for size in INPUT_SIZES {
        let data = input(size);
        let mut output = [0u8; 32];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                digest.update(black_box(data));
                digest.do_final(black_box(&mut output));
                black_box(output);
            });
        });
    }

    group.finish();
}

fn bench_portable(c: &mut Criterion) {
    bench_backend(c, "portable", Blake3PortableDigest::new());
}

#[cfg(feature = "blake3")]
fn bench_upstream(c: &mut Criterion) {
    bench_backend(c, "upstream", Blake3UpstreamDigest::new());
}

#[cfg(not(feature = "blake3"))]
criterion_group!(benches, bench_portable);
#[cfg(feature = "blake3")]
criterion_group!(benches, bench_portable, bench_upstream);
criterion_main!(benches);
