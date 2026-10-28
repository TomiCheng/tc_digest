//! BLAKE2s end-to-end throughput benchmarks.
//!
//! Run the runtime-dispatched backend:
//! `cargo bench -p tc_blake --bench blake2s`
//!
//! Run the portable backend by disabling the SIMD path in `tc_runtime`:
//! `cargo bench -p tc_blake --bench blake2s --features tc_runtime/disable-x86-sse2`

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tc_blake::Blake2sDigest;
use tc_digest::Digest;

const INPUT_SIZES: [usize; 5] = [64, 128, 1024, 64 * 1024, 1024 * 1024];

fn backend_name() -> &'static str {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if tc_runtime::intrinsics::x86::Sse2::detect().is_some() {
        return "sse2";
    }

    "portable"
}

fn input(size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(17))
        .collect()
}

fn bench_unkeyed(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("blake2s/unkeyed/{}", backend_name()));

    for size in INPUT_SIZES {
        let data = input(size);
        let mut digest = Blake2sDigest::new();
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

fn bench_keyed(c: &mut Criterion) {
    let key: Vec<u8> = (0..32).collect();
    let mut group = c.benchmark_group(format!("blake2s/keyed/{}", backend_name()));

    for size in INPUT_SIZES {
        let data = input(size);
        let mut digest = Blake2sDigest::with_key(&key);
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

criterion_group!(benches, bench_unkeyed, bench_keyed);
criterion_main!(benches);
