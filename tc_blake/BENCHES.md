# tc_blake benchmarks

Throughput of the vector code against the portable code, and of the `blake3`
backend against the portable BLAKE3, measured with the Criterion benchmarks in
`benches/`. These are figures from one machine, to show the size of each
backend's effect, not a guarantee.

## Setup

- Intel Core i7-1185G7 (AVX2, AVX-512), Windows 11, on a laptop.
- Rust 1.98.0 stable, the `bench` profile, Criterion 0.7.
- `--warm-up-time 3 --measurement-time 15`; each figure is Criterion's median.
- The messages are 64 bytes to 1 MiB of a fixed pattern; output is the default
  digest length, 64 bytes for BLAKE2b and 32 bytes for BLAKE2s and BLAKE3.
- Measured on 2026-10-28.

The vector and the portable figures for BLAKE2 come from separate runs, so a
ratio near 1.0 is within the noise of the machine. The two BLAKE3 backends come
from the same run.

## BLAKE2b: AVX2 against portable

Portable figures with `--features tc_runtime/disable-x86-avx2`.

| Message | Unkeyed AVX2 | Unkeyed portable | Ratio | Keyed AVX2 | Keyed portable | Ratio |
|---|---|---|---|---|---|---|
| 64 B | 306 MiB/s | 256 MiB/s | 1.20 | 166 MiB/s | 126 MiB/s | 1.32 |
| 128 B | 630 MiB/s | 514 MiB/s | 1.23 | 325 MiB/s | 222 MiB/s | 1.46 |
| 1 KiB | 709 MiB/s | 583 MiB/s | 1.22 | 651 MiB/s | 482 MiB/s | 1.35 |
| 64 KiB | 740 MiB/s | 552 MiB/s | 1.34 | 739 MiB/s | 521 MiB/s | 1.42 |
| 1 MiB | 777 MiB/s | 537 MiB/s | 1.45 | 750 MiB/s | 537 MiB/s | 1.40 |

## BLAKE2s: SSE2 against portable

Portable figures with `--features tc_runtime/disable-x86-sse2`.

| Message | Unkeyed SSE2 | Unkeyed portable | Ratio | Keyed SSE2 | Keyed portable | Ratio |
|---|---|---|---|---|---|---|
| 64 B | 267 MiB/s | 297 MiB/s | 0.90 | 198 MiB/s | 158 MiB/s | 1.25 |
| 128 B | 328 MiB/s | 324 MiB/s | 1.01 | 252 MiB/s | 219 MiB/s | 1.15 |
| 1 KiB | 416 MiB/s | 354 MiB/s | 1.17 | 391 MiB/s | 329 MiB/s | 1.19 |
| 64 KiB | 431 MiB/s | 358 MiB/s | 1.20 | 448 MiB/s | 334 MiB/s | 1.34 |
| 1 MiB | 437 MiB/s | 360 MiB/s | 1.21 | 437 MiB/s | 327 MiB/s | 1.34 |

## BLAKE3: the `blake3` crate against portable

Both with `--features blake3`, unkeyed.

| Message | `blake3` crate | Portable | Ratio |
|---|---|---|---|
| 64 B | 507 MiB/s | 197 MiB/s | 2.6 |
| 1 KiB | 1228 MiB/s | 314 MiB/s | 3.9 |
| 4 KiB | 3867 MiB/s | 331 MiB/s | 11.7 |
| 64 KiB | 6603 MiB/s | 313 MiB/s | 21 |
| 1 MiB | 7150 MiB/s | 325 MiB/s | 22 |

## Reading

- The BLAKE2 vector code gives a moderate gain on long messages, about 1.3 to
  1.45 times for BLAKE2b and 1.2 to 1.35 times for BLAKE2s. On a single 64-byte
  block, BLAKE2s with SSE2 is about 10% slower than the portable code.
- The `blake3` crate is 12 to 22 times faster than the portable BLAKE3 from
  4 KiB up, about 7 GiB/s: it hashes several chunks at once with the widest
  vectors the CPU has, AVX-512 here.
- The portable BLAKE3 compresses one block at a time and reaches about
  0.33 GiB/s, below BLAKE2b.
