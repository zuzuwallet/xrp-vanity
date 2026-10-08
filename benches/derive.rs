#![forbid(unsafe_code)]

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use zeroize::Zeroize;

use xrpl_vanity::{address_starts_with, derive_from_entropy};

fn bench_derive(c: &mut Criterion) {
    // Published ripple-address-codec test entropy. Not a wallet this program saves.
    let entropy = [
        0x4c, 0x3a, 0x1d, 0x21, 0x3f, 0xbd, 0xfb, 0x14, 0xc7, 0xc2, 0x8d, 0x60, 0x94, 0x69, 0xb3,
        0x41,
    ];
    c.bench_function("derive_from_entropy", |b| {
        b.iter(|| {
            let derived = derive_from_entropy(black_box(&entropy)).unwrap();
            black_box(derived.address);
        });
    });
    c.bench_function("hot_prefix_compare", |b| {
        b.iter(|| {
            let matched = address_starts_with(black_box(&entropy), black_box("rZuZu")).unwrap();
            black_box(matched);
        });
    });
    c.bench_function("getrandom_and_hot_prefix", |b| {
        b.iter(|| {
            let mut entropy = [0u8; 16];
            getrandom::getrandom(&mut entropy).unwrap();
            let matched = address_starts_with(black_box(&entropy), black_box("r")).unwrap();
            black_box(matched);
            entropy.zeroize();
        });
    });
}

criterion_group!(benches, bench_derive);
criterion_main!(benches);
