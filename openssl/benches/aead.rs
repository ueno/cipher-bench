// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use cipher_bench::{bench_aead, AeadAlgorithm};
use openssl::GcmAes128CtxBuilder;
use std::convert::TryInto;

pub fn aeads(c: &mut Criterion) {
    let mut group = c.benchmark_group("openssl/aeads");
    let parameters: Vec<usize> = (1..=cipher_bench::ITER).collect();

    for i in parameters {
        group.throughput(Throughput::Bytes(
            (i * cipher_bench::STEP).try_into().unwrap(),
        ));

        let builder = GcmAes128CtxBuilder::new();
        bench_aead(&mut group, AeadAlgorithm::GcmAes128, builder, i);
    }

    group.finish();
}

criterion_group!(benches, aeads);
criterion_main!(benches);
