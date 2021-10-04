// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use cipher_bench::{bench_aead, AeadAlgorithm};
use nettle::Aes128GcmCtxBuilder;
use std::convert::TryInto;

pub fn aeads(c: &mut Criterion) {
    let mut group = c.benchmark_group("nettle/aeads");
    let parameters: Vec<usize> = (1..=cipher_bench::ITER).collect();

    for i in parameters {
        group.throughput(Throughput::Bytes(
            (i * cipher_bench::STEP).try_into().unwrap(),
        ));

        let builder = Aes128GcmCtxBuilder::new();
        bench_aead(&mut group, AeadAlgorithm::Aes128Gcm, builder, i);
    }

    group.finish();
}

criterion_group!(benches, aeads);
criterion_main!(benches);
