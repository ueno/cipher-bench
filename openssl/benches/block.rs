// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use cipher_bench::{bench_block, BlockCipherAlgorithm};
use openssl::Aes128CbcCtxBuilder;
use std::convert::TryInto;

pub fn block_ciphers(c: &mut Criterion) {
    let mut group = c.benchmark_group("nettle/block-ciphers");
    let parameters: Vec<usize> = (1..=cipher_bench::ITER).collect();

    for i in parameters {
        group.throughput(Throughput::Bytes(
            (i * cipher_bench::STEP).try_into().unwrap(),
        ));

        let builder = Aes128CbcCtxBuilder::new();
        bench_block(&mut group, BlockCipherAlgorithm::Aes128Cbc, builder, i);
    }

    group.finish();
}

criterion_group!(benches, block_ciphers);
criterion_main!(benches);
