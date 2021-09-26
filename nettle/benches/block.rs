// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use cipher_bench::{bench_block, BlockCipherAlgorithm};
use nettle::CbcAes128CtxBuilder;
use std::convert::TryInto;

pub fn block_ciphers(c: &mut Criterion) {
    let mut group = c.benchmark_group("block-ciphers");
    let parameters: Vec<usize> = (1..=cipher_bench::ITER).collect();

    for i in parameters {
        group.throughput(Throughput::Bytes(
            (i * cipher_bench::STEP).try_into().unwrap(),
        ));

        let builder = CbcAes128CtxBuilder::new();
        bench_block(&mut group, BlockCipherAlgorithm::CbcAes128, builder, i);
    }

    group.finish();
}

criterion_group!(benches, block_ciphers);
criterion_main!(benches);
