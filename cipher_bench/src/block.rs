// SPDX-License-Identifier: Apache-2.0

pub enum BlockCipherAlgorithm {
    CbcAes128,
}

impl BlockCipherAlgorithm {
    pub fn name(&self) -> &str {
        match self {
            BlockCipherAlgorithm::CbcAes128 => "aes-128-cbc",
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            BlockCipherAlgorithm::CbcAes128 => 16,
        }
    }

    pub fn nonce_len(&self) -> usize {
        match self {
            BlockCipherAlgorithm::CbcAes128 => 16,
        }
    }
}

pub trait BlockCipher {
    fn encrypt(&mut self, ptext: &[u8], ctext: &mut [u8]);
    fn decrypt(&mut self, ctext: &[u8], ptext: &mut [u8]);
}

pub trait BlockCipherBuilder {
    fn nonce(&mut self, nonce: &[u8]) -> &mut Self;
    fn for_encryption(&mut self, key: &[u8]) -> Box<dyn BlockCipher>;
    fn for_decryption(&mut self, key: &[u8]) -> Box<dyn BlockCipher>;
}

pub fn bench_block<B, M>(
    group: &mut criterion::BenchmarkGroup<M>,
    algorithm: BlockCipherAlgorithm,
    mut builder: B,
    count: usize,
) where
    B: BlockCipherBuilder,
    M: criterion::measurement::Measurement,
{
    let len = crate::STEP * count;

    group.bench_with_input(
        criterion::BenchmarkId::new(algorithm.name(), count),
        &len,
        |b, param| {
            use criterion::black_box;
            use rand::prelude::*;

            let mut rng = rand::thread_rng();

            let mut key_bytes = vec![0u8; algorithm.key_len()];
            rng.fill(key_bytes.as_mut_slice());

            let mut nonce_bytes = vec![0u8; algorithm.nonce_len()];
            rng.fill(nonce_bytes.as_mut_slice());

            let mut ctx = builder
                .nonce(&nonce_bytes)
                .for_encryption(&key_bytes);

            let pbuf = vec![0u8; *param];
            let mut cbuf = vec![0u8; *param];

            b.iter(|| {
                ctx.encrypt(black_box(&pbuf), black_box(&mut cbuf));
            });
        });
}
