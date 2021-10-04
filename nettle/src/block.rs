// SPDX-License-Identifier: Apache-2.0

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/block.rs"));

use cipher_bench::{BlockCipher, BlockCipherBuilder};
use std::mem;
use std::os::raw::c_void;

pub struct Aes128CbcCtxBuilder {
    iv: Option<Vec<u8>>,
}

impl Aes128CbcCtxBuilder {
    pub fn new() -> Self {
        Self { iv: None }
    }
}

impl BlockCipherBuilder for Aes128CbcCtxBuilder {
    fn nonce(&mut self, iv: &[u8]) -> &mut Self {
        self.iv.replace(iv.to_vec());
        self
    }

    fn for_encryption(&mut self, key: &[u8]) -> Box<dyn BlockCipher> {
        let ctx = unsafe {
            let mut ctx: aes128_ctx = mem::zeroed();
            nettle_aes128_set_encrypt_key(&mut ctx, key.as_ptr() as _);
            ctx
        };
        Box::new(Aes128CbcCtx {
            ctx,
            iv: self.iv.take().unwrap(),
        })
    }

    fn for_decryption(&mut self, key: &[u8]) -> Box<dyn BlockCipher> {
        let ctx = unsafe {
            let mut ctx: aes128_ctx = mem::zeroed();
            nettle_aes128_set_decrypt_key(&mut ctx, key.as_ptr() as _);
            ctx
        };
        Box::new(Aes128CbcCtx {
            ctx,
            iv: self.iv.take().unwrap(),
        })
    }
}

pub struct Aes128CbcCtx {
    ctx: aes128_ctx,
    iv: Vec<u8>,
}

impl BlockCipher for Aes128CbcCtx {
    fn encrypt(&mut self, ptext: &[u8], ctext: &mut [u8]) {
        unsafe {
            let encrypt: extern "C" fn(*const c_void, u64, *mut u8, *const u8) =
                mem::transmute(nettle_aes128_encrypt as *const c_void);

            nettle_cbc_encrypt(
                (&self.ctx as *const aes128_ctx) as *const c_void,
                Some(encrypt),
                AES_BLOCK_SIZE as _,
                self.iv.as_mut_ptr() as *mut _,
                ctext.len() as _,
                ctext.as_mut_ptr() as *mut _,
                ptext.as_ptr() as _,
            );
        }
    }

    fn decrypt(&mut self, ctext: &[u8], ptext: &mut [u8]) {
        unsafe {
            let decrypt: extern "C" fn(*const c_void, u64, *mut u8, *const u8) =
                mem::transmute(nettle_aes128_decrypt as *const c_void);

            nettle_cbc_decrypt(
                (&self.ctx as *const aes128_ctx) as *const c_void,
                Some(decrypt),
                AES_BLOCK_SIZE as _,
                self.iv.as_mut_ptr() as *mut _,
                ptext.len() as _,
                ptext.as_mut_ptr() as *mut _,
                ctext.as_ptr() as _,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipher_bench::BlockCipherAlgorithm;
    use rand::prelude::*;
    use std::convert::TryInto;

    #[test]
    fn roundtrip() {
        let mut rng = rand::thread_rng();

        let mut key_bytes = vec![0u8; BlockCipherAlgorithm::Aes128Cbc.key_len()];
        rng.fill(key_bytes.as_mut_slice());

        let mut nonce_bytes = vec![0u8; BlockCipherAlgorithm::Aes128Cbc.nonce_len()];
        rng.fill(nonce_bytes.as_mut_slice());

        let mut data_bytes = vec![0u8; 1024];
        rng.fill(data_bytes.as_mut_slice());

        let mut ptext = vec![0u8; 1024];
        ptext.copy_from_slice(data_bytes.as_slice());
        let mut ctext = vec![0u8; 1024];

        let mut builder = Aes128CbcCtxBuilder::new();

        let mut ctx = builder.nonce(&nonce_bytes).for_encryption(&key_bytes);
        ctx.encrypt(&ptext, &mut ctext);

        let mut ctx = builder.nonce(&nonce_bytes).for_decryption(&key_bytes);
        ctx.decrypt(&ctext, &mut ptext);

        assert_eq!(ptext, data_bytes);
    }
}
