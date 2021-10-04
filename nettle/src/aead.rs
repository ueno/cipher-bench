// SPDX-License-Identifier: Apache-2.0

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/aead.rs"));

use cipher_bench::{Aead, AeadBuilder};
use std::mem;

pub struct Aes128GcmCtxBuilder {
    iv: Option<Vec<u8>>,
}

impl Aes128GcmCtxBuilder {
    pub fn new() -> Self {
        Self { iv: None }
    }

    fn build(&mut self, key: &[u8]) -> Box<dyn Aead> {
        let ctx = unsafe {
            let mut ctx: gcm_aes128_ctx = mem::zeroed();
            nettle_gcm_aes128_set_key(&mut ctx, key.as_ptr() as _);
            let iv = self.iv.take().unwrap();
            nettle_gcm_aes128_set_iv(&mut ctx, iv.len() as _, iv.as_ptr() as _);
            ctx
        };
        Box::new(Aes128GcmCtx { ctx })
    }
}

impl AeadBuilder for Aes128GcmCtxBuilder {
    fn nonce(&mut self, iv: &[u8]) -> &mut Self {
        self.iv.replace(iv.to_vec());
        self
    }

    fn for_encryption(&mut self, key: &[u8]) -> Box<dyn Aead> {
        self.build(key)
    }

    fn for_decryption(&mut self, key: &[u8]) -> Box<dyn Aead> {
        self.build(key)
    }
}

pub struct Aes128GcmCtx {
    ctx: gcm_aes128_ctx,
}

impl Aead for Aes128GcmCtx {
    fn encrypt(&mut self, ptext: &[u8], ctext: &mut [u8]) {
        unsafe {
            nettle_gcm_aes128_encrypt(
                &mut self.ctx as *mut gcm_aes128_ctx,
                ctext.len() as _,
                ctext.as_mut_ptr() as *mut _,
                ptext.as_ptr() as _,
            );
        }
    }

    fn decrypt(&mut self, ctext: &[u8], ptext: &mut [u8]) {
        unsafe {
            nettle_gcm_aes128_decrypt(
                &mut self.ctx as *mut gcm_aes128_ctx,
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
    use cipher_bench::AeadAlgorithm;
    use rand::prelude::*;
    use std::convert::TryInto;

    #[test]
    fn roundtrip() {
        let mut rng = rand::thread_rng();

        let mut key_bytes = vec![0u8; AeadAlgorithm::Aes128Gcm.key_len()];
        rng.fill(key_bytes.as_mut_slice());

        let mut nonce_bytes = vec![0u8; AeadAlgorithm::Aes128Gcm.nonce_len()];
        rng.fill(nonce_bytes.as_mut_slice());

        let mut data_bytes = vec![0u8; 1024];
        rng.fill(data_bytes.as_mut_slice());

        let mut ptext = vec![0u8; 1024];
        ptext.copy_from_slice(data_bytes.as_slice());
        let mut ctext = vec![0u8; 1024];

        let mut builder = Aes128GcmCtxBuilder::new();

        let mut ctx = builder.nonce(&nonce_bytes).for_encryption(&key_bytes);
        ctx.encrypt(&ptext, &mut ctext);

        let mut ctx = builder.nonce(&nonce_bytes).for_decryption(&key_bytes);
        ctx.decrypt(&ctext, &mut ptext);

        assert_eq!(ptext, data_bytes);
    }
}
