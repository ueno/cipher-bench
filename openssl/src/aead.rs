// SPDX-License-Identifier: Apache-2.0

use crate::evp;
use cipher_bench::{Aead, AeadBuilder};
use std::os::raw::c_int;
use std::ptr;

pub struct GcmAes128CtxBuilder {
    iv: Option<Vec<u8>>,
}

impl GcmAes128CtxBuilder {
    pub fn new() -> Self {
        Self { iv: None }
    }

    fn build(&mut self, key: &[u8], for_encryption: bool) -> Box<dyn Aead> {
        let ctx = unsafe {
            let ctx: *mut evp::EVP_CIPHER_CTX = evp::EVP_CIPHER_CTX_new();
            let cipher = evp::EVP_aes_128_gcm();
            let iv = self.iv.take().unwrap();
            let _ = evp::EVP_CipherInit_ex(
                ctx,
                cipher,
                ptr::null_mut::<evp::ENGINE>(),
                key.as_ptr() as _,
                iv.as_ptr() as _,
                for_encryption as _,
            );
            ctx
        };
        Box::new(GcmAes128Ctx { ctx })
    }
}

impl AeadBuilder for GcmAes128CtxBuilder {
    fn nonce(&mut self, iv: &[u8]) -> &mut Self {
        self.iv.replace(iv.to_vec());
        self
    }

    fn for_encryption(&mut self, key: &[u8]) -> Box<dyn Aead> {
        self.build(key, true)
    }

    fn for_decryption(&mut self, key: &[u8]) -> Box<dyn Aead> {
        self.build(key, false)
    }
}

pub struct GcmAes128Ctx {
    ctx: *mut evp::EVP_CIPHER_CTX,
}

impl Aead for GcmAes128Ctx {
    fn encrypt(&mut self, ptext: &[u8], ctext: &mut [u8]) {
        let mut outl = ctext.len() as c_int;
        unsafe {
            evp::EVP_EncryptUpdate(
                self.ctx,
                ctext.as_mut_ptr() as *mut _,
                &mut outl,
                ptext.as_ptr() as _,
                ptext.len() as _,
            );
        }
    }

    fn decrypt(&mut self, ctext: &[u8], ptext: &mut [u8]) {
        let mut outl = ptext.len() as c_int;
        unsafe {
            evp::EVP_DecryptUpdate(
                self.ctx,
                ptext.as_mut_ptr() as *mut _,
                &mut outl,
                ctext.as_ptr() as _,
                ctext.len() as _,
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

        let mut key_bytes = vec![0u8; AeadAlgorithm::GcmAes128.key_len()];
        rng.fill(key_bytes.as_mut_slice());

        let mut nonce_bytes = vec![0u8; AeadAlgorithm::GcmAes128.nonce_len()];
        rng.fill(nonce_bytes.as_mut_slice());

        let mut data_bytes = vec![0u8; 1024];
        rng.fill(data_bytes.as_mut_slice());

        let mut ptext = vec![0u8; 1024];
        ptext.copy_from_slice(data_bytes.as_slice());
        let mut ctext = vec![0u8; 1024];

        let mut builder = GcmAes128CtxBuilder::new();

        let mut ctx = builder.nonce(&nonce_bytes).for_encryption(&key_bytes);
        ctx.encrypt(&ptext, &mut ctext);

        let mut ctx = builder.nonce(&nonce_bytes).for_decryption(&key_bytes);
        ctx.decrypt(&ctext, &mut ptext);

        assert_eq!(ptext, data_bytes);
    }
}
