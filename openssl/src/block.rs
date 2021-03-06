// SPDX-License-Identifier: Apache-2.0

use crate::evp;
use cipher_bench::{BlockCipher, BlockCipherBuilder};
use std::os::raw::c_int;
use std::ptr;

pub struct Aes128CbcCtxBuilder {
    iv: Option<Vec<u8>>,
}

impl Aes128CbcCtxBuilder {
    pub fn new() -> Self {
        Self { iv: None }
    }

    fn build(&mut self, key: &[u8], for_encryption: bool) -> Box<dyn BlockCipher> {
        let ctx = unsafe {
            let ctx: *mut evp::EVP_CIPHER_CTX = evp::EVP_CIPHER_CTX_new();
            let cipher = evp::EVP_aes_128_cbc();
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
        Box::new(Aes128CbcCtx { ctx })
    }
}

impl BlockCipherBuilder for Aes128CbcCtxBuilder {
    fn nonce(&mut self, iv: &[u8]) -> &mut Self {
        self.iv.replace(iv.to_vec());
        self
    }

    fn for_encryption(&mut self, key: &[u8]) -> Box<dyn BlockCipher> {
        self.build(&key, true)
    }

    fn for_decryption(&mut self, key: &[u8]) -> Box<dyn BlockCipher> {
        self.build(&key, false)
    }
}

pub struct Aes128CbcCtx {
    ctx: *mut evp::EVP_CIPHER_CTX,
}

impl BlockCipher for Aes128CbcCtx {
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
