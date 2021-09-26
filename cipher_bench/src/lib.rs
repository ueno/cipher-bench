// SPDX-License-Identifier: Apache-2.0

mod block;
pub use block::*;

mod aead;
pub use aead::*;

pub const STEP: usize = 1024;
pub const ITER: usize = 8;
