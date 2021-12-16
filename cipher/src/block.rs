//! Traits used to define functionality of [block ciphers][1] and [modes of operation][2].
//!
//! # About block ciphers
//!
//! Block ciphers are keyed, deterministic permutations of a fixed-sized input
//! "block" providing a reversible transformation to/from an encrypted output.
//! They are one of the fundamental structural components of [symmetric cryptography][3].
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher
//! [2]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
//! [3]: https://en.wikipedia.org/wiki/Symmetric-key_algorithm

use generic_array::ArrayLength;
use inout::{InOut, InOutBuf, NotEqualError};

pub use crypto_common::{Block, BlockSizeUser};

/// Marker trait for block ciphers.
pub trait BlockCipher: BlockSizeUser {}

pub trait ParProc: BlockSizeUser {
    fn par_proc(&self, blocks: InOutBuf<'_, Block<Self>>);
}

pub trait ParProcMut: BlockSizeUser {
    fn par_proc_mut(&mut self, blocks: InOutBuf<'_, Block<Self>>);
}

impl<B: ArrayLength<u8>> BlockSizeUser for &dyn ParProc<BlockSize = B> {
    type BlockSize = B;
}

impl<B: ArrayLength<u8>> ParProcMut for &dyn ParProc<BlockSize = B> {
    #[inline(always)]
    fn par_proc_mut(&mut self, blocks: InOutBuf<'_, Block<Self>>) {
        self.par_proc(blocks);
    }
}

struct DummyParProc<'a, T: BlockSizeUser> {
    state: &'a T,
    proc: fn(&T, InOut<'_, Block<T>>)
}

impl<'a, T: BlockSizeUser> BlockSizeUser for DummyParProc<'a, T> {
    type BlockSize = T::BlockSize;
}

impl<'a, T: BlockSizeUser> ParProc for DummyParProc<'a, T> {
    #[inline(always)]
    fn par_proc(&self, mut blocks: InOutBuf<'_, Block<Self>>) {
        assert_eq!(blocks.len(), 1);
        let Self { state, proc } = self;
        proc(state, blocks.get(0));
    }
}

struct DummyParProcMut<'a, T: BlockSizeUser> {
    state: &'a mut T,
    proc: fn(&mut T, InOut<'_, Block<T>>)
}

impl<'a, T: BlockSizeUser> BlockSizeUser for DummyParProcMut<'a, T> {
    type BlockSize = T::BlockSize;
}

impl<'a, T: BlockSizeUser> ParProcMut for DummyParProcMut<'a, T> {
    #[inline(always)]
    fn par_proc_mut(&mut self, mut blocks: InOutBuf<'_, Block<Self>>) {
        assert_eq!(blocks.len(), 1);
        let Self { state, proc } = self;
        proc(state, blocks.get(0));
    }
}

/// Encrypt-only functionality for block ciphers.
pub trait BlockEncrypt: BlockSizeUser + Sized {
    /// Encrypt single `inout` block.
    fn encrypt_block_inout(&self, block: InOut<'_, Block<Self>>);

    /// Encrypt `blocks` with `gen_in` and `body` hooks.
    fn encrypt_with_callback(
        &self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &dyn ParProc<BlockSize = Self::BlockSize>,
        ),
    ) {
        f(
            &mut [Default::default(); 1],
            &DummyParProc {
                state: self,
                proc: Self::encrypt_block_inout,
            },
        );
    }

    /// Encrypt single block in-place.
    #[inline]
    fn encrypt_block(&self, block: &mut Block<Self>) {
        self.encrypt_block_inout(block.into())
    }

    /// Encrypt single block block-to-block, i.e. encrypt
    /// block from `in_block` and write result to `out_block`.
    #[inline]
    fn encrypt_block_b2b(&self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        self.encrypt_block_inout((in_block, out_block).into())
    }

    /// Encrypt `inout` blocks.
    #[inline]
    fn encrypt_blocks_inout(&self, mut blocks: InOutBuf<'_, Block<Self>>) {
        self.encrypt_with_callback(|tmp, proc| {
            let chunk_len = tmp.len();
            while blocks.len() >= chunk_len {
                let (chunk, tail) = blocks.split_at(chunk_len);
                blocks = tail;
                proc.par_proc(chunk);
            }
            proc.par_proc(blocks);
        });
    }

    /// Encrypt blocks in-place.
    #[inline]
    fn encrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        self.encrypt_blocks_inout(blocks.into());
    }

    /// Encrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn encrypt_blocks_b2b(
        &self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks)
            .map(|blocks| self.encrypt_blocks_inout(blocks))
    }
}

/// Decrypt-only functionality for block ciphers.
pub trait BlockDecrypt: BlockSizeUser + Sized {
    /// Decrypt single `inout` block.
    fn decrypt_block_inout(&self, block: InOut<'_, Block<Self>>);

    /// Decrypt `blocks` with `gen_in` and `body` hooks.
    fn decrypt_with_callback(
        &self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &dyn ParProc<BlockSize = Self::BlockSize>,
        ),
    ) {
        f(
            &mut [Default::default(); 1],
            &DummyParProc {
                state: self,
                proc: Self::decrypt_block_inout,
            },
        );
    }

    /// Decrypt single block in-place.
    #[inline]
    fn decrypt_block(&self, block: &mut Block<Self>) {
        self.decrypt_block_inout(block.into())
    }

    /// Decrypt single block block-to-block, i.e. decrypt
    /// block from `in_block` and write result to `out_block`.
    #[inline]
    fn decrypt_block_b2b(&self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        self.decrypt_block_inout((in_block, out_block).into())
    }

    /// Decrypt `inout` blocks.
    #[inline]
    fn decrypt_blocks_inout(&self, mut blocks: InOutBuf<'_, Block<Self>>) {
        self.decrypt_with_callback(|tmp, proc| {
            let chunk_len = tmp.len();
            while blocks.len() >= chunk_len {
                let (chunk, tail) = blocks.split_at(chunk_len);
                blocks = tail;
                proc.par_proc(chunk);
            }
            proc.par_proc(blocks);
        });
    }

    /// Decrypt blocks in-place.
    #[inline]
    fn decrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        self.decrypt_blocks_inout(blocks.into());
    }

    /// Decrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn decrypt_blocks_b2b(
        &self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks)
            .map(|blocks| self.decrypt_blocks_inout(blocks))
    }
}

/// Decrypt-only functionality for block ciphers and modes with mutable access to `self`.
///
/// The main use case for this trait is blocks modes, but it also can be used
/// for hardware cryptographic engines which require `&mut self` access to an
/// underlying hardware peripheral.
pub trait BlockEncryptMut: BlockSizeUser + Sized {
    /// Encrypt single `inout` block.
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>);

    /// Encrypt `blocks` with `gen_in` and `body` hooks.
    fn encrypt_with_callback_mut(
        &mut self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &mut dyn ParProcMut<BlockSize = Self::BlockSize>,
        ),
    ) {
        f(
            &mut [Default::default(); 1],
            &mut DummyParProcMut {
                state: self,
                proc: Self::encrypt_block_inout_mut,
            },
        );
    }

    /// Encrypt single block in-place.
    #[inline]
    fn encrypt_block_mut(&mut self, block: &mut Block<Self>) {
        self.encrypt_block_inout_mut(block.into())
    }

    /// Encrypt single block block-to-block, i.e. encrypt
    /// block from `in_block` and write result to `out_block`.
    #[inline]
    fn encrypt_block_b2b_mut(&mut self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        self.encrypt_block_inout_mut((in_block, out_block).into())
    }

    /// Encrypt `inout` blocks.
    #[inline]
    fn encrypt_blocks_inout_mut(&mut self, mut blocks: InOutBuf<'_, Block<Self>>) {
        self.encrypt_with_callback_mut(|tmp, proc| {
            let chunk_len = tmp.len();
            while blocks.len() >= chunk_len {
                let (chunk, tail) = blocks.split_at(chunk_len);
                blocks = tail;
                proc.par_proc_mut(chunk);
            }
            proc.par_proc_mut(blocks);
        });
    }

    /// Encrypt blocks in-place.
    #[inline]
    fn encrypt_blocks_mut(&mut self, blocks: &mut [Block<Self>]) {
        self.encrypt_blocks_inout_mut(blocks.into());
    }

    /// Encrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn encrypt_blocks_b2b_mut(
        &mut self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks)
            .map(|blocks| self.encrypt_blocks_inout_mut(blocks))
    }
}

/// Decrypt-only functionality for block ciphers and modes with mutable access to `self`.
///
/// The main use case for this trait is blocks modes, but it also can be used
/// for hardware cryptographic engines which require `&mut self` access to an
/// underlying hardware peripheral.
pub trait BlockDecryptMut: BlockSizeUser + Sized {
    /// Decrypt single `inout` block.
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>);

    /// Decrypt `blocks` with `gen_in` and `body` hooks.
    fn decrypt_with_callback_mut(
        &mut self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &mut dyn ParProcMut<BlockSize = Self::BlockSize>,
        ),
    ) {
        f(
            &mut [Default::default(); 1],
            &mut DummyParProcMut {
                state: self,
                proc: Self::decrypt_block_inout_mut,
            },
        );
    }

    /// Decrypt single block in-place.
    #[inline]
    fn decrypt_block_mut(&mut self, block: &mut Block<Self>) {
        self.decrypt_block_inout_mut(block.into())
    }

    /// Decrypt single block block-to-block, i.e. decrypt
    /// block from `in_block` and write result to `out_block`.
    #[inline]
    fn decrypt_block_b2b_mut(&mut self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        self.decrypt_block_inout_mut((in_block, out_block).into())
    }

    /// Decrypt `inout` blocks.
    #[inline]
    fn decrypt_blocks_inout_mut(&mut self, mut blocks: InOutBuf<'_, Block<Self>>) {
        self.decrypt_with_callback_mut(|tmp, proc| {
            let chunk_len = tmp.len();
            while blocks.len() >= chunk_len {
                let (chunk, tail) = blocks.split_at(chunk_len);
                blocks = tail;
                proc.par_proc_mut(chunk);
            }
            proc.par_proc_mut(blocks);
        });
    }

    /// Decrypt blocks in-place.
    #[inline]
    fn decrypt_blocks_mut(&mut self, blocks: &mut [Block<Self>]) {
        self.decrypt_blocks_inout_mut(blocks.into());
    }

    /// Decrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn decrypt_blocks_b2b_mut(
        &mut self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks)
            .map(|blocks| self.decrypt_blocks_inout_mut(blocks))
    }
}

impl<Alg: BlockEncrypt> BlockEncryptMut for Alg {
    #[inline(always)]
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.encrypt_block_inout(block)
    }

    fn encrypt_with_callback_mut(
        &mut self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &mut dyn ParProcMut<BlockSize = Self::BlockSize>,
        ),
    ) {
        Alg::encrypt_with_callback(self, |t, mut proc| f(t, &mut proc));
    }
}

impl<Alg: BlockDecrypt> BlockDecryptMut for Alg {
    #[inline(always)]
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.decrypt_block_inout(block)
    }

    fn decrypt_with_callback_mut(
        &mut self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &mut dyn ParProcMut<BlockSize = Self::BlockSize>,
        ),
    ) {
        Alg::decrypt_with_callback(self, |t, mut proc| f(t, &mut proc));
    }
}

impl<Alg: BlockEncrypt> BlockEncrypt for &Alg {
    #[inline(always)]
    fn encrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        Alg::encrypt_block_inout(self, block);
    }

    fn encrypt_with_callback(
        &self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &dyn ParProc<BlockSize = Self::BlockSize>,
        ),
    ) {
        Alg::encrypt_with_callback(self, f);
    }
}

impl<Alg: BlockDecrypt> BlockDecrypt for &Alg {
    #[inline(always)]
    fn decrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        Alg::decrypt_block_inout(self, block);
    }

    fn decrypt_with_callback(
        &self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &dyn ParProc<BlockSize = Self::BlockSize>,
        ),
    ) {
        Alg::decrypt_with_callback(self, f);
    }
}

// TODO: ideally it would be nice to implement `BlockEncryptMut`/`BlockDecryptMut`,
// for `&mut Alg` where `Alg: BlockEncryptMut/BlockDecryptMut`, but, unfortunately,
// it conflicts with impl for `Alg: BlockEncrypt/BlockDecrypt`.
