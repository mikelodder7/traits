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

use generic_array::typenum::U1;
use inout::{ChunkProc, InCtrl, InOut, InOutBuf, NotEqualError};

pub use crypto_common::{Block, BlockSizeUser};

/// Marker trait for block ciphers.
pub trait BlockCipher: BlockSizeUser {}

/// Encrypt-only functionality for block ciphers.
pub trait BlockEncrypt: BlockSizeUser {
    /// Encrypt single `inout` block.
    fn encrypt_block_inout(&self, block: InOut<'_, Block<Self>>);

    /// Encrypt `blocks` with `gen_in` and `body` hooks.
    fn encrypt_with_callback(
        f: impl FnOnce(
            &mut [Block<Self>],
            fn(&Self, InOutBuf<'_, Block<Self>>),
        ),
    ) {
        f(
            &mut [Default::default(); 1],
            |s, blocks| {
                assert_eq!(blocks.len(), 1);
                BlockEncrypt::encrypt_block_inout(s, blocks.get(0));
            },
        );
    }
/*
    /// Encrypt `blocks` with callback hooks.
    fn encrypt_blocks_with_hook<B: ChunkProc<Block<Self>>>(
        &self,
        blocks: B,
        body: impl FnMut(B, &mut [Block<Self>]),
    ) {
        self.encrypt_blocks_with_gen(blocks, |_| InCtrl::In, body);
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

    /// Encrypt blocks in-place.
    #[inline]
    fn encrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        self.encrypt_blocks_with_hook(blocks, |chunk, res| chunk.clone_from_slice(res));
    }

    /// Encrypt `inout` blocks with given post hook.
    #[inline]
    fn encrypt_blocks_inout(&self, blocks: InOutBuf<'_, Block<Self>>) {
        self.encrypt_blocks_with_hook(blocks, |chunk, res| chunk.get_out().clone_from_slice(res));
    }

    /// Encrypt blocks buffer-to-buffer with given post hook.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn encrypt_blocks_b2b(
        &self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        self.encrypt_blocks_with_hook(InOutBuf::new(in_blocks, out_blocks)?, |chunk, res| {
            chunk.get_out().clone_from_slice(res)
        });
        Ok(())
    }
*/
}

/// Decrypt-only functionality for block ciphers.
pub trait BlockDecrypt: BlockSizeUser {
    /// Decrypt single `inout` block.
    fn decrypt_block_inout(&self, block: InOut<'_, Block<Self>>);

    /// Decrypt `blocks` with `gen_in` and `body` hooks.
    fn decrypt_with_callback(
        f: impl FnOnce(
            &mut [Block<Self>],
            fn(&Self, InOutBuf<'_, Block<Self>>),
        ),
    ) {
        f(
            &mut [Default::default(); 1],
            |s, blocks| {
                assert_eq!(blocks.len(), 1);
                BlockDecrypt::decrypt_block_inout(s, blocks.get(0));
            },
        );
    }
/*
    /// Decrypt `blocks` with callback hooks.
    fn decrypt_blocks_with_hook<B: ChunkProc<Block<Self>>>(
        &self,
        blocks: B,
        body: impl FnMut(B, &mut [Block<Self>]),
    ) {
        self.decrypt_blocks_with_gen(blocks, |_| InCtrl::In, body);
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

    /// Decrypt blocks in-place.
    #[inline]
    fn decrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        self.decrypt_blocks_with_hook(blocks, |chunk, res| chunk.clone_from_slice(res));
    }

    /// Decrypt `inout` blocks with given post hook.
    #[inline]
    fn decrypt_blocks_inout(&self, blocks: InOutBuf<'_, Block<Self>>) {
        self.decrypt_blocks_with_hook(blocks, |chunk, res| chunk.get_out().clone_from_slice(res));
    }

    /// Decrypt blocks buffer-to-buffer with given post hook.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn decrypt_blocks_b2b(
        &self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        self.decrypt_blocks_with_hook(InOutBuf::new(in_blocks, out_blocks)?, |chunk, res| {
            chunk.get_out().clone_from_slice(res)
        });
        Ok(())
    }
*/
}

/// Decrypt-only functionality for block ciphers and modes with mutable access to `self`.
///
/// The main use case for this trait is blocks modes, but it also can be used
/// for hardware cryptographic engines which require `&mut self` access to an
/// underlying hardware peripheral.
pub trait BlockEncryptMut: BlockSizeUser {
    /// Encrypt single `inout` block.
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>);

    /// Encrypt `blocks` with `gen_in` and `body` hooks.
    fn encrypt_with_callback_mut(
        f: impl FnOnce(
            &mut [Block<Self>],
            fn(&mut Self, InOutBuf<'_, Block<Self>>),
        ),
    ) {
        f(
            &mut [Default::default(); 1],
            |s, blocks| {
                assert_eq!(blocks.len(), 1);
                BlockEncryptMut::encrypt_block_inout_mut(s, blocks.get(0));
            },
        );
    }
/*
    /// Encrypt `blocks` with callback hooks.
    fn encrypt_blocks_with_hook_mut<B: ChunkProc<Block<Self>>>(
        &mut self,
        blocks: B,
        body: impl FnMut(B, &mut [Block<Self>]),
    ) {
        self.encrypt_blocks_with_gen_mut(blocks, |_| InCtrl::In, body);
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

    /// Encrypt blocks in-place.
    #[inline]
    fn encrypt_blocks_mut(&mut self, blocks: &mut [Block<Self>]) {
        self.encrypt_blocks_with_hook_mut(blocks, |chunk, res| chunk.clone_from_slice(res));
    }

    /// Encrypt `inout` blocks with given post hook.
    #[inline]
    fn encrypt_blocks_inout_mut(&mut self, blocks: InOutBuf<'_, Block<Self>>) {
        self.encrypt_blocks_with_hook_mut(blocks, |chunk, res| {
            chunk.get_out().clone_from_slice(res)
        });
    }

    /// Encrypt blocks buffer-to-buffer with given post hook.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn encrypt_blocks_b2b_mut(
        &mut self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        self.encrypt_blocks_with_hook_mut(InOutBuf::new(in_blocks, out_blocks)?, |chunk, res| {
            chunk.get_out().clone_from_slice(res)
        });
        Ok(())
    }
*/
}

/// Decrypt-only functionality for block ciphers and modes with mutable access to `self`.
///
/// The main use case for this trait is blocks modes, but it also can be used
/// for hardware cryptographic engines which require `&mut self` access to an
/// underlying hardware peripheral.
pub trait BlockDecryptMut: BlockSizeUser {
    /// Decrypt single `inout` block.
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>);

    /// Decrypt `blocks` with `gen_in` and `body` hooks.
    fn decrypt_with_callback_mut(
        f: impl FnOnce(
            &mut [Block<Self>],
            fn(&mut Self, InOutBuf<'_, Block<Self>>),
        ),
    ) {
        f(
            &mut [Default::default(); 1],
            |s, blocks| {
                assert_eq!(blocks.len(), 1);
                BlockDecryptMut::decrypt_block_inout_mut(s, blocks.get(0));
            },
        );
    }
/*
    /// Decrypt `blocks` with callback hooks.
    fn decrypt_blocks_with_hook_mut<B: ChunkProc<Block<Self>>>(
        &mut self,
        blocks: B,
        body: impl FnMut(B, &mut [Block<Self>]),
    ) {
        self.decrypt_blocks_with_gen_mut(blocks, |_| InCtrl::In, body);
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

    /// Decrypt blocks in-place.
    #[inline]
    fn decrypt_blocks_mut(&mut self, blocks: &mut [Block<Self>]) {
        self.decrypt_blocks_with_hook_mut(blocks, |chunk, res| chunk.clone_from_slice(res));
    }

    /// Decrypt `inout` blocks with given post hook.
    #[inline]
    fn decrypt_blocks_inout_mut(&mut self, blocks: InOutBuf<'_, Block<Self>>) {
        self.decrypt_blocks_with_hook_mut(blocks, |chunk, res| {
            chunk.get_out().clone_from_slice(res)
        });
    }

    /// Decrypt blocks buffer-to-buffer with given post hook.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn decrypt_blocks_b2b_mut(
        &mut self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        self.decrypt_blocks_with_hook_mut(InOutBuf::new(in_blocks, out_blocks)?, |chunk, res| {
            chunk.get_out().clone_from_slice(res)
        });
        Ok(())
    }
*/
}
/*
impl<Alg: BlockEncrypt> BlockEncryptMut for Alg {
    #[inline]
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.encrypt_block_inout(block)
    }

    fn encrypt_with_callback_mut(
        &mut self,
        f: impl FnOnce(
            &mut Self,
            &mut [Block<Self>],
            fn(&mut Self, InOutBuf<'_, Block<Self>>),
        ),
    ) {
        Alg::encrypt_with_callback(self, |s, t, enc| {
            f(&mut s, t, unsafe { core::mem::transmute(enc) });
        });
    }
}

impl<Alg: BlockDecrypt> BlockDecryptMut for Alg {
    #[inline]
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.decrypt_block_inout(block)
    }

    fn decrypt_with_callback_mut(
        &mut self,
        f: impl FnOnce(
            &mut Self,
            &mut [Block<Self>],
            fn(&mut Self, InOutBuf<'_, Block<Self>>),
        ),
    ) {
        
    }
}
*/

impl<Alg: BlockEncrypt> BlockEncrypt for &Alg {
    #[inline]
    fn encrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        Alg::encrypt_block_inout(self, block);
    }

    fn encrypt_with_callback(
        f: impl FnOnce(
            &mut [Block<Self>],
            fn(&Self, InOutBuf<'_, Block<Self>>),
        ),
    ) {
        Alg::encrypt_with_callback(|t, enc| {
            f(t, |_, _| {});
        });
    }
}

impl<Alg: BlockDecrypt> BlockDecrypt for &Alg {
    #[inline]
    fn decrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        Alg::decrypt_block_inout(self, block);
    }

    fn decrypt_with_callback(
        f: impl FnOnce(
            &mut [Block<Self>],
            fn(&Self, InOutBuf<'_, Block<Self>>),
        ),
    ) {
        // Alg::decrypt_with_callback(self, f);
    }
}

// TODO: ideally it would be nice to implement `BlockEncryptMut`/`BlockDecryptMut`,
// for `&mut Alg` where `Alg: BlockEncryptMut/BlockDecryptMut`, but, unfortunately,
// it conflicts with impl for `Alg: BlockEncrypt/BlockDecrypt`.
