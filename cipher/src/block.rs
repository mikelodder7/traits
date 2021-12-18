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
use crypto_common::{Block, BlockSizeUser};
use inout::{InOut, InOutBuf, NotEqualError};

/// Marker trait for block ciphers.
pub trait BlockCipher: BlockSizeUser {}

/// Encrypt-only functionality for block ciphers.
pub trait BlockEncrypt: BlockSizeUser + Sized {
    fn callback_encrypt(
        &self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &dyn Fn(InOut<'_, Block<Self>>),
            &dyn Fn(InOutBuf<'_, Block<Self>>),
        ),
    );

    /// Encrypt single `inout` block.
    #[inline(always)]
    fn encrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        self.callback_encrypt(|_, enc, _| enc(block));
    }

    /// Encrypt single block in-place.
    #[inline(always)]
    fn encrypt_block(&self, block: &mut Block<Self>) {
        self.encrypt_block_inout(block.into())
    }

    /// Encrypt single block block-to-block, i.e. encrypt
    /// block from `in_block` and write result to `out_block`.
    #[inline(always)]
    fn encrypt_block_b2b(&self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        self.encrypt_block_inout((in_block, out_block).into())
    }

    /// Encrypt `inout` blocks.
    #[inline(always)]
    fn encrypt_blocks_inout(&self, mut blocks: InOutBuf<'_, Block<Self>>) {
        self.callback_encrypt(|tmp, enc, par_enc| {
            let chunk_len = tmp.len();
            while blocks.len() >= chunk_len {
                let (chunk, tail) = blocks.split_at(chunk_len);
                blocks = tail;
                par_enc(chunk);
            }
            for block in blocks {
                enc(block);
            }
        });
    }

    /// Encrypt blocks in-place.
    #[inline(always)]
    fn encrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        self.encrypt_blocks_inout(blocks.into());
    }

    /// Encrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline(always)]
    fn encrypt_blocks_b2b(
        &self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks).map(|blocks| self.encrypt_blocks_inout(blocks))
    }
}

/// Decrypt-only functionality for block ciphers.
pub trait BlockDecrypt: BlockSizeUser + Sized {
    fn callback_decrypt(
        &self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &dyn Fn(InOut<'_, Block<Self>>),
            &dyn Fn(InOutBuf<'_, Block<Self>>),
        ),
    );

    /// Decrypt single `inout` block.
    #[inline(always)]
    fn decrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        self.callback_decrypt(|_, dec, _| dec(block));
    }

    /// Decrypt single block in-place.
    #[inline(always)]
    fn decrypt_block(&self, block: &mut Block<Self>) {
        self.decrypt_block_inout(block.into())
    }

    /// Decrypt single block block-to-block, i.e. decrypt
    /// block from `in_block` and write result to `out_block`.
    #[inline(always)]
    fn decrypt_block_b2b(&self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        self.decrypt_block_inout((in_block, out_block).into())
    }

    /// Decrypt `inout` blocks.
    #[inline(always)]
    fn decrypt_blocks_inout(&self, mut blocks: InOutBuf<'_, Block<Self>>) {
        self.callback_decrypt(|tmp, dec, par_dec| {
            let chunk_len = tmp.len();
            while blocks.len() >= chunk_len {
                let (chunk, tail) = blocks.split_at(chunk_len);
                blocks = tail;
                par_dec(chunk);
            }
            for block in blocks {
                dec(block);
            }
        });
    }

    /// Decrypt blocks in-place.
    #[inline(always)]
    fn decrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        self.decrypt_blocks_inout(blocks.into());
    }

    /// Decrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline(always)]
    fn decrypt_blocks_b2b(
        &self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks).map(|blocks| self.decrypt_blocks_inout(blocks))
    }
}

/// Decrypt-only functionality for block ciphers and modes with mutable access to `self`.
///
/// The main use case for this trait is blocks modes, but it also can be used
/// for hardware cryptographic engines which require `&mut self` access to an
/// underlying hardware peripheral.
pub trait BlockEncryptMut: BlockSizeUser + Sized {
    fn callback_encrypt_mut(
        &mut self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &mut dyn FnMut(InOut<'_, Block<Self>>),
            &mut dyn FnMut(InOutBuf<'_, Block<Self>>),
        ),
    );

    /// Encrypt single `inout` block.
    #[inline(always)]
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.callback_encrypt_mut(|_, enc, _| enc(block));
    }

    /// Encrypt single block in-place.
    #[inline(always)]
    fn encrypt_block_mut(&mut self, block: &mut Block<Self>) {
        self.encrypt_block_inout_mut(block.into())
    }

    /// Encrypt single block block-to-block, i.e. encrypt
    /// block from `in_block` and write result to `out_block`.
    #[inline(always)]
    fn encrypt_block_b2b_mut(&mut self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        self.encrypt_block_inout_mut((in_block, out_block).into())
    }

    /// Encrypt `inout` blocks.
    #[inline(always)]
    fn encrypt_blocks_inout_mut(&mut self, mut blocks: InOutBuf<'_, Block<Self>>) {
        self.callback_encrypt_mut(|tmp, enc, par_enc| {
            let chunk_len = tmp.len();
            while blocks.len() >= chunk_len {
                let (chunk, tail) = blocks.split_at(chunk_len);
                blocks = tail;
                par_enc(chunk);
            }
            for block in blocks {
                enc(block);
            }
        });
    }

    /// Encrypt blocks in-place.
    #[inline(always)]
    fn encrypt_blocks_mut(&mut self, blocks: &mut [Block<Self>]) {
        self.encrypt_blocks_inout_mut(blocks.into());
    }

    /// Encrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline(always)]
    fn encrypt_blocks_b2b_mut(
        &mut self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks).map(|blocks| self.encrypt_blocks_inout_mut(blocks))
    }
}

/// Decrypt-only functionality for block ciphers and modes with mutable access to `self`.
///
/// The main use case for this trait is blocks modes, but it also can be used
/// for hardware cryptographic engines which require `&mut self` access to an
/// underlying hardware peripheral.
pub trait BlockDecryptMut: BlockSizeUser + Sized {
    fn callback_decrypt_mut(
        &mut self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &mut dyn FnMut(InOut<'_, Block<Self>>),
            &mut dyn FnMut(InOutBuf<'_, Block<Self>>),
        ),
    );

    /// Decrypt single `inout` block.
    #[inline(always)]
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.callback_decrypt_mut(|_, dec, _| dec(block));
    }

    /// Decrypt single block in-place.
    #[inline(always)]
    fn decrypt_block_mut(&mut self, block: &mut Block<Self>) {
        self.decrypt_block_inout_mut(block.into())
    }

    /// Decrypt single block block-to-block, i.e. decrypt
    /// block from `in_block` and write result to `out_block`.
    #[inline(always)]
    fn decrypt_block_b2b_mut(&mut self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        self.decrypt_block_inout_mut((in_block, out_block).into())
    }

    /// Decrypt `inout` blocks.
    #[inline(always)]
    fn decrypt_blocks_inout_mut(&mut self, mut blocks: InOutBuf<'_, Block<Self>>) {
        self.callback_decrypt_mut(|tmp, dec, par_dec| {
            let chunk_len = tmp.len();
            while blocks.len() >= chunk_len {
                let (chunk, tail) = blocks.split_at(chunk_len);
                blocks = tail;
                par_dec(chunk);
            }
            for block in blocks {
                dec(block);
            }
        });
    }

    /// Decrypt blocks in-place.
    #[inline(always)]
    fn decrypt_blocks_mut(&mut self, blocks: &mut [Block<Self>]) {
        self.decrypt_blocks_inout_mut(blocks.into());
    }

    /// Decrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline(always)]
    fn decrypt_blocks_b2b_mut(
        &mut self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks).map(|blocks| self.decrypt_blocks_inout_mut(blocks))
    }
}

impl<Alg: BlockEncrypt> BlockEncryptMut for Alg {
    #[inline(always)]
    fn callback_encrypt_mut(
        &mut self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &mut dyn FnMut(InOut<'_, Block<Self>>),
            &mut dyn FnMut(InOutBuf<'_, Block<Self>>),
        ),
    ) {
        Alg::callback_encrypt(self, |b, mut enc, mut par_enc| f(b, &mut enc, &mut par_enc))
    }
}

impl<Alg: BlockDecrypt> BlockDecryptMut for Alg {
    #[inline(always)]
    fn callback_decrypt_mut(
        &mut self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &mut dyn FnMut(InOut<'_, Block<Self>>),
            &mut dyn FnMut(InOutBuf<'_, Block<Self>>),
        ),
    ) {
        Alg::callback_decrypt(self, |b, mut dec, mut par_dec| f(b, &mut dec, &mut par_dec))
    }
}

impl<Alg: BlockEncrypt> BlockEncrypt for &Alg {
    #[inline(always)]
    fn callback_encrypt(
        &self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &dyn Fn(InOut<'_, Block<Self>>),
            &dyn Fn(InOutBuf<'_, Block<Self>>),
        ),
    ) {
        Alg::callback_encrypt(self, f);
    }
}

impl<Alg: BlockDecrypt> BlockDecrypt for &Alg {
    #[inline(always)]
    fn callback_decrypt(
        &self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &dyn Fn(InOut<'_, Block<Self>>),
            &dyn Fn(InOutBuf<'_, Block<Self>>),
        ),
    ) {
        Alg::callback_decrypt(self, f);
    }
}

// TODO: ideally it would be nice to implement `BlockEncryptMut`/`BlockDecryptMut`,
// for `&mut Alg` where `Alg: BlockEncryptMut/BlockDecryptMut`, but, unfortunately,
// it conflicts with impl for `Alg: BlockEncrypt/BlockDecrypt`.
