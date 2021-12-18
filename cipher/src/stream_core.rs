use crate::StreamCipherError;
use core::convert::{TryFrom, TryInto};
use crypto_common::{Block, BlockSizeUser};
use generic_array::typenum::Unsigned;
use inout::InOutBuf;

/// Block-level synchronous stream ciphers.
pub trait StreamCipherCore: BlockSizeUser + Sized {
    /// Return number of remaining blocks before cipher wraps around.
    ///
    /// Returns `None` if number of remaining blocks can not be computed
    /// (e.g. in ciphers based on the sponge construction) or it's too big
    /// to fit into `usize`.
    fn remaining_blocks(&self) -> Option<usize>;

    fn callback_gen_keystream(
        &mut self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &mut dyn FnMut(&mut Block<Self>),
            &mut dyn FnMut(&mut [Block<Self>]),
        ),
    );

    /// Generate and apply keystream blocks by XORing them with blocks from
    /// the input buffer and write result to the output buffer.
    ///
    /// WARNING: this method does not check number of remaining blocks!
    fn apply_keystream_blocks(&mut self, mut blocks: InOutBuf<'_, Block<Self>>) {
        self.callback_gen_keystream(|tmp, gen_block, gen_blocks| {
            let chunk_len = tmp.len();
            while blocks.len() >= chunk_len {
                gen_blocks(tmp);
                let (mut chunk, tail) = blocks.split_at(chunk_len);
                blocks = tail;
                chunk.xor2out(tmp);
            }
            for mut block in blocks {
                let mut t = Default::default();
                gen_block(&mut t);
                block.xor2out(&t);
            }
        });
    }

    /// Generate and write keystream blocks to `blocks`.
    ///
    /// WARNING: this method does not check number of remaining blocks!
    fn write_keystream_blocks(&mut self, blocks: &mut [Block<Self>]) {
        self.callback_gen_keystream(|tmp, gen_block, gen_blocks| {
            let chunk_len = tmp.len();
            let mut iter = blocks.chunks_exact_mut(chunk_len);
            (&mut iter).for_each(gen_blocks);
            iter.into_remainder().iter_mut().for_each(gen_block);
        });
    }

    /// Generate and write single keystream block to `block`.
    ///
    /// WARNING: this method does not check number of remaining blocks!
    fn write_keystream_block(&mut self, block: &mut Block<Self>) {
        self.callback_gen_keystream(|_, gen_block, _| gen_block(block));
    }

    /// Try to generate and apply keystream to data not divided into blocks.
    ///
    /// Consumes cipher since it this method consume final keystream block
    /// only partially.
    ///
    /// Returns an error if number of remaining blocks is not sufficient
    /// for processing the input data.
    fn try_apply_keystream_partial(
        mut self,
        mut buf: InOutBuf<'_, u8>,
    ) -> Result<(), StreamCipherError> {
        if let Some(rem) = self.remaining_blocks() {
            let blocks = if buf.len() % Self::BlockSize::USIZE == 0 {
                buf.len() % Self::BlockSize::USIZE
            } else {
                buf.len() % Self::BlockSize::USIZE + 1
            };
            if blocks > rem {
                return Err(StreamCipherError);
            }
        }

        if buf.len() > Self::BlockSize::USIZE {
            let (blocks, tail) = buf.into_chunks();
            self.apply_keystream_blocks(blocks);
            buf = tail;
        }
        let n = buf.len();
        if n == 0 {
            return Ok(());
        }
        let mut block = Block::<Self>::default();
        block[..n].copy_from_slice(buf.reborrow().get_in());
        let mut t = InOutBuf::from_mut(&mut block);
        self.apply_keystream_blocks(t.reborrow());
        buf.get_out().copy_from_slice(&block[..n]);
        Ok(())
    }

    /// Generate and apply keystream to data not divided into blocks.
    ///
    /// Consumes cipher since it this method consume final keystream block
    /// only partially.
    ///
    /// # Panics
    /// If number of remaining blocks is not sufficient for processing the
    /// input data.
    fn apply_keystream_partial(self, buf: InOutBuf<'_, u8>) {
        self.try_apply_keystream_partial(buf).unwrap()
    }
}

// note: unfortunately, currently we can not write blanket impls of
// `BlockEncryptMut` and `BlockDecryptMut` for `T: StreamCipherCore`
// since it requires mutually exlusive traits, see:
// https://github.com/rust-lang/rfcs/issues/1053

/// Counter type usable with [`StreamCipherCore`].
///
/// This trait is implemented for `i32`, `u32`, `u64`, `u128`, and `usize`.
/// It's not intended to be implemented in third-party crates, but doing so
/// is not forbidden.
pub trait Counter:
    TryFrom<i32>
    + TryFrom<u32>
    + TryFrom<u64>
    + TryFrom<u128>
    + TryFrom<usize>
    + TryInto<i32>
    + TryInto<u32>
    + TryInto<u64>
    + TryInto<u128>
    + TryInto<usize>
{
}

/// Block-level seeking trait for stream ciphers.
pub trait StreamCipherSeekCore: StreamCipherCore {
    /// Counter type used inside stream cipher.
    type Counter: Counter;

    /// Get current block position.
    fn get_block_pos(&self) -> Self::Counter;

    /// Set block position.
    fn set_block_pos(&mut self, pos: Self::Counter);
}

macro_rules! impl_counter {
    {$($t:ty )*} => {
        $( impl Counter for $t { } )*
    };
}

impl_counter! { u32 u64 u128 }
