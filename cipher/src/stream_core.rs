use crate::StreamCipherError;
use core::convert::{TryFrom, TryInto};
use crypto_common::{Block, BlockSizeUser};
use generic_array::typenum::Unsigned;
use inout::InOutBuf;

pub trait StreamProc: BlockSizeUser {
    fn stream_proc(&mut self, blocks: &mut [Block<Self>]);
}

/// Block-level synchronous stream ciphers.
pub trait StreamCipherCore: BlockSizeUser + Sized {
    /// Return number of remaining blocks before cipher wraps around.
    ///
    /// Returns `None` if number of remaining blocks can not be computed
    /// (e.g. in ciphers based on the sponge construction) or it's too big
    /// to fit into `usize`.
    fn remaining_blocks(&self) -> Option<usize>;

    fn gen_keystream_with_callback(
        &mut self,
        f: impl FnOnce(
            &mut [Block<Self>],
            &mut dyn StreamProc<BlockSize = Self::BlockSize>,
        ),
    );

    /// Apply keystream blocks with post hook.
    ///
    /// WARNING: this method does not check number of remaining blocks!
    fn apply_keystream_blocks(
        &mut self,
        mut blocks: InOutBuf<'_, Block<Self>>,
        mut post_fn: impl FnMut(&[Block<Self>]),
    ) {
        self.gen_keystream_with_callback(|tmp, proc| {
            let chunk_len = tmp.len();
            while blocks.len() >= chunk_len {
                let (mut chunk, tail) = blocks.split_at(chunk_len);
                blocks = tail;
                proc.stream_proc(tmp);
                chunk.xor2out(tmp);
                post_fn(chunk.get_out());
            }
            if blocks.is_empty() {
                return;
            }
            let n = blocks.len();
            let tmp = &mut tmp[..n];
            proc.stream_proc(tmp);
            blocks.xor2out(tmp);
            post_fn(blocks.get_out());
        });
    }

    /// Write keystream blocks to `buf`.
    ///
    /// WARNING: this method does not check number of remaining blocks!
    fn write_keystream_blocks(&mut self, blocks: &mut [Block<Self>]) {
        self.gen_keystream_with_callback(|tmp, proc| {
            let mut blocks = blocks;
            let chunk_len = tmp.len();
            while blocks.len() >= chunk_len {
                let (chunk, tail) = blocks.split_at_mut(chunk_len);
                blocks = tail;
                proc.stream_proc(chunk);
            }
            if blocks.is_empty() {
                return;
            }
            proc.stream_proc(blocks);
        });
    }

    /// Try to apply keystream to data not divided into blocks.
    ///
    /// Consumes cipher since it may consume final keystream block only
    /// partially.
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
            self.apply_keystream_blocks(blocks, |_| {});
            buf = tail;
        }
        let n = buf.len();
        if n == 0 {
            return Ok(());
        }
        let mut block = Block::<Self>::default();
        block[..n].copy_from_slice(buf.reborrow().get_in());
        let mut t = InOutBuf::from_mut(&mut block);
        self.apply_keystream_blocks(t.reborrow(), |_| {});
        buf.get_out().copy_from_slice(&block[..n]);
        Ok(())
    }

    /// Try to apply keystream to data not divided into blocks.
    ///
    /// Consumes cipher since it may consume final keystream block only
    /// partially.
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
