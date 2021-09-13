use core::fmt;
use digest::{
    block_buffer::BlockBuffer,
    consts::{U32, U64},
    core_api::{
        AlgorithmName, BlockSizeUser, BufferUser, CoreWrapper, FixedOutputCore, OutputSizeUser,
        Reset, UpdateCore,
    },
    generic_array::GenericArray,
};

use crate::streebog::StreebogState;

/// Core Streebog256 hasher state.
#[derive(Clone)]
pub struct Streebog256Core {
    state: StreebogState,
}

impl BlockSizeUser for Streebog256Core {
    type BlockSize = U64;
}

impl BufferUser for Streebog256Core {
    type Buffer = BlockBuffer<U64>;
}

impl OutputSizeUser for Streebog256Core {
    type OutputSize = U32;
}

impl UpdateCore for Streebog256Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[GenericArray<u8, Self::BlockSize>]) {
        self.state.update_blocks(blocks);
    }
}

impl FixedOutputCore for Streebog256Core {
    #[inline]
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut BlockBuffer<Self::BlockSize>,
        out: &mut GenericArray<u8, Self::OutputSize>,
    ) {
        self.state.finalize(buffer);
        out.copy_from_slice(&self.state.h[32..])
    }
}

impl Default for Streebog256Core {
    #[inline]
    fn default() -> Self {
        let state = StreebogState {
            h: [1u8; 64],
            n: Default::default(),
            sigma: Default::default(),
        };
        Self { state }
    }
}

impl Reset for Streebog256Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Streebog256Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Streebog256")
    }
}

impl fmt::Debug for Streebog256Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Streebog256Core { ... }")
    }
}

/// Streebog256 hasher state.
pub type Streebog256 = CoreWrapper<Streebog256Core>;
