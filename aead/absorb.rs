//! Associated Data (AAD) absorption with domain separation and `0x80` padding.

use crate::core::constants::{DOMAIN_AAD, RATE_BYTES, ROUNDS_DATA};
use crate::core::permute::permute;
use crate::core::state::State;
use crate::utils::zeroize::zeroize_bytes;

/// Absorbs arbitrary-length Associated Data into the sponge state.
///
/// AAD is authenticated (bound into the final tag) but not encrypted.
pub fn absorb_aad(state: &mut State, aad: &[u8]) {
    state.words[5] ^= DOMAIN_AAD;

    if !aad.is_empty() {
        let mut chunks = aad.chunks_exact(RATE_BYTES);
        for chunk in chunks.by_ref() {
            let block: &[u8; RATE_BYTES] = chunk.try_into().expect("16-byte AAD block");
            state.xor_rate_block(block);
            permute(state, ROUNDS_DATA);
        }

        let rem = chunks.remainder();
        let mut padded = [0u8; RATE_BYTES];
        padded[..rem.len()].copy_from_slice(rem);
        padded[rem.len()] = 0x80;
        state.xor_rate_block(&padded);
        zeroize_bytes(&mut padded);
        permute(state, ROUNDS_DATA);
    }

    // Explicit phase-boundary bit so empty and non-empty AAD never collide
    state.words[5] ^= 1;
}
