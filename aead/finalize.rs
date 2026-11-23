//! AEAD finalization and 256-bit authentication tag extraction.

use crate::core::constants::{
    DOMAIN_FINAL, KEY_BYTES, RATE_BYTES, ROUNDS_DATA, ROUNDS_FULL, TAG_BYTES,
};
use crate::core::permute::permute;
use crate::core::state::State;
use crate::utils::zeroize::zeroize_bytes;

/// Finalizes the duplex sponge state and squeezes a 256-bit (32-byte) authentication tag.
///
/// The secret key is injected into the capacity prior to final permutation AND
/// XOR-masked into the squeezed tag halves to bind tag forgery resistance directly to the key.
pub fn finalize_tag(state: &mut State, key: &[u8; KEY_BYTES]) -> [u8; TAG_BYTES] {
    state.words[5] ^= DOMAIN_FINAL;
    state.xor_capacity_key(key);
    permute(state, ROUNDS_FULL);

    let mut tag = [0u8; TAG_BYTES];

    let mut first_half = state.rate_bytes();
    for i in 0..RATE_BYTES {
        tag[i] = first_half[i] ^ key[i];
    }
    zeroize_bytes(&mut first_half);

    permute(state, ROUNDS_DATA);

    let mut second_half = state.rate_bytes();
    for i in 0..RATE_BYTES {
        tag[RATE_BYTES + i] = second_half[i] ^ key[RATE_BYTES + i];
    }
    zeroize_bytes(&mut second_half);

    tag
}
