//! Duplex sponge plaintext encryption phase.

use crate::core::constants::{DOMAIN_MSG, RATE_BYTES, ROUNDS_DATA};
use crate::core::permute::permute;
use crate::core::state::State;

/// Encrypts `plaintext` in duplex sponge mode while updating `state` in place.
///
/// Full 16-byte blocks are XORed against the 128-bit rate, overwriting the rate
/// with the resulting ciphertext before applying `WilisPerm-384` (12 rounds).
/// The final partial block (0..15 bytes) is domain-padded with `0x80`.
pub fn encrypt_blocks(state: &mut State, plaintext: &[u8]) -> Vec<u8> {
    state.words[5] ^= DOMAIN_MSG;

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut chunks = plaintext.chunks_exact(RATE_BYTES);

    for chunk in chunks.by_ref() {
        let ks = state.rate_bytes();
        let mut c_block = [0u8; RATE_BYTES];
        for i in 0..RATE_BYTES {
            c_block[i] = chunk[i] ^ ks[i];
        }
        ciphertext.extend_from_slice(&c_block);
        state.set_rate_bytes(&c_block);
        permute(state, ROUNDS_DATA);
    }

    let rem = chunks.remainder();
    let mut rate = state.rate_bytes();
    for (i, &p) in rem.iter().enumerate() {
        let c = p ^ rate[i];
        ciphertext.push(c);
        rate[i] = c;
    }
    // Multi-rate domain padding at exact remainder offset (handles rem.len() == 0 too)
    rate[rem.len()] ^= 0x80;
    state.set_rate_bytes(&rate);

    ciphertext
}
