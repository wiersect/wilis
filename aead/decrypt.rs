//! Duplex sponge ciphertext decryption phase.

use crate::core::constants::{DOMAIN_MSG, RATE_BYTES, ROUNDS_DATA};
use crate::core::permute::permute;
use crate::core::state::State;

/// Decrypts `ciphertext` in duplex sponge mode while updating `state` in place.
///
/// Callers MUST verify the authentication tag via [`crate::aead::finalize::finalize_tag`]
/// before releasing or trusting the returned plaintext bytes.
pub fn decrypt_blocks(state: &mut State, ciphertext: &[u8]) -> Vec<u8> {
    state.words[5] ^= DOMAIN_MSG;

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut chunks = ciphertext.chunks_exact(RATE_BYTES);

    for chunk in chunks.by_ref() {
        let ks = state.rate_bytes();
        let c_block: &[u8; RATE_BYTES] = chunk.try_into().expect("16-byte ciphertext block");
        let mut p_block = [0u8; RATE_BYTES];
        for i in 0..RATE_BYTES {
            p_block[i] = c_block[i] ^ ks[i];
        }
        plaintext.extend_from_slice(&p_block);
        state.set_rate_bytes(c_block);
        permute(state, ROUNDS_DATA);
    }

    let rem = chunks.remainder();
    let mut rate = state.rate_bytes();
    for (i, &c) in rem.iter().enumerate() {
        let p = c ^ rate[i];
        plaintext.push(p);
        rate[i] = c;
    }
    rate[rem.len()] ^= 0x80;
    state.set_rate_bytes(&rate);

    plaintext
}
