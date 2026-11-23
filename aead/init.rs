//! AEAD state initialization with 256-bit key, 192-bit nonce, and post-init key whitening.

use crate::core::constants::{DOMAIN_INIT, KEY_BYTES, NONCE_BYTES, ROUNDS_FULL};
use crate::core::permute::permute;
use crate::core::state::State;

/// Initializes the 384-bit duplex sponge state from a 256-bit key and 192-bit nonce.
///
/// Key whitening is applied after permutation so that even hypothetical state
/// recovery during later phases cannot trivially invert back to the secret key.
pub fn init_state(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES]) -> State {
    let k0 = u64::from_le_bytes(key[0..8].try_into().expect("8 bytes"));
    let k1 = u64::from_le_bytes(key[8..16].try_into().expect("8 bytes"));
    let k2 = u64::from_le_bytes(key[16..24].try_into().expect("8 bytes"));
    let k3 = u64::from_le_bytes(key[24..32].try_into().expect("8 bytes"));

    let n0 = u64::from_le_bytes(nonce[0..8].try_into().expect("8 bytes"));
    let n1 = u64::from_le_bytes(nonce[8..16].try_into().expect("8 bytes"));
    let n2 = u64::from_le_bytes(nonce[16..24].try_into().expect("8 bytes"));

    let mut state = State::from_words([DOMAIN_INIT, k0, k1, k2, k3, n0]);
    permute(&mut state, ROUNDS_FULL);

    // Absorb the remaining 128 bits of the 192-bit nonce
    state.words[0] ^= n1;
    state.words[1] ^= n2;
    permute(&mut state, ROUNDS_FULL);

    // Post-initialization key whitening into the 256-bit capacity
    state.xor_capacity_key(key);

    state
}
