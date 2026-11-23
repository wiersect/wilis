//! Public `seal` and `open` AEAD operations for `WilisAEAD`.

use crate::aead::absorb::absorb_aad;
use crate::aead::decrypt::decrypt_blocks;
use crate::aead::encrypt::encrypt_blocks;
use crate::aead::finalize::finalize_tag;
use crate::aead::init::init_state;
use crate::core::constants::{KEY_BYTES, NONCE_BYTES, TAG_BYTES};
use crate::error::{WilisError, Result};
use crate::utils::constant_time::ct_eq;
use crate::utils::zeroize::zeroize_bytes;

/// Encrypts `plaintext` and authenticates both `aad` and `plaintext`,
/// returning `(ciphertext, 32-byte tag)`.
///
/// # Nonce Safety
/// Never reuse the same `(key, nonce)` pair for two distinct messages.
pub fn seal(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; TAG_BYTES]) {
    let mut state = init_state(key, nonce);
    absorb_aad(&mut state, aad);
    let ciphertext = encrypt_blocks(&mut state, plaintext);
    let tag = finalize_tag(&mut state, key);
    (ciphertext, tag)
}

/// Decrypts `ciphertext` and verifies the 256-bit `tag` against `aad` in constant time.
///
/// If authentication fails, the decrypted buffer is immediately wiped from memory
/// before returning [`WilisError::AuthenticationFailed`].
pub fn open(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_BYTES],
) -> Result<Vec<u8>> {
    let mut state = init_state(key, nonce);
    absorb_aad(&mut state, aad);
    let mut plaintext = decrypt_blocks(&mut state, ciphertext);
    let expected_tag = finalize_tag(&mut state, key);

    if !ct_eq(&expected_tag, tag) {
        zeroize_bytes(&mut plaintext);
        return Err(WilisError::AuthenticationFailed);
    }

    Ok(plaintext)
}
