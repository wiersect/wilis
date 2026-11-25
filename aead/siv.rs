//! Nonce-Misuse-Resistant Authenticated Encryption (`WilisAEAD-SIV`).
//!
//! Two-pass Synthetic Initialization Vector (SIV / MRAE) construction built strictly from
//! `WilisMAC` and `WilisAEAD`:
//! 1. Derives domain-separated `(K_siv, K_enc)` subkeys from the 256-bit master key.
//! 2. Pass 1 computes a 256-bit synthetic IV (`siv_tag`) over `(nonce, aad, plaintext)` under `K_siv`.
//! 3. Pass 2 encrypts `plaintext` with `WilisAEAD` under `(K_enc, siv_tag[0..24])`, binding
//!    both the full 256-bit `siv_tag`, `nonce`, and `aad` into the AEAD tag.
//!
//! Even if a caller accidentally reuses the exact same `(key, nonce)` pair for distinct
//! plaintexts, ciphertexts remain completely independent and indistinguishable from random
//! (leaking at most exact plaintext+AAD equality, the theoretical optimum for deterministic MRAE).

use crate::aead::{open, seal};
use crate::core::constants::{KEY_BYTES, NONCE_BYTES, TAG_BYTES};
use crate::error::{Result, WilisError};
use crate::mac::{derive_subkey, WilisMac};
use crate::utils::constant_time::ct_eq;
use crate::utils::zeroize::zeroize_bytes;

/// Total tag size for `WilisAEAD-SIV`: 32-byte synthetic IV + 32-byte AEAD tag = 64 bytes.
pub const SIV_TAG_BYTES: usize = TAG_BYTES * 2;

fn compute_siv(
    k_siv: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> [u8; TAG_BYTES] {
    let mut m = WilisMac::new(k_siv);
    m.update(b"WSIV_SIV_V1:");
    m.update(nonce);
    m.update(&(aad.len() as u64).to_le_bytes());
    m.update(aad);
    m.update(&(plaintext.len() as u64).to_le_bytes());
    m.update(plaintext);
    m.finalize()
}

fn build_siv_bound_aad(
    siv: &[u8; TAG_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity((12 + TAG_BYTES + NONCE_BYTES + 8).saturating_add(aad.len()));
    out.extend_from_slice(b"WSIV_ENC_V1:");
    out.extend_from_slice(siv);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    out.extend_from_slice(aad);
    out
}

/// Encrypts and authenticates `plaintext` in Nonce-Misuse-Resistant SIV mode,
/// returning `(ciphertext, 64-byte [siv_32 || aead_tag_32])`.
pub fn siv_seal(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; SIV_TAG_BYTES]) {
    let k_siv = derive_subkey(key, b"WSIV_KEY_MAC_V1");
    let k_enc = derive_subkey(key, b"WSIV_KEY_ENC_V1");

    let siv = compute_siv(k_siv.as_bytes(), nonce, aad, plaintext);
    let syn_nonce: [u8; NONCE_BYTES] = siv[0..NONCE_BYTES].try_into().expect("24 bytes");
    let bound_aad = build_siv_bound_aad(&siv, nonce, aad);
    let (ct, aead_tag) = seal(k_enc.as_bytes(), &syn_nonce, &bound_aad, plaintext);

    let mut full_tag = [0u8; SIV_TAG_BYTES];
    full_tag[0..TAG_BYTES].copy_from_slice(&siv);
    full_tag[TAG_BYTES..SIV_TAG_BYTES].copy_from_slice(&aead_tag);
    (ct, full_tag)
}

/// Decrypts and verifies a `WilisAEAD-SIV` ciphertext and 64-byte tag in constant time.
///
/// Recomputes and checks BOTH the AEAD tag and the 256-bit synthetic IV before releasing plaintext.
pub fn siv_open(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
    full_tag: &[u8; SIV_TAG_BYTES],
) -> Result<Vec<u8>> {
    let k_siv = derive_subkey(key, b"WSIV_KEY_MAC_V1");
    let k_enc = derive_subkey(key, b"WSIV_KEY_ENC_V1");

    let siv: [u8; TAG_BYTES] = full_tag[0..TAG_BYTES].try_into().expect("32 bytes");
    let aead_tag: [u8; TAG_BYTES] = full_tag[TAG_BYTES..SIV_TAG_BYTES]
        .try_into()
        .expect("32 bytes");
    let syn_nonce: [u8; NONCE_BYTES] = siv[0..NONCE_BYTES].try_into().expect("24 bytes");
    let bound_aad = build_siv_bound_aad(&siv, nonce, aad);

    let mut plaintext = open(k_enc.as_bytes(), &syn_nonce, &bound_aad, ciphertext, &aead_tag)?;

    let expected_siv = compute_siv(k_siv.as_bytes(), nonce, aad, &plaintext);
    if !ct_eq(&expected_siv, &siv) {
        zeroize_bytes(&mut plaintext);
        return Err(WilisError::AuthenticationFailed);
    }
    Ok(plaintext)
}
