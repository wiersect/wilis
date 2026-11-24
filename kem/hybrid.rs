//! Post-Quantum Hybrid Public-Key Encryption (`WilisKEM` + `WilisAEAD`).
//!
//! Allows anyone holding only the recipient's public key (`WKP1`) to encrypt arbitrary
//! messages or files cleanly into a `WPKE` v1 container that only the holder of `WKS1`
//! can authenticate and decrypt.

use crate::aead::{open, seal};
use crate::core::constants::{NONCE_BYTES, TAG_BYTES};
use crate::error::{Result, WilisError};
use crate::kem::mlwe::{
    decapsulate, encapsulate, KemCiphertext, KemPublicKey, KemSecretKey, KEM_CT_BYTES,
};
use crate::utils::random::generate_nonce;

const PKE_MAGIC: [u8; 4] = *b"WPKE";
const PKE_VERSION: u8 = 1;

fn build_pke_aad(header_prefix: &[u8], user_aad: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header_prefix.len().saturating_add(8).saturating_add(user_aad.len()));
    aad.extend_from_slice(header_prefix);
    aad.extend_from_slice(&(user_aad.len() as u64).to_le_bytes());
    aad.extend_from_slice(user_aad);
    aad
}

/// Encrypts `plaintext` directly to a recipient's post-quantum [`KemPublicKey`].
///
/// Wire format (`WPKE` v1):
/// `[ "WPKE": 4B ][ ver=1: 1B ][ kem_ct: 1668B ][ nonce: 24B ][ aead_ct: N ][ tag: 32B ]`
pub fn pub_encrypt(
    recipient_pk: &KemPublicKey,
    plaintext: &[u8],
    user_aad: &[u8],
) -> Result<Vec<u8>> {
    let (kem_ct, shared_secret) = encapsulate(recipient_pk)?;
    let nonce = generate_nonce()?;
    let kem_ct_bytes = kem_ct.to_bytes();

    let header_len = 4 + 1 + KEM_CT_BYTES + NONCE_BYTES;
    let mut header = Vec::with_capacity(header_len);
    header.extend_from_slice(&PKE_MAGIC);
    header.push(PKE_VERSION);
    header.extend_from_slice(&kem_ct_bytes);
    header.extend_from_slice(&nonce);

    let aad = build_pke_aad(&header, user_aad);
    let (aead_ct, tag) = seal(shared_secret.as_bytes(), &nonce, &aad, plaintext);

    let mut packet = Vec::with_capacity(header.len() + aead_ct.len() + TAG_BYTES);
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&aead_ct);
    packet.extend_from_slice(&tag);
    Ok(packet)
}

/// Authenticates and decrypts a `WPKE` v1 hybrid post-quantum packet using [`KemSecretKey`].
pub fn pub_decrypt(
    recipient_sk: &KemSecretKey,
    packet: &[u8],
    user_aad: &[u8],
) -> Result<Vec<u8>> {
    let header_len = 4 + 1 + KEM_CT_BYTES + NONCE_BYTES;
    if packet.len() < header_len + TAG_BYTES || packet[0..4] != PKE_MAGIC {
        return Err(WilisError::InvalidFormat(
            "invalid or truncated WPKE post-quantum encrypted packet".into(),
        ));
    }
    if packet[4] != PKE_VERSION {
        return Err(WilisError::InvalidFormat(format!(
            "unsupported WPKE version: {}",
            packet[4]
        )));
    }

    let kem_ct = KemCiphertext::from_bytes(&packet[5..5 + KEM_CT_BYTES])?;
    let nonce: [u8; NONCE_BYTES] = packet[5 + KEM_CT_BYTES..header_len]
        .try_into()
        .expect("24-byte nonce");

    let shared_secret = decapsulate(recipient_sk, &kem_ct);
    let tag_start = packet.len() - TAG_BYTES;
    let aead_ct = &packet[header_len..tag_start];
    let tag: &[u8; TAG_BYTES] = packet[tag_start..].try_into().expect("32-byte tag");

    let aad = build_pke_aad(&packet[..header_len], user_aad);
    open(shared_secret.as_bytes(), &nonce, &aad, aead_ct, tag)
}
