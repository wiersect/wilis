//! Unified Post-Quantum Signcryption (`WPSC` v1: `WilisKEM` + `WilisSLH` + `WilisAEAD`).
//!
//! Encrypts and signs a message in ONE atomic post-quantum envelope that binds:
//! - Sender's stateless `WilisSLH` identity (`WLP1`)
//! - Recipient's `WilisKEM` public key digest (blocking Surreptitious Forwarding Attacks!)
//! - User AAD and encrypted payload inside an Encrypt-then-Sign-and-Bind construction.

use crate::aead::{open, seal};
use crate::core::constants::{NONCE_BYTES, TAG_BYTES};
use crate::error::{Result, WilisError};
use crate::hash::{hash, WilisHash};
use crate::kem::{decapsulate, encapsulate, KemCiphertext, KemPublicKey, KemSecretKey, KEM_CT_BYTES};
use crate::sign::stateless::{SlhPublicKey, SlhSecretKey, SlhSignature, SLH_SIG_BYTES};
use crate::utils::random::generate_nonce;

const SIGNCRYPT_MAGIC: [u8; 4] = *b"WPSC";
const SIGNCRYPT_VERSION: u8 = 1;

fn build_signcrypt_aad(
    sender_pk: &SlhPublicKey,
    recipient_pk: &KemPublicKey,
    kem_ct_bytes: &[u8],
    nonce: &[u8; NONCE_BYTES],
    user_aad: &[u8],
) -> Vec<u8> {
    let spk_h = hash(&sender_pk.to_bytes());
    let rpk_h = hash(&recipient_pk.to_bytes());
    let mut aad = Vec::with_capacity((8 + 32 + 32 + KEM_CT_BYTES + NONCE_BYTES + 8).saturating_add(user_aad.len()));
    aad.extend_from_slice(b"WPSC_V1:");
    aad.extend_from_slice(&spk_h);
    aad.extend_from_slice(&rpk_h);
    aad.extend_from_slice(kem_ct_bytes);
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(&(user_aad.len() as u64).to_le_bytes());
    aad.extend_from_slice(user_aad);
    aad
}

fn signcrypt_transcript(
    sender_pk: &SlhPublicKey,
    recipient_pk: &KemPublicKey,
    kem_ct_bytes: &[u8],
    nonce: &[u8; NONCE_BYTES],
    aead_ct: &[u8],
    tag: &[u8; TAG_BYTES],
    user_aad: &[u8],
) -> [u8; 32] {
    let mut h = WilisHash::new();
    h.update(b"WPSC_SIG_V1");
    h.update(&sender_pk.to_bytes());
    h.update(&recipient_pk.to_bytes());
    h.update(kem_ct_bytes);
    h.update(nonce);
    h.update(&(user_aad.len() as u64).to_le_bytes());
    h.update(user_aad);
    h.update(&(aead_ct.len() as u64).to_le_bytes());
    h.update(aead_ct);
    h.update(tag);
    h.finalize()
}

/// Signcrypts `plaintext` from `sender_sk` to `recipient_pk` into a `WPSC` v1 packet.
///
/// Wire layout:
/// `[ "WPSC": 4B ][ ver=1: 1B ][ kem_ct: 1668B ][ nonce: 24B ][ sig: 8165B ][ aead_ct: N ][ tag: 32B ]`
pub fn signcrypt(
    sender_sk: &SlhSecretKey,
    recipient_pk: &KemPublicKey,
    plaintext: &[u8],
    user_aad: &[u8],
) -> Result<Vec<u8>> {
    let sender_pk = sender_sk.public_key();
    let (kem_ct, shared_secret) = encapsulate(recipient_pk)?;
    let nonce = generate_nonce()?;
    let kem_ct_bytes = kem_ct.to_bytes();

    let aad = build_signcrypt_aad(&sender_pk, recipient_pk, &kem_ct_bytes, &nonce, user_aad);
    let (aead_ct, tag) = seal(shared_secret.as_bytes(), &nonce, &aad, plaintext);

    let transcript = signcrypt_transcript(
        &sender_pk,
        recipient_pk,
        &kem_ct_bytes,
        &nonce,
        &aead_ct,
        &tag,
        user_aad,
    );
    let sig = sender_sk.sign(&transcript)?;
    let sig_bytes = sig.to_bytes();

    let mut out = Vec::with_capacity(4 + 1 + KEM_CT_BYTES + NONCE_BYTES + SLH_SIG_BYTES + aead_ct.len() + TAG_BYTES);
    out.extend_from_slice(&SIGNCRYPT_MAGIC);
    out.push(SIGNCRYPT_VERSION);
    out.extend_from_slice(&kem_ct_bytes);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sig_bytes);
    out.extend_from_slice(&aead_ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Verifies the sender's post-quantum signature FIRST, then decapsulates and decrypts a `WPSC` v1 packet.
pub fn unsigncrypt(
    sender_pk: &SlhPublicKey,
    recipient_sk: &KemSecretKey,
    packet: &[u8],
    user_aad: &[u8],
) -> Result<Vec<u8>> {
    let header_len = 4 + 1 + KEM_CT_BYTES + NONCE_BYTES + SLH_SIG_BYTES;
    if packet.len() < header_len + TAG_BYTES
        || packet[0..4] != SIGNCRYPT_MAGIC
        || packet[4] != SIGNCRYPT_VERSION
    {
        return Err(WilisError::InvalidFormat(
            "invalid or truncated WPSC post-quantum signcrypted packet".into(),
        ));
    }

    let mut pos = 5;
    let kem_ct_bytes = &packet[pos..pos + KEM_CT_BYTES];
    let kem_ct = KemCiphertext::from_bytes(kem_ct_bytes)?;
    pos += KEM_CT_BYTES;

    let nonce: [u8; NONCE_BYTES] = packet[pos..pos + NONCE_BYTES].try_into().expect("24 bytes");
    pos += NONCE_BYTES;

    let sig = SlhSignature::from_bytes(&packet[pos..pos + SLH_SIG_BYTES])?;
    pos += SLH_SIG_BYTES;

    let tag_start = packet.len() - TAG_BYTES;
    let aead_ct = &packet[pos..tag_start];
    let tag: &[u8; TAG_BYTES] = packet[tag_start..].try_into().expect("32 bytes");

    let recipient_pk = recipient_sk.public_key();
    let transcript = signcrypt_transcript(
        sender_pk,
        recipient_pk,
        kem_ct_bytes,
        &nonce,
        aead_ct,
        tag,
        user_aad,
    );
    if !sender_pk.verify(&transcript, &sig) {
        return Err(WilisError::AuthenticationFailed);
    }

    let shared_secret = decapsulate(recipient_sk, &kem_ct);
    let aad = build_signcrypt_aad(sender_pk, recipient_pk, kem_ct_bytes, &nonce, user_aad);
    open(shared_secret.as_bytes(), &nonce, &aad, aead_ct, tag)
}
