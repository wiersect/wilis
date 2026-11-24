//! High-level container sealing and opening API for `WILS` v1 single-shot containers.

use crate::aead::{open, seal};
use crate::core::constants::{HASH_BYTES, KEY_BYTES, TAG_BYTES};
use crate::error::{Result, WilisError};
use crate::format::header::{ContainerHeader, KeyMode, FORMAT_VERSION};
use crate::kdf::{derive_key_with_keyfile, KdfParams};
use crate::utils::random::{generate_nonce, generate_salt};

/// Builds the full authenticated AAD binding the serialized header and optional user AAD.
fn build_bound_aad(header_bytes: &[u8], user_aad: &[u8]) -> Vec<u8> {
    let mut bound = Vec::with_capacity(header_bytes.len().saturating_add(8).saturating_add(user_aad.len()));
    bound.extend_from_slice(header_bytes);
    bound.extend_from_slice(&(user_aad.len() as u64).to_le_bytes());
    bound.extend_from_slice(user_aad);
    bound
}

/// Encrypts `plaintext` with a raw 256-bit key into a self-contained `WILS` v1 container.
pub fn encrypt_with_key(
    key: &[u8; KEY_BYTES],
    plaintext: &[u8],
    user_aad: &[u8],
) -> Result<Vec<u8>> {
    let nonce = generate_nonce()?;
    let header = ContainerHeader {
        version: FORMAT_VERSION,
        mode: KeyMode::RawKey,
        nonce,
        chunk_size: None,
    };
    let header_bytes = header.to_bytes();
    let bound_aad = build_bound_aad(&header_bytes, user_aad);
    let (ciphertext, tag) = seal(key, &nonce, &bound_aad, plaintext);

    let mut container = Vec::with_capacity(header_bytes.len() + ciphertext.len() + TAG_BYTES);
    container.extend_from_slice(&header_bytes);
    container.extend_from_slice(&ciphertext);
    container.extend_from_slice(&tag);
    Ok(container)
}

/// Decrypts a `WILS` v1 container encrypted in raw-key mode.
pub fn decrypt_with_key(
    key: &[u8; KEY_BYTES],
    container: &[u8],
    user_aad: &[u8],
) -> Result<Vec<u8>> {
    let (header, header_len) = ContainerHeader::parse(container)?;
    if header.version != FORMAT_VERSION {
        return Err(WilisError::InvalidFormat(format!(
            "container version {} requires streaming decoder",
            header.version
        )));
    }
    if header.mode != KeyMode::RawKey {
        return Err(WilisError::InvalidFormat(
            "container was encrypted with a passphrase, not a raw key".to_string(),
        ));
    }
    if container.len() < header_len + TAG_BYTES {
        return Err(WilisError::InvalidFormat(
            "container is truncated (missing authentication tag)".to_string(),
        ));
    }

    let header_bytes = &container[..header_len];
    let tag_start = container.len() - TAG_BYTES;
    let ciphertext = &container[header_len..tag_start];
    let tag: &[u8; TAG_BYTES] = container[tag_start..]
        .try_into()
        .expect("32-byte auth tag");

    let bound_aad = build_bound_aad(header_bytes, user_aad);
    open(key, &header.nonce, &bound_aad, ciphertext, tag)
}

/// Encrypts `plaintext` with a passphrase using `WilisKDF` into a `WILS` v1 container.
pub fn encrypt_with_passphrase(
    passphrase: &[u8],
    plaintext: &[u8],
    user_aad: &[u8],
    params: KdfParams,
) -> Result<Vec<u8>> {
    encrypt_with_passphrase_and_keyfile(passphrase, None, plaintext, user_aad, params)
}

/// Encrypts `plaintext` with a passphrase + optional 2FA keyfile digest into a `WILS` v1 container.
pub fn encrypt_with_passphrase_and_keyfile(
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    plaintext: &[u8],
    user_aad: &[u8],
    params: KdfParams,
) -> Result<Vec<u8>> {
    let salt = generate_salt()?;
    let nonce = generate_nonce()?;
    let derived_key = derive_key_with_keyfile(passphrase, keyfile_hash, &salt, params)?;

    let header = ContainerHeader {
        version: FORMAT_VERSION,
        mode: KeyMode::Passphrase { params, salt },
        nonce,
        chunk_size: None,
    };
    let header_bytes = header.to_bytes();
    let bound_aad = build_bound_aad(&header_bytes, user_aad);
    let (ciphertext, tag) = seal(derived_key.as_bytes(), &nonce, &bound_aad, plaintext);

    let mut container = Vec::with_capacity(header_bytes.len() + ciphertext.len() + TAG_BYTES);
    container.extend_from_slice(&header_bytes);
    container.extend_from_slice(&ciphertext);
    container.extend_from_slice(&tag);
    Ok(container)
}

/// Decrypts a `WILS` v1 container encrypted in passphrase mode.
pub fn decrypt_with_passphrase(
    passphrase: &[u8],
    container: &[u8],
    user_aad: &[u8],
) -> Result<Vec<u8>> {
    decrypt_with_passphrase_and_keyfile(passphrase, None, container, user_aad)
}

/// Decrypts a `WILS` v1 container encrypted in passphrase (+ optional 2FA keyfile) mode.
pub fn decrypt_with_passphrase_and_keyfile(
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    container: &[u8],
    user_aad: &[u8],
) -> Result<Vec<u8>> {
    let (header, header_len) = ContainerHeader::parse(container)?;
    if header.version != FORMAT_VERSION {
        return Err(WilisError::InvalidFormat(format!(
            "container version {} requires streaming decoder",
            header.version
        )));
    }
    let (params, salt) = match header.mode {
        KeyMode::Passphrase { params, salt } => (params, salt),
        KeyMode::RawKey => {
            return Err(WilisError::InvalidFormat(
                "container was encrypted with a raw key, not a passphrase".to_string(),
            ));
        }
    };
    if container.len() < header_len + TAG_BYTES {
        return Err(WilisError::InvalidFormat(
            "container is truncated (missing authentication tag)".to_string(),
        ));
    }

    let derived_key = derive_key_with_keyfile(passphrase, keyfile_hash, &salt, params)?;
    let header_bytes = &container[..header_len];
    let tag_start = container.len() - TAG_BYTES;
    let ciphertext = &container[header_len..tag_start];
    let tag: &[u8; TAG_BYTES] = container[tag_start..]
        .try_into()
        .expect("32-byte auth tag");

    let bound_aad = build_bound_aad(header_bytes, user_aad);
    open(
        derived_key.as_bytes(),
        &header.nonce,
        &bound_aad,
        ciphertext,
        tag,
    )
}
