//! Encrypted persistent `PqRatchetSession` state storage (`WRST` v1).
//!
//! Serializes a live [`PqRatchetSession`] (`WPQS` v1), seals it under `WilisKDF` v2 +
//! `WilisAEAD` with strict domain AAD (`wilis-ratchet-state-v1`), and persists atomically
//! with owner-only `0600` Unix permissions (`write_secret_file`) and zeroization.

use std::path::Path;

use crate::core::constants::HASH_BYTES;
use crate::error::{Result, WilisError};
use crate::format::{decrypt_with_passphrase_and_keyfile, encrypt_with_passphrase_and_keyfile};
use crate::kdf::KdfParams;
use crate::ratchet::pq_session::PqRatchetSession;
use crate::utils::zeroize::{read_bounded_file, write_secret_file, zeroize_bytes};

pub const WRST_MAGIC: [u8; 4] = *b"WRST";
pub const WRST_VERSION: u8 = 1;
const WRST_AAD: &[u8] = b"wilis-ratchet-state-v1";
const MAX_WRST_FILE_BYTES: usize = 2 * 1024 * 1024;

/// Encrypts a [`PqRatchetSession`] into a canonical `WRST` v1 container.
pub fn seal_pq_session(
    session: &PqRatchetSession,
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    params: KdfParams,
) -> Result<Vec<u8>> {
    let mut raw = session.to_state_bytes();
    let enc_res = encrypt_with_passphrase_and_keyfile(
        passphrase,
        keyfile_hash,
        &raw,
        WRST_AAD,
        params,
    );
    zeroize_bytes(&mut raw);
    let inner = enc_res?;

    let mut out = Vec::with_capacity(5 + inner.len());
    out.extend_from_slice(&WRST_MAGIC);
    out.push(WRST_VERSION);
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Authenticates, decrypts, and restores a [`PqRatchetSession`] from `WRST` v1 bytes.
pub fn open_pq_session(
    data: &[u8],
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
) -> Result<PqRatchetSession> {
    if data.len() < 5 || data[0..4] != WRST_MAGIC || data[4] != WRST_VERSION {
        return Err(WilisError::InvalidFormat(
            "invalid or truncated WRST ratchet state container".into(),
        ));
    }
    let mut raw = decrypt_with_passphrase_and_keyfile(
        passphrase,
        keyfile_hash,
        &data[5..],
        WRST_AAD,
    )?;
    let res = PqRatchetSession::from_state_bytes(&raw);
    zeroize_bytes(&mut raw);
    res
}

/// Atomically saves an encrypted `WRST` v1 ratchet session to `path` (mode `0600` on Unix).
pub fn save_pq_session(
    path: &Path,
    session: &PqRatchetSession,
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    params: KdfParams,
) -> Result<()> {
    let sealed = seal_pq_session(session, passphrase, keyfile_hash, params)?;
    write_secret_file(path, &sealed)
}

/// Loads and authenticates an encrypted `WRST` v1 ratchet session from `path`.
pub fn load_pq_session(
    path: &Path,
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
) -> Result<PqRatchetSession> {
    let data = read_bounded_file(path, MAX_WRST_FILE_BYTES)?;
    open_pq_session(&data, passphrase, keyfile_hash)
}
