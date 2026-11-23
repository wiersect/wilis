//! Operating-system cryptographically secure random byte generator (zero dependencies).

use std::fs::File;
use std::io::Read;

use crate::core::constants::{KEY_BYTES, NONCE_BYTES, SALT_BYTES};
use crate::error::{WilisError, Result};
use crate::utils::zeroize::SecretKey;

/// Fills `dest` with cryptographically secure random bytes read from `/dev/urandom`.
pub fn fill_random(dest: &mut [u8]) -> Result<()> {
    let mut file = File::open("/dev/urandom")
        .map_err(|e| WilisError::RandomSourceError(format!("failed to open /dev/urandom: {e}")))?;
    file.read_exact(dest).map_err(|e| {
        WilisError::RandomSourceError(format!("failed to read random bytes: {e}"))
    })?;
    Ok(())
}

/// Generates a fresh 256-bit random [`SecretKey`].
pub fn generate_key() -> Result<SecretKey> {
    let mut raw = [0u8; KEY_BYTES];
    fill_random(&mut raw)?;
    Ok(SecretKey::from_bytes(raw))
}

/// Generates a fresh 192-bit random nonce.
pub fn generate_nonce() -> Result<[u8; NONCE_BYTES]> {
    let mut nonce = [0u8; NONCE_BYTES];
    fill_random(&mut nonce)?;
    Ok(nonce)
}

/// Generates a fresh 192-bit random KDF salt.
pub fn generate_salt() -> Result<[u8; SALT_BYTES]> {
    let mut salt = [0u8; SALT_BYTES];
    fill_random(&mut salt)?;
    Ok(salt)
}
