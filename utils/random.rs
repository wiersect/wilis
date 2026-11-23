//! Cross-platform operating-system CSPRNG (zero external dependencies).
//!
//! - Unix (Linux, macOS, BSD): reads directly from `/dev/urandom`.
//! - Windows: invokes the native OS `BCryptGenRandom` (`bcrypt.dll`) with
//!   `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.

use crate::core::constants::{KEY_BYTES, NONCE_BYTES, SALT_BYTES};
use crate::error::{Result, WilisError};
use crate::utils::zeroize::{zeroize_bytes, SecretKey};

/// Fills `dest` with cryptographically secure random bytes from the OS CSPRNG.
#[cfg(unix)]
pub fn fill_random(dest: &mut [u8]) -> Result<()> {
    use std::fs::File;
    use std::io::Read;

    if dest.is_empty() {
        return Ok(());
    }
    let mut file = File::open("/dev/urandom")
        .map_err(|e| WilisError::RandomSourceError(format!("failed to open /dev/urandom: {e}")))?;
    if let Err(e) = file.read_exact(dest) {
        zeroize_bytes(dest);
        return Err(WilisError::RandomSourceError(format!(
            "failed to read random bytes: {e}"
        )));
    }
    Ok(())
}

/// Fills `dest` with cryptographically secure random bytes via Windows `BCryptGenRandom`.
#[cfg(windows)]
pub fn fill_random(dest: &mut [u8]) -> Result<()> {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }

    let mut failed_status: Option<i32> = None;
    for chunk in dest.chunks_mut(1 << 24) {
        // SAFETY: `chunk` is valid, writable memory of length `chunk.len() <= 2^24 < u32::MAX`.
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            failed_status = Some(status);
            break;
        }
    }
    if let Some(status) = failed_status {
        zeroize_bytes(dest);
        return Err(WilisError::RandomSourceError(format!(
            "BCryptGenRandom failed with NTSTATUS 0x{:08x}",
            status as u32
        )));
    }
    Ok(())
}

/// Generates a fresh 256-bit random [`SecretKey`].
pub fn generate_key() -> Result<SecretKey> {
    let mut raw = [0u8; KEY_BYTES];
    fill_random(&mut raw)?;
    let key = SecretKey::from_bytes(raw);
    zeroize_bytes(&mut raw);
    Ok(key)
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
