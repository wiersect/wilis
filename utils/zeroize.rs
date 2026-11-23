//! Volatile memory wiping utilities and auto-zeroizing secret key wrapper.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

use crate::core::constants::KEY_BYTES;
use crate::error::Result;

/// Securely overwrites a byte slice with zeros using volatile writes so the
/// compiler cannot optimize away the wipe as a dead store.
pub fn zeroize_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, mutable reference within `buf`.
        unsafe {
            ptr::write_volatile(byte as *mut u8, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Securely overwrites a `u64` slice with zeros using volatile writes.
pub fn zeroize_u64_slice(buf: &mut [u64]) {
    for word in buf.iter_mut() {
        // SAFETY: `word` is a valid, aligned, mutable reference within `buf`.
        unsafe {
            ptr::write_volatile(word as *mut u64, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// A 256-bit secret key wrapper that redacts debug formatting and automatically
/// wipes its bytes from memory when dropped.
#[derive(Clone)]
pub struct SecretKey {
    bytes: [u8; KEY_BYTES],
}

impl SecretKey {
    /// Wraps a raw 32-byte key.
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self { bytes }
    }

    /// Exposes the underlying 32-byte array for cryptographic operations.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.bytes);
    }
}

/// Writes sensitive key/vault bytes to `path` with strict owner-only permissions (`0600`)
/// on Unix platforms so other local users cannot read secret key files.
pub fn write_secret_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

/// Returns `true` if two filesystem paths point to the exact same file (blocks in-place truncation).
pub fn paths_refer_to_same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => false,
    }
}
