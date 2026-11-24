//! Volatile memory wiping utilities, auto-zeroizing secret key wrapper, and
//! symlink-safe atomic file persistence (`O_EXCL` + CSPRNG temp suffix + `sync_all`).

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

use crate::core::constants::KEY_BYTES;
use crate::error::{Result, WilisError};
use crate::utils::hex::encode_hex;
use crate::utils::random::fill_random;

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

/// Creates a uniquely named sibling temporary file next to `target` using OS CSPRNG
/// entropy and `create_new(true)` (`O_CREAT | O_EXCL` on Unix, `CREATE_NEW` on Windows).
///
/// Guarantees:
/// - Never follows pre-existing symlinks (immune to predictable `.tmp` symlink attacks).
/// - Never collides across concurrent `wilis` invocations in the same directory.
/// - Sets strict `0600` permissions from file creation on Unix when `owner_only == true`.
pub fn create_unique_temp_file(target: &Path, owner_only: bool) -> Result<(PathBuf, File)> {
    let _ = owner_only; // Enforced via 0600 mode on Unix platforms
    let mut rnd = [0u8; 8];
    for _ in 0..16 {
        fill_random(&mut rnd)?;
        let suffix = encode_hex(&rnd);
        let mut tmp_os = target.as_os_str().to_os_string();
        tmp_os.push(".wilis-");
        tmp_os.push(&suffix);
        tmp_os.push(".tmp");
        let tmp_path = PathBuf::from(tmp_os);

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        if owner_only {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        match opts.open(&tmp_path) {
            Ok(file) => {
                #[cfg(unix)]
                if owner_only {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(e) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
                        drop(file);
                        let _ = fs::remove_file(&tmp_path);
                        return Err(e.into());
                    }
                }
                return Ok((tmp_path, file));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Err(WilisError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to allocate unique temporary file after 16 attempts",
    )))
}

/// Atomically writes `data` to `target` via a CSPRNG-named `O_EXCL` sibling temp file,
/// calls `sync_all()` for crash durability, and renames onto `target`.
///
/// When `owner_only == true`, enforces Unix `0600` permissions from birth and refuses to
/// replace a symbolic link at `target`.
pub fn write_atomic_file(target: &Path, data: &[u8], owner_only: bool) -> Result<()> {
    if owner_only {
        if let Ok(meta) = fs::symlink_metadata(target) {
            if meta.file_type().is_symlink() {
                return Err(WilisError::InvalidFormat(format!(
                    "refusing to write sensitive file through/onto symlink '{}'",
                    target.display()
                )));
            }
        }
    }

    let (tmp_path, mut file) = create_unique_temp_file(target, owner_only)?;
    let write_and_sync = (|| -> io::Result<()> {
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);

    if let Err(e) = write_and_sync {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }

    if let Err(e) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    Ok(())
}

/// Atomically writes sensitive key/vault bytes to `path` with strict owner-only
/// permissions (`0600` on Unix), `O_EXCL` temp creation, and `sync_all()` durability.
pub fn write_secret_file(path: &Path, data: &[u8]) -> Result<()> {
    write_atomic_file(path, data, true)
}

/// Returns `true` if two filesystem paths refer to the exact same underlying file
/// (matching normalized paths, canonical symlink targets, and Unix device+inode for hard links).
pub fn paths_refer_to_same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    if let (Ok(ca), Ok(cb)) = (fs::canonicalize(a), fs::canonicalize(b)) {
        if ca == cb {
            return true;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(ma), Ok(mb)) = (fs::metadata(a), fs::metadata(b)) {
            if ma.dev() == mb.dev() && ma.ino() == mb.ino() {
                return true;
            }
        }
    }
    false
}
