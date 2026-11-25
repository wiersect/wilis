//! OS-level process memory hardening, locked secret buffers (`mlock`/`VirtualLock`),
//! and multi-pass secure file shredding (`wilis shred`).
//!
//! Zero external dependencies: binds directly to standard OS symbols (`libc` on Unix,
//! `kernel32` on Windows) with graceful fallback when unprivileged containers or low
//! `RLIMIT_MEMLOCK` quotas prevent locking pages.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Result, WilisError};
use crate::utils::hex::encode_hex;
use crate::utils::random::fill_random;
use crate::utils::zeroize::zeroize_bytes;

#[cfg(unix)]
mod os {
    use core::ffi::{c_int, c_void};

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[repr(C)]
    struct Rlimit {
        rlim_cur: u64,
        rlim_max: u64,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const RLIMIT_CORE: c_int = 4;

    #[cfg(target_os = "linux")]
    const PR_SET_DUMPABLE: c_int = 4;

    extern "C" {
        fn mlock(addr: *const c_void, len: usize) -> c_int;
        fn munlock(addr: *const c_void, len: usize) -> c_int;

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        fn setrlimit(resource: c_int, rlim: *const Rlimit) -> c_int;

        #[cfg(target_os = "linux")]
        fn prctl(option: c_int, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> c_int;
    }

    pub fn harden_process() {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let zero_limit = Rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: Valid pointer to properly laid-out `rlimit` struct for `RLIMIT_CORE`.
            unsafe {
                let _ = setrlimit(RLIMIT_CORE, &zero_limit);
            }
        }
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `PR_SET_DUMPABLE` takes a single boolean integer argument (0 = undumpable).
            unsafe {
                let _ = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
            }
        }
    }

    pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        // SAFETY: `ptr` points to a live allocation of at least `len` bytes.
        unsafe { mlock(ptr as *const c_void, len) == 0 }
    }

    pub fn unlock_memory(ptr: *const u8, len: usize) {
        if len == 0 {
            return;
        }
        // SAFETY: `ptr` and `len` match the prior `mlock` call on this live allocation.
        unsafe {
            let _ = munlock(ptr as *const c_void, len);
        }
    }
}

#[cfg(windows)]
mod os {
    use core::ffi::c_void;

    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualLock(lp_address: *const c_void, dw_size: usize) -> i32;
        fn VirtualUnlock(lp_address: *const c_void, dw_size: usize) -> i32;
        fn SetErrorMode(u_mode: u32) -> u32;
    }

    pub fn harden_process() {
        // SAFETY: `SetErrorMode` is a thread-safe process error-mode flag setter.
        unsafe {
            let _ = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        }
    }

    pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        // SAFETY: `ptr` points to a live allocation of at least `len` bytes.
        unsafe { VirtualLock(ptr as *const c_void, len) != 0 }
    }

    pub fn unlock_memory(ptr: *const u8, len: usize) {
        if len == 0 {
            return;
        }
        // SAFETY: `ptr` and `len` match the prior `VirtualLock` call on this live allocation.
        unsafe {
            let _ = VirtualUnlock(ptr as *const c_void, len);
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod os {
    pub fn harden_process() {}
    pub fn lock_memory(_ptr: *const u8, _len: usize) -> bool {
        false
    }
    pub fn unlock_memory(_ptr: *const u8, _len: usize) {}
}

/// Applies best-effort OS process hardening against core dumps and unauthorized tracing:
/// - Unix: sets `RLIMIT_CORE = 0` (disables core dumps); on Linux also calls
///   `prctl(PR_SET_DUMPABLE, 0)` to block non-root `ptrace` attachment.
/// - Windows: disables crash error dialogs/WER boxes via `SetErrorMode`.
pub fn harden_process_memory() {
    os::harden_process();
}

/// A fixed-address heap buffer that attempts to pin its memory pages in RAM
/// (`mlock` on Unix / `VirtualLock` on Windows) to prevent swapping secrets to disk,
/// redacts `Debug` output, and unconditionally volatile-zeroizes before unlocking on drop.
pub struct LockedBuf {
    buf: Box<[u8]>,
    locked: bool,
}

impl LockedBuf {
    /// Allocates a zero-initialized locked buffer of `len` bytes.
    pub fn new(len: usize) -> Self {
        let buf = vec![0u8; len].into_boxed_slice();
        let locked = os::lock_memory(buf.as_ptr(), buf.len());
        Self { buf, locked }
    }

    /// Allocates a locked buffer initialized with a copy of `data`.
    pub fn from_slice(data: &[u8]) -> Self {
        let mut lb = Self::new(data.len());
        lb.buf.copy_from_slice(data);
        lb
    }

    /// Returns `true` if the OS successfully pinned the backing pages in RAM.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl fmt::Debug for LockedBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LockedBuf([REDACTED], len={}, locked={})",
            self.buf.len(),
            self.locked
        )
    }
}

impl Drop for LockedBuf {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.buf);
        if self.locked {
            os::unlock_memory(self.buf.as_ptr(), self.buf.len());
        }
    }
}

/// Securely overwrites a regular file in-place with `passes` passes (`passes - 1` CSPRNG
/// passes followed by a final all-zero pass), calls `sync_all()` after every pass,
/// truncates the file to 0 bytes, renames it to a random sibling name to obscure its
/// directory entry, and removes it.
///
/// Safety guarantees:
/// - Strictly rejects symlinks and directories (never follows symbolic links).
/// - On Unix, verifies `(dev, ino)` match between `symlink_metadata` and opened handle
///   to defeat TOCTOU symlink-swap races.
/// - Note: On copy-on-write filesystems (APFS, Btrfs, ZFS) or wear-leveled SSDs,
///   in-place overwrite is best-effort and full-disk encryption remains recommended.
pub fn shred_file(path: &Path, passes: usize) -> Result<()> {
    if passes == 0 || passes > 32 {
        return Err(WilisError::InvalidParameters(
            "shred passes must be within 1..=32".into(),
        ));
    }

    let sym_meta = fs::symlink_metadata(path)?;
    if sym_meta.file_type().is_symlink() {
        return Err(WilisError::InvalidFormat(format!(
            "refusing to shred symbolic link '{}'",
            path.display()
        )));
    }
    if !sym_meta.file_type().is_file() {
        return Err(WilisError::InvalidFormat(format!(
            "refusing to shred non-regular file '{}'",
            path.display()
        )));
    }

    let mut file = OpenOptions::new().write(true).open(path)?;
    let f_meta = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if sym_meta.dev() != f_meta.dev() || sym_meta.ino() != f_meta.ino() {
            return Err(WilisError::InvalidFormat(format!(
                "file '{}' changed during shred open (TOCTOU detected)",
                path.display()
            )));
        }
    }

    let file_len = f_meta.len();
    let mut buf = vec![0u8; 64 * 1024];

    let wipe_res = (|| -> Result<()> {
        for pass in 0..passes {
            let is_final_zero_pass = pass + 1 == passes;
            file.seek(SeekFrom::Start(0))?;
            let mut remaining = file_len;
            while remaining > 0 {
                let chunk = remaining.min(buf.len() as u64) as usize;
                if is_final_zero_pass {
                    buf[..chunk].fill(0);
                } else {
                    fill_random(&mut buf[..chunk])?;
                }
                file.write_all(&buf[..chunk])?;
                remaining -= chunk as u64;
            }
            file.sync_all()?;
        }
        file.set_len(0)?;
        file.sync_all()?;
        Ok(())
    })();
    zeroize_bytes(&mut buf);
    drop(file);
    wipe_res?;

    // Obfuscate original filename in the parent directory entry before unlinking
    let mut rnd = [0u8; 8];
    fill_random(&mut rnd)?;
    let obf_name = format!(".wilis-shred-{}", encode_hex(&rnd));
    let obf_path: PathBuf = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(obf_name),
        _ => PathBuf::from(obf_name),
    };

    if !obf_path.exists() && fs::rename(path, &obf_path).is_ok() {
        fs::remove_file(&obf_path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}
