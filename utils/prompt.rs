//! Cross-platform terminal passphrase prompting & 2FA keyfile hashing (zero dependencies).

use std::fs::File;
use std::io::{self, BufRead, Read, Write};

use crate::core::constants::HASH_BYTES;
use crate::error::{Result, WilisError};
use crate::hash::WilisHash;
use crate::utils::constant_time::ct_eq;
use crate::utils::zeroize::zeroize_bytes;

/// RAII guard that disables terminal echo on Unix (`stty -echo`) and restores it on drop.
#[cfg(unix)]
struct EchoGuard {
    active: bool,
}

#[cfg(unix)]
impl EchoGuard {
    fn disable() -> Self {
        let ok = std::process::Command::new("stty")
            .arg("-echo")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        Self { active: ok }
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = std::process::Command::new("stty").arg("echo").status();
        }
    }
}

/// RAII guard on Windows using `SetConsoleMode` to disable `ENABLE_ECHO_INPUT`.
#[cfg(windows)]
struct EchoGuard {
    handle: *mut core::ffi::c_void,
    original_mode: u32,
    active: bool,
}

#[cfg(windows)]
impl EchoGuard {
    fn disable() -> Self {
        const STD_INPUT_HANDLE: u32 = (-10i32) as u32;
        const ENABLE_ECHO_INPUT: u32 = 0x0004;

        #[link(name = "kernel32")]
        extern "system" {
            fn GetStdHandle(n_std_handle: u32) -> *mut core::ffi::c_void;
            fn GetConsoleMode(h_console_handle: *mut core::ffi::c_void, lp_mode: *mut u32) -> i32;
            fn SetConsoleMode(h_console_handle: *mut core::ffi::c_void, dw_mode: u32) -> i32;
        }

        // SAFETY: Standard Win32 console handle queries on process stdin.
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode: u32 = 0;
            if !handle.is_null() && GetConsoleMode(handle, &mut mode) != 0 {
                let ok = SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) != 0;
                return Self {
                    handle,
                    original_mode: mode,
                    active: ok,
                };
            }
        }
        Self {
            handle: core::ptr::null_mut(),
            original_mode: 0,
            active: false,
        }
    }
}

#[cfg(windows)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        if self.active {
            #[link(name = "kernel32")]
            extern "system" {
                fn SetConsoleMode(h_console_handle: *mut core::ffi::c_void, dw_mode: u32) -> i32;
            }
            // SAFETY: Restores the original console mode captured in `disable()`.
            unsafe {
                let _ = SetConsoleMode(self.handle, self.original_mode);
            }
        }
    }
}

/// Prompts the user for a passphrase with terminal echo disabled (prevents shoulder-surfing
/// and keeps secrets out of shell command history).
pub fn read_hidden_passphrase(prompt: &str, confirm: bool) -> Result<String> {
    let mut first = prompt_once(prompt)?;
    if first.is_empty() {
        return Err(WilisError::InvalidKey(
            "passphrase must not be empty".to_string(),
        ));
    }
    if confirm {
        let mut second = match prompt_once("Confirm passphrase: ") {
            Ok(s) => s,
            Err(e) => {
                // SAFETY: Overwriting UTF-8 string bytes with 0x00 preserves UTF-8 validity.
                zeroize_bytes(unsafe { first.as_bytes_mut() });
                return Err(e);
            }
        };
        let matches = ct_eq(first.as_bytes(), second.as_bytes());
        // SAFETY: Overwriting UTF-8 string bytes with 0x00 preserves UTF-8 validity.
        zeroize_bytes(unsafe { second.as_bytes_mut() });
        if !matches {
            zeroize_bytes(unsafe { first.as_bytes_mut() });
            return Err(WilisError::InvalidKey(
                "passphrases do not match".to_string(),
            ));
        }
    }
    Ok(first)
}

fn prompt_once(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;

    let _guard = EchoGuard::disable();
    let mut line = String::new();
    let stdin = io::stdin();
    let read_res = stdin.lock().read_line(&mut line);
    drop(_guard);
    eprintln!();
    if let Err(e) = read_res {
        // SAFETY: Overwriting UTF-8 string bytes with 0x00 preserves UTF-8 validity.
        zeroize_bytes(unsafe { line.as_bytes_mut() });
        return Err(e.into());
    }

    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// Streams a keyfile through `WilisHash-256` to produce a 256-bit 2FA keyfile digest.
pub fn hash_keyfile(path: &str) -> Result<[u8; HASH_BYTES]> {
    let mut file = File::open(path)?;
    let mut hasher = WilisHash::new();
    let mut buf = [0u8; 64 * 1024];

    let read_res = (|| -> Result<u64> {
        let mut total: u64 = 0;
        loop {
            let n = match file.read(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total = total.saturating_add(n as u64);
        }
        Ok(total)
    })();
    zeroize_bytes(&mut buf);
    let total = read_res?;

    if total == 0 {
        return Err(WilisError::InvalidKey(format!(
            "keyfile '{path}' is empty"
        )));
    }

    Ok(hasher.finalize())
}
