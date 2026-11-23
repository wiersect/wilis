//! Secure hidden terminal passphrase prompting & 2FA keyfile hashing (zero dependencies).

use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::process::Command;

use crate::core::constants::HASH_BYTES;
use crate::error::{Result, WilisError};
use crate::hash::WilisHash;

/// RAII guard that disables terminal echo via `stty -echo` and restores it on drop.
struct EchoGuard {
    active: bool,
}

impl EchoGuard {
    fn disable() -> Self {
        let ok = Command::new("stty")
            .arg("-echo")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        Self { active: ok }
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = Command::new("stty").arg("echo").status();
        }
    }
}

/// Prompts the user for a passphrase with terminal echo disabled (prevents shoulder-surfing
/// and keeps secrets out of shell command history).
pub fn read_hidden_passphrase(prompt: &str, confirm: bool) -> Result<String> {
    let first = prompt_once(prompt)?;
    if first.is_empty() {
        return Err(WilisError::InvalidKey(
            "passphrase must not be empty".to_string(),
        ));
    }
    if confirm {
        let second = prompt_once("Confirm passphrase: ")?;
        if first != second {
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
    stdin.lock().read_line(&mut line)?;
    drop(_guard);
    eprintln!();

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
    let mut total: u64 = 0;

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }

    if total == 0 {
        return Err(WilisError::InvalidKey(format!(
            "keyfile '{path}' is empty"
        )));
    }

    Ok(hasher.finalize())
}
