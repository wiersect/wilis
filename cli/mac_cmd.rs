//! CLI handlers for `WilisMAC` (`mac`, `mac-verify`) and OS CSPRNG (`rand`).

use std::fs::File;
use std::io::Read;

use crate::core::constants::{KEY_BYTES, TAG_BYTES};
use crate::error::{Result, WilisError};
use crate::mac::WilisMac;
use crate::utils::constant_time::ct_eq;
use crate::utils::hex::{decode_hex, encode_hex};
use crate::utils::random::fill_random;
use crate::utils::zeroize::{zeroize_bytes, SecretKey};

fn compute_file_mac(key: &[u8; KEY_BYTES], path: &str) -> Result<[u8; TAG_BYTES]> {
    let mut m = WilisMac::new(key);
    let mut buf = [0u8; 64 * 1024];
    let read_res = (|| -> Result<()> {
        if path == "-" {
            let stdin = std::io::stdin();
            let mut reader = stdin.lock();
            loop {
                let n = match reader.read(&mut buf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                };
                if n == 0 {
                    break;
                }
                m.update(&buf[..n]);
            }
        } else {
            let mut f = File::open(path)?;
            loop {
                let n = match f.read(&mut buf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                };
                if n == 0 {
                    break;
                }
                m.update(&buf[..n]);
            }
        }
        Ok(())
    })();
    zeroize_bytes(&mut buf);
    read_res?;
    Ok(m.finalize())
}

/// Computes and prints a 256-bit `WilisMAC` hex tag for a file or UTF-8 string.
pub fn run_mac(key: SecretKey, file_path: Option<&str>, text: Option<&str>) -> Result<()> {
    let tag = match (file_path, text) {
        (Some(p), None) => compute_file_mac(key.as_bytes(), p)?,
        (None, Some(t)) => crate::mac::mac(key.as_bytes(), t.as_bytes()),
        _ => {
            return Err(WilisError::CliUsage(
                "mac requires either --file <PATH> or <TEXT>".into(),
            ));
        }
    };
    println!("{}", encode_hex(&tag));
    Ok(())
}

/// Verifies a 256-bit `WilisMAC` hex tag in constant time.
pub fn run_mac_verify(
    key: SecretKey,
    expected_hex: &str,
    file_path: Option<&str>,
    text: Option<&str>,
) -> Result<()> {
    let expected_bytes = decode_hex(expected_hex)?;
    if expected_bytes.len() != TAG_BYTES {
        return Err(WilisError::InvalidEncoding(format!(
            "expected {}-byte (64-hex) MAC tag, got {} bytes",
            TAG_BYTES,
            expected_bytes.len()
        )));
    }
    let actual = match (file_path, text) {
        (Some(p), None) => compute_file_mac(key.as_bytes(), p)?,
        (None, Some(t)) => crate::mac::mac(key.as_bytes(), t.as_bytes()),
        _ => {
            return Err(WilisError::CliUsage(
                "mac-verify requires either --file <PATH> or <TEXT>".into(),
            ));
        }
    };

    if ct_eq(&actual, &expected_bytes) {
        println!("MAC VALID");
        Ok(())
    } else {
        Err(WilisError::AuthenticationFailed)
    }
}

/// Generates `num_bytes` cryptographically secure random bytes as lowercase hex.
pub fn run_rand(num_bytes: usize) -> Result<()> {
    if num_bytes == 0 || num_bytes > 1024 * 1024 {
        return Err(WilisError::InvalidParameters(
            "rand byte count must be within 1..=1048576".into(),
        ));
    }
    let mut buf = vec![0u8; num_bytes];
    fill_random(&mut buf)?;
    let mut hex = encode_hex(&buf);
    zeroize_bytes(&mut buf);
    println!("{hex}");
    // SAFETY: Overwriting UTF-8 hex bytes with 0x00 preserves UTF-8 validity.
    zeroize_bytes(unsafe { hex.as_bytes_mut() });
    Ok(())
}
