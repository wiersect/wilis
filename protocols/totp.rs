//! RFC 4226 / RFC 6238-style HOTP & TOTP 2FA One-Time Password generator (`WilisTOTP`)
//! built strictly on `WilisMAC-256` with pure-Rust RFC 4648 Base32 decoding.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::constants::KEY_BYTES;
use crate::error::{Result, WilisError};
use crate::hash::hash;
use crate::mac::mac;
use crate::utils::constant_time::ct_eq;
use crate::utils::zeroize::zeroize_bytes;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes arbitrary bytes into canonical RFC 4648 Base32 (no padding).
pub fn encode_base32(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buffer = (buffer << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

/// Decodes RFC 4648 Base32 text (case-insensitive, ignores spaces/hyphens and optional `=` padding).
pub fn decode_base32(input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for ch in input.bytes() {
        if ch.is_ascii_whitespace() || ch == b'-' || ch == b'=' {
            continue;
        }
        let val: u32 = match ch {
            b'A'..=b'Z' => (ch - b'A') as u32,
            b'a'..=b'z' => (ch - b'a') as u32,
            b'2'..=b'7' => (ch - b'2' + 26) as u32,
            _ => {
                zeroize_bytes(&mut out);
                return Err(WilisError::InvalidEncoding(format!(
                    "invalid Base32 character: '{}'",
                    ch as char
                )));
            }
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    if out.is_empty() {
        return Err(WilisError::InvalidEncoding("empty Base32 secret".into()));
    }
    Ok(out)
}

/// Computes an RFC-4226 dynamic-truncation HOTP code (`6..=8` digits) powered by `WilisMAC-256`.
pub fn generate_hotp(secret: &[u8], counter: u64, digits: u32) -> Result<String> {
    if secret.is_empty() {
        return Err(WilisError::InvalidKey("OTP secret must not be empty".into()));
    }
    if !(6..=8).contains(&digits) {
        return Err(WilisError::InvalidParameters(
            "OTP digits must be in 6..=8".into(),
        ));
    }

    // Derive fixed 256-bit MAC key from arbitrary-length secret
    let mut mac_key = [0u8; KEY_BYTES];
    if secret.len() == KEY_BYTES {
        mac_key.copy_from_slice(secret);
    } else {
        let mut tagged = Vec::with_capacity(12 + secret.len());
        tagged.extend_from_slice(b"WTOTP_KEY_V1");
        tagged.extend_from_slice(secret);
        mac_key = hash(&tagged);
        zeroize_bytes(&mut tagged);
    }

    let tag = mac(&mac_key, &counter.to_be_bytes());
    zeroize_bytes(&mut mac_key);

    let offset = (tag[31] & 0x1B) as usize; // 0..=27 so offset+4 <= 31
    let bin_code = (((tag[offset] & 0x7F) as u32) << 24)
        | ((tag[offset + 1] as u32) << 16)
        | ((tag[offset + 2] as u32) << 8)
        | (tag[offset + 3] as u32);
    let modulus = 10u32.pow(digits);
    let code = bin_code % modulus;
    Ok(format!("{:0width$}", code, width = digits as usize))
}

/// Computes a TOTP code for `unix_secs` and `period` (typically 30s), returning `(code, seconds_remaining)`.
pub fn generate_totp_at(
    secret: &[u8],
    unix_secs: u64,
    period: u64,
    digits: u32,
) -> Result<(String, u64)> {
    if period == 0 {
        return Err(WilisError::InvalidParameters("TOTP period must be > 0".into()));
    }
    let step = unix_secs / period;
    let remaining = period - (unix_secs % period);
    let code = generate_hotp(secret, step, digits)?;
    Ok((code, remaining))
}

/// Computes the current TOTP code from the system wall clock (default 30s period, 6 digits).
pub fn generate_totp_now(secret: &[u8], period: u64, digits: u32) -> Result<(String, u64)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| WilisError::InvalidParameters("system clock before UNIX epoch".into()))?
        .as_secs();
    generate_totp_at(secret, now, period, digits)
}

/// Verifies `candidate_code` against `unix_secs` within `+/- skew_steps` in constant time.
pub fn verify_totp_at(
    secret: &[u8],
    candidate_code: &str,
    unix_secs: u64,
    period: u64,
    digits: u32,
    skew_steps: u64,
) -> Result<bool> {
    if period == 0 {
        return Err(WilisError::InvalidParameters("TOTP period must be > 0".into()));
    }
    let step = unix_secs / period;
    let start = step.saturating_sub(skew_steps);
    let end = step.saturating_add(skew_steps);
    let mut matched = false;
    for s in start..=end {
        let expected = generate_hotp(secret, s, digits)?;
        if ct_eq(expected.as_bytes(), candidate_code.as_bytes()) {
            matched = true;
        }
    }
    Ok(matched)
}
