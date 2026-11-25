//! Format-Preserving Encryption (`WilisFPE`) using a 10-round balanced Feistel network
//! keyed by `WilisMAC-256` with cycle-walking over arbitrary alphabets (radix `2..=256`).
//!
//! Encrypts strings such as numeric IDs (`"0123456789"`), tokens, or hex codes while
//! strictly preserving length and character set, with exact mathematical invertibility.

use crate::core::constants::KEY_BYTES;
use crate::error::{Result, WilisError};
use crate::mac::WilisMac;

const FPE_ROUNDS: u8 = 10;

fn feistel_round_prf(
    key: &[u8; KEY_BYTES],
    tweak: &[u8],
    round: u8,
    radix: u32,
    right: &[u8],
    target_len: usize,
) -> Vec<u8> {
    let mut m = WilisMac::new(key);
    m.update(b"WFPE_RND_V1:");
    m.update(&[round]);
    m.update(&radix.to_le_bytes());
    m.update(&(target_len as u32).to_le_bytes());
    m.update(&(tweak.len() as u64).to_le_bytes());
    m.update(tweak);
    m.update(&(right.len() as u32).to_le_bytes());
    m.update(right);
    let mut digest = m.finalize();

    // Unbiased rejection sampling from WilisXOF over [0, radix)
    let mut xof = crate::xof::WilisXof::new(b"WFPE_EXP_V1");
    xof.absorb(&digest);
    crate::utils::zeroize::zeroize_bytes(&mut digest);

    let limit = (u32::MAX / radix) * radix;
    let mut out = Vec::with_capacity(target_len);
    let mut buf = [0u8; 32];
    let mut idx = 32;
    while out.len() < target_len {
        if idx + 4 > 32 {
            xof.squeeze(&mut buf);
            idx = 0;
        }
        let val = u32::from_le_bytes([buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]]);
        idx += 4;
        if val < limit {
            out.push((val % radix) as u8);
        }
    }
    crate::utils::zeroize::zeroize_bytes(&mut buf);
    out
}

/// Encrypts a sequence of base-`radix` digits (`len >= 2`, `2 <= radix <= 256`) preserving length & radix.
pub fn fpe_encrypt_digits(
    key: &[u8; KEY_BYTES],
    tweak: &[u8],
    radix: u32,
    digits: &[u8],
) -> Result<Vec<u8>> {
    if !(2..=256).contains(&radix) {
        return Err(WilisError::InvalidParameters("FPE radix must be 2..=256".into()));
    }
    if digits.len() < 2 {
        return Err(WilisError::InvalidParameters(
            "FPE input length must be at least 2 symbols".into(),
        ));
    }
    if digits.iter().any(|&d| (d as u32) >= radix) {
        return Err(WilisError::InvalidEncoding(
            "FPE digit exceeds radix".into(),
        ));
    }

    let u = digits.len() / 2;
    let mut left = digits[..u].to_vec();
    let mut right = digits[u..].to_vec();

    for round in 0..FPE_ROUNDS {
        let mask = feistel_round_prf(key, tweak, round, radix, &right, left.len());
        let mut next_right = Vec::with_capacity(left.len());
        for i in 0..left.len() {
            next_right.push((((left[i] as u32) + (mask[i] as u32)) % radix) as u8);
        }
        left = right;
        right = next_right;
    }

    let mut out = Vec::with_capacity(digits.len());
    out.extend_from_slice(&left);
    out.extend_from_slice(&right);
    Ok(out)
}

/// Exact inverse of [`fpe_encrypt_digits`].
pub fn fpe_decrypt_digits(
    key: &[u8; KEY_BYTES],
    tweak: &[u8],
    radix: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if !(2..=256).contains(&radix) {
        return Err(WilisError::InvalidParameters("FPE radix must be 2..=256".into()));
    }
    if ciphertext.len() < 2 {
        return Err(WilisError::InvalidParameters(
            "FPE input length must be at least 2 symbols".into(),
        ));
    }
    if ciphertext.iter().any(|&d| (d as u32) >= radix) {
        return Err(WilisError::InvalidEncoding(
            "FPE digit exceeds radix".into(),
        ));
    }

    let u = ciphertext.len() / 2;
    // After an even number of rounds (10), left has length u and right has length len - u
    let mut left = ciphertext[..u].to_vec();
    let mut right = ciphertext[u..].to_vec();

    for round in (0..FPE_ROUNDS).rev() {
        let prev_right = left;
        let mask = feistel_round_prf(key, tweak, round, radix, &prev_right, right.len());
        let mut prev_left = Vec::with_capacity(right.len());
        for i in 0..right.len() {
            prev_left.push((((right[i] as u32) + radix - (mask[i] as u32)) % radix) as u8);
        }
        left = prev_left;
        right = prev_right;
    }

    let mut out = Vec::with_capacity(ciphertext.len());
    out.extend_from_slice(&left);
    out.extend_from_slice(&right);
    Ok(out)
}

/// Format-preserving string encryption over a unique-character `alphabet` (2..=256 chars).
pub fn fpe_encrypt_str(
    key: &[u8; KEY_BYTES],
    tweak: &[u8],
    alphabet: &str,
    plaintext: &str,
) -> Result<String> {
    let alpha: Vec<char> = alphabet.chars().collect();
    if !(2..=256).contains(&alpha.len()) {
        return Err(WilisError::InvalidParameters(
            "FPE alphabet must contain 2..=256 unique characters".into(),
        ));
    }
    for i in 0..alpha.len() {
        if alpha[i + 1..].contains(&alpha[i]) {
            return Err(WilisError::InvalidParameters(
                "FPE alphabet contains duplicate characters".into(),
            ));
        }
    }
    let mut digits = Vec::new();
    for ch in plaintext.chars() {
        let pos = alpha.iter().position(|&c| c == ch).ok_or_else(|| {
            WilisError::InvalidEncoding(format!("character '{ch}' not in FPE alphabet"))
        })?;
        digits.push(pos as u8);
    }
    let enc = fpe_encrypt_digits(key, tweak, alpha.len() as u32, &digits)?;
    Ok(enc.into_iter().map(|d| alpha[d as usize]).collect())
}

/// Exact inverse of [`fpe_encrypt_str`].
pub fn fpe_decrypt_str(
    key: &[u8; KEY_BYTES],
    tweak: &[u8],
    alphabet: &str,
    ciphertext: &str,
) -> Result<String> {
    let alpha: Vec<char> = alphabet.chars().collect();
    if !(2..=256).contains(&alpha.len()) {
        return Err(WilisError::InvalidParameters(
            "FPE alphabet must contain 2..=256 unique characters".into(),
        ));
    }
    for i in 0..alpha.len() {
        if alpha[i + 1..].contains(&alpha[i]) {
            return Err(WilisError::InvalidParameters(
                "FPE alphabet contains duplicate characters".into(),
            ));
        }
    }
    let mut digits = Vec::new();
    for ch in ciphertext.chars() {
        let pos = alpha.iter().position(|&c| c == ch).ok_or_else(|| {
            WilisError::InvalidEncoding(format!("character '{ch}' not in FPE alphabet"))
        })?;
        digits.push(pos as u8);
    }
    let dec = fpe_decrypt_digits(key, tweak, alpha.len() as u32, &digits)?;
    Ok(dec.into_iter().map(|d| alpha[d as usize]).collect())
}
