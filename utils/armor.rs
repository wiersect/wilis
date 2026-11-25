//! PEM-style ASCII Armor (`WilisArmor`) with 64-character canonical Base64 wrapping
//! and a domain-separated 24-bit `WilisHash-256` integrity checksum.
//!
//! Format:
//! ```text
//! -----BEGIN WILIS MESSAGE-----
//! Version: Wilis v0.5.0
//!
//! <64-char Base64 lines>
//! =<4-char Base64 of 24-bit WilisHash-256 checksum>
//! -----END WILIS MESSAGE-----
//! ```

use crate::error::{Result, WilisError};
use crate::hash::WilisHash;
use crate::utils::base64::{decode_base64, encode_base64};
use crate::utils::constant_time::ct_eq;
use crate::utils::zeroize::zeroize_bytes;

/// Armor block label for `WILS` symmetric encrypted messages/containers.
pub const ARMOR_MESSAGE: &str = "WILIS MESSAGE";

/// Armor block label for `WPKE` post-quantum public-key encrypted payloads.
pub const ARMOR_ENCRYPTED: &str = "WILIS ENCRYPTED";

/// Armor block label for `WSIG` post-quantum digital signatures.
pub const ARMOR_SIGNATURE: &str = "WILIS SIGNATURE";

/// Armor block label for `WKP1`/`WPK1` post-quantum public keys.
pub const ARMOR_PUBLIC_KEY: &str = "WILIS PUBLIC KEY";

const BEGIN_PREFIX: &str = "-----BEGIN ";
const END_PREFIX: &str = "-----END ";
const FENCE_SUFFIX: &str = "-----";
const LINE_WIDTH: usize = 64;
const MAX_ARMOR_HEADERS: usize = 16;

fn validate_armor_label(label: &str) -> Result<()> {
    if label.is_empty()
        || label.len() > 48
        || label.starts_with(' ')
        || label.ends_with(' ')
        || !label
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' ' || b == b'-')
    {
        return Err(WilisError::InvalidEncoding(format!(
            "invalid WilisArmor block label '{label}'"
        )));
    }
    Ok(())
}

fn compute_armor_checksum(label: &str, data: &[u8]) -> [u8; 3] {
    let mut h = WilisHash::new();
    h.update(b"WARM_CHK_V1");
    h.update(&(label.len() as u64).to_le_bytes());
    h.update(label.as_bytes());
    h.update(&(data.len() as u64).to_le_bytes());
    h.update(data);
    let digest = h.finalize();
    [digest[0], digest[1], digest[2]]
}

/// Returns `true` if `text` begins with a PEM-style `-----BEGIN ` armor header.
#[inline]
pub fn looks_armored(text: &str) -> bool {
    text.trim_start().starts_with(BEGIN_PREFIX)
}

/// Encodes `data` into a canonical `WilisArmor` block with 64-char Base64 wrapping
/// and a 24-bit `WilisHash-256` integrity checksum.
pub fn armor_encode(label: &str, data: &[u8]) -> Result<String> {
    validate_armor_label(label)?;
    let b64 = encode_base64(data);
    let chk = compute_armor_checksum(label, data);
    let chk_b64 = encode_base64(&chk);

    let mut out = String::with_capacity(b64.len() + b64.len() / LINE_WIDTH + 128);
    out.push_str(BEGIN_PREFIX);
    out.push_str(label);
    out.push_str(FENCE_SUFFIX);
    out.push('\n');
    out.push_str("Version: Wilis v");
    out.push_str(env!("CARGO_PKG_VERSION"));
    out.push_str("\n\n");

    let mut pos = 0;
    while pos < b64.len() {
        let end = (pos + LINE_WIDTH).min(b64.len());
        out.push_str(&b64[pos..end]);
        out.push('\n');
        pos = end;
    }

    out.push('=');
    out.push_str(&chk_b64);
    out.push('\n');
    out.push_str(END_PREFIX);
    out.push_str(label);
    out.push_str(FENCE_SUFFIX);
    Ok(out)
}

/// Decodes and integrity-verifies a `WilisArmor` block, returning `(label, raw_bytes)`.
///
/// Rejects mismatched BEGIN/END labels, missing or corrupted 24-bit checksums,
/// non-canonical Base64 padding, and trailing data outside the armor block.
pub fn armor_decode(text: &str, expected_label: Option<&str>) -> Result<(String, Vec<u8>)> {
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .collect();

    let first_idx = lines
        .iter()
        .position(|l| !l.trim().is_empty())
        .ok_or_else(|| WilisError::InvalidEncoding("empty WilisArmor input".into()))?;
    let last_idx = lines
        .iter()
        .rposition(|l| !l.trim().is_empty())
        .ok_or_else(|| WilisError::InvalidEncoding("empty WilisArmor input".into()))?;

    if last_idx <= first_idx {
        return Err(WilisError::InvalidEncoding(
            "truncated WilisArmor block".into(),
        ));
    }

    let begin_line = lines[first_idx].trim();
    let end_line = lines[last_idx].trim();

    let label = begin_line
        .strip_prefix(BEGIN_PREFIX)
        .and_then(|s| s.strip_suffix(FENCE_SUFFIX))
        .ok_or_else(|| WilisError::InvalidEncoding("malformed WilisArmor BEGIN line".into()))?;
    validate_armor_label(label)?;

    let end_label = end_line
        .strip_prefix(END_PREFIX)
        .and_then(|s| s.strip_suffix(FENCE_SUFFIX))
        .ok_or_else(|| WilisError::InvalidEncoding("malformed WilisArmor END line".into()))?;
    if label != end_label {
        return Err(WilisError::InvalidEncoding(format!(
            "mismatched WilisArmor BEGIN ('{label}') and END ('{end_label}') labels"
        )));
    }
    if let Some(exp) = expected_label {
        if label != exp {
            return Err(WilisError::InvalidEncoding(format!(
                "unexpected WilisArmor label '{label}' (expected '{exp}')"
            )));
        }
    }

    let inner = &lines[first_idx + 1..last_idx];
    // Parse optional RFC-style `Key: Value` headers separated by a blank line
    let mut body_start = 0usize;
    let mut header_count = 0usize;
    if let Some(first_inner) = inner.first() {
        if first_inner.contains(':') {
            let mut found_sep = false;
            for (idx, line) in inner.iter().enumerate() {
                if line.trim().is_empty() {
                    body_start = idx + 1;
                    found_sep = true;
                    break;
                }
                if !line.contains(':') {
                    return Err(WilisError::InvalidEncoding(
                        "malformed WilisArmor header line (missing ':')".into(),
                    ));
                }
                header_count += 1;
                if header_count > MAX_ARMOR_HEADERS {
                    return Err(WilisError::InvalidEncoding(
                        "too many WilisArmor header lines".into(),
                    ));
                }
            }
            if !found_sep {
                return Err(WilisError::InvalidEncoding(
                    "missing blank line separating WilisArmor headers from payload".into(),
                ));
            }
        }
    }

    let body_lines: Vec<&str> = inner[body_start..]
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    let checksum_line = body_lines
        .last()
        .copied()
        .ok_or_else(|| WilisError::InvalidEncoding("missing WilisArmor checksum line".into()))?;
    let chk_b64 = checksum_line
        .strip_prefix('=')
        .ok_or_else(|| {
            WilisError::InvalidEncoding("missing '='-prefixed WilisArmor checksum".into())
        })?;
    if chk_b64.len() != 4 {
        return Err(WilisError::InvalidEncoding(
            "invalid WilisArmor checksum length (expected 4 Base64 chars)".into(),
        ));
    }
    let stored_chk = decode_base64(chk_b64)?;
    if stored_chk.len() != 3 {
        return Err(WilisError::InvalidEncoding(
            "invalid WilisArmor checksum byte length".into(),
        ));
    }

    let mut joined_b64 = String::new();
    for line in &body_lines[..body_lines.len() - 1] {
        if line.starts_with("-----") {
            // SAFETY: Overwriting ASCII Base64 bytes with 0x00 preserves UTF-8 validity.
            zeroize_bytes(unsafe { joined_b64.as_bytes_mut() });
            return Err(WilisError::InvalidEncoding(
                "nested or duplicate WilisArmor fence detected".into(),
            ));
        }
        joined_b64.push_str(line);
    }

    let payload_res = decode_base64(&joined_b64);
    // SAFETY: Overwriting ASCII Base64 bytes with 0x00 preserves UTF-8 validity.
    zeroize_bytes(unsafe { joined_b64.as_bytes_mut() });
    let mut payload = payload_res?;

    let actual_chk = compute_armor_checksum(label, &payload);
    if !ct_eq(&stored_chk, &actual_chk) {
        zeroize_bytes(&mut payload);
        return Err(WilisError::AuthenticationFailed);
    }

    Ok((label.to_string(), payload))
}
