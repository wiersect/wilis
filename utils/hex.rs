//! Pure-Rust hexadecimal encoder and decoder.

use crate::error::{WilisError, Result};

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Encodes raw bytes as a lowercase hexadecimal string.
pub fn encode_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(HEX_LOWER[(b >> 4) as usize] as char);
        out.push(HEX_LOWER[(b & 0x0F) as usize] as char);
    }
    out
}

/// Decodes a hexadecimal string (case-insensitive, surrounding whitespace trimmed) into bytes.
pub fn decode_hex(input: &str) -> Result<Vec<u8>> {
    let cleaned = input.trim();
    if cleaned.len() % 2 != 0 {
        return Err(WilisError::InvalidEncoding(
            "hex string must have an even number of characters".to_string(),
        ));
    }

    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);

    for pair in bytes.chunks_exact(2) {
        let hi = decode_nibble(pair[0])?;
        let lo = decode_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }

    Ok(out)
}

fn decode_nibble(ch: u8) -> Result<u8> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        b'A'..=b'F' => Ok(ch - b'A' + 10),
        _ => Err(WilisError::InvalidEncoding(format!(
            "invalid hex character: '{}'",
            ch as char
        ))),
    }
}
