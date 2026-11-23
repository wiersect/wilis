//! Pure-Rust standard Base64 (RFC 4648) encoder and decoder.

use crate::error::{WilisError, Result};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes arbitrary bytes into standard Base64 with `=` padding.
pub fn encode_base64(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }

    out
}

/// Decodes standard Base64 text (ignoring ASCII whitespace) into raw bytes.
pub fn decode_base64(input: &str) -> Result<Vec<u8>> {
    let filtered: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();

    if filtered.is_empty() {
        return Ok(Vec::new());
    }

    if filtered.len() % 4 != 0 {
        return Err(WilisError::InvalidEncoding(
            "Base64 length must be a multiple of 4".to_string(),
        ));
    }

    let mut out = Vec::with_capacity((filtered.len() / 4) * 3);
    let total_chunks = filtered.len() / 4;

    for (chunk_idx, chunk) in filtered.chunks_exact(4).enumerate() {
        let is_last = chunk_idx + 1 == total_chunks;
        let pad_count = chunk.iter().filter(|&&b| b == b'=').count();

        if pad_count > 0 && !is_last {
            return Err(WilisError::InvalidEncoding(
                "unexpected '=' padding before final Base64 block".to_string(),
            ));
        }

        if pad_count > 2 || (pad_count == 1 && chunk[3] != b'=') || (pad_count == 2 && (chunk[2] != b'=' || chunk[3] != b'=')) {
            return Err(WilisError::InvalidEncoding(
                "malformed Base64 padding".to_string(),
            ));
        }

        let v0 = decode_symbol(chunk[0])? as u32;
        let v1 = decode_symbol(chunk[1])? as u32;
        let v2 = if chunk[2] == b'=' { 0 } else { decode_symbol(chunk[2])? as u32 };
        let v3 = if chunk[3] == b'=' { 0 } else { decode_symbol(chunk[3])? as u32 };

        let triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;

        out.push(((triple >> 16) & 0xFF) as u8);
        if chunk[2] != b'=' {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if chunk[3] != b'=' {
            out.push((triple & 0xFF) as u8);
        }
    }

    Ok(out)
}

fn decode_symbol(b: u8) -> Result<u8> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(WilisError::InvalidEncoding(format!(
            "invalid Base64 byte: 0x{b:02x}"
        ))),
    }
}
