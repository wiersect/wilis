//! `WilisLZ` — Pure-Rust, zero-dependency lossless LZSS compression (`WLZ1`)
//! with strict decompression-bomb protection.
//!
//! ## Wire Format (`WLZ1`)
//! - `[magic: 4B = "WLZ1"]`
//! - `[orig_len: u64 LE]` — exact expected uncompressed byte length
//! - Sequence of groups:
//!   - `flag_byte: u8` (8 items, LSB first: `0` = 1 literal byte, `1` = 2-byte LE back-ref)
//!   - Back-reference token `u16 LE`:
//!     - `distance = ((token >> 4) as usize) + 1` (`1..=4096`)
//!     - `length = ((token & 0x0F) as usize) + 3` (`3..=18`)
//! - Canonical rule: unused high bits in the final flag byte MUST be zero, and the
//!   stream MUST end at exact EOF once `orig_len` bytes are reconstructed.
//!
//! ## Security Note (CRIME / BREACH)
//! Compression before encryption is strictly opt-in because ciphertext lengths can leak
//! information about compressible attacker-controlled + secret mixed inputs.

use crate::error::{Result, WilisError};

pub const WLZ_MAGIC: [u8; 4] = *b"WLZ1";
const WLZ_HEADER_BYTES: usize = 12;

const WINDOW_SIZE: usize = 4096;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 18;
const HASH_BITS: usize = 12;
const HASH_SIZE: usize = 1 << HASH_BITS;
const NO_POS: u32 = u32::MAX;

#[inline]
fn hash3(b0: u8, b1: u8, b2: u8) -> usize {
    let v = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
    ((v.wrapping_mul(2_654_435_761)) >> (32 - HASH_BITS)) as usize
}

/// Compresses `input` into a canonical `WLZ1` lossless byte stream.
pub fn compress(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(WLZ_HEADER_BYTES + input.len() + (input.len() / 8) + 2);
    out.extend_from_slice(&WLZ_MAGIC);
    out.extend_from_slice(&(input.len() as u64).to_le_bytes());

    if input.is_empty() {
        return out;
    }

    // 1-slot hash table per 3-byte trigram for fast O(N) sliding-window lookup
    let mut head = vec![NO_POS; HASH_SIZE];
    let mut pos: usize = 0;

    while pos < input.len() {
        let flag_idx = out.len();
        out.push(0u8);
        let mut flag: u8 = 0;

        for bit in 0..8 {
            if pos >= input.len() {
                break;
            }

            let mut best_len = 0usize;
            let mut best_dist = 0usize;

            if pos + MIN_MATCH <= input.len() {
                let h = hash3(input[pos], input[pos + 1], input[pos + 2]);
                let cand = head[h];
                if pos <= u32::MAX as usize {
                    head[h] = pos as u32;
                }

                if cand != NO_POS {
                    let cpos = cand as usize;
                    if cpos < pos {
                        let dist = pos - cpos;
                        if dist <= WINDOW_SIZE {
                            let max_len = MAX_MATCH.min(input.len() - pos);
                            let mut m = 0usize;
                            while m < max_len && input[cpos + m] == input[pos + m] {
                                m += 1;
                            }
                            if m >= MIN_MATCH {
                                best_len = m;
                                best_dist = dist;
                            }
                        }
                    }
                }
            }

            if best_len >= MIN_MATCH {
                flag |= 1u8 << bit;
                let token: u16 = (((best_dist - 1) as u16) << 4) | ((best_len - MIN_MATCH) as u16);
                out.extend_from_slice(&token.to_le_bytes());
                // Insert intermediate trigram positions for better subsequent matches
                let end = pos + best_len;
                let mut k = pos + 1;
                while k < end && k + MIN_MATCH <= input.len() && k <= u32::MAX as usize {
                    let h = hash3(input[k], input[k + 1], input[k + 2]);
                    head[h] = k as u32;
                    k += 1;
                }
                pos = end;
            } else {
                out.push(input[pos]);
                pos += 1;
            }
        }

        out[flag_idx] = flag;
    }

    out
}

/// Decompresses a `WLZ1` stream while enforcing a strict `max_output_bytes` ceiling
/// to defend against zip/decompression bombs.
pub fn decompress(input: &[u8], max_output_bytes: usize) -> Result<Vec<u8>> {
    if input.len() < WLZ_HEADER_BYTES || input[0..4] != WLZ_MAGIC {
        return Err(WilisError::InvalidFormat(
            "invalid or truncated WLZ1 compressed header".into(),
        ));
    }

    let orig_len_u64 = u64::from_le_bytes(input[4..12].try_into().expect("8 bytes"));
    if orig_len_u64 > max_output_bytes as u64 {
        return Err(WilisError::InvalidFormat(format!(
            "WLZ1 declared output size ({orig_len_u64}) exceeds safety limit ({max_output_bytes})"
        )));
    }
    let orig_len = orig_len_u64 as usize;

    // Cap initial allocation so malformed tiny payloads claiming huge orig_len cannot OOM
    let init_cap = orig_len.min(input.len().saturating_mul(16).max(64));
    let mut out = Vec::with_capacity(init_cap);
    let mut pos = WLZ_HEADER_BYTES;

    while out.len() < orig_len {
        if pos >= input.len() {
            return Err(WilisError::InvalidFormat(
                "truncated WLZ1 compressed stream".into(),
            ));
        }
        let flag = input[pos];
        pos += 1;

        for bit in 0..8 {
            if out.len() == orig_len {
                // Canonical check: remaining unused high bits in the final flag byte must be 0
                let remaining_mask = !((1u8 << bit).wrapping_sub(1));
                if (flag & remaining_mask) != 0 {
                    return Err(WilisError::InvalidFormat(
                        "non-canonical trailing flag bits in WLZ1 stream".into(),
                    ));
                }
                break;
            }

            if (flag & (1u8 << bit)) == 0 {
                if pos >= input.len() {
                    return Err(WilisError::InvalidFormat(
                        "truncated WLZ1 literal byte".into(),
                    ));
                }
                out.push(input[pos]);
                pos += 1;
            } else {
                if input.len() - pos < 2 {
                    return Err(WilisError::InvalidFormat(
                        "truncated WLZ1 back-reference token".into(),
                    ));
                }
                let token = u16::from_le_bytes([input[pos], input[pos + 1]]);
                pos += 2;
                let dist = ((token >> 4) as usize) + 1;
                let match_len = ((token & 0x0F) as usize) + MIN_MATCH;

                if dist > out.len() {
                    return Err(WilisError::InvalidFormat(
                        "WLZ1 back-reference exceeds decoded history".into(),
                    ));
                }
                if out.len().saturating_add(match_len) > orig_len {
                    return Err(WilisError::InvalidFormat(
                        "WLZ1 back-reference overflows declared output length".into(),
                    ));
                }
                // Copy byte-by-byte to properly support overlapping RLE matches (dist < match_len)
                for _ in 0..match_len {
                    let b = out[out.len() - dist];
                    out.push(b);
                }
            }
        }
    }

    if pos != input.len() {
        return Err(WilisError::InvalidFormat(
            "unexpected trailing bytes after WLZ1 compressed stream".into(),
        ));
    }

    Ok(out)
}
