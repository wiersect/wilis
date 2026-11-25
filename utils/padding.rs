//! Canonical length-hiding block padding (`WilisPad` v1) to mitigate traffic-analysis
//! and plaintext-length side channels in encrypted containers.
//!
//! Wire layout (`WPAD` v1):
//! `[ "WPAD": 4B ][ plaintext_len: u64 LE (8B) ][ plaintext: L bytes ][ 0x80: 1B ][ 0x00 * pad_zeros ]`
//!
//! Total length is strictly rounded up to a multiple of `block_size` (`16..=65536` bytes).
//! Unpadding verifies the `0x80` sentinel and every trailing `0x00` byte in constant time.

use crate::error::{Result, WilisError};

/// Magic prefix identifying a canonical `WilisPad` payload.
pub const PAD_MAGIC: [u8; 4] = *b"WPAD";

/// Minimum supported padding block granularity (16 bytes).
pub const MIN_PAD_BLOCK_SIZE: usize = 16;

/// Maximum supported padding block granularity (64 KiB).
pub const MAX_PAD_BLOCK_SIZE: usize = 65_536;

/// Fixed framing overhead: 4-byte magic + 8-byte u64 length + 1-byte `0x80` sentinel.
const PAD_OVERHEAD: usize = 4 + 8 + 1;

/// Pads `plaintext` to the smallest multiple of `block_size` strictly holding
/// `PAD_OVERHEAD + plaintext.len()` bytes.
pub fn pad_to_block(plaintext: &[u8], block_size: usize) -> Result<Vec<u8>> {
    if !(MIN_PAD_BLOCK_SIZE..=MAX_PAD_BLOCK_SIZE).contains(&block_size) {
        return Err(WilisError::InvalidParameters(format!(
            "pad block_size {block_size} out of range [{MIN_PAD_BLOCK_SIZE}..={MAX_PAD_BLOCK_SIZE}]"
        )));
    }

    let min_total = plaintext
        .len()
        .checked_add(PAD_OVERHEAD)
        .ok_or_else(|| WilisError::InvalidParameters("padded length overflow".into()))?;
    let padded_len = min_total
        .div_ceil(block_size)
        .checked_mul(block_size)
        .ok_or_else(|| WilisError::InvalidParameters("padded length overflow".into()))?;

    let mut out = vec![0u8; padded_len];
    out[0..4].copy_from_slice(&PAD_MAGIC);
    out[4..12].copy_from_slice(&(plaintext.len() as u64).to_le_bytes());
    out[12..12 + plaintext.len()].copy_from_slice(plaintext);
    out[12 + plaintext.len()] = 0x80;
    Ok(out)
}

/// Strictly validates and strips `WilisPad` v1 framing, verifying the `0x80` sentinel
/// and every trailing zero byte in constant time.
pub fn unpad_strict(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < PAD_OVERHEAD || padded[0..4] != PAD_MAGIC {
        return Err(WilisError::InvalidFormat(
            "invalid or missing WilisPad framing header".into(),
        ));
    }

    let pt_len_u64 = u64::from_le_bytes(padded[4..12].try_into().expect("8 bytes"));
    let max_pt = (padded.len() - PAD_OVERHEAD) as u64;
    if pt_len_u64 > max_pt {
        return Err(WilisError::InvalidFormat(
            "corrupted WilisPad plaintext length exceeds buffer".into(),
        ));
    }
    let pt_len = pt_len_u64 as usize;

    // Constant-time validation of sentinel (0x80) and all trailing zero padding bytes
    let mut bad: u8 = core::hint::black_box(padded[12 + pt_len] ^ 0x80);
    for &b in &padded[13 + pt_len..] {
        bad |= core::hint::black_box(b);
    }
    if core::hint::black_box(bad) != 0 {
        return Err(WilisError::InvalidFormat(
            "corrupted WilisPad padding sentinel or non-zero trailing bytes".into(),
        ));
    }

    Ok(padded[12..12 + pt_len].to_vec())
}

/// Returns `true` if `data` starts with the `WilisPad` framing prefix and meets minimum length.
#[inline]
pub fn has_pad_magic(data: &[u8]) -> bool {
    data.len() >= PAD_OVERHEAD && data[0..4] == PAD_MAGIC
}
