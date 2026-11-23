//! Per-chunk nonce derivation and anti-reordering/anti-truncation AAD construction.

use crate::core::constants::{HASH_BYTES, NONCE_BYTES};

/// Default plaintext chunk size for streaming encryption (64 KiB).
pub const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;

/// Minimum allowed streaming chunk size (1 KiB).
pub const MIN_CHUNK_SIZE: u32 = 1024;

/// Maximum allowed streaming chunk size (4 MiB) to bound memory usage.
pub const MAX_CHUNK_SIZE: u32 = 4 * 1024 * 1024;

/// Derives a unique 192-bit chunk nonce by XORing the 64-bit `chunk_index` and
/// final-chunk flag into the last 9 bytes of `base_nonce`.
///
/// Supports up to `2^64 - 1` chunks (~1 sextillion bytes at 64 KiB/chunk) without nonce reuse.
pub fn derive_chunk_nonce(
    base_nonce: &[u8; NONCE_BYTES],
    chunk_index: u64,
    is_final: bool,
) -> [u8; NONCE_BYTES] {
    let mut nonce = *base_nonce;
    let idx_bytes = chunk_index.to_le_bytes();
    for i in 0..8 {
        nonce[16 + i] ^= idx_bytes[i];
    }
    if is_final {
        nonce[15] ^= 0xFF;
    }
    nonce
}

/// Builds per-chunk authenticated AAD binding the header digest, exact chunk position,
/// finality flag, and user-supplied AAD.
pub fn build_chunk_aad(
    header_digest: &[u8; HASH_BYTES],
    chunk_index: u64,
    is_final: bool,
    user_aad: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HASH_BYTES + 8 + 1 + 8 + user_aad.len());
    aad.extend_from_slice(header_digest);
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.push(if is_final { 1 } else { 0 });
    aad.extend_from_slice(&(user_aad.len() as u64).to_le_bytes());
    aad.extend_from_slice(user_aad);
    aad
}
