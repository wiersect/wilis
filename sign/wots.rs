//! Tweaked Winternitz One-Time Signature Plus (`WOTS+`) built on `WilisHash-256`.
//!
//! Parameters:
//! - Security parameter `n = 32` bytes (256 bits)
//! - Winternitz base `w = 16` (4-bit nibbles, max chain length `15`)
//! - Message chains `L1 = 64`, checksum chains `L2 = 3`, total chains `L = 67`

use crate::core::constants::HASH_BYTES;
use crate::hash::WilisHash;
use crate::utils::zeroize::zeroize_bytes;

/// Winternitz parameter `w = 16` (4-bit nibbles).
pub const WOTS_W: u8 = 16;

/// Maximum chain step index (`w - 1 = 15`).
pub const WOTS_MAX_STEP: u8 = WOTS_W - 1;

/// Number of 4-bit message nibble chains (`256 / 4 = 64`).
pub const WOTS_LEN1: usize = 64;

/// Number of 4-bit checksum chains (`64 * 15 = 960 < 16^3 = 4096`).
pub const WOTS_LEN2: usize = 3;

/// Total WOTS+ chains per one-time keypair (`64 + 3 = 67`).
pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;

/// Expands a 256-bit message digest into 67 base-16 digits (64 message + 3 checksum).
pub fn encode_digest_to_nibbles(digest: &[u8; HASH_BYTES]) -> [u8; WOTS_LEN] {
    let mut digits = [0u8; WOTS_LEN];
    let mut checksum: u32 = 0;

    for (i, &byte) in digest.iter().enumerate() {
        let hi = byte >> 4;
        let lo = byte & 0x0F;
        digits[i * 2] = hi;
        digits[i * 2 + 1] = lo;
        checksum += (WOTS_MAX_STEP - hi) as u32;
        checksum += (WOTS_MAX_STEP - lo) as u32;
    }

    // Encode 12-bit checksum big-endian into the final 3 base-16 digits
    digits[WOTS_LEN1] = ((checksum >> 8) & 0x0F) as u8;
    digits[WOTS_LEN1 + 1] = ((checksum >> 4) & 0x0F) as u8;
    digits[WOTS_LEN1 + 2] = (checksum & 0x0F) as u8;

    digits
}

/// Deterministically derives the `chain_idx`-th secret element for a given leaf.
pub fn derive_wots_secret_elem(
    secret_seed: &[u8; HASH_BYTES],
    pub_seed: &[u8; HASH_BYTES],
    leaf_idx: u32,
    chain_idx: u16,
) -> [u8; HASH_BYTES] {
    let mut h = WilisHash::new();
    h.update(b"WSIG_SK1");
    h.update(secret_seed);
    h.update(pub_seed);
    h.update(&leaf_idx.to_le_bytes());
    h.update(&chain_idx.to_le_bytes());
    h.finalize()
}

/// Evaluates `steps` tweaked WOTS+ hash chain iterations starting at `start_step`.
///
/// # Panics
/// Panics if `start_step + steps > WOTS_MAX_STEP` (15).
pub fn wots_chain(
    mut value: [u8; HASH_BYTES],
    start_step: u8,
    steps: u8,
    pub_seed: &[u8; HASH_BYTES],
    leaf_idx: u32,
    chain_idx: u16,
) -> [u8; HASH_BYTES] {
    let end_step = (start_step as u16) + (steps as u16);
    assert!(
        end_step <= WOTS_MAX_STEP as u16,
        "wots_chain step range {start_step}..{end_step} exceeds WOTS_MAX_STEP ({WOTS_MAX_STEP})"
    );
    for step in (start_step as u16)..end_step {
        let step_u8 = step as u8;
        let mut h_mask = WilisHash::new();
        h_mask.update(b"WSIG_BM1");
        h_mask.update(pub_seed);
        h_mask.update(&leaf_idx.to_le_bytes());
        h_mask.update(&chain_idx.to_le_bytes());
        h_mask.update(&[step_u8]);
        let bitmask = h_mask.finalize();

        let mut h_key = WilisHash::new();
        h_key.update(b"WSIG_KY1");
        h_key.update(pub_seed);
        h_key.update(&leaf_idx.to_le_bytes());
        h_key.update(&chain_idx.to_le_bytes());
        h_key.update(&[step_u8]);
        let key = h_key.finalize();

        let mut masked = [0u8; HASH_BYTES];
        for i in 0..HASH_BYTES {
            masked[i] = value[i] ^ bitmask[i];
        }

        let mut h_fn = WilisHash::new();
        h_fn.update(b"WSIG_FN1");
        h_fn.update(&key);
        h_fn.update(&masked);
        zeroize_bytes(&mut masked);
        value = h_fn.finalize();
    }
    value
}

/// Computes the compressed 256-bit Merkle leaf hash for a given WOTS+ leaf index.
pub fn compute_leaf_pk_hash(
    secret_seed: &[u8; HASH_BYTES],
    pub_seed: &[u8; HASH_BYTES],
    leaf_idx: u32,
) -> [u8; HASH_BYTES] {
    let mut h_leaf = WilisHash::new();
    h_leaf.update(b"WSIG_LF1");
    h_leaf.update(pub_seed);
    h_leaf.update(&leaf_idx.to_le_bytes());

    for chain_idx in 0..WOTS_LEN {
        let mut sk_i = derive_wots_secret_elem(secret_seed, pub_seed, leaf_idx, chain_idx as u16);
        let pk_i = wots_chain(sk_i, 0, WOTS_MAX_STEP, pub_seed, leaf_idx, chain_idx as u16);
        zeroize_bytes(&mut sk_i);
        h_leaf.update(&pk_i);
    }

    h_leaf.finalize()
}

/// Produces a 67-element WOTS+ signature over a 256-bit randomized message digest.
pub fn wots_sign_digest(
    secret_seed: &[u8; HASH_BYTES],
    pub_seed: &[u8; HASH_BYTES],
    leaf_idx: u32,
    digest: &[u8; HASH_BYTES],
) -> [[u8; HASH_BYTES]; WOTS_LEN] {
    let digits = encode_digest_to_nibbles(digest);
    let mut sig = [[0u8; HASH_BYTES]; WOTS_LEN];

    for chain_idx in 0..WOTS_LEN {
        let mut sk_i = derive_wots_secret_elem(secret_seed, pub_seed, leaf_idx, chain_idx as u16);
        sig[chain_idx] = wots_chain(
            sk_i,
            0,
            digits[chain_idx],
            pub_seed,
            leaf_idx,
            chain_idx as u16,
        );
        zeroize_bytes(&mut sk_i);
    }

    sig
}

/// Recovers the compressed Merkle leaf hash from a WOTS+ signature and 256-bit digest.
pub fn wots_recover_leaf_pk_hash(
    sig: &[[u8; HASH_BYTES]; WOTS_LEN],
    pub_seed: &[u8; HASH_BYTES],
    leaf_idx: u32,
    digest: &[u8; HASH_BYTES],
) -> [u8; HASH_BYTES] {
    let digits = encode_digest_to_nibbles(digest);
    let mut h_leaf = WilisHash::new();
    h_leaf.update(b"WSIG_LF1");
    h_leaf.update(pub_seed);
    h_leaf.update(&leaf_idx.to_le_bytes());

    for chain_idx in 0..WOTS_LEN {
        let start = digits[chain_idx];
        let remaining = WOTS_MAX_STEP - start;
        let pk_i = wots_chain(
            sig[chain_idx],
            start,
            remaining,
            pub_seed,
            leaf_idx,
            chain_idx as u16,
        );
        h_leaf.update(&pk_i);
    }

    h_leaf.finalize()
}
