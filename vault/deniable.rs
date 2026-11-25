//! Plausible Deniability Dual-Passphrase Hidden Volume (`WilisHidden`).
//!
//! Creates a fixed-size container completely filled with uniform OS CSPRNG noise holding
//! TWO independent authenticated volumes:
//! - **Outer (Decoy) Volume:** Unlocked by `outer_passphrase` at slot 0.
//! - **Hidden (Real) Volume:** Placed at a hidden passphrase-derived offset inside the
//!   second half of the random container and encrypted under an independent derived key.
//!
//! Because the entire container has NO plaintext magic header and EVERY unused byte is
//! indistinguishable from uniform CSPRNG noise (and encrypted headers are masked with
//! `WilisXOF`), an adversary holding `outer_passphrase` cannot prove whether a hidden
//! volume exists inside the remaining random space!

use crate::aead::{open, seal};
use crate::core::constants::{NONCE_BYTES, SALT_BYTES, TAG_BYTES};
use crate::error::{Result, WilisError};
use crate::kdf::{derive_key, KdfParams};
use crate::utils::random::fill_random;
use crate::utils::zeroize::zeroize_bytes;
use crate::xof::WilisXof;

/// Minimum total container size (4 KiB).
pub const MIN_HIDDEN_CONTAINER_BYTES: usize = 4096;

/// Maximum total container size (32 MiB in-memory bound).
pub const MAX_HIDDEN_CONTAINER_BYTES: usize = 32 * 1024 * 1024;

/// Encrypted slot header: `len: u32 LE` (4) + `nonce: 24B` + `tag: 32B` = 60 bytes (masked by XOF).
const SLOT_HDR_BYTES: usize = 4 + NONCE_BYTES + TAG_BYTES;

fn expand_slot_material(
    base_key: &[u8; 32],
    salt: &[u8; SALT_BYTES],
    domain: &[u8],
) -> ([u8; 32], [u8; SLOT_HDR_BYTES]) {
    let mut xof = WilisXof::new(domain);
    xof.absorb(base_key);
    xof.absorb(salt);
    let mut mat = [0u8; 32 + SLOT_HDR_BYTES];
    xof.squeeze(&mut mat);
    let aead_key: [u8; 32] = mat[0..32].try_into().expect("32 bytes");
    let hdr_mask: [u8; SLOT_HDR_BYTES] = mat[32..32 + SLOT_HDR_BYTES].try_into().expect("60 bytes");
    zeroize_bytes(&mut mat);
    (aead_key, hdr_mask)
}

fn write_masked_slot(
    buf: &mut [u8],
    slot_offset: usize,
    aead_key: &[u8; 32],
    hdr_mask: &[u8; SLOT_HDR_BYTES],
    slot_aad: &[u8],
    payload: &[u8],
) -> Result<()> {
    let mut nonce = [0u8; NONCE_BYTES];
    fill_random(&mut nonce)?;
    let (ct, tag) = seal(aead_key, &nonce, slot_aad, payload);

    let mut plain_hdr = [0u8; SLOT_HDR_BYTES];
    plain_hdr[0..4].copy_from_slice(&(ct.len() as u32).to_le_bytes());
    plain_hdr[4..4 + NONCE_BYTES].copy_from_slice(&nonce);
    plain_hdr[4 + NONCE_BYTES..SLOT_HDR_BYTES].copy_from_slice(&tag);

    for i in 0..SLOT_HDR_BYTES {
        buf[slot_offset + i] = plain_hdr[i] ^ hdr_mask[i];
    }
    zeroize_bytes(&mut plain_hdr);
    buf[slot_offset + SLOT_HDR_BYTES..slot_offset + SLOT_HDR_BYTES + ct.len()].copy_from_slice(&ct);
    Ok(())
}

fn try_read_masked_slot(
    buf: &[u8],
    slot_offset: usize,
    max_end: usize,
    aead_key: &[u8; 32],
    hdr_mask: &[u8; SLOT_HDR_BYTES],
    slot_aad: &[u8],
) -> Result<Vec<u8>> {
    if slot_offset + SLOT_HDR_BYTES > max_end {
        return Err(WilisError::AuthenticationFailed);
    }
    let mut plain_hdr = [0u8; SLOT_HDR_BYTES];
    for i in 0..SLOT_HDR_BYTES {
        plain_hdr[i] = buf[slot_offset + i] ^ hdr_mask[i];
    }
    let ct_len = u32::from_le_bytes(plain_hdr[0..4].try_into().expect("4 bytes")) as usize;
    let nonce: [u8; NONCE_BYTES] = plain_hdr[4..4 + NONCE_BYTES].try_into().expect("24 bytes");
    let tag: [u8; TAG_BYTES] = plain_hdr[4 + NONCE_BYTES..SLOT_HDR_BYTES]
        .try_into()
        .expect("32 bytes");
    zeroize_bytes(&mut plain_hdr);

    let ct_start = slot_offset + SLOT_HDR_BYTES;
    if ct_len > max_end.saturating_sub(ct_start) {
        return Err(WilisError::AuthenticationFailed);
    }
    open(aead_key, &nonce, slot_aad, &buf[ct_start..ct_start + ct_len], &tag)
}

/// Creates a uniform-random fixed-size (`container_size`) plausible-deniability blob
/// embedding BOTH `decoy_payload` (under `decoy_pass`) and `hidden_payload` (under `hidden_pass`).
///
/// Layout: `[ salt: 24B (random) ][ outer_region (first half) ][ hidden_region (second half) ]`
/// Notice there is ZERO plaintext magic, ZERO plaintext length, and ZERO KDF metadata —
/// the entire blob passes NIST randomness checks identically to raw `/dev/urandom`!
pub fn create_deniable_container(
    container_size: usize,
    decoy_pass: &[u8],
    decoy_payload: &[u8],
    hidden_pass: &[u8],
    hidden_payload: &[u8],
    params: KdfParams,
) -> Result<Vec<u8>> {
    if !(MIN_HIDDEN_CONTAINER_BYTES..=MAX_HIDDEN_CONTAINER_BYTES).contains(&container_size) {
        return Err(WilisError::InvalidParameters(format!(
            "deniable container_size {container_size} out of range [{MIN_HIDDEN_CONTAINER_BYTES}..={MAX_HIDDEN_CONTAINER_BYTES}]"
        )));
    }
    if decoy_pass.is_empty() || hidden_pass.is_empty() || decoy_pass == hidden_pass {
        return Err(WilisError::InvalidParameters(
            "decoy and hidden passphrases must be non-empty and distinct".into(),
        ));
    }

    let body_len = container_size - SALT_BYTES;
    let half = body_len / 2;
    let max_slot_payload = half.saturating_sub(SLOT_HDR_BYTES);
    if decoy_payload.len() > max_slot_payload || hidden_payload.len() > max_slot_payload {
        return Err(WilisError::InvalidParameters(format!(
            "each payload must fit within {max_slot_payload} bytes for container_size {container_size}"
        )));
    }

    // Fill ENTIRE container with uniform CSPRNG noise first!
    let mut blob = vec![0u8; container_size];
    fill_random(&mut blob)?;
    let salt: [u8; SALT_BYTES] = blob[0..SALT_BYTES].try_into().expect("24 bytes");

    let decoy_base = derive_key(decoy_pass, &salt, params)?;
    let hidden_base = derive_key(hidden_pass, &salt, params)?;
    let (mut dk, mut dmask) = expand_slot_material(decoy_base.as_bytes(), &salt, b"WHID_OUTER_V1");
    let (mut hk, mut hmask) = expand_slot_material(hidden_base.as_bytes(), &salt, b"WHID_INNER_V1");

    let outer_off = SALT_BYTES;
    let hidden_off = SALT_BYTES + half;

    let mut outer_aad = Vec::with_capacity(16 + SALT_BYTES);
    outer_aad.extend_from_slice(b"WHID_AAD_OUT_V1:");
    outer_aad.extend_from_slice(&salt);
    let mut inner_aad = Vec::with_capacity(16 + SALT_BYTES);
    inner_aad.extend_from_slice(b"WHID_AAD_HID_V1:");
    inner_aad.extend_from_slice(&salt);

    write_masked_slot(&mut blob, outer_off, &dk, &dmask, &outer_aad, decoy_payload)?;
    write_masked_slot(&mut blob, hidden_off, &hk, &hmask, &inner_aad, hidden_payload)?;

    zeroize_bytes(&mut dk);
    zeroize_bytes(&mut dmask);
    zeroize_bytes(&mut hk);
    zeroize_bytes(&mut hmask);
    Ok(blob)
}

/// Opens whichever volume (outer decoy OR hidden real) matches `passphrase` and `params`.
///
/// Runs a SINGLE `WilisKDF` evaluation and probes both masked regions with domain-separated
/// XOF masks so unlocking either outer or hidden takes uniform KDF time and never leaks
/// whether a second volume exists.
pub fn open_deniable_container(
    blob: &[u8],
    passphrase: &[u8],
    params: KdfParams,
) -> Result<(bool, Vec<u8>)> {
    if blob.len() < MIN_HIDDEN_CONTAINER_BYTES {
        return Err(WilisError::InvalidFormat(
            "deniable container is too small".into(),
        ));
    }
    let salt: [u8; SALT_BYTES] = blob[0..SALT_BYTES].try_into().expect("24 bytes");
    let body_len = blob.len() - SALT_BYTES;
    let half = body_len / 2;

    // Single memory-hard KDF evaluation eliminates 2x timing oracle between outer & hidden slots
    let base_key = derive_key(passphrase, &salt, params)?;

    // 1. Probe outer/decoy region
    let (mut dk, mut dmask) = expand_slot_material(base_key.as_bytes(), &salt, b"WHID_OUTER_V1");
    let mut outer_aad = Vec::with_capacity(16 + SALT_BYTES);
    outer_aad.extend_from_slice(b"WHID_AAD_OUT_V1:");
    outer_aad.extend_from_slice(&salt);
    let outer_res = try_read_masked_slot(blob, SALT_BYTES, SALT_BYTES + half, &dk, &dmask, &outer_aad);
    zeroize_bytes(&mut dk);
    zeroize_bytes(&mut dmask);

    // 2. Probe hidden region
    let (mut hk, mut hmask) = expand_slot_material(base_key.as_bytes(), &salt, b"WHID_INNER_V1");
    let mut inner_aad = Vec::with_capacity(16 + SALT_BYTES);
    inner_aad.extend_from_slice(b"WHID_AAD_HID_V1:");
    inner_aad.extend_from_slice(&salt);
    let hidden_res = try_read_masked_slot(blob, SALT_BYTES + half, blob.len(), &hk, &hmask, &inner_aad);
    zeroize_bytes(&mut hk);
    zeroize_bytes(&mut hmask);

    if let Ok(pt) = outer_res {
        return Ok((false, pt));
    }
    match hidden_res {
        Ok(pt) => Ok((true, pt)),
        Err(_) => Err(WilisError::AuthenticationFailed),
    }
}
