//! C-ABI exported cryptographic functions for `libwilis`.
//!
//! Return codes:
//! - `0`: Success (`WILIS_OK`)
//! - `-1`: Null pointer or invalid argument (`WILIS_ERR_INVALID_ARG`)
//! - `-2`: Authentication / verification failed (`WILIS_ERR_AUTH_FAILED`)
//! - `-3`: OS CSPRNG or internal failure (`WILIS_ERR_INTERNAL`)

use core::slice;

use crate::aead::{open, seal};
use crate::core::constants::{HASH_BYTES, KEY_BYTES, NONCE_BYTES, SALT_BYTES, TAG_BYTES};
use crate::hash::hash;
use crate::kdf::{derive_key, KdfParams};
use crate::utils::random::fill_random;

pub const WILIS_OK: i32 = 0;
pub const WILIS_ERR_INVALID_ARG: i32 = -1;
pub const WILIS_ERR_AUTH_FAILED: i32 = -2;
pub const WILIS_ERR_INTERNAL: i32 = -3;

/// Helper safely converting `(ptr, len)` to a byte slice, allowing `NULL` when `len == 0`.
unsafe fn read_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(slice::from_raw_parts(ptr, len))
}

/// Computes the 256-bit `WilisHash-256` digest of `data[..data_len]` into `out_32`.
///
/// # Safety
/// - `out_32` must point to at least 32 writable bytes.
/// - If `data_len > 0`, `data` must point to at least `data_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn wilis_hash_256(data: *const u8, data_len: usize, out_32: *mut u8) -> i32 {
    if out_32.is_null() {
        return WILIS_ERR_INVALID_ARG;
    }
    let input = match read_slice(data, data_len) {
        Some(s) => s,
        None => return WILIS_ERR_INVALID_ARG,
    };
    let digest = hash(input);
    slice::from_raw_parts_mut(out_32, HASH_BYTES).copy_from_slice(&digest);
    WILIS_OK
}

/// Encrypts `pt[..pt_len]` using `WilisAEAD`, writing ciphertext to `ct_out[..pt_len]`
/// and the 32-byte authentication tag to `tag_32_out`.
///
/// # Safety
/// - `key_32`, `nonce_24`, and `tag_32_out` must point to valid 32, 24, and 32-byte buffers.
/// - If `pt_len > 0`, `pt` and `ct_out` must point to `pt_len` readable/writable bytes.
#[no_mangle]
pub unsafe extern "C" fn wilis_aead_seal(
    key_32: *const u8,
    nonce_24: *const u8,
    aad: *const u8,
    aad_len: usize,
    pt: *const u8,
    pt_len: usize,
    ct_out: *mut u8,
    tag_32_out: *mut u8,
) -> i32 {
    if key_32.is_null() || nonce_24.is_null() || tag_32_out.is_null() {
        return WILIS_ERR_INVALID_ARG;
    }
    let aad_slice = match read_slice(aad, aad_len) {
        Some(s) => s,
        None => return WILIS_ERR_INVALID_ARG,
    };
    let pt_slice = match read_slice(pt, pt_len) {
        Some(s) => s,
        None => return WILIS_ERR_INVALID_ARG,
    };
    if pt_len > 0 && ct_out.is_null() {
        return WILIS_ERR_INVALID_ARG;
    }

    let key: [u8; KEY_BYTES] = slice::from_raw_parts(key_32, KEY_BYTES)
        .try_into()
        .expect("32 bytes");
    let nonce: [u8; NONCE_BYTES] = slice::from_raw_parts(nonce_24, NONCE_BYTES)
        .try_into()
        .expect("24 bytes");

    let (ct, tag) = seal(&key, &nonce, aad_slice, pt_slice);
    if pt_len > 0 {
        slice::from_raw_parts_mut(ct_out, pt_len).copy_from_slice(&ct);
    }
    slice::from_raw_parts_mut(tag_32_out, TAG_BYTES).copy_from_slice(&tag);
    WILIS_OK
}

/// Authenticates and decrypts `ct[..ct_len]` using `WilisAEAD`, writing plaintext to `pt_out`.
///
/// Returns `WILIS_ERR_AUTH_FAILED (-2)` if authentication fails (leaving `pt_out` untouched/zeroed).
///
/// # Safety
/// - `key_32`, `nonce_24`, and `tag_32` must point to valid 32, 24, and 32-byte buffers.
/// - If `ct_len > 0`, `ct` and `pt_out` must point to `ct_len` readable/writable bytes.
#[no_mangle]
pub unsafe extern "C" fn wilis_aead_open(
    key_32: *const u8,
    nonce_24: *const u8,
    aad: *const u8,
    aad_len: usize,
    ct: *const u8,
    ct_len: usize,
    tag_32: *const u8,
    pt_out: *mut u8,
) -> i32 {
    if key_32.is_null() || nonce_24.is_null() || tag_32.is_null() {
        return WILIS_ERR_INVALID_ARG;
    }
    let aad_slice = match read_slice(aad, aad_len) {
        Some(s) => s,
        None => return WILIS_ERR_INVALID_ARG,
    };
    let ct_slice = match read_slice(ct, ct_len) {
        Some(s) => s,
        None => return WILIS_ERR_INVALID_ARG,
    };
    if ct_len > 0 && pt_out.is_null() {
        return WILIS_ERR_INVALID_ARG;
    }

    let key: [u8; KEY_BYTES] = slice::from_raw_parts(key_32, KEY_BYTES)
        .try_into()
        .expect("32 bytes");
    let nonce: [u8; NONCE_BYTES] = slice::from_raw_parts(nonce_24, NONCE_BYTES)
        .try_into()
        .expect("24 bytes");
    let tag: [u8; TAG_BYTES] = slice::from_raw_parts(tag_32, TAG_BYTES)
        .try_into()
        .expect("32 bytes");

    match open(&key, &nonce, aad_slice, ct_slice, &tag) {
        Ok(pt) => {
            if ct_len > 0 {
                slice::from_raw_parts_mut(pt_out, ct_len).copy_from_slice(&pt);
            }
            WILIS_OK
        }
        Err(_) => {
            if ct_len > 0 {
                let out_slice = slice::from_raw_parts_mut(pt_out, ct_len);
                crate::utils::zeroize::zeroize_bytes(out_slice);
            }
            WILIS_ERR_AUTH_FAILED
        }
    }
}

/// Derives a 256-bit key using hybrid memory-hard `WilisKDF` v2.
///
/// # Safety
/// - `salt_24` must point to 24 readable bytes and `key_32_out` to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn wilis_kdf_derive(
    pass: *const u8,
    pass_len: usize,
    salt_24: *const u8,
    memory_blocks: u32,
    passes: u32,
    key_32_out: *mut u8,
) -> i32 {
    if salt_24.is_null() || key_32_out.is_null() {
        return WILIS_ERR_INVALID_ARG;
    }
    let pass_slice = match read_slice(pass, pass_len) {
        Some(s) => s,
        None => return WILIS_ERR_INVALID_ARG,
    };
    let salt: [u8; SALT_BYTES] = slice::from_raw_parts(salt_24, SALT_BYTES)
        .try_into()
        .expect("24 bytes");
    let params = KdfParams {
        memory_blocks,
        passes,
    };

    match derive_key(pass_slice, &salt, params) {
        Ok(key) => {
            slice::from_raw_parts_mut(key_32_out, KEY_BYTES).copy_from_slice(key.as_bytes());
            WILIS_OK
        }
        Err(_) => WILIS_ERR_INVALID_ARG,
    }
}

/// Fills `out[..len]` with cryptographically secure OS random bytes.
///
/// # Safety
/// - If `len > 0`, `out` must point to at least `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn wilis_random_bytes(out: *mut u8, len: usize) -> i32 {
    if len == 0 {
        return WILIS_OK;
    }
    if out.is_null() {
        return WILIS_ERR_INVALID_ARG;
    }
    let buf = slice::from_raw_parts_mut(out, len);
    match fill_random(buf) {
        Ok(()) => WILIS_OK,
        Err(_) => WILIS_ERR_INTERNAL,
    }
}
