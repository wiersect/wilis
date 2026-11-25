//! C-ABI exported cryptographic functions for `libwilis` v0.4.6.
//!
//! Safety & hardening guarantees:
//! - Every `extern "C"` boundary catches Rust panics via `std::panic::catch_unwind`
//!   so panics never unwind across C/Python FFI (preventing UB).
//! - Rejects null pointers (unless paired with `len == 0`) and lengths `> isize::MAX`
//!   (preventing Rust slice precondition UB).
//! - Explicitly finishes reading input slices before writing output buffers so
//!   in-place AEAD / hash / MAC / XOF calls do not alias `&[u8]` and `&mut [u8]`.
//! - Rejects overlapping output buffers in multi-output KEM functions.
//!
//! Return codes:
//! - `0`: Success (`WILIS_OK`)
//! - `-1`: Null pointer or invalid argument (`WILIS_ERR_INVALID_ARG`)
//! - `-2`: Authentication / verification failed (`WILIS_ERR_AUTH_FAILED`)
//! - `-3`: OS CSPRNG or internal failure (`WILIS_ERR_INTERNAL`)

use core::slice;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::aead::{open, seal};
use crate::core::constants::{HASH_BYTES, KEY_BYTES, NONCE_BYTES, SALT_BYTES, TAG_BYTES};
use crate::hash::hash;
use crate::kdf::{derive_key, KdfParams};
use crate::kem::{
    decapsulate, encapsulate, keygen, KemCiphertext, KemPublicKey, KemSecretKey, KEM_CT_BYTES,
    KEM_PK_BYTES, KEM_SK_BYTES, KEM_SS_BYTES,
};
use crate::mac::mac;
use crate::utils::random::fill_random;
use crate::utils::zeroize::zeroize_bytes;
use crate::xof::WilisXof;

pub const WILIS_OK: i32 = 0;
pub const WILIS_ERR_INVALID_ARG: i32 = -1;
pub const WILIS_ERR_AUTH_FAILED: i32 = -2;
pub const WILIS_ERR_INTERNAL: i32 = -3;

#[inline]
fn ffi_guard<F: FnOnce() -> i32>(f: F) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(WILIS_ERR_INTERNAL)
}

#[inline]
fn valid_slice_len(len: usize) -> bool {
    len <= isize::MAX as usize
}

/// Returns `true` if two byte buffers `[a, a+a_len)` and `[b, b+b_len)` overlap in memory.
#[inline]
fn ranges_overlap(a: *const u8, a_len: usize, b: *const u8, b_len: usize) -> bool {
    if a_len == 0 || b_len == 0 {
        return false;
    }
    let a_start = a as usize;
    let b_start = b as usize;
    let a_end = a_start.saturating_add(a_len);
    let b_end = b_start.saturating_add(b_len);
    a_start < b_end && b_start < a_end
}

/// Helper safely converting `(ptr, len)` to a byte slice, allowing `NULL` when `len == 0`
/// and rejecting `len > isize::MAX` to satisfy Rust's `slice::from_raw_parts` invariant.
unsafe fn read_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() || !valid_slice_len(len) {
        return None;
    }
    Some(slice::from_raw_parts(ptr, len))
}

/// Computes the 256-bit `WilisHash-256` digest of `data[..data_len]` into `out_32`.
///
/// # Safety
/// - `out_32` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn wilis_hash_256(data: *const u8, data_len: usize, out_32: *mut u8) -> i32 {
    ffi_guard(|| {
        if out_32.is_null() {
            return WILIS_ERR_INVALID_ARG;
        }
        let digest = {
            let input = match read_slice(data, data_len) {
                Some(s) => s,
                None => return WILIS_ERR_INVALID_ARG,
            };
            hash(input)
        };
        slice::from_raw_parts_mut(out_32, HASH_BYTES).copy_from_slice(&digest);
        WILIS_OK
    })
}

/// Computes a 256-bit keyed `WilisMAC` tag over `msg[..msg_len]` under `key_32`.
///
/// # Safety
/// - `key_32` and `tag_32_out` must point to 32 readable/writable bytes.
#[no_mangle]
pub unsafe extern "C" fn wilis_mac_256(
    key_32: *const u8,
    msg: *const u8,
    msg_len: usize,
    tag_32_out: *mut u8,
) -> i32 {
    ffi_guard(|| {
        if key_32.is_null() || tag_32_out.is_null() {
            return WILIS_ERR_INVALID_ARG;
        }
        let tag = {
            let input = match read_slice(msg, msg_len) {
                Some(s) => s,
                None => return WILIS_ERR_INVALID_ARG,
            };
            let mut key: [u8; KEY_BYTES] = slice::from_raw_parts(key_32, KEY_BYTES)
                .try_into()
                .expect("32 bytes");
            let t = mac(&key, input);
            zeroize_bytes(&mut key);
            t
        };
        slice::from_raw_parts_mut(tag_32_out, TAG_BYTES).copy_from_slice(&tag);
        WILIS_OK
    })
}

/// Derives `out_len` deterministic pseudorandom bytes via `WilisXOF` from `(label, seed)`.
///
/// # Safety
/// - If `out_len > 0`, `out` must point to at least `out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn wilis_xof_derive(
    label: *const u8,
    label_len: usize,
    seed: *const u8,
    seed_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    ffi_guard(|| {
        if !valid_slice_len(out_len) {
            return WILIS_ERR_INVALID_ARG;
        }
        let mut xof = {
            let label_slice = match read_slice(label, label_len) {
                Some(s) => s,
                None => return WILIS_ERR_INVALID_ARG,
            };
            let seed_slice = match read_slice(seed, seed_len) {
                Some(s) => s,
                None => return WILIS_ERR_INVALID_ARG,
            };
            if out_len == 0 {
                return WILIS_OK;
            }
            if out.is_null() {
                return WILIS_ERR_INVALID_ARG;
            }
            let mut x = WilisXof::new(label_slice);
            x.absorb(seed_slice);
            x
        };
        // Input slices are out of scope before creating mutable output slice (safe if in-place)
        let out_slice = slice::from_raw_parts_mut(out, out_len);
        xof.squeeze(out_slice);
        WILIS_OK
    })
}

/// Encrypts `pt[..pt_len]` using `WilisAEAD` (supports in-place `ct_out == pt`).
///
/// # Safety
/// - `key_32`, `nonce_24`, and `tag_32_out` must point to valid 32, 24, and 32-byte buffers.
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
    ffi_guard(|| {
        if key_32.is_null() || nonce_24.is_null() || tag_32_out.is_null() {
            return WILIS_ERR_INVALID_ARG;
        }
        if !valid_slice_len(pt_len) || (pt_len > 0 && ct_out.is_null()) {
            return WILIS_ERR_INVALID_ARG;
        }
        if pt_len > 0 && ranges_overlap(ct_out, pt_len, tag_32_out, TAG_BYTES) {
            return WILIS_ERR_INVALID_ARG;
        }

        let (ct, tag) = {
            let aad_slice = match read_slice(aad, aad_len) {
                Some(s) => s,
                None => return WILIS_ERR_INVALID_ARG,
            };
            let pt_slice = match read_slice(pt, pt_len) {
                Some(s) => s,
                None => return WILIS_ERR_INVALID_ARG,
            };
            let mut key: [u8; KEY_BYTES] = slice::from_raw_parts(key_32, KEY_BYTES)
                .try_into()
                .expect("32 bytes");
            let nonce: [u8; NONCE_BYTES] = slice::from_raw_parts(nonce_24, NONCE_BYTES)
                .try_into()
                .expect("24 bytes");

            let out = seal(&key, &nonce, aad_slice, pt_slice);
            zeroize_bytes(&mut key);
            out
        };

        // All input borrows have ended; writing to `ct_out` (even if `ct_out == pt`) is alias-safe
        if pt_len > 0 {
            slice::from_raw_parts_mut(ct_out, pt_len).copy_from_slice(&ct);
        }
        slice::from_raw_parts_mut(tag_32_out, TAG_BYTES).copy_from_slice(&tag);
        WILIS_OK
    })
}

/// Authenticates and decrypts `ct[..ct_len]` using `WilisAEAD` (supports in-place `pt_out == ct`).
///
/// # Safety
/// - `key_32`, `nonce_24`, and `tag_32` must point to valid 32, 24, and 32-byte buffers.
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
    ffi_guard(|| {
        if key_32.is_null() || nonce_24.is_null() || tag_32.is_null() {
            return WILIS_ERR_INVALID_ARG;
        }
        if !valid_slice_len(ct_len) || (ct_len > 0 && pt_out.is_null()) {
            return WILIS_ERR_INVALID_ARG;
        }

        let res = {
            let aad_slice = match read_slice(aad, aad_len) {
                Some(s) => s,
                None => return WILIS_ERR_INVALID_ARG,
            };
            let ct_slice = match read_slice(ct, ct_len) {
                Some(s) => s,
                None => return WILIS_ERR_INVALID_ARG,
            };
            let mut key: [u8; KEY_BYTES] = slice::from_raw_parts(key_32, KEY_BYTES)
                .try_into()
                .expect("32 bytes");
            let nonce: [u8; NONCE_BYTES] = slice::from_raw_parts(nonce_24, NONCE_BYTES)
                .try_into()
                .expect("24 bytes");
            let tag: [u8; TAG_BYTES] = slice::from_raw_parts(tag_32, TAG_BYTES)
                .try_into()
                .expect("32 bytes");

            let r = open(&key, &nonce, aad_slice, ct_slice, &tag);
            zeroize_bytes(&mut key);
            r
        };

        // All input borrows have ended; writing/zeroizing `pt_out` is alias-safe
        match res {
            Ok(mut pt) => {
                if ct_len > 0 {
                    slice::from_raw_parts_mut(pt_out, ct_len).copy_from_slice(&pt);
                }
                zeroize_bytes(&mut pt);
                WILIS_OK
            }
            Err(_) => {
                if ct_len > 0 {
                    let out_slice = slice::from_raw_parts_mut(pt_out, ct_len);
                    zeroize_bytes(out_slice);
                }
                WILIS_ERR_AUTH_FAILED
            }
        }
    })
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
    ffi_guard(|| {
        if salt_24.is_null() || key_32_out.is_null() {
            return WILIS_ERR_INVALID_ARG;
        }
        let derived = {
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
            derive_key(pass_slice, &salt, params)
        };

        match derived {
            Ok(key) => {
                slice::from_raw_parts_mut(key_32_out, KEY_BYTES).copy_from_slice(key.as_bytes());
                WILIS_OK
            }
            Err(_) => {
                zeroize_bytes(slice::from_raw_parts_mut(key_32_out, KEY_BYTES));
                WILIS_ERR_INVALID_ARG
            }
        }
    })
}

/// Generates a post-quantum `WilisKEM` keypair into `pk_out` (`1284` B) and `sk_out` (`2600` B).
///
/// # Safety
/// - `pk_out` and `sk_out` must be distinct, non-overlapping writable buffers of
///   `KEM_PK_BYTES` (1284) and `KEM_SK_BYTES` (2600) bytes respectively.
#[no_mangle]
pub unsafe extern "C" fn wilis_kem_keygen(pk_out: *mut u8, sk_out: *mut u8) -> i32 {
    ffi_guard(|| {
        if pk_out.is_null()
            || sk_out.is_null()
            || ranges_overlap(pk_out, KEM_PK_BYTES, sk_out, KEM_SK_BYTES)
        {
            return WILIS_ERR_INVALID_ARG;
        }
        match keygen() {
            Ok((sk, pk)) => {
                slice::from_raw_parts_mut(pk_out, KEM_PK_BYTES).copy_from_slice(&pk.to_bytes());
                let mut sk_bytes = sk.to_bytes();
                slice::from_raw_parts_mut(sk_out, KEM_SK_BYTES).copy_from_slice(&sk_bytes);
                zeroize_bytes(&mut sk_bytes);
                WILIS_OK
            }
            Err(_) => {
                zeroize_bytes(slice::from_raw_parts_mut(pk_out, KEM_PK_BYTES));
                zeroize_bytes(slice::from_raw_parts_mut(sk_out, KEM_SK_BYTES));
                WILIS_ERR_INTERNAL
            }
        }
    })
}

/// Encapsulates a 256-bit shared secret to `pk` (`1284` B), writing `ct_out` (`1668` B) and `ss_out` (`32` B).
///
/// # Safety
/// - `ct_out` and `ss_32_out` must be distinct, non-overlapping buffers matching
///   `KEM_CT_BYTES` and `KEM_SS_BYTES`.
#[no_mangle]
pub unsafe extern "C" fn wilis_kem_encapsulate(
    pk: *const u8,
    ct_out: *mut u8,
    ss_32_out: *mut u8,
) -> i32 {
    ffi_guard(|| {
        if pk.is_null()
            || ct_out.is_null()
            || ss_32_out.is_null()
            || ranges_overlap(ct_out, KEM_CT_BYTES, ss_32_out, KEM_SS_BYTES)
        {
            return WILIS_ERR_INVALID_ARG;
        }
        let pk_obj = match KemPublicKey::from_bytes(slice::from_raw_parts(pk, KEM_PK_BYTES)) {
            Ok(k) => k,
            Err(_) => {
                zeroize_bytes(slice::from_raw_parts_mut(ct_out, KEM_CT_BYTES));
                zeroize_bytes(slice::from_raw_parts_mut(ss_32_out, KEM_SS_BYTES));
                return WILIS_ERR_INVALID_ARG;
            }
        };
        match encapsulate(&pk_obj) {
            Ok((ct, ss)) => {
                slice::from_raw_parts_mut(ct_out, KEM_CT_BYTES).copy_from_slice(&ct.to_bytes());
                slice::from_raw_parts_mut(ss_32_out, KEM_SS_BYTES).copy_from_slice(ss.as_bytes());
                WILIS_OK
            }
            Err(_) => {
                zeroize_bytes(slice::from_raw_parts_mut(ct_out, KEM_CT_BYTES));
                zeroize_bytes(slice::from_raw_parts_mut(ss_32_out, KEM_SS_BYTES));
                WILIS_ERR_INTERNAL
            }
        }
    })
}

/// Decapsulates `ct` (`1668` B) using `sk` (`2600` B), writing the 256-bit shared secret to `ss_32_out`.
///
/// # Safety
/// - Buffers must match `KEM_SK_BYTES`, `KEM_CT_BYTES`, and `KEM_SS_BYTES`.
#[no_mangle]
pub unsafe extern "C" fn wilis_kem_decapsulate(
    sk: *const u8,
    ct: *const u8,
    ss_32_out: *mut u8,
) -> i32 {
    ffi_guard(|| {
        if sk.is_null() || ct.is_null() || ss_32_out.is_null() {
            return WILIS_ERR_INVALID_ARG;
        }
        let ss_res = {
            let sk_obj = match KemSecretKey::from_bytes(slice::from_raw_parts(sk, KEM_SK_BYTES)) {
                Ok(k) => k,
                Err(_) => return {
                    zeroize_bytes(slice::from_raw_parts_mut(ss_32_out, KEM_SS_BYTES));
                    WILIS_ERR_INVALID_ARG
                },
            };
            let ct_obj = match KemCiphertext::from_bytes(slice::from_raw_parts(ct, KEM_CT_BYTES)) {
                Ok(c) => c,
                Err(_) => return {
                    zeroize_bytes(slice::from_raw_parts_mut(ss_32_out, KEM_SS_BYTES));
                    WILIS_ERR_INVALID_ARG
                },
            };
            decapsulate(&sk_obj, &ct_obj)
        };
        slice::from_raw_parts_mut(ss_32_out, KEM_SS_BYTES).copy_from_slice(ss_res.as_bytes());
        WILIS_OK
    })
}

/// Fills `out[..len]` with cryptographically secure OS random bytes.
///
/// # Safety
/// - If `len > 0`, `out` must point to at least `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn wilis_random_bytes(out: *mut u8, len: usize) -> i32 {
    ffi_guard(|| {
        if len == 0 {
            return WILIS_OK;
        }
        if out.is_null() || !valid_slice_len(len) {
            return WILIS_ERR_INVALID_ARG;
        }
        let buf = slice::from_raw_parts_mut(out, len);
        match fill_random(buf) {
            Ok(()) => WILIS_OK,
            Err(_) => WILIS_ERR_INTERNAL,
        }
    })
}
