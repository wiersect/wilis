//! Tests for the exported C-ABI Foreign Function Interface (`ffi::c_api`).

use wilis::ffi::c_api::{
    wilis_aead_open, wilis_aead_seal, wilis_hash_256, wilis_kdf_derive, wilis_random_bytes,
    WILIS_ERR_AUTH_FAILED, WILIS_ERR_INVALID_ARG, WILIS_OK,
};
use wilis::hash::hash;

#[test]
fn ffi_hash_random_kdf_and_aead_round_trip() {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    let mut salt = [0u8; 24];

    unsafe {
        assert_eq!(wilis_random_bytes(key.as_mut_ptr(), key.len()), WILIS_OK);
        assert_eq!(
            wilis_random_bytes(nonce.as_mut_ptr(), nonce.len()),
            WILIS_OK
        );
        assert_eq!(wilis_random_bytes(salt.as_mut_ptr(), salt.len()), WILIS_OK);
        assert_eq!(wilis_random_bytes(core::ptr::null_mut(), 0), WILIS_OK);
        assert_eq!(
            wilis_random_bytes(core::ptr::null_mut(), 16),
            WILIS_ERR_INVALID_ARG
        );

        // Hash matches Rust API
        let msg = b"FFI WilisHash-256 test payload";
        let mut digest = [0u8; 32];
        assert_eq!(
            wilis_hash_256(msg.as_ptr(), msg.len(), digest.as_mut_ptr()),
            WILIS_OK
        );
        assert_eq!(digest, hash(msg));

        // KDF works and rejects invalid params
        let mut derived = [0u8; 32];
        let pass = b"ffi-pass";
        assert_eq!(
            wilis_kdf_derive(
                pass.as_ptr(),
                pass.len(),
                salt.as_ptr(),
                64,
                2,
                derived.as_mut_ptr(),
            ),
            WILIS_OK
        );
        assert_eq!(
            wilis_kdf_derive(
                pass.as_ptr(),
                pass.len(),
                salt.as_ptr(),
                1,
                1,
                derived.as_mut_ptr(),
            ),
            WILIS_ERR_INVALID_ARG
        );

        // AEAD seal & open (including empty AAD with NULL pointer)
        let pt = b"Confidential bytes crossing the C ABI boundary!";
        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; 32];
        assert_eq!(
            wilis_aead_seal(
                key.as_ptr(),
                nonce.as_ptr(),
                core::ptr::null(),
                0,
                pt.as_ptr(),
                pt.len(),
                ct.as_mut_ptr(),
                tag.as_mut_ptr(),
            ),
            WILIS_OK
        );

        let mut recovered = vec![0u8; pt.len()];
        assert_eq!(
            wilis_aead_open(
                key.as_ptr(),
                nonce.as_ptr(),
                core::ptr::null(),
                0,
                ct.as_ptr(),
                ct.len(),
                tag.as_ptr(),
                recovered.as_mut_ptr(),
            ),
            WILIS_OK
        );
        assert_eq!(recovered, pt);

        // Tampered tag MUST fail with WILIS_ERR_AUTH_FAILED and zeroize output buffer!
        tag[0] ^= 0x01;
        recovered.fill(0xAA);
        assert_eq!(
            wilis_aead_open(
                key.as_ptr(),
                nonce.as_ptr(),
                core::ptr::null(),
                0,
                ct.as_ptr(),
                ct.len(),
                tag.as_ptr(),
                recovered.as_mut_ptr(),
            ),
            WILIS_ERR_AUTH_FAILED
        );
        assert!(recovered.iter().all(|&b| b == 0));
    }
}
