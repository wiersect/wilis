//! Tests for the exported C-ABI Foreign Function Interface (`ffi::c_api`) v0.4.0.

use wilis::ffi::c_api::{
    wilis_aead_open, wilis_aead_seal, wilis_hash_256, wilis_kdf_derive, wilis_kem_decapsulate,
    wilis_kem_encapsulate, wilis_kem_keygen, wilis_mac_256, wilis_random_bytes, wilis_xof_derive,
    WILIS_ERR_AUTH_FAILED, WILIS_ERR_INVALID_ARG, WILIS_OK,
};
use wilis::hash::hash;
use wilis::kem::{KEM_CT_BYTES, KEM_PK_BYTES, KEM_SK_BYTES, KEM_SS_BYTES};
use wilis::mac::mac;
use wilis::xof::WilisXof;

#[test]
fn ffi_hash_mac_xof_random_kdf_aead_and_kem_round_trip() {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    let mut salt = [0u8; 24];

    unsafe {
        assert_eq!(wilis_random_bytes(key.as_mut_ptr(), key.len()), WILIS_OK);
        assert_eq!(wilis_random_bytes(nonce.as_mut_ptr(), nonce.len()), WILIS_OK);
        assert_eq!(wilis_random_bytes(salt.as_mut_ptr(), salt.len()), WILIS_OK);
        assert_eq!(wilis_random_bytes(core::ptr::null_mut(), 0), WILIS_OK);
        assert_eq!(
            wilis_random_bytes(core::ptr::null_mut(), 16),
            WILIS_ERR_INVALID_ARG
        );

        // Hash matches Rust API
        let msg = b"FFI Wilis v0.4.0 test payload";
        let mut digest = [0u8; 32];
        assert_eq!(
            wilis_hash_256(msg.as_ptr(), msg.len(), digest.as_mut_ptr()),
            WILIS_OK
        );
        assert_eq!(digest, hash(msg));

        // MAC matches Rust API
        let mut mac_tag = [0u8; 32];
        assert_eq!(
            wilis_mac_256(key.as_ptr(), msg.as_ptr(), msg.len(), mac_tag.as_mut_ptr()),
            WILIS_OK
        );
        assert_eq!(mac_tag, mac(&key, msg));

        // XOF matches Rust API
        let mut xof_out = [0u8; 77];
        let lbl = b"ffi-xof";
        assert_eq!(
            wilis_xof_derive(
                lbl.as_ptr(),
                lbl.len(),
                msg.as_ptr(),
                msg.len(),
                xof_out.as_mut_ptr(),
                xof_out.len(),
            ),
            WILIS_OK
        );
        assert_eq!(xof_out.as_slice(), WilisXof::derive(lbl, msg, 77).as_slice());

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

        // Post-Quantum KEM keygen -> encapsulate -> decapsulate over C-ABI
        let mut pk = vec![0u8; KEM_PK_BYTES];
        let mut sk = vec![0u8; KEM_SK_BYTES];
        let mut kem_ct = vec![0u8; KEM_CT_BYTES];
        let mut ss1 = [0u8; KEM_SS_BYTES];
        let mut ss2 = [0u8; KEM_SS_BYTES];

        assert_eq!(wilis_kem_keygen(pk.as_mut_ptr(), sk.as_mut_ptr()), WILIS_OK);
        assert_eq!(
            wilis_kem_encapsulate(pk.as_ptr(), kem_ct.as_mut_ptr(), ss1.as_mut_ptr()),
            WILIS_OK
        );
        assert_eq!(
            wilis_kem_decapsulate(sk.as_ptr(), kem_ct.as_ptr(), ss2.as_mut_ptr()),
            WILIS_OK
        );
        assert_eq!(ss1, ss2);
    }
}
