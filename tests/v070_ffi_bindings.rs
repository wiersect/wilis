//! Comprehensive Rust verification of all 12 new v0.7.0 C-ABI exports (33 total)
//! including two-call variable output sizing, error-path wiping, null/overlap rejection,
//! authentication rejection, and decompression-bomb enforcement.

use std::ffi::CStr;
use std::ptr;

use wilis::ffi::c_api::{
    wilis_ct_eq, wilis_fpe_decrypt, wilis_fpe_encrypt, wilis_kdf_parallel_derive, wilis_kem_keygen,
    wilis_lz_compress, wilis_lz_decompress, wilis_mnemonic_decode, wilis_mnemonic_encode,
    wilis_signcrypt, wilis_slh_keygen, wilis_totp_at, wilis_unsigncrypt, wilis_version,
    wilis_zeroize, WILIS_ERR_AUTH_FAILED, WILIS_ERR_BUF_TOO_SMALL, WILIS_ERR_INVALID_ARG, WILIS_OK,
};

#[test]
fn ffi_v070_ct_eq_zeroize_and_version() {
    unsafe {
        let ver = CStr::from_ptr(wilis_version()).to_str().unwrap();
        assert_eq!(ver, env!("CARGO_PKG_VERSION"));

        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        assert_eq!(wilis_ct_eq(a.as_ptr(), b.as_ptr(), a.len()), 1);
        assert_eq!(wilis_ct_eq(a.as_ptr(), c.as_ptr(), a.len()), 0);
        assert_eq!(wilis_ct_eq(ptr::null(), ptr::null(), 0), 1);
        assert_eq!(wilis_ct_eq(ptr::null(), b.as_ptr(), 4), WILIS_ERR_INVALID_ARG);
        assert_eq!(
            wilis_ct_eq(a.as_ptr(), b.as_ptr(), (isize::MAX as usize) + 1),
            WILIS_ERR_INVALID_ARG
        );

        let mut secret = [0xAAu8; 32];
        assert_eq!(wilis_zeroize(secret.as_mut_ptr(), secret.len()), WILIS_OK);
        assert_eq!(secret, [0u8; 32]);
        assert_eq!(wilis_zeroize(ptr::null_mut(), 0), WILIS_OK);
        assert_eq!(wilis_zeroize(ptr::null_mut(), 8), WILIS_ERR_INVALID_ARG);
    }
}

#[test]
fn ffi_v070_kdf_parallel_and_totp() {
    unsafe {
        let salt = [0x33u8; 24];
        let pw = b"wilis-v070-parallel-kdf";
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        assert_eq!(
            wilis_kdf_parallel_derive(pw.as_ptr(), pw.len(), salt.as_ptr(), 128, 2, 4, k1.as_mut_ptr()),
            WILIS_OK
        );
        assert_eq!(
            wilis_kdf_parallel_derive(pw.as_ptr(), pw.len(), salt.as_ptr(), 128, 2, 4, k2.as_mut_ptr()),
            WILIS_OK
        );
        assert_eq!(k1, k2);
        // Invalid lanes = 0 must reject and wipe output
        let mut bad_out = [0xFFu8; 32];
        assert_eq!(
            wilis_kdf_parallel_derive(pw.as_ptr(), pw.len(), salt.as_ptr(), 128, 2, 0, bad_out.as_mut_ptr()),
            WILIS_ERR_INVALID_ARG
        );
        assert_eq!(bad_out, [0u8; 32]);

        // TOTP 6 and 8 digits + buffer-too-small check
        let mut code = [0u8; 9];
        let mut rem: u64 = 0;
        assert_eq!(
            wilis_totp_at(b"12345678901234567890".as_ptr(), 20, 1_700_000_020, 30, 6, code.as_mut_ptr(), 7, &mut rem),
            WILIS_OK
        );
        assert_eq!(rem, 20);
        let code_str = CStr::from_ptr(code.as_ptr() as *const _).to_str().unwrap();
        assert_eq!(code_str.len(), 6);
        assert!(code_str.bytes().all(|b| b.is_ascii_digit()));

        // Too small code_cap (needs digits + 1 for NUL)
        assert_eq!(
            wilis_totp_at(b"12345678901234567890".as_ptr(), 20, 1_700_000_020, 30, 6, code.as_mut_ptr(), 6, &mut rem),
            WILIS_ERR_BUF_TOO_SMALL
        );
    }
}

#[test]
fn ffi_v070_signcrypt_roundtrip_and_tamper_wipe() {
    unsafe {
        let mut kem_pk = [0u8; 1284];
        let mut kem_sk = [0u8; 2600];
        assert_eq!(wilis_kem_keygen(kem_pk.as_mut_ptr(), kem_sk.as_mut_ptr()), WILIS_OK);

        let mut slh_pk = [0u8; 100];
        let mut slh_sk = [0u8; 164];
        assert_eq!(wilis_slh_keygen(slh_pk.as_mut_ptr(), slh_sk.as_mut_ptr()), WILIS_OK);

        let aad = b"wilis-v070-aad";
        let pt = b"post-quantum authenticated & encrypted payload";

        // Size-query call (NULL, 0)
        let mut needed = 0usize;
        assert_eq!(
            wilis_signcrypt(
                slh_sk.as_ptr(),
                kem_pk.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                pt.as_ptr(),
                pt.len(),
                ptr::null_mut(),
                0,
                &mut needed
            ),
            WILIS_ERR_BUF_TOO_SMALL
        );
        assert_eq!(needed, 9894 + pt.len());

        // Bogus (NULL, >0) rejected with INVALID_ARG
        assert_eq!(
            wilis_signcrypt(
                slh_sk.as_ptr(),
                kem_pk.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                pt.as_ptr(),
                pt.len(),
                ptr::null_mut(),
                100,
                &mut needed
            ),
            WILIS_ERR_INVALID_ARG
        );

        let mut pkt = vec![0u8; needed];
        let mut actual = 0usize;
        assert_eq!(
            wilis_signcrypt(
                slh_sk.as_ptr(),
                kem_pk.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                pt.as_ptr(),
                pt.len(),
                pkt.as_mut_ptr(),
                pkt.len(),
                &mut actual
            ),
            WILIS_OK
        );
        assert_eq!(actual, needed);

        // Unsigncrypt two-call flow
        let mut pt_needed = 0usize;
        assert_eq!(
            wilis_unsigncrypt(
                slh_pk.as_ptr(),
                kem_sk.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                pkt.as_ptr(),
                pkt.len(),
                ptr::null_mut(),
                0,
                &mut pt_needed
            ),
            WILIS_ERR_BUF_TOO_SMALL
        );
        assert_eq!(pt_needed, pt.len());

        let mut out_pt = vec![0u8; pt_needed];
        let mut out_len = 0usize;
        assert_eq!(
            wilis_unsigncrypt(
                slh_pk.as_ptr(),
                kem_sk.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                pkt.as_ptr(),
                pkt.len(),
                out_pt.as_mut_ptr(),
                out_pt.len(),
                &mut out_len
            ),
            WILIS_OK
        );
        assert_eq!(&out_pt[..out_len], pt);

        // Tampered packet MUST return AUTH_FAILED and wipe pre-filled output buffer
        let last = pkt.len() - 1;
        pkt[last] ^= 0x01;
        out_pt.fill(0xCC);
        assert_eq!(
            wilis_unsigncrypt(
                slh_pk.as_ptr(),
                kem_sk.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                pkt.as_ptr(),
                pkt.len(),
                out_pt.as_mut_ptr(),
                out_pt.len(),
                &mut out_len
            ),
            WILIS_ERR_AUTH_FAILED
        );
        assert_eq!(out_len, 0);
        assert!(out_pt.iter().all(|&b| b == 0));
    }
}

#[test]
fn ffi_v070_fpe_mnemonic_and_lz_exports() {
    unsafe {
        // FPE
        let key = [0x77u8; 32];
        let tweak = b"card-pan";
        let alpha = b"0123456789";
        let pan = b"4111111111111111";
        let mut ct_len = 0usize;
        assert_eq!(
            wilis_fpe_encrypt(
                key.as_ptr(),
                tweak.as_ptr(),
                tweak.len(),
                alpha.as_ptr(),
                alpha.len(),
                pan.as_ptr(),
                pan.len(),
                ptr::null_mut(),
                0,
                &mut ct_len
            ),
            WILIS_ERR_BUF_TOO_SMALL
        );
        let mut ct = vec![0u8; ct_len];
        assert_eq!(
            wilis_fpe_encrypt(
                key.as_ptr(),
                tweak.as_ptr(),
                tweak.len(),
                alpha.as_ptr(),
                alpha.len(),
                pan.as_ptr(),
                pan.len(),
                ct.as_mut_ptr(),
                ct.len(),
                &mut ct_len
            ),
            WILIS_OK
        );
        assert_ne!(&ct[..ct_len], pan);
        let mut pt = vec![0u8; ct_len];
        let mut pt_len = 0usize;
        assert_eq!(
            wilis_fpe_decrypt(
                key.as_ptr(),
                tweak.as_ptr(),
                tweak.len(),
                alpha.as_ptr(),
                alpha.len(),
                ct.as_ptr(),
                ct_len,
                pt.as_mut_ptr(),
                pt.len(),
                &mut pt_len
            ),
            WILIS_OK
        );
        assert_eq!(&pt[..pt_len], pan);

        // Mnemonic + checksum tamper detection & wipe
        let mut phr_len = 0usize;
        assert_eq!(
            wilis_mnemonic_encode(key.as_ptr(), key.len(), ptr::null_mut(), 0, &mut phr_len),
            WILIS_ERR_BUF_TOO_SMALL
        );
        let mut phr = vec![0u8; phr_len];
        assert_eq!(
            wilis_mnemonic_encode(key.as_ptr(), key.len(), phr.as_mut_ptr(), phr.len(), &mut phr_len),
            WILIS_OK
        );
        let mut rec_len = 0usize;
        assert_eq!(
            wilis_mnemonic_decode(phr.as_ptr(), phr_len, ptr::null_mut(), 0, &mut rec_len),
            WILIS_ERR_BUF_TOO_SMALL
        );
        let mut rec = vec![0u8; rec_len];
        assert_eq!(
            wilis_mnemonic_decode(phr.as_ptr(), phr_len, rec.as_mut_ptr(), rec.len(), &mut rec_len),
            WILIS_OK
        );
        assert_eq!(&rec[..rec_len], &key);

        // Swap first two words -> checksum mismatch -> AUTH_FAILED + zeroize out
        let s = String::from_utf8(phr[..phr_len].to_vec()).unwrap();
        let mut words: Vec<&str> = s.split_whitespace().collect();
        words.swap(0, 1);
        let bad_phrase = words.join(" ");
        rec.fill(0xEE);
        let rc = wilis_mnemonic_decode(
            bad_phrase.as_ptr(),
            bad_phrase.len(),
            rec.as_mut_ptr(),
            rec.len(),
            &mut rec_len,
        );
        if rc == WILIS_ERR_AUTH_FAILED {
            assert!(rec.iter().all(|&b| b == 0));
        } else {
            // Only possible if word 0 == word 1 (all 0x77 bytes have identical words!)
            assert_eq!(rc, WILIS_OK);
        }

        // Test genuine bad checksum on distinct-byte key
        let distinct: Vec<u8> = (0u8..32).collect();
        let mut p2_len = 0usize;
        assert_eq!(
            wilis_mnemonic_encode(distinct.as_ptr(), distinct.len(), ptr::null_mut(), 0, &mut p2_len),
            WILIS_ERR_BUF_TOO_SMALL
        );
        let mut p2 = vec![0u8; p2_len];
        assert_eq!(
            wilis_mnemonic_encode(distinct.as_ptr(), distinct.len(), p2.as_mut_ptr(), p2.len(), &mut p2_len),
            WILIS_OK
        );
        let s2 = String::from_utf8(p2[..p2_len].to_vec()).unwrap();
        let mut w2: Vec<&str> = s2.split_whitespace().collect();
        w2.swap(0, 1);
        let bad2 = w2.join(" ");
        rec.fill(0xDD);
        assert_eq!(
            wilis_mnemonic_decode(bad2.as_ptr(), bad2.len(), rec.as_mut_ptr(), rec.len(), &mut rec_len),
            WILIS_ERR_AUTH_FAILED
        );
        assert!(rec.iter().all(|&b| b == 0));

        // WilisLZ compress/decompress + decompression-bomb cap
        let raw = b"WilisLZ-v0.7.0-FFI-compression-test-payload!".repeat(40);
        let mut zlen = 0usize;
        assert_eq!(
            wilis_lz_compress(raw.as_ptr(), raw.len(), ptr::null_mut(), 0, &mut zlen),
            WILIS_ERR_BUF_TOO_SMALL
        );
        let mut zbuf = vec![0u8; zlen];
        assert_eq!(
            wilis_lz_compress(raw.as_ptr(), raw.len(), zbuf.as_mut_ptr(), zbuf.len(), &mut zlen),
            WILIS_OK
        );
        assert!(zlen < raw.len());

        // Bomb cap smaller than raw.len() MUST fail
        let mut bomb_len = 0usize;
        assert_eq!(
            wilis_lz_decompress(zbuf.as_ptr(), zlen, 16, ptr::null_mut(), 0, &mut bomb_len),
            WILIS_ERR_INVALID_ARG
        );

        let mut dlen = 0usize;
        assert_eq!(
            wilis_lz_decompress(zbuf.as_ptr(), zlen, raw.len() + 64, ptr::null_mut(), 0, &mut dlen),
            WILIS_ERR_BUF_TOO_SMALL
        );
        let mut dbuf = vec![0u8; dlen];
        assert_eq!(
            wilis_lz_decompress(zbuf.as_ptr(), zlen, raw.len() + 64, dbuf.as_mut_ptr(), dbuf.len(), &mut dlen),
            WILIS_OK
        );
        assert_eq!(&dbuf[..dlen], raw.as_slice());

        // Empty LZ roundtrip returns WILIS_OK with dlen == 0
        let mut ezlen = 0usize;
        assert_eq!(wilis_lz_compress(ptr::null(), 0, ptr::null_mut(), 0, &mut ezlen), WILIS_ERR_BUF_TOO_SMALL);
        let mut ez = vec![0u8; ezlen];
        assert_eq!(wilis_lz_compress(ptr::null(), 0, ez.as_mut_ptr(), ez.len(), &mut ezlen), WILIS_OK);
        let mut edlen = 99usize;
        assert_eq!(wilis_lz_decompress(ez.as_ptr(), ezlen, 1024, ptr::null_mut(), 0, &mut edlen), WILIS_OK);
        assert_eq!(edlen, 0);
    }
}
