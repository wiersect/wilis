//! Adversarial parser fuzzing & bug-audit regression tests.
//!
//! Feeds truncated, malformed, oversized-field, and pseudo-random adversarial inputs
//! into EVERY binary/text parser in Wilis to guarantee zero panics on untrusted data.

use std::io::Cursor;

use wilis::archive::unpack_directory;
use wilis::format::{decrypt_with_key, decrypt_with_passphrase, ContainerHeader};
use wilis::kem::{pub_decrypt, keygen, KemCiphertext, KemPublicKey, KemSecretKey};
use wilis::ratchet::RatchetPacket;
use wilis::sign::{Signature, SigningKey, VerifyingKey};
use wilis::split::{combine_shares, Share};
use wilis::stream::decrypt_stream_with_key;
use wilis::utils::base64::decode_base64;
use wilis::utils::hex::decode_hex;
use wilis::vault::Vault;
use wilis::xof::WilisXof;

#[test]
fn all_parsers_are_panic_free_on_adversarial_and_fuzz_inputs() {
    let key = [0x11u8; 32];
    let (kem_sk, _) = keygen().unwrap();
    let mut rng = WilisXof::new(b"wilis-fuzz-audit-v040");

    // Structured adversarial corpus: empty, magic-only, max-integer headers, all-0x00, all-0xFF
    let mut corpus: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0xFF; 16],
        vec![0x00; 128],
        b"WILS".to_vec(),
        b"WILS\x01\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF".to_vec(),
        b"WILS\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF".to_vec(),
        b"WDIR\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF".to_vec(),
        b"WVLT\x01\xFF\xFF\xFF\xFF".to_vec(),
        b"WSIG\x01\x06\x00\x00\x00\x00".to_vec(),
        b"WSHR\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
        b"WPKE\x01".to_vec(),
        b"WRAT\x01\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
    ];

    // Add 300 pseudo-random payloads of varying sizes (1..=300 bytes)
    for len in 1..=300usize {
        corpus.push(rng.squeeze_vec(len));
    }

    let tmp_dir = std::env::temp_dir().join(format!("wilis_fuzz_dir_{}", std::process::id()));

    for data in &corpus {
        let _ = ContainerHeader::parse(data);
        let _ = decrypt_with_key(&key, data, b"");
        let _ = decrypt_with_passphrase(b"pass", data, b"");
        let mut sink = Vec::new();
        let _ = decrypt_stream_with_key(&key, &mut Cursor::new(data), &mut sink, b"");
        let _ = Signature::from_bytes(data);
        let _ = SigningKey::from_bytes(data);
        let _ = VerifyingKey::from_bytes(data);
        let _ = Share::from_bytes(data);
        let _ = Vault::from_bytes(data);
        let _ = unpack_directory(&mut Cursor::new(data), &tmp_dir);
        let _ = KemPublicKey::from_bytes(data);
        let _ = KemSecretKey::from_bytes(data);
        let _ = KemCiphertext::from_bytes(data);
        let _ = pub_decrypt(&kem_sk, data, b"");
        let _ = RatchetPacket::from_bytes(data);

        if let Ok(as_str) = core::str::from_utf8(data) {
            let _ = decode_base64(as_str);
            let _ = decode_hex(as_str);
            let _ = Share::decode_string(as_str);
        }
    }

    // Manually constructed invalid Share must fail cleanly without panicking
    let bad_share = Share {
        index: 1,
        threshold: 0,
        total: 0,
        commitment: [0; 8],
        data: vec![],
    };
    assert!(combine_shares(&[bad_share]).is_err());

    // Trailing garbage in an otherwise valid WDIR archive MUST be rejected
    let mut trailing_wdir = Vec::new();
    trailing_wdir.extend_from_slice(b"WDIR\x01");
    trailing_wdir.extend_from_slice(&0u64.to_le_bytes()); // 0 files
    trailing_wdir.push(0x99); // unexpected trailing garbage
    assert!(unpack_directory(&mut Cursor::new(&trailing_wdir), &tmp_dir).is_err());

    let _ = std::fs::remove_dir_all(&tmp_dir);
}


#[test]
fn regression_v041_audit_fixes_verified() {
    use wilis::archive::encrypt_directory_with_key;
    use wilis::audit::avalanche::analyze_bic;
    use wilis::audit::randomness::analyze_keystream_randomness;
    use wilis::cli::args::AuthInput;
    use wilis::cli::file_cmd;
    use wilis::error::WilisError;
    use wilis::ratchet::RatchetSession;
    use wilis::split::split_secret;
    use wilis::utils::zeroize::SecretKey;

    // 1. XOF empty-label vs non-empty-label collision fix
    let mut forged_empty_seed = Vec::new();
    forged_empty_seed.extend_from_slice(&4u64.to_le_bytes());
    forged_empty_seed.extend_from_slice(b"ABCD");
    forged_empty_seed.push(b'X');
    let out_empty = WilisXof::derive(b"", &forged_empty_seed, 32);
    let out_labeled = WilisXof::derive(b"ABCD", b"X", 32);
    assert_ne!(
        out_empty, out_labeled,
        "empty XOF domain label must not collide with length-prefixed non-empty label"
    );

    // 2. Base64 non-canonical padding bits rejected
    assert_eq!(decode_base64("AA==").unwrap(), vec![0x00]);
    assert!(decode_base64("AB==").is_err()); // non-zero low 4 bits
    assert_eq!(decode_base64("AAA=").unwrap(), vec![0x00, 0x00]);
    assert!(decode_base64("AAB=").is_err()); // non-zero low 2 bits

    // 3. Shamir share index > total rejected & extra corrupted backup share caught!
    let mut bad_idx_share = split_secret(b"secret-32-byte-value-for-shamir!", 5, 3).unwrap();
    let mut raw_s = bad_idx_share[0].to_bytes();
    raw_s[5] = 99; // index = 99 > total = 5
    assert!(Share::from_bytes(&raw_s).is_err());

    // Tamper 4th share when combining 4 shares of a 3-of-5 split -> MUST reject!
    bad_idx_share[3].data[0] ^= 0x01;
    assert!(matches!(
        combine_shares(&bad_idx_share[0..4]),
        Err(WilisError::AuthenticationFailed)
    ));

    // 4. Ratchet u64::MAX counter packet cleanly rejected without overflow panic
    let mut sess = RatchetSession::from_shared_secret(&[0x55; 32], false);
    let max_pkt = RatchetPacket {
        counter: u64::MAX,
        ciphertext: vec![0; 8],
        tag: [0; 32],
    };
    assert!(matches!(
        sess.decrypt_packet(&max_pkt, b""),
        Err(WilisError::AuthenticationFailed)
    ));

    // 5. Audit edge cases (samples=0, sample_bytes=0) never panic or produce NaN pass
    assert!(!analyze_bic(0).passed);
    assert!(!analyze_keystream_randomness(0).all_passed);
    assert!(!analyze_keystream_randomness(10).all_passed);

    // 6. CLI file_cmd blocks --in == --out AND preserves existing --out on wrong key!
    let base = std::env::temp_dir().join(format!("wilis_v041_reg_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let src = base.join("orig.bin");
    let enc = base.join("orig.wils");
    let existing = base.join("precious.txt");
    std::fs::write(&src, b"original-data").unwrap();
    std::fs::write(&existing, b"DO-NOT-CLOBBER").unwrap();

    // Same-file in-place encryption must fail without truncating src
    assert!(file_cmd::run_encrypt(
        AuthInput::RawKey(SecretKey::from_bytes([0x11; 32])),
        "",
        src.to_str().unwrap(),
        src.to_str().unwrap(),
    )
    .is_err());
    assert_eq!(std::fs::read(&src).unwrap(), b"original-data");

    // Encrypt cleanly, then attempt decrypt onto `existing` with WRONG key -> `existing` preserved!
    file_cmd::run_encrypt(
        AuthInput::RawKey(SecretKey::from_bytes([0x11; 32])),
        "",
        src.to_str().unwrap(),
        enc.to_str().unwrap(),
    )
    .unwrap();
    assert!(file_cmd::run_decrypt(
        AuthInput::RawKey(SecretKey::from_bytes([0x22; 32])),
        "",
        enc.to_str().unwrap(),
        existing.to_str().unwrap(),
    )
    .is_err());
    assert_eq!(
        std::fs::read(&existing).unwrap(),
        b"DO-NOT-CLOBBER",
        "failed decrypt must not overwrite existing file at --out"
    );

    // 7. WilisDir refuses placing output archive inside source directory
    let inside_out = base.join("inside.wils");
    assert!(encrypt_directory_with_key(&[0x11; 32], &base, &inside_out, b"").is_err());

    // 8. SigningKey rejects corrupted next_index > 2^height
    let (sk, _) = SigningKey::generate(2).unwrap();
    let mut sk_raw = sk.to_bytes();
    sk_raw[5..9].copy_from_slice(&999u32.to_le_bytes());
    let body_len = sk_raw.len() - 32;
    let new_chk = wilis::hash::hash(&sk_raw[..body_len]);
    sk_raw[body_len..].copy_from_slice(&new_chk);
    assert!(SigningKey::from_bytes(&sk_raw).is_err());

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn regression_v042_audit_fixes_verified() {
    use wilis::archive::unpack::sanitize_archive_path;
    use wilis::cli::args::{parse_args, Command};
    use wilis::ffi::c_api::{
        wilis_aead_open, wilis_aead_seal, wilis_hash_256, wilis_kem_encapsulate, wilis_kem_keygen,
        wilis_random_bytes, wilis_xof_derive, WILIS_ERR_INVALID_ARG, WILIS_OK,
    };
    use wilis::kem::poly::{Poly, KEM_N, KEM_Q};
    use wilis::kem::{KEM_CT_BYTES, KEM_PK_BYTES, KEM_SK_BYTES, KEM_SS_BYTES};

    // 1. Constant-time Poly::to_msg_bits matches exact spec threshold [1920..=5760] for ALL c in 0..7681
    for base in (0..KEM_Q).step_by(KEM_N) {
        let mut p = Poly::zero();
        for i in 0..KEM_N {
            let c = (base as usize + i).min((KEM_Q - 1) as usize) as u16;
            p.coeffs[i] = c;
        }
        let bits = p.to_msg_bits();
        for i in 0..KEM_N {
            let c = p.coeffs[i];
            let got = (bits[i / 8] >> (i % 8)) & 1;
            let expected = if (1920..=5760).contains(&c) { 1u8 } else { 0u8 };
            assert_eq!(got, expected, "to_msg_bits mismatch at coeff {c}");
        }
    }

    // 2. Branchless Barrett reduction in Poly::mul matches exact i64 rem_euclid on extreme inputs
    let max_poly = Poly {
        coeffs: [KEM_Q - 1; KEM_N],
    };
    let prod = max_poly.mul(&max_poly);
    // Exact check: ((q-1) * sum X^i)^2 mod (X^256 + 1, q) = (-1)^2 * (sum X^i)^2
    // Coeff k equals (k + 1) - (255 - k) = 2k - 254 (mod q)
    for k in 0..KEM_N {
        let exact = (2 * k as i64 - 254).rem_euclid(KEM_Q as i64) as u16;
        assert_eq!(prod.coeffs[k], exact, "Barrett mul mismatch at index {k}");
    }
    // Branchless add/sub boundary checks at 0 and q-1
    let zero_poly = Poly::zero();
    assert_eq!(max_poly.add(&max_poly).coeffs[0], KEM_Q - 2);
    assert_eq!(zero_poly.sub(&max_poly).coeffs[0], 1);
    assert_eq!(max_poly.sub(&max_poly).coeffs[0], 0);

    // 3. C-FFI in-place AEAD, oversized length rejection (> isize::MAX), and overlap rejection
    unsafe {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 24];
        let orig = b"In-place C-FFI buffer safety check!";
        let mut buf = orig.to_vec();
        let mut tag = [0u8; 32];
        assert_eq!(
            wilis_aead_seal(
                key.as_ptr(),
                nonce.as_ptr(),
                b"aad".as_ptr(),
                3,
                buf.as_ptr(),
                buf.len(),
                buf.as_mut_ptr(), // in-place!
                tag.as_mut_ptr(),
            ),
            WILIS_OK
        );
        assert_ne!(buf.as_slice(), orig.as_slice());
        assert_eq!(
            wilis_aead_open(
                key.as_ptr(),
                nonce.as_ptr(),
                b"aad".as_ptr(),
                3,
                buf.as_ptr(),
                buf.len(),
                tag.as_ptr(),
                buf.as_mut_ptr(), // in-place!
            ),
            WILIS_OK
        );
        assert_eq!(buf.as_slice(), orig.as_slice());

        // Lengths > isize::MAX must cleanly return WILIS_ERR_INVALID_ARG (never UB/panic)
        let mut out32 = [0u8; 32];
        assert_eq!(
            wilis_hash_256(key.as_ptr(), usize::MAX, out32.as_mut_ptr()),
            WILIS_ERR_INVALID_ARG
        );
        assert_eq!(
            wilis_random_bytes(out32.as_mut_ptr(), usize::MAX),
            WILIS_ERR_INVALID_ARG
        );
        assert_eq!(
            wilis_xof_derive(
                key.as_ptr(),
                32,
                key.as_ptr(),
                32,
                out32.as_mut_ptr(),
                usize::MAX
            ),
            WILIS_ERR_INVALID_ARG
        );

        // Overlapping multi-output KEM buffers must be rejected cleanly
        let mut shared_buf = vec![0u8; KEM_PK_BYTES + KEM_SK_BYTES];
        assert_eq!(
            wilis_kem_keygen(shared_buf.as_mut_ptr(), shared_buf.as_mut_ptr()),
            WILIS_ERR_INVALID_ARG
        );
        let mut pk = vec![0u8; KEM_PK_BYTES];
        let mut sk = vec![0u8; KEM_SK_BYTES];
        assert_eq!(wilis_kem_keygen(pk.as_mut_ptr(), sk.as_mut_ptr()), WILIS_OK);
        let mut overlap_ct = vec![0u8; KEM_CT_BYTES + KEM_SS_BYTES];
        assert_eq!(
            wilis_kem_encapsulate(
                pk.as_ptr(),
                overlap_ct.as_mut_ptr(),
                overlap_ct.as_mut_ptr()
            ),
            WILIS_ERR_INVALID_ARG
        );
    }

    // 4. Archive path hardening (Windows reserved names, colons, trailing dots/spaces, duplicates, symlinks)
    let base = std::env::temp_dir().join(format!("wilis_v042_reg_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    for bad in [
        "C:evil.txt",
        "foo:ads",
        "CON",
        "nul.txt",
        "sub/COM1.bin",
        "sub/LPT9",
        "trailing.",
        "trailing ",
        "ctrl\x07char",
    ] {
        assert!(
            sanitize_archive_path(&base, bad).is_err(),
            "expected archive path '{bad}' to be rejected"
        );
    }

    // Duplicate entries in a WDIR stream must be rejected
    let mut dup_wdir = Vec::new();
    dup_wdir.extend_from_slice(b"WDIR\x01");
    dup_wdir.extend_from_slice(&2u64.to_le_bytes());
    for _ in 0..2 {
        dup_wdir.extend_from_slice(&5u32.to_le_bytes());
        dup_wdir.extend_from_slice(b"a.txt");
        dup_wdir.extend_from_slice(&1u64.to_le_bytes());
        dup_wdir.push(b'x');
    }
    let dup_dest = base.join("dup_out");
    assert!(unpack_directory(&mut Cursor::new(&dup_wdir), &dup_dest).is_err());

    // Symlink-escape check on Unix: pre-existing symlink inside dest_dir MUST be rejected!
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside = base.join("outside_secret.txt");
        std::fs::write(&outside, b"UNTOUCHED").unwrap();
        let extract_dir = base.join("extract_sym");
        std::fs::create_dir_all(&extract_dir).unwrap();
        symlink(&outside, extract_dir.join("escape.txt")).unwrap();

        let mut sym_wdir = Vec::new();
        sym_wdir.extend_from_slice(b"WDIR\x01");
        sym_wdir.extend_from_slice(&1u64.to_le_bytes());
        sym_wdir.extend_from_slice(&10u32.to_le_bytes());
        sym_wdir.extend_from_slice(b"escape.txt");
        sym_wdir.extend_from_slice(&4u64.to_le_bytes());
        sym_wdir.extend_from_slice(b"PWN!");

        assert!(unpack_directory(&mut Cursor::new(&sym_wdir), &extract_dir).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"UNTOUCHED");
    }

    // 5. CLI parser hardening (extra args, --pass + --pass-prompt conflict, empty --pass, `--` separator, vault flags)
    let to_vec = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert!(parse_args(&to_vec(&["keygen", "--extra"])).is_err());
    assert!(parse_args(&to_vec(&["audit", "extra"])).is_err());
    assert!(parse_args(&to_vec(&["hash", "a", "b"])).is_err());
    assert!(parse_args(&to_vec(&["hash", "--file", "a", "b"])).is_err());
    assert!(parse_args(&to_vec(&["encrypt-text", "--pass", "", "hello"])).is_err());
    assert!(parse_args(&to_vec(&["encrypt-text", "--pass", "p", "--pass-prompt", "hello"])).is_err());
    assert!(parse_args(&to_vec(&["vault", "init", "--file", "v", "--pass", "p", "--name", "k"])).is_err());
    assert!(parse_args(&to_vec(&["vault", "get", "--file", "v", "--pass", "p", "--name", "k", "--value", "x"])).is_err());
    assert!(matches!(
        parse_args(&to_vec(&["hash", "--", "--literal-text"])).unwrap(),
        Command::HashText { text } if text == "--literal-text"
    ));
    assert!(matches!(
        parse_args(&to_vec(&["encrypt-text", "--pass", "secret", "--", "--msg"])).unwrap(),
        Command::EncryptText { plaintext, .. } if plaintext == "--msg"
    ));

    // 6. WilisSign: Signature::from_bytes rejects leaf_index >= 2^height & VerifyingKey::verify never panics on height > 31
    let (mut sk, pk) = SigningKey::generate(2).unwrap();
    let sig = sk.sign(b"test").unwrap();
    let mut bad_sig_bytes = sig.to_bytes();
    bad_sig_bytes[6..10].copy_from_slice(&4u32.to_le_bytes()); // height=2 -> valid leaves are 0..=3
    assert!(Signature::from_bytes(&bad_sig_bytes).is_err());

    let invalid_vk = VerifyingKey {
        height: 99,
        pub_seed: pk.pub_seed,
        root: pk.root,
    };
    assert!(!invalid_vk.verify(b"test", &sig));

    let _ = std::fs::remove_dir_all(&base);
}
