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
