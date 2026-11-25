//! Locked Known-Answer Test Vectors (KAT) & v0.4.3 Audit Regression Suite.
//!
//! These hardcoded golden vectors lock exact wire-format and mathematical
//! compatibility across versions and CPU architectures (x86_64, ARM64, 32-bit/64-bit)
//! for every cryptographic primitive in Wilis.

use wilis::aead::{open, seal};
use wilis::cli::args::parse_args;
use wilis::core::constants::{ROUNDS_DATA, ROUNDS_FULL};
use wilis::core::permute::{permute, permute_inverse};
use wilis::core::state::State;
use wilis::format::header::{ContainerHeader, KeyMode, FORMAT_VERSION_V2};
use wilis::hash::hash;
use wilis::kdf::{derive_key, derive_key_with_keyfile, KdfParams};
use wilis::kem::poly::Poly;
use wilis::mac::{derive_subkey, mac};
use wilis::ratchet::RatchetSession;
use wilis::sign::merkle::build_merkle_tree;
use wilis::sign::wots::{
    compute_leaf_pk_hash, wots_chain, wots_recover_leaf_pk_hash, wots_sign_digest,
};
use wilis::stream::chunk_nonce::DEFAULT_CHUNK_SIZE;
use wilis::utils::base64::{decode_base64, encode_base64};
use wilis::utils::hex::encode_hex;
use wilis::xof::WilisXof;

#[test]
fn kat_core_permutation_hash_xof_mac_aead_and_kdf_vectors() {
    // 1. WilisPerm-384 (16-round & 12-round + exact inverse bijection)
    let mut s16 = State::from_words([0, 1, 2, 3, 4, 5]);
    permute(&mut s16, ROUNDS_FULL);
    assert_eq!(
        encode_hex(&s16.to_bytes()),
        "77be099ac8cf1efeaac75b9c3b412670d1c3f1653e63521185ab6cfcadd0365ec2a660bd651f8e1e049b4762ef1044be"
    );
    permute_inverse(&mut s16, ROUNDS_FULL);
    assert_eq!(s16.words, [0, 1, 2, 3, 4, 5]);

    let mut s12 = State::from_words([0, 1, 2, 3, 4, 5]);
    permute(&mut s12, ROUNDS_DATA);
    assert_eq!(
        encode_hex(&s12.to_bytes()),
        "96b658ee278a5237547d93d5afa8c0122316a47a2dae995f8ea112a72c92fd92f71c827d3825faa9ced84c38c60ec2b9"
    );
    permute_inverse(&mut s12, ROUNDS_DATA);
    assert_eq!(s12.words, [0, 1, 2, 3, 4, 5]);

    // 2. WilisHash-256
    assert_eq!(
        encode_hex(&hash(b"")),
        "a7470288849756b2d5d1e43ffe3a97492aea9753bbcebfa2e974caa291f79c37"
    );
    assert_eq!(
        encode_hex(&hash(b"abc")),
        "6c3ec00ee93a5ed75470df77b51abc00a538db9e1801ff7697e5c33427ef70b3"
    );
    assert_eq!(
        encode_hex(&hash(b"0123456789abcdef")),
        "2b8089bf35ab0f4b01d84246c16cab328ea66b2b18bd0e86f19301073cf613c5"
    );

    // 3. WilisXOF (empty vs non-empty domain labels)
    assert_eq!(
        encode_hex(&WilisXof::derive(b"", b"wilis-kat-seed", 48)),
        "8815ff41ba940259b2709ee801aa3245832848677e66bab2702e7b302b61418a73727556d78e71490949d0fed184d50b"
    );
    assert_eq!(
        encode_hex(&WilisXof::derive(b"KAT_XOF_V1", b"wilis-kat-seed", 48)),
        "1cc448cd403cf9fe5cfc52bb7150013590485b05545e2d6c652a00cb46b668eb487beaa8e631da72055f198d40ef4e1b"
    );

    // 4. WilisMAC & derive_subkey
    let key = [0x2Au8; 32];
    assert_eq!(
        encode_hex(&mac(&key, b"Wilis KAT message")),
        "31a320a3d73c835f37234d7f362717e9e5cef7189027d75ebfdcbbb6a7164803"
    );
    assert_eq!(
        encode_hex(derive_subkey(&key, b"kat-context").as_bytes()),
        "1592dcd4049227aa53f76928561f615c51f34123879e3685e9b90f04f7416629"
    );

    // 5. WilisAEAD (empty & multi-block authenticated encryption)
    let nonce = [0x17u8; 24];
    let (e_ct, e_tag) = seal(&key, &nonce, b"", b"");
    assert!(e_ct.is_empty());
    assert_eq!(
        encode_hex(&e_tag),
        "fefab3e89d5b04452b8f211700f3e31edcf1e9d27b55158c6579d4b3be28fb4a"
    );

    let msg = b"Wilis deterministic AEAD KAT payload 0123456789!";
    let (ct, tag) = seal(&key, &nonce, b"kat-aad-header", msg);
    assert_eq!(
        encode_hex(&ct),
        "5ef3b1c26dd754d4c80e8a3a11c26b81b2851bf15d13d6c13862ee1c14573f2e33dbcaa54d8edffd028457b34cc63def"
    );
    assert_eq!(
        encode_hex(&tag),
        "2333aaba5bf1fbb19ed428ab294e4ba813f3ec04456155c47ac9f984221bf710"
    );
    assert_eq!(open(&key, &nonce, b"kat-aad-header", &ct, &tag).unwrap(), msg);

    // 6. WilisKDF v2 (locks 32-bit/64-bit cross-platform determinism with & without 2FA keyfile)
    let salt = [0x5Cu8; 24];
    let kf = [0x9Au8; 32];
    let k_plain = derive_key(b"wilis-kat-passphrase", &salt, KdfParams::FAST_TEST).unwrap();
    let k_2fa = derive_key_with_keyfile(b"wilis-kat-passphrase", Some(&kf), &salt, KdfParams::FAST_TEST).unwrap();
    assert_eq!(
        encode_hex(k_plain.as_bytes()),
        "f6a3a8e89fc57fc7138e19203093dc4c701f9b3107cb72ed5346ab9d535d856b"
    );
    assert_eq!(
        encode_hex(k_2fa.as_bytes()),
        "999f31801d9bc71b2786a1eb3d62ca8fc4acd1f5d335f929637a26d8f7885fa4"
    );
}

#[test]
fn kat_post_quantum_kem_sign_and_ratchet_vectors() {
    let key = [0x2Au8; 32];

    // 1. WilisKEM deterministic Module-LWE polynomial ring vector (Barrett + CBD_2 + 13-bit packing)
    let p_a = Poly::sample_uniform(&key, 1, 2);
    let p_s = Poly::sample_cbd2(&key, 0);
    let p_e = Poly::sample_cbd2(&key, 3);
    let p_t = p_a.mul(&p_s).add(&p_e);
    assert_eq!(
        encode_hex(&hash(&p_t.pack())),
        "8a4b934176f9a9bbb4eaa589a9ea40ea3e137edb2ce9760da09dbf71e9898bae"
    );

    // 2. WilisSign deterministic WOTS+ leaf, Merkle root & recovery vector
    let sk_seed = [0x33u8; 32];
    let pk_seed = [0x77u8; 32];
    let leaf0 = compute_leaf_pk_hash(&sk_seed, &pk_seed, 0);
    let levels = build_merkle_tree(&sk_seed, &pk_seed, 2);
    let root = levels[2][0];
    let digest = hash(b"wilis-sign-kat-digest");
    let wots_sig = wots_sign_digest(&sk_seed, &pk_seed, 0, &digest);
    assert_eq!(wots_recover_leaf_pk_hash(&wots_sig, &pk_seed, 0, &digest), leaf0);
    assert_eq!(
        encode_hex(&leaf0),
        "b98469f752f53e7da26ed14341b963d91af8279af17ded75881b00959c42bbde"
    );
    assert_eq!(
        encode_hex(&root),
        "ecaee9e20fb30894fe93aaa36307c6c3e0050913e183cc55baea53921aacfc47"
    );

    // 3. WilisRatchet deterministic wire packets & bidirectional round-trip
    let mut alice = RatchetSession::from_shared_secret(&key, true);
    let mut bob = RatchetSession::from_shared_secret(&key, false);
    let p0 = alice.encrypt_next(b"kat-msg-0", b"hdr");
    let p1 = alice.encrypt_next(b"kat-msg-1", b"hdr");
    assert_eq!(
        encode_hex(&p0.to_bytes()),
        "57524154010000000000000000c90c70e4389fc2e151cac68fb87e6933aa53321e82bbc633149ea1daa5543d322ea7b87342904209cd"
    );
    assert_eq!(
        encode_hex(&p1.to_bytes()),
        "5752415401010000000000000097d6b6c4846222d4853058401ce5fcdb75e917252b82ee30bd34fed3c03c56c4a090ecbcfc662734c7"
    );
    assert_eq!(bob.decrypt_packet(&p0, b"hdr").unwrap(), b"kat-msg-0");
    assert_eq!(bob.decrypt_packet(&p1, b"hdr").unwrap(), b"kat-msg-1");
}

#[test]
fn regression_v043_audit_fixes_verified() {
    // 1. wots_chain rejects out-of-range u8 wrapping step bounds instead of silently wrapping
    let overflow_caught = std::panic::catch_unwind(|| {
        wots_chain([0x11u8; 32], 200, 100, &[0x22u8; 32], 0, 0)
    });
    assert!(overflow_caught.is_err());

    // 2. ContainerHeader::to_bytes never panics when version == 2 and chunk_size is None
    let hdr = ContainerHeader {
        version: FORMAT_VERSION_V2,
        mode: KeyMode::RawKey,
        nonce: [0xABu8; 24],
        chunk_size: None,
    };
    let raw = hdr.to_bytes();
    let (parsed, _) = ContainerHeader::parse(&raw).unwrap();
    assert_eq!(parsed.chunk_size, Some(DEFAULT_CHUNK_SIZE));

    // 3. Base64 zeroizing decode rejects invalid symbols & preserves exact canonical round-trips
    let sample = b"\x00\xFFWilis v0.4.3 KAT";
    assert_eq!(decode_base64(&encode_base64(sample)).unwrap(), sample);
    assert!(decode_base64("AAAA!AAA").is_err());

    // 4. CLI ZeroizeStr cleanly handles early `?` failure after `--pass` without leaking/panicking
    let args: Vec<String> = [
        "encrypt-file",
        "--pass",
        "super-secret-pass",
        "--strength",
        "bogus-tier",
        "--in",
        "a",
        "--out",
        "b",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert!(parse_args(&args).is_err());
}

#[test]
fn regression_v044_audit_fixes_verified() {
    use wilis::audit::key_sensitivity::analyze_kem_cca2;
    use wilis::cli::args::AuthInput;
    use wilis::cli::file_cmd;
    use wilis::utils::hex::decode_hex;
    use wilis::utils::zeroize::{paths_refer_to_same_file, write_secret_file, SecretKey};

    // 1. analyze_kem_cca2(0) must NOT vacuously pass
    let kem0 = analyze_kem_cca2(0);
    assert!(!kem0.passed && !kem0.zero_failures && !kem0.implicit_rejection_ok);

    // 2. decode_hex cleanly rejects mid-string corruption
    assert!(decode_hex("deadbeefZZ").is_err());

    let base = std::env::temp_dir().join(format!("wilis_v044_reg_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    // 3. file_cmd::run_decrypt on a directory preserves OS I/O error (NOT misleading "too short")
    #[cfg(unix)]
    {
        use wilis::error::WilisError;
        let out_p = base.join("out.bin");
        let err = file_cmd::run_decrypt(
            AuthInput::RawKey(SecretKey::from_bytes([0x11; 32])),
            "",
            base.to_str().unwrap(),
            out_p.to_str().unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(err, WilisError::Io(_)),
            "expected WilisError::Io on directory input, got {err:?}"
        );
    }

    // 4. Cross-platform atomic write_secret_file + same-file detection + encrypt/decrypt round-trip
    let orig = base.join("orig.bin");
    write_secret_file(&orig, b"top-secret-payload").unwrap();
    assert!(paths_refer_to_same_file(&orig, &orig));
    let enc = base.join("orig.wils");
    let dec = base.join("dec.bin");

    file_cmd::run_encrypt(
        AuthInput::RawKey(SecretKey::from_bytes([0x44; 32])),
        "",
        orig.to_str().unwrap(),
        enc.to_str().unwrap(),
    )
    .unwrap();
    file_cmd::run_decrypt(
        AuthInput::RawKey(SecretKey::from_bytes([0x44; 32])),
        "",
        enc.to_str().unwrap(),
        dec.to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(std::fs::read(&dec).unwrap(), b"top-secret-payload");

    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};

        // Decrypted output must have owner-only 0600 permissions
        let mode = std::fs::metadata(&dec).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "decrypted file mode should be 0600, got {:o}", mode);

        // Hard link must be detected as referring to the same file
        let hard = base.join("orig_hardlink.bin");
        std::fs::hard_link(&orig, &hard).unwrap();
        assert!(paths_refer_to_same_file(&orig, &hard));

        // write_secret_file must refuse writing onto an existing symlink and leave target intact
        let target = base.join("innocent_target.txt");
        std::fs::write(&target, b"DO-NOT-TOUCH").unwrap();
        let sym_dest = base.join("secret_symlink.wks");
        symlink(&target, &sym_dest).unwrap();
        assert!(write_secret_file(&sym_dest, b"NEW-SECRET").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"DO-NOT-TOUCH");
    }

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn regression_v045_audit_fixes_verified() {
    use std::io::Cursor;
    use wilis::aead::seal;
    use wilis::archive::unpack_directory;
    use wilis::cli::kem_cmd;
    use wilis::sign::SigningKey;
    use wilis::stream::chunk_nonce::{build_chunk_aad, derive_chunk_nonce};
    use wilis::stream::decrypt_stream_with_key;
    use wilis::vault::Vault;

    let base = std::env::temp_dir().join(format!("wilis_v045_reg_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    // 1. Canonical WILS v2 stream framing: forge a valid-TAG non-final 0-byte chunk -> MUST reject!
    let key = [0x61u8; 32];
    let hdr = ContainerHeader {
        version: FORMAT_VERSION_V2,
        mode: KeyMode::RawKey,
        nonce: [0x22u8; 24],
        chunk_size: Some(1024),
    };
    let hdr_bytes = hdr.to_bytes();
    let hdr_digest = hash(&hdr_bytes);
    let c0_nonce = derive_chunk_nonce(&hdr.nonce, 0, false);
    let c0_aad = build_chunk_aad(&hdr_digest, 0, false, b"");
    let (_, c0_tag) = seal(&key, &c0_nonce, &c0_aad, b""); // 0-byte non-final chunk!
    let mut forged_stream = Vec::new();
    forged_stream.extend_from_slice(&hdr_bytes);
    forged_stream.extend_from_slice(&0u32.to_le_bytes());
    forged_stream.push(0u8); // is_final = false with ct_len = 0 != 1024
    forged_stream.extend_from_slice(&c0_tag);
    let mut sink = Vec::new();
    assert!(decrypt_stream_with_key(&key, &mut Cursor::new(&forged_stream), &mut sink, b"").is_err());

    // 2. WilisDir rejects case-folding duplicate ("Secret.txt" vs "secret.txt") & file-vs-dir conflict
    let mut ci_wdir = Vec::new();
    ci_wdir.extend_from_slice(b"WDIR\x01");
    ci_wdir.extend_from_slice(&2u64.to_le_bytes());
    for name in [b"Secret.txt".as_slice(), b"secret.txt".as_slice()] {
        ci_wdir.extend_from_slice(&(name.len() as u32).to_le_bytes());
        ci_wdir.extend_from_slice(name);
        ci_wdir.extend_from_slice(&1u64.to_le_bytes());
        ci_wdir.push(b'A');
    }
    assert!(unpack_directory(&mut Cursor::new(&ci_wdir), &base.join("ci_out")).is_err());

    let mut conflict_wdir = Vec::new();
    conflict_wdir.extend_from_slice(b"WDIR\x01");
    conflict_wdir.extend_from_slice(&2u64.to_le_bytes());
    for name in [b"sub/item".as_slice(), b"sub/item/nested.txt".as_slice()] {
        conflict_wdir.extend_from_slice(&(name.len() as u32).to_le_bytes());
        conflict_wdir.extend_from_slice(name);
        conflict_wdir.extend_from_slice(&1u64.to_le_bytes());
        conflict_wdir.push(b'B');
    }
    assert!(unpack_directory(&mut Cursor::new(&conflict_wdir), &base.join("conf_out")).is_err());

    // 3. SigningKey::from_bytes rejects corrupted Merkle root EVEN IF outer checksum is recomputed!
    let (sk, _) = SigningKey::generate(2).unwrap();
    let mut sk_raw = sk.to_bytes();
    let root_offset = 9 + 64;
    sk_raw[root_offset] ^= 0x01; // corrupt Merkle root
    let body_len = sk_raw.len() - 32;
    let recomputed_chk = hash(&sk_raw[..body_len]);
    sk_raw[body_len..].copy_from_slice(&recomputed_chk);
    assert!(SigningKey::from_bytes(&sk_raw).is_err());

    // 4. Vault rejects control/escape characters in secret names (blocks terminal injection)
    let mut v = Vault::new();
    assert!(v.set("bad\nname", "val").is_err());
    assert!(v.set("ansi\x1b[2J", "val").is_err());
    assert!(v.set("clean_key", "multiline\nsecret\nvalue").is_ok());

    // 5. CLI rejects duplicate flags, keyfile==out clobber, & pub-encrypt/decrypt key clobber
    let to_vec = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert!(parse_args(&to_vec(&["encrypt-text", "--pass", "p1", "--pass", "p2", "hi"])).is_err());
    assert!(parse_args(&to_vec(&["rand", "--bytes", "16", "--bytes", "32"])).is_err());

    let kf_path = base.join("2fa.key");
    std::fs::write(&kf_path, b"2fa-secret-keyfile").unwrap();
    assert!(parse_args(&to_vec(&[
        "encrypt-file",
        "--pass",
        "p1",
        "--keyfile",
        kf_path.to_str().unwrap(),
        "--in",
        "some_in.bin",
        "--out",
        kf_path.to_str().unwrap(),
    ]))
    .is_err());

    assert!(kem_cmd::run_kem_keygen("").is_err());
    assert!(kem_cmd::run_kem_keygen("dir/").is_err());
    let pfx = base.join("alice");
    kem_cmd::run_kem_keygen(pfx.to_str().unwrap()).unwrap();
    let wkp = base.join("alice.wkp");
    let wks = base.join("alice.wks");
    let sample_in = base.join("msg.bin");
    std::fs::write(&sample_in, b"hello").unwrap();
    // Refuses overwriting public key or secret key!
    assert!(kem_cmd::run_pub_encrypt(
        wkp.to_str().unwrap(),
        "",
        sample_in.to_str().unwrap(),
        wkp.to_str().unwrap(),
    )
    .is_err());
    assert!(kem_cmd::run_pub_decrypt(
        wks.to_str().unwrap(),
        "",
        sample_in.to_str().unwrap(),
        wks.to_str().unwrap(),
    )
    .is_err());

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn regression_v046_audit_fixes_verified() {
    use wilis::archive::unpack::validate_wdir_buffer;
    use wilis::ffi::c_api::{
        wilis_kdf_derive, wilis_kem_decapsulate, wilis_kem_encapsulate, WILIS_ERR_INVALID_ARG,
    };
    use wilis::kem::{keygen, KemSecretKey, KEM_CT_BYTES, KEM_PK_BYTES, KEM_SK_BYTES, KEM_SS_BYTES};
    use wilis::utils::zeroize::read_bounded_file;

    // 1. KemSecretKey::from_bytes detects 1-bit flip inside secret vector `s` via e = t - A*s in CBD_2!
    let (sk, _) = keygen().unwrap();
    let mut sk_raw = sk.to_bytes();
    sk_raw[10] ^= 0x01; // Flip 1 bit inside packed `s[0]` (leaving pk & pk_hash untouched!)
    assert!(
        KemSecretKey::from_bytes(&sk_raw).is_err(),
        "corrupted secret vector `s` must fail Module-LWE consistency check"
    );

    // 2. read_bounded_file rejects oversized files without reading past max_bytes + 1
    let base = std::env::temp_dir().join(format!("wilis_v046_reg_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let big = base.join("oversized.key");
    std::fs::write(&big, vec![0xAAu8; 4096]).unwrap();
    assert!(read_bounded_file(&big, 1284).is_err());
    assert_eq!(read_bounded_file(&big, 4096).unwrap().len(), 4096);

    // 3. validate_wdir_buffer rejects trailing/corrupted WDIR WITHOUT creating dest_dir on disk
    let untouched_dest = base.join("never_created_dir");
    let mut bad_wdir = Vec::new();
    bad_wdir.extend_from_slice(b"WDIR\x01");
    bad_wdir.extend_from_slice(&1u64.to_le_bytes());
    bad_wdir.extend_from_slice(&5u32.to_le_bytes());
    bad_wdir.extend_from_slice(b"a.txt");
    bad_wdir.extend_from_slice(&1u64.to_le_bytes());
    bad_wdir.push(b'x');
    bad_wdir.push(0x99); // unexpected trailing byte
    assert!(validate_wdir_buffer(&bad_wdir, &untouched_dest).is_err());
    assert!(
        !untouched_dest.exists(),
        "dry-run WDIR validation must not create directories on failure"
    );

    // 4. pack_directory rejects case-folding duplicates on case-sensitive filesystems (Linux)
    #[cfg(target_os = "linux")]
    {
        use wilis::archive::pack::pack_directory;
        let dup_src = base.join("case_src");
        std::fs::create_dir_all(&dup_src).unwrap();
        std::fs::write(dup_src.join("Note.txt"), b"one").unwrap();
        std::fs::write(dup_src.join("note.txt"), b"two").unwrap();
        let mut sink = Vec::new();
        assert!(
            pack_directory(&dup_src, &mut sink).is_err(),
            "pack_directory must reject case-insensitive duplicates at pack time"
        );
    }

    // 5. C-FFI defensive output zeroization on invalid arguments
    unsafe {
        let salt = [0x11u8; 24];
        let mut key_out = [0xEEu8; 32];
        assert_eq!(
            wilis_kdf_derive(b"pw".as_ptr(), 2, salt.as_ptr(), 1, 1, key_out.as_mut_ptr()),
            WILIS_ERR_INVALID_ARG
        );
        assert!(key_out.iter().all(|&b| b == 0));

        let bad_pk = vec![0xFFu8; KEM_PK_BYTES];
        let mut ct_out = vec![0xDDu8; KEM_CT_BYTES];
        let mut ss_out = [0xCCu8; KEM_SS_BYTES];
        assert_eq!(
            wilis_kem_encapsulate(bad_pk.as_ptr(), ct_out.as_mut_ptr(), ss_out.as_mut_ptr()),
            WILIS_ERR_INVALID_ARG
        );
        assert!(ct_out.iter().all(|&b| b == 0) && ss_out.iter().all(|&b| b == 0));

        let bad_sk = vec![0xFFu8; KEM_SK_BYTES];
        let mut ss_out2 = [0xBBu8; KEM_SS_BYTES];
        assert_eq!(
            wilis_kem_decapsulate(bad_sk.as_ptr(), ct_out.as_ptr(), ss_out2.as_mut_ptr()),
            WILIS_ERR_INVALID_ARG
        );
        assert!(ss_out2.iter().all(|&b| b == 0));
    }

    let _ = std::fs::remove_dir_all(&base);
}
