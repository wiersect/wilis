//! Comprehensive integration & security tests for Wilis v0.5.0 features:
//! - Multi-Recipient Streaming Post-Quantum Encryption (`WPKE` v2)
//! - Post-Quantum Authenticated Handshake & Post-Compromise Security Ratchet (`WHSH`/`WRP2`/`WPRK`)
//! - Canonical Length-Hiding Padding (`WilisPad`)
//! - PEM-style ASCII Armor with 24-bit `WilisHash-256` checksum (`WilisArmor`)
//! - Constant-Memory Streaming File Signatures (`WSIG` v2) & CLI end-to-end flows
//! - Expanded C-FFI (`libwilis` v0.5.0: `wilis_version`, `wilis_subkey_derive`, `wilis_sign_*`)

use std::ffi::CStr;
use std::io::Cursor;

use wilis::cli::args::{parse_args, Command};
use wilis::cli::{kem_cmd, sign_cmd, text_cmd};
use wilis::error::WilisError;
use wilis::ffi::c_api::{
    wilis_sign_keygen, wilis_sign_message, wilis_subkey_derive, wilis_verify_message,
    wilis_version, WILIS_ERR_AUTH_FAILED, WILIS_ERR_INVALID_ARG, WILIS_OK,
};
use wilis::kem::{
    keygen, pub_decrypt_multi, pub_decrypt_multi_stream, pub_encrypt, pub_encrypt_multi,
    pub_encrypt_multi_stream, WPKE_SLOT_BYTES,
};
use wilis::mac::derive_subkey;
use wilis::ratchet::{HandshakeInit, PqMessagePacket, PqRatchetSession, PqRekeyPacket};
use wilis::sign::{SigningKey, SIGN_PK_BYTES, SIGN_SK_BYTES, SIG_VERSION_V1, SIG_VERSION_V2};
use wilis::stream::chunk_nonce::MIN_CHUNK_SIZE;
use wilis::utils::armor::{
    armor_decode, armor_encode, ARMOR_ENCRYPTED, ARMOR_MESSAGE, ARMOR_PUBLIC_KEY, ARMOR_SIGNATURE,
};
use wilis::utils::padding::{pad_to_block, unpad_strict};
use wilis::utils::zeroize::SecretKey;

#[test]
fn wpke_v2_multi_recipient_streaming_and_tamper_resistance() {
    let (sk1, pk1) = keygen().unwrap();
    let (sk2, pk2) = keygen().unwrap();
    let (sk3, pk3) = keygen().unwrap();
    let (sk_outsider, _) = keygen().unwrap();

    // Multi-chunk 150 KiB payload across non-default 4 KiB chunks
    let payload: Vec<u8> = (0..150_000usize).map(|i| ((i * 31) ^ (i >> 5)) as u8).collect();
    let mut encrypted = Vec::new();
    let (in_b, out_b) = pub_encrypt_multi_stream(
        &[&pk1, &pk2, &pk3],
        &mut Cursor::new(&payload),
        &mut encrypted,
        b"multi-aad",
        4096,
    )
    .unwrap();
    assert_eq!(in_b as usize, payload.len());
    assert_eq!(out_b as usize, encrypted.len());

    // Every authorized recipient recovers exact payload
    for sk in [&sk1, &sk2, &sk3] {
        let mut out = Vec::new();
        let n = pub_decrypt_multi_stream(sk, &mut Cursor::new(&encrypted), &mut out, b"multi-aad")
            .unwrap();
        assert_eq!(n as usize, payload.len());
        assert_eq!(out, payload);
    }

    // Outsider secret key MUST fail
    let mut outsider_out = Vec::new();
    assert!(matches!(
        pub_decrypt_multi_stream(&sk_outsider, &mut Cursor::new(&encrypted), &mut outsider_out, b"multi-aad"),
        Err(WilisError::AuthenticationFailed)
    ));

    // Wrong AAD MUST fail
    assert!(pub_decrypt_multi(&sk1, &encrypted, b"wrong-aad").is_err());

    // Duplicate recipient public keys rejected
    assert!(pub_encrypt_multi(&[&pk1, &pk1], b"msg", b"").is_err());

    // Empty recipient list rejected
    assert!(pub_encrypt_multi(&[], b"msg", b"").is_err());

    // Swapping slot 0 and slot 1 MUST break header binding & slot AAD!
    let mut swapped = encrypted.clone();
    let slot0_start = 34;
    let slot1_start = slot0_start + WPKE_SLOT_BYTES;
    let s0 = swapped[slot0_start..slot1_start].to_vec();
    let s1 = swapped[slot1_start..slot1_start + WPKE_SLOT_BYTES].to_vec();
    swapped[slot0_start..slot1_start].copy_from_slice(&s1);
    swapped[slot1_start..slot1_start + WPKE_SLOT_BYTES].copy_from_slice(&s0);
    assert!(pub_decrypt_multi(&sk1, &swapped, b"multi-aad").is_err());

    // Trailing garbage byte MUST be rejected
    let mut trailing = encrypted.clone();
    trailing.push(0x42);
    assert!(pub_decrypt_multi(&sk2, &trailing, b"multi-aad").is_err());

    // Backward compatibility: pub_decrypt_multi also seamlessly opens legacy WPKE v1
    let legacy_v1 = pub_encrypt(&pk1, b"legacy v1 payload", b"v1-aad").unwrap();
    assert_eq!(
        pub_decrypt_multi(&sk1, &legacy_v1, b"v1-aad").unwrap(),
        b"legacy v1 payload"
    );

    // Smallest valid chunk size works on empty payload too
    let mut empty_enc = Vec::new();
    pub_encrypt_multi_stream(
        &[&pk1],
        &mut Cursor::new(b""),
        &mut empty_enc,
        b"",
        MIN_CHUNK_SIZE,
    )
    .unwrap();
    assert_eq!(pub_decrypt_multi(&sk1, &empty_enc, b"").unwrap(), b"");
}

#[test]
fn pq_handshake_and_post_compromise_security_ratchet() {
    let (mut alice_sign_sk, alice_vk) = SigningKey::generate(3).unwrap();
    let (_, mallory_vk) = SigningKey::generate(2).unwrap();
    let (bob_kem_sk, bob_kem_pk) = keygen().unwrap();

    // 1. Authenticated PQ Handshake (WHSH v1)
    let (mut alice, init) =
        PqRatchetSession::initiate_handshake(&mut alice_sign_sk, &bob_kem_pk, b"wilis-chat-v1")
            .unwrap();
    let init_roundtrip = HandshakeInit::from_bytes(&init.to_bytes()).unwrap();
    assert_eq!(init_roundtrip, init);

    // Wrong verifying key or wrong context MUST reject handshake
    assert!(matches!(
        PqRatchetSession::accept_handshake(&bob_kem_sk, &mallory_vk, &init_roundtrip, b"wilis-chat-v1"),
        Err(WilisError::AuthenticationFailed)
    ));
    assert!(matches!(
        PqRatchetSession::accept_handshake(&bob_kem_sk, &alice_vk, &init_roundtrip, b"wrong-ctx"),
        Err(WilisError::AuthenticationFailed)
    ));

    let mut bob = PqRatchetSession::accept_handshake(
        &bob_kem_sk,
        &alice_vk,
        &init_roundtrip,
        b"wilis-chat-v1",
    )
    .unwrap();
    assert_eq!(alice.epoch(), 0);
    assert_eq!(bob.epoch(), 0);

    // Epoch 0 bidirectional messages + wire serialization
    let pkt0 = alice.encrypt_next(b"hello from epoch 0", b"meta");
    let pkt0_rt = PqMessagePacket::from_bytes(&pkt0.to_bytes()).unwrap();
    assert_eq!(bob.decrypt_packet(&pkt0_rt, b"meta").unwrap(), b"hello from epoch 0");

    // 2. PCS Rekey Epoch 0 -> Epoch 1 (Alice initiates; forged rekey rejected transactionally)
    let rk1 = alice.initiate_rekey().unwrap();
    let mut bad_rk1 = PqRekeyPacket::from_bytes(&rk1.to_bytes()).unwrap();
    bad_rk1.mac_tag[0] ^= 0x80;
    assert!(matches!(
        bob.accept_rekey(&bad_rk1),
        Err(WilisError::AuthenticationFailed)
    ));
    assert_eq!(bob.epoch(), 0, "forged rekey must not advance epoch");

    let rk1_rt = PqRekeyPacket::from_bytes(&rk1.to_bytes()).unwrap();
    bob.accept_rekey(&rk1_rt).unwrap();
    assert_eq!(alice.epoch(), 1);
    assert_eq!(bob.epoch(), 1);

    // Cross-epoch replay of Epoch 0 message MUST fail in Epoch 1
    assert!(matches!(
        bob.decrypt_packet(&pkt0_rt, b"meta"),
        Err(WilisError::AuthenticationFailed)
    ));

    // Replaying Epoch 1 rekey MUST fail
    assert!(matches!(
        bob.accept_rekey(&rk1_rt),
        Err(WilisError::AuthenticationFailed)
    ));

    // 3. Reverse PCS Rekey Epoch 1 -> Epoch 2 (Bob initiates to Alice's fresh ephemeral KEM key!)
    let rk2 = bob.initiate_rekey().unwrap();
    alice.accept_rekey(&PqRekeyPacket::from_bytes(&rk2.to_bytes()).unwrap()).unwrap();
    assert_eq!(alice.epoch(), 2);
    assert_eq!(bob.epoch(), 2);

    let pkt2_a = alice.encrypt_next(b"post-compromise healed A->B", b"e2");
    let pkt2_b = bob.encrypt_next(b"post-compromise healed B->A", b"e2");
    assert_eq!(bob.decrypt_packet(&pkt2_a, b"e2").unwrap(), b"post-compromise healed A->B");
    assert_eq!(alice.decrypt_packet(&pkt2_b, b"e2").unwrap(), b"post-compromise healed B->A");
}

#[test]
fn wilis_pad_length_hiding_and_tamper_rejection() {
    for &block in &[16usize, 64, 256, 4096] {
        for &len in &[0usize, 1, 3, 8, 15, 16, 51, 52, 53, 300] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 17) as u8).collect();
            let padded = pad_to_block(&pt, block).unwrap();
            assert_eq!(padded.len() % block, 0);
            assert!(padded.len() >= len + 13);
            assert_eq!(unpad_strict(&padded).unwrap(), pt);
        }
    }

    // Two distinct short messages produce IDENTICAL ciphertext length after padding
    let p_a = pad_to_block(b"hi", 256).unwrap();
    let p_b = pad_to_block(b"elisrhma", 256).unwrap();
    let p_c = pad_to_block(b"much longer secret sentence hidden to 256B", 256).unwrap();
    assert_eq!(p_a.len(), 256);
    assert_eq!(p_b.len(), 256);
    assert_eq!(p_c.len(), 256);

    // Tamper trailing zero byte, sentinel 0x80, or embedded length -> rejected
    let mut bad_zero = p_b.clone();
    bad_zero[255] ^= 0x01;
    assert!(unpad_strict(&bad_zero).is_err());

    let mut bad_sentinel = p_b.clone();
    bad_sentinel[12 + 8] = 0x00;
    assert!(unpad_strict(&bad_sentinel).is_err());

    let mut bad_len = p_b.clone();
    bad_len[4..12].copy_from_slice(&999u64.to_le_bytes());
    assert!(unpad_strict(&bad_len).is_err());

    // Invalid block sizes rejected
    assert!(pad_to_block(b"x", 8).is_err());
    assert!(pad_to_block(b"x", 100_000).is_err());
}

#[test]
fn wilis_armor_encoding_checksum_and_rejection() {
    let payload: Vec<u8> = (0..137u8).collect();
    for label in [ARMOR_MESSAGE, ARMOR_ENCRYPTED, ARMOR_SIGNATURE, ARMOR_PUBLIC_KEY] {
        let armored = armor_encode(label, &payload).unwrap();
        assert!(armored.starts_with(&format!("-----BEGIN {label}-----\n")));
        assert!(armored.ends_with(&format!("-----END {label}-----")));

        let (dec_label, dec_bytes) = armor_decode(&armored, Some(label)).unwrap();
        assert_eq!(dec_label, label);
        assert_eq!(dec_bytes, payload);

        // Wrong expected label rejected
        assert!(armor_decode(&armored, Some("OTHER LABEL")).is_err());
    }

    // Single-character flip inside payload breaks 24-bit WilisHash-256 armor checksum!
    let armored = armor_encode(ARMOR_MESSAGE, b"Wilis v0.5.0 armored secret!").unwrap();
    let mut corrupted = armored.clone();
    let idx = corrupted.find("\n\n").unwrap() + 4;
    let rep = if &corrupted[idx..idx + 1] == "A" { "B" } else { "A" };
    corrupted.replace_range(idx..idx + 1, rep);
    assert!(matches!(
        armor_decode(&corrupted, Some(ARMOR_MESSAGE)),
        Err(WilisError::AuthenticationFailed)
    ));

    // Mismatched BEGIN/END labels rejected
    let mismatched = armored.replace("END WILIS MESSAGE", "END WILIS SIGNATURE");
    assert!(armor_decode(&mismatched, None).is_err());

    // Trailing smuggling text outside armor fence rejected
    let trailing = format!("{armored}\nextra-smuggled-line");
    assert!(armor_decode(&trailing, None).is_err());

    // Invalid armor label rejected
    assert!(armor_encode("bad\nlabel", b"x").is_err());
}

#[test]
fn streaming_wsig_v2_and_cli_e2e_v050() {
    let base = std::env::temp_dir().join(format!("wilis_v050_e2e_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    // 1. Streaming WSIG v2 vs direct WSIG v1 strict domain separation
    let (mut sk, pk) = SigningKey::generate(3).unwrap();
    let big_data: Vec<u8> = (0..140_000usize).map(|i| (i * 13) as u8).collect();
    let sig_v1 = sk.sign(&big_data).unwrap();
    let sig_v2 = sk.sign_stream(&mut Cursor::new(&big_data)).unwrap();
    assert_eq!(sig_v1.version, SIG_VERSION_V1);
    assert_eq!(sig_v2.version, SIG_VERSION_V2);

    assert!(pk.verify(&big_data, &sig_v1));
    assert!(!pk.verify(&big_data, &sig_v2), "WSIG v2 must not validate under v1 verify()");
    assert!(pk.verify_stream(&mut Cursor::new(&big_data), &sig_v2).unwrap());
    assert!(
        !pk.verify_stream(&mut Cursor::new(&big_data), &sig_v1).unwrap(),
        "WSIG v1 must not validate under v2 verify_stream()"
    );

    // 2. CLI multi-recipient pub-encrypt (--pk x2 + --armor) & pub-decrypt + binary streaming
    let a_pfx = base.join("alice");
    let b_pfx = base.join("bob");
    kem_cmd::run_kem_keygen(a_pfx.to_str().unwrap()).unwrap();
    kem_cmd::run_kem_keygen(b_pfx.to_str().unwrap()).unwrap();
    let plain_file = base.join("secret.bin");
    std::fs::write(&plain_file, &big_data).unwrap();

    let bin_wpke = base.join("multi.wpke");
    let arm_wpke = base.join("multi_armored.wpke.asc");
    let pks = vec![
        base.join("alice.wkp").to_string_lossy().to_string(),
        base.join("bob.wkp").to_string_lossy().to_string(),
    ];
    kem_cmd::run_pub_encrypt_multi(&pks, "team-aad", plain_file.to_str().unwrap(), bin_wpke.to_str().unwrap(), false).unwrap();
    kem_cmd::run_pub_encrypt_multi(&pks, "team-aad", plain_file.to_str().unwrap(), arm_wpke.to_str().unwrap(), true).unwrap();

    let out_a = base.join("out_a.bin");
    let out_b = base.join("out_b.bin");
    kem_cmd::run_pub_decrypt(base.join("alice.wks").to_str().unwrap(), "team-aad", bin_wpke.to_str().unwrap(), out_a.to_str().unwrap()).unwrap();
    kem_cmd::run_pub_decrypt(base.join("bob.wks").to_str().unwrap(), "team-aad", arm_wpke.to_str().unwrap(), out_b.to_str().unwrap()).unwrap();
    assert_eq!(std::fs::read(&out_a).unwrap(), big_data);
    assert_eq!(std::fs::read(&out_b).unwrap(), big_data);

    // 3. CLI streaming sign (--armor & binary) + verify
    let s_pfx = base.join("signer");
    sign_cmd::run_sign_keygen(s_pfx.to_str().unwrap(), 3).unwrap();
    let sig_bin = base.join("doc.wsig");
    let sig_arm = base.join("doc.wsig.asc");
    sign_cmd::run_sign_file_ex(base.join("signer.wsk").to_str().unwrap(), plain_file.to_str().unwrap(), sig_bin.to_str().unwrap(), false).unwrap();
    sign_cmd::run_sign_file_ex(base.join("signer.wsk").to_str().unwrap(), plain_file.to_str().unwrap(), sig_arm.to_str().unwrap(), true).unwrap();
    sign_cmd::run_verify_file(base.join("signer.wpk").to_str().unwrap(), plain_file.to_str().unwrap(), sig_bin.to_str().unwrap()).unwrap();
    sign_cmd::run_verify_file(base.join("signer.wpk").to_str().unwrap(), plain_file.to_str().unwrap(), sig_arm.to_str().unwrap()).unwrap();

    // 4. CLI argument parser accepts --pad, --unpad, --armor, and multi --pk
    let to_vec = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert!(matches!(
        parse_args(&to_vec(&["encrypt-text", "--pass", "pw", "--pad", "256", "--armor", "hi"])).unwrap(),
        Command::EncryptText { pad_block: Some(256), armor: true, .. }
    ));
    assert!(matches!(
        parse_args(&to_vec(&["decrypt-text", "--pass", "pw", "--unpad", "AAAA"])).unwrap(),
        Command::DecryptText { unpad: true, .. }
    ));
    assert!(matches!(
        parse_args(&to_vec(&["pub-encrypt", "--pk", "a.wkp", "--pk", "b.wkp", "--armor", "--in", "i", "--out", "o"])).unwrap(),
        Command::PubEncrypt { pk_paths, armor: true, .. } if pk_paths.len() == 2
    ));

    // Verify text_cmd encrypt_ex + decrypt_ex round-trip with pad + armor
    let key = SecretKey::from_bytes([0x55; 32]);
    let padded = pad_to_block(b"elisrhma", 128).unwrap();
    let ct = wilis::format::encrypt_with_key(key.as_bytes(), &padded, b"t").unwrap();
    let arm = armor_encode(ARMOR_MESSAGE, &ct).unwrap();
    text_cmd::run_decrypt_ex(wilis::cli::args::AuthInput::RawKey(key.clone()), "t", &arm, true).unwrap();
    // Without --unpad, padded payload produces clear UTF-8 hint error
    assert!(text_cmd::run_decrypt_ex(wilis::cli::args::AuthInput::RawKey(key), "t", &arm, false).is_err());

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn ffi_v050_version_subkey_and_post_quantum_sign() {
    unsafe {
        // 1. wilis_version()
        let ver = CStr::from_ptr(wilis_version()).to_str().unwrap();
        assert_eq!(ver, env!("CARGO_PKG_VERSION"));

        // 2. wilis_subkey_derive() matches Rust derive_subkey()
        let mk = [0x99u8; 32];
        let ctx = b"ffi-subkey-ctx";
        let mut sub_out = [0u8; 32];
        assert_eq!(
            wilis_subkey_derive(mk.as_ptr(), ctx.as_ptr(), ctx.len(), sub_out.as_mut_ptr()),
            WILIS_OK
        );
        assert_eq!(&sub_out, derive_subkey(&mk, ctx).as_bytes());

        // 3. wilis_sign_keygen -> wilis_sign_message (stateful update) -> wilis_verify_message
        let mut pk = [0u8; SIGN_PK_BYTES];
        let mut sk = [0u8; SIGN_SK_BYTES];
        assert_eq!(wilis_sign_keygen(1, pk.as_mut_ptr(), sk.as_mut_ptr()), WILIS_ERR_INVALID_ARG);
        assert_eq!(wilis_sign_keygen(2, pk.as_mut_ptr(), sk.as_mut_ptr()), WILIS_OK);

        let msg = b"Post-quantum signature over C-ABI v0.5.0";
        let mut sig = vec![0u8; 2506];
        let mut sig_len: usize = 0;

        // Overlap rejection
        assert_eq!(
            wilis_sign_message(
                sk.as_mut_ptr(),
                msg.as_ptr(),
                msg.len(),
                sk.as_mut_ptr(),
                SIGN_SK_BYTES,
                &mut sig_len,
            ),
            WILIS_ERR_INVALID_ARG
        );

        let sk_before = sk;
        assert_eq!(
            wilis_sign_message(
                sk.as_mut_ptr(),
                msg.as_ptr(),
                msg.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut sig_len,
            ),
            WILIS_OK
        );
        assert_ne!(sk, sk_before, "sk_inout must advance stateful leaf index");
        assert!(sig_len > 2000 && sig_len <= 2506);

        assert_eq!(
            wilis_verify_message(pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr(), sig_len),
            WILIS_OK
        );
        sig[15] ^= 0x01;
        assert_eq!(
            wilis_verify_message(pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr(), sig_len),
            WILIS_ERR_AUTH_FAILED
        );
    }
}
