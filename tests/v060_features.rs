//! Comprehensive integration & security test suite for all Wilis v0.6.0 features.

use std::collections::HashSet;
use std::io::Cursor;
use std::net::TcpListener;
use std::thread;

use wilis::aead::{siv_open, siv_seal, SIV_TAG_BYTES};
use wilis::archive::{
    decrypt_directory_v2_with_key, encrypt_directory_v2_with_key,
};
use wilis::core::constants::ROUNDS_FULL;
use wilis::core::permute::permute;
use wilis::core::simd::{active_simd_backend, permute_4x};
use wilis::core::state::State;
use wilis::error::WilisError;
use wilis::ffi::c_api::{
    wilis_siv_open, wilis_siv_seal, wilis_slh_keygen, wilis_slh_sign, wilis_slh_verify,
    wilis_tree_hash_256, WILIS_ERR_AUTH_FAILED, WILIS_ERR_INVALID_ARG, WILIS_OK,
};
use wilis::hash::{build_chunk_proof, tree_hash, verify_chunk_proof};
use wilis::kdf::{derive_key_parallel, KdfParams, ParallelKdfParams};
use wilis::kem::poly::{Poly, KEM_N, KEM_Q};
use wilis::kem::{keygen, signcrypt, unsigncrypt};
use wilis::net::{recv_file_over_tcp, recv_file_pake, send_file_over_tcp, send_file_pake};
use wilis::protocols::fpe::{fpe_decrypt_str, fpe_encrypt_str};
use wilis::protocols::pake::{
    pake_client_finish, pake_client_start, pake_server_finish, pake_server_respond,
};
use wilis::protocols::timelock::TimeLockPuzzle;
use wilis::protocols::totp::{decode_base32, encode_base32, generate_totp_at, verify_totp_at};
use wilis::protocols::vss::{vss_combine, vss_proactive_refresh, vss_split, vss_verify_share};
use wilis::protocols::zkp::{zkp_keygen, zkp_prove, zkp_verify, ZkpProof};
use wilis::ratchet::{load_pq_session, save_pq_session, PqRatchetSession};
use wilis::sign::{
    SigningKey, SlhPublicKey, SlhSecretKey, SlhSignature, SLH_PK_BYTES, SLH_SIG_BYTES, SLH_SK_BYTES,
};
use wilis::stream::{encrypt_seekable_with_key, encrypt_seekable_with_passphrase, SeekableReader};
use wilis::utils::compress::{compress, decompress};
use wilis::utils::keywrap::{is_wrapped_secret_key, unwrap_secret_key, wrap_secret_key, Keyring};
use wilis::utils::memlock::{harden_process_memory, shred_file, LockedBuf};
use wilis::utils::mnemonic::{decode_mnemonic, encode_mnemonic, WORDLIST_256};
use wilis::utils::stego::{generate_blank_bmp, stego_capacity_bytes, stego_embed, stego_extract};
use wilis::vault::{create_deniable_container, open_deniable_container, Vault};
use wilis::xof::WilisXof;

fn unique_tmp(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("wilis_v060_{label}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn ntt_matches_schoolbook_across_random_and_extreme_polynomials() {
    let mut xof = WilisXof::new(b"ntt-test-v060");
    let mut buf = [0u8; 512];

    for _ in 0..12 {
        xof.squeeze(&mut buf);
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        for i in 0..KEM_N {
            a.coeffs[i] = u16::from_le_bytes([buf[i * 2], buf[i * 2 + 1]]) % KEM_Q;
        }
        xof.squeeze(&mut buf);
        for i in 0..KEM_N {
            b.coeffs[i] = u16::from_le_bytes([buf[i * 2], buf[i * 2 + 1]]) % KEM_Q;
        }
        assert_eq!(a.mul(&b), a.mul_schoolbook(&b));
    }

    // Extreme boundary: all zeros and all q-1
    let zero = Poly::zero();
    let maxp = Poly {
        coeffs: [KEM_Q - 1; KEM_N],
    };
    assert_eq!(zero.mul(&maxp), zero);
    assert_eq!(maxp.mul(&maxp), maxp.mul_schoolbook(&maxp));
}

#[test]
fn simd_permute_4x_is_bit_exact_with_scalar_across_rounds() {
    assert!(!active_simd_backend().is_empty());
    let base = [
        State::from_words([0, 1, 2, 3, 4, 5]),
        State::from_words([u64::MAX, 0xDEAD_BEEF, 0xCAFE_BABE, 1337, 42, 99]),
        State::from_words([0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210, 7, 8, 9, 10]),
        State::from_words([0x5555_AAAA, 0xAAAA_5555, 0x1111, 0x2222, 0x3333, 0x4444]),
    ];

    for rounds in [1usize, 4, 12, ROUNDS_FULL] {
        let mut simd_states = base.clone();
        let mut scalar_states = base.clone();
        permute_4x(&mut simd_states, rounds);
        for s in &mut scalar_states {
            permute(s, rounds);
        }
        assert_eq!(simd_states, scalar_states, "SIMD mismatch at rounds={rounds}");
    }
}

#[test]
fn aead_siv_is_nonce_misuse_resistant_and_authenticates_aad() {
    let key = [0x33u8; 32];
    let reused_nonce = [0x99u8; 24];

    let (ct1, tag1) = siv_seal(&key, &reused_nonce, b"ctx", b"payload alpha");
    let (ct2, tag2) = siv_seal(&key, &reused_nonce, b"ctx", b"payload beta!");
    let (ct1_again, tag1_again) = siv_seal(&key, &reused_nonce, b"ctx", b"payload alpha");

    assert_eq!(ct1, ct1_again);
    assert_eq!(tag1, tag1_again);
    assert_ne!(ct1, ct2);
    assert_ne!(tag1, tag2);

    assert_eq!(
        siv_open(&key, &reused_nonce, b"ctx", &ct1, &tag1).unwrap(),
        b"payload alpha"
    );
    assert!(matches!(
        siv_open(&key, &reused_nonce, b"wrong-aad", &ct1, &tag1),
        Err(WilisError::AuthenticationFailed)
    ));
    let mut bad_tag = tag1;
    bad_tag[0] ^= 1;
    assert!(siv_open(&key, &reused_nonce, b"ctx", &ct1, &bad_tag).is_err());

    // Empty message works cleanly
    let (ect, etag) = siv_seal(&key, &reused_nonce, b"", b"");
    assert!(ect.is_empty());
    assert_eq!(siv_open(&key, &reused_nonce, b"", &ect, &etag).unwrap(), b"");
}

#[test]
fn tree_hash_parallel_and_merkle_range_proofs_work_across_sizes() {
    // Empty payload
    let (empty_root, empty_chunk, empty_proof) = build_chunk_proof(&[], 0).unwrap();
    assert_eq!(empty_root, tree_hash(&[]));
    assert!(verify_chunk_proof(&empty_root, &empty_chunk, &empty_proof));

    // Multi-core payload (~150 KiB = 37 chunks, odd trailing chunks)
    let mut data = vec![0u8; 150_123];
    for (i, b) in data.iter_mut().enumerate() {
        *b = ((i * 31 + 7) & 0xFF) as u8;
    }
    let root = tree_hash(&data);
    assert_eq!(root, tree_hash(&data));

    for chunk_idx in [0u64, 1, 17, 36] {
        let (proof_root, mut chunk, proof) = build_chunk_proof(&data, chunk_idx).unwrap();
        assert_eq!(proof_root, root);
        assert!(verify_chunk_proof(&root, &chunk, &proof));

        chunk[0] ^= 0x80;
        assert!(!verify_chunk_proof(&root, &chunk, &proof));
    }
    assert!(build_chunk_proof(&data, 37).is_err());
}

#[test]
fn parallel_kdf_v3_is_deterministic_and_binds_2fa_keyfile() {
    let salt = [0x42u8; 24];
    let p = ParallelKdfParams::FAST_TEST;
    let k1 = derive_key_parallel(b"strong-pass", None, &salt, p).unwrap();
    let k2 = derive_key_parallel(b"strong-pass", None, &salt, p).unwrap();
    assert_eq!(k1.as_bytes(), k2.as_bytes());

    let kf = [0xABu8; 32];
    let k_2fa = derive_key_parallel(b"strong-pass", Some(&kf), &salt, p).unwrap();
    assert_ne!(k1.as_bytes(), k_2fa.as_bytes());

    let bad_lanes = ParallelKdfParams {
        memory_blocks: 128,
        passes: 2,
        lanes: 0,
    };
    assert!(derive_key_parallel(b"pw", None, &salt, bad_lanes).is_err());
}

#[test]
fn slh_stateless_signatures_and_pq_signcryption_work_and_resist_forwarding() {
    let (slh_sk, slh_pk) = SlhSecretKey::generate().unwrap();
    let cloned_sk = slh_sk.clone();

    // Serialization + integrity checks
    let sk_bytes = slh_sk.to_bytes();
    let pk_bytes = slh_pk.to_bytes();
    assert_eq!(sk_bytes.len(), SLH_SK_BYTES);
    assert_eq!(pk_bytes.len(), SLH_PK_BYTES);
    let slh_sk_rt = SlhSecretKey::from_bytes(&sk_bytes).unwrap();
    let slh_pk_rt = SlhPublicKey::from_bytes(&pk_bytes).unwrap();

    // Corrupting secret seed must fail checksum / root consistency check
    let mut bad_sk = sk_bytes.clone();
    bad_sk[10] ^= 0x01;
    assert!(SlhSecretKey::from_bytes(&bad_sk).is_err());

    // Stateless signing (immutable &self, cloned key, distinct randomized signatures)
    for i in 0..4u8 {
        let msg = format!("stateless-pq-msg-{i}");
        let sig = if i % 2 == 0 {
            slh_sk_rt.sign(msg.as_bytes()).unwrap()
        } else {
            cloned_sk.sign(msg.as_bytes()).unwrap()
        };
        let sig_bytes = sig.to_bytes();
        assert_eq!(sig_bytes.len(), SLH_SIG_BYTES);
        let sig_rt = SlhSignature::from_bytes(&sig_bytes).unwrap();
        assert!(slh_pk_rt.verify(msg.as_bytes(), &sig_rt));
        assert!(!slh_pk_rt.verify(b"tampered", &sig_rt));
    }

    // Unified Post-Quantum Signcryption (WPSC v1)
    let (bob_sk, bob_pk) = keygen().unwrap();
    let (eve_sk, _eve_pk) = keygen().unwrap();
    let (_, other_sender_pk) = SlhSecretKey::generate().unwrap();

    let packet = signcrypt(&slh_sk, &bob_pk, b"Top-secret PQ signed message", b"hdr").unwrap();
    let opened = unsigncrypt(&slh_pk, &bob_sk, &packet, b"hdr").unwrap();
    assert_eq!(opened, b"Top-secret PQ signed message");

    // Wrong recipient (anti-surreptitious forwarding), wrong sender, wrong AAD all fail
    assert!(unsigncrypt(&slh_pk, &eve_sk, &packet, b"hdr").is_err());
    assert!(unsigncrypt(&other_sender_pk, &bob_sk, &packet, b"hdr").is_err());
    assert!(unsigncrypt(&slh_pk, &bob_sk, &packet, b"bad-aad").is_err());
}

#[test]
fn advanced_protocols_totp_fpe_vss_zkp_timelock_pake_all_verify() {
    // 1. TOTP & Base32
    let secret = b"12345678901234567890";
    let b32 = encode_base32(secret);
    assert_eq!(decode_base32(&b32).unwrap(), secret);
    let (code, rem) = generate_totp_at(secret, 1_700_000_020, 30, 6).unwrap();
    assert_eq!(code.len(), 6);
    assert_eq!(rem, 20);
    assert!(verify_totp_at(secret, &code, 1_700_000_020, 30, 6, 1).unwrap());
    assert!(verify_totp_at(secret, &code, 1_700_000_050, 30, 6, 1).unwrap());
    assert!(!verify_totp_at(secret, "000000", 1_700_000_020, 30, 6, 0).unwrap() || code == "000000");

    // 2. FPE (both odd and even lengths, custom alphabets)
    let fpe_key = [0x77u8; 32];
    for sample in ["12", "123", "4532015112830366", "987654321", "00000"] {
        let enc = fpe_encrypt_str(&fpe_key, b"acct-id", "0123456789", sample).unwrap();
        assert_eq!(enc.len(), sample.len());
        assert!(enc.chars().all(|c| c.is_ascii_digit()));
        let dec = fpe_decrypt_str(&fpe_key, b"acct-id", "0123456789", &enc).unwrap();
        assert_eq!(dec, sample);
    }

    // 3. VSS + Proactive Share Refresh
    let master = b"wilis-vss-proactive-master-32b!!";
    let (cmt0, shares0) = vss_split(master, 5, 3).unwrap();
    for s in &shares0 {
        assert!(vss_verify_share(&cmt0, s));
    }
    assert_eq!(vss_combine(&cmt0, &shares0[0..3]).unwrap(), master);

    let (cmt1, shares1) = vss_proactive_refresh(&cmt0, &shares0).unwrap();
    assert_eq!(cmt1.epoch, 1);
    assert_ne!(shares0[0].share.data, shares1[0].share.data);
    assert!(!vss_verify_share(&cmt1, &shares0[0]));
    assert!(vss_verify_share(&cmt1, &shares1[2]));
    assert_eq!(vss_combine(&cmt1, &[shares1[1].clone(), shares1[3].clone(), shares1[4].clone()]).unwrap(), master);

    // 4. ZKP (Fiat-Shamir one-time hash Sigma proof)
    let seed = [0x5Cu8; 32];
    let stmt = zkp_keygen(&seed);
    let proof = zkp_prove(&seed, &stmt, b"login-challenge-42").unwrap();
    let proof_rt = ZkpProof::from_bytes(&proof.to_bytes()).unwrap();
    assert!(zkp_verify(&stmt, &proof_rt, b"login-challenge-42"));
    assert!(!zkp_verify(&stmt, &proof_rt, b"wrong-challenge"));

    // 5. TimeLock sequential puzzle
    let puzzle = TimeLockPuzzle::lock(b"future-secret", b"auction-1", 500).unwrap();
    let puzzle_rt = TimeLockPuzzle::from_bytes(&puzzle.to_bytes()).unwrap();
    assert_eq!(puzzle_rt.unlock(b"auction-1").unwrap(), b"future-secret");
    assert!(puzzle_rt.unlock(b"wrong-aad").is_err());

    // 6. Post-Quantum PAKE
    let (c_st, c_hello) = pake_client_start(b"shared-pass", b"pake-ctx", KdfParams::FAST_TEST).unwrap();
    let (s_st, s_hello) = pake_server_respond(b"shared-pass", b"pake-ctx", &c_hello).unwrap();
    let (k_cli, c_fin) = pake_client_finish(c_st, &s_hello).unwrap();
    let k_srv = pake_server_finish(s_st, &c_fin).unwrap();
    assert_eq!(k_cli.as_bytes(), k_srv.as_bytes());

    // Wrong password rejected immediately
    assert!(pake_server_respond(b"wrong-pass", b"pake-ctx", &c_hello).is_err());
}

#[test]
fn mnemonic_keywrap_keyring_hidden_volume_and_stego_bmp_wav() {
    // 1. Mnemonic 256 uniqueness + checksum typo detection
    let uniq: HashSet<&str> = WORDLIST_256.iter().copied().collect();
    assert_eq!(uniq.len(), 256, "WORDLIST_256 must have 256 unique words");
    let key = [0xE3u8; 32];
    let phrase = encode_mnemonic(&key).unwrap();
    assert_eq!(phrase.split_whitespace().count(), 34);
    assert_eq!(decode_mnemonic(&phrase).unwrap(), key);
    let bad_phrase = phrase.replacen(phrase.split_whitespace().next().unwrap(), "acorn", 1);
    if bad_phrase != phrase {
        assert!(decode_mnemonic(&bad_phrase).is_err());
    }

    // 2. KeyWrap (WENC v1) & Keyring (WKRN v1)
    let (kem_sk, kem_pk) = keygen().unwrap();
    let wrapped = wrap_secret_key(&kem_sk.to_bytes(), b"wrap-pass", None, KdfParams::FAST_TEST).unwrap();
    assert!(is_wrapped_secret_key(&wrapped));
    assert_eq!(unwrap_secret_key(&wrapped, b"wrap-pass", None).unwrap(), kem_sk.to_bytes());
    assert!(unwrap_secret_key(&wrapped, b"bad-pass", None).is_err());

    let dir = unique_tmp("keyring");
    let ring_path = dir.join("contacts.wkrn");
    let mut kr = Keyring::new();
    kr.add_key("alice", kem_pk.to_bytes(), 2_000_000_000).unwrap();
    kr.save(&ring_path).unwrap();
    let mut kr_loaded = Keyring::load(&ring_path).unwrap();
    assert!(kr_loaded.get("alice").unwrap().is_usable_at(1_700_000_000));
    assert!(!kr_loaded.get("alice").unwrap().is_usable_at(2_000_000_001));
    kr_loaded.revoke("alice", "key rotated").unwrap();
    assert!(!kr_loaded.get("alice").unwrap().is_usable_at(1_700_000_000));

    // 3. Plausible Deniability Hidden Volume
    let blob = create_deniable_container(
        8192,
        b"decoy-pw",
        b"boring tax receipts",
        b"real-hidden-pw",
        b"journalist whistleblower evidence",
        KdfParams::FAST_TEST,
    )
    .unwrap();
    assert_eq!(blob.len(), 8192);
    let (is_h1, pt1) = open_deniable_container(&blob, b"decoy-pw", KdfParams::FAST_TEST).unwrap();
    assert!(!is_h1 && pt1 == b"boring tax receipts");
    let (is_h2, pt2) = open_deniable_container(&blob, b"real-hidden-pw", KdfParams::FAST_TEST).unwrap();
    assert!(is_h2 && pt2 == b"journalist whistleblower evidence");
    assert!(open_deniable_container(&blob, b"wrong-pw", KdfParams::FAST_TEST).is_err());

    // 4. Steganography: 24-bit BMP & synthetic 16-bit PCM WAV
    let stego_key = [0x91u8; 32];
    let bmp = generate_blank_bmp(64, 64);
    let (_, cap) = stego_capacity_bytes(&bmp).unwrap();
    assert!(cap > 1000);
    let embedded = stego_embed(&bmp, &stego_key, b"hidden inside bmp!").unwrap();
    assert_eq!(stego_extract(&embedded, &stego_key).unwrap(), b"hidden inside bmp!");
    assert!(stego_extract(&embedded, &[0x92u8; 32]).is_err());

    // Minimal valid 16-bit PCM WAV carrier (4000 bytes of PCM samples = 2000 slots = 234B capacity)
    let pcm_len: u32 = 4000;
    let mut wav = Vec::with_capacity(44 + pcm_len as usize);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + pcm_len).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
    wav.extend_from_slice(&1u16.to_le_bytes()); // mono
    wav.extend_from_slice(&44100u32.to_le_bytes());
    wav.extend_from_slice(&88200u32.to_le_bytes());
    wav.extend_from_slice(&2u16.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes()); // 16-bit
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&pcm_len.to_le_bytes());
    wav.resize(44 + pcm_len as usize, 0x20);

    let stego_wav = stego_embed(&wav, &stego_key, b"hidden in pcm wav!").unwrap();
    assert_eq!(stego_extract(&stego_wav, &stego_key).unwrap(), b"hidden in pcm wav!");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn memlock_shred_lzss_seekable_and_streaming_wdir_v2() {
    harden_process_memory();
    let lb = LockedBuf::from_slice(b"pinned-secret-bytes");
    assert_eq!(lb.as_slice(), b"pinned-secret-bytes");
    assert!(format!("{lb:?}").contains("[REDACTED]"));

    let dir = unique_tmp("sys_io");
    let target = dir.join("secret.tmp");
    std::fs::write(&target, b"classified buffer contents").unwrap();
    shred_file(&target, 2).unwrap();
    assert!(!target.exists());

    // WilisLZ compression + RLE + zip-bomb ceiling rejection
    let sample = b"AAAAABBBBBAAAAABBBBBAAAAABBBBB Hello WilisLZ compression test! ".repeat(50);
    let comp = compress(&sample);
    assert!(comp.len() < sample.len());
    assert_eq!(decompress(&comp, sample.len()).unwrap(), sample);
    assert!(decompress(&comp, sample.len() - 1).is_err());

    // WSEK v1 random-access O(1) seekable container
    let key = [0x44u8; 32];
    let mut plain = vec![0u8; 10_000];
    for (i, b) in plain.iter_mut().enumerate() {
        *b = ((i * 17 + 3) & 0xFF) as u8;
    }
    let mut wsek_buf = Vec::new();
    encrypt_seekable_with_key(&key, &mut Cursor::new(&plain), &mut wsek_buf, b"seek-aad", 1024).unwrap();
    let mut reader = SeekableReader::open_with_key(Cursor::new(&wsek_buf), &key, b"seek-aad").unwrap();
    assert_eq!(reader.len(), 10_000);
    // Cross-chunk range read [900..3100)
    assert_eq!(reader.read_at(900, 2200).unwrap(), &plain[900..3100]);
    // Tail slice read
    assert_eq!(reader.read_at(9900, 100).unwrap(), &plain[9900..10_000]);
    reader.verify_all().unwrap();

    // Passphrase WSEK roundtrip
    let mut wsek_pw = Vec::new();
    encrypt_seekable_with_passphrase(
        b"pw",
        None,
        &mut Cursor::new(&plain[..2500]),
        &mut wsek_pw,
        b"",
        KdfParams::FAST_TEST,
        1024,
    )
    .unwrap();
    let mut r_pw = SeekableReader::open_with_passphrase(Cursor::new(&wsek_pw), b"pw", None, b"").unwrap();
    assert_eq!(r_pw.read_at(500, 1200).unwrap(), &plain[500..1700]);

    // Constant-memory streaming WDIR v2 (empty dir + executable bit + LZSS compression)
    let src_dir = dir.join("src_folder");
    let empty_sub = src_dir.join("empty_nested/deep_empty");
    std::fs::create_dir_all(&empty_sub).unwrap();
    let rep_file = src_dir.join("notes.txt");
    std::fs::write(&rep_file, b"wilis streaming v2 archive line\n".repeat(200)).unwrap();
    let bin_file = src_dir.join("run.sh");
    std::fs::write(&bin_file, b"#!/bin/sh\necho ok\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin_file, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let archive_path = dir.join("folder_v2.wils");
    let out_dir = dir.join("restored_v2");
    let (cnt, _) = encrypt_directory_v2_with_key(&key, &src_dir, &archive_path, b"dir-aad", true).unwrap();
    assert_eq!(cnt, 3); // notes.txt, run.sh, empty_nested/deep_empty
    let restored_cnt = decrypt_directory_v2_with_key(&key, &archive_path, &out_dir, b"dir-aad").unwrap();
    assert_eq!(restored_cnt, 3);
    assert!(out_dir.join("empty_nested/deep_empty").is_dir());
    assert_eq!(std::fs::read(out_dir.join("notes.txt")).unwrap(), std::fs::read(&rep_file).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(out_dir.join("run.sh")).unwrap().permissions().mode();
        assert_ne!(mode & 0o100, 0, "executable bit should be preserved on Unix");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wilis_net_pq_tcp_pki_and_pake_loopback_file_transfer() {
    let dir = unique_tmp("tcp_net");
    let src_file = dir.join("transfer.bin");
    // 140 KiB -> multiple 64 KiB chunks over TCP
    let payload: Vec<u8> = (0..140_000usize).map(|i| ((i * 13 + 5) & 0xFF) as u8).collect();
    std::fs::write(&src_file, &payload).unwrap();

    // 1. PKI Mode (WilisKEM + WilisSign + PqRatchetSession)
    let (mut alice_sign_sk, alice_vk) = SigningKey::generate(3).unwrap();
    let (bob_kem_sk, bob_kem_pk) = keygen().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let recv_dir_pki = dir.join("recv_pki");

    let recv_dir_clone = recv_dir_pki.clone();
    let srv = thread::spawn(move || {
        recv_file_over_tcp(&listener, &recv_dir_clone, &bob_kem_sk, &alice_vk, b"net-test").unwrap()
    });
    let sent = send_file_over_tcp(&addr, &src_file, &mut alice_sign_sk, &bob_kem_pk, b"net-test").unwrap();
    let recvd = srv.join().unwrap();
    assert_eq!(sent.bytes_sent, payload.len() as u64);
    assert_eq!(recvd.bytes_received, payload.len() as u64);
    assert_eq!(sent.digest, recvd.digest);
    assert_eq!(std::fs::read(&recvd.saved_path).unwrap(), payload);

    // 2. Zero-PKI PAKE Mode (WilisPAKE + ephemeral KEM PCS Ratchet)
    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = listener2.local_addr().unwrap().to_string();
    let recv_dir_pake = dir.join("recv_pake");
    let recv_dir2_clone = recv_dir_pake.clone();
    let srv2 = thread::spawn(move || {
        recv_file_pake(&listener2, &recv_dir2_clone, b"p2p-passphrase", b"pake-net").unwrap()
    });
    let sent2 = send_file_pake(
        &addr2,
        &src_file,
        b"p2p-passphrase",
        b"pake-net",
        KdfParams::FAST_TEST,
    )
    .unwrap();
    let recvd2 = srv2.join().unwrap();
    assert_eq!(sent2.digest, recvd2.digest);
    assert_eq!(std::fs::read(&recvd2.saved_path).unwrap(), payload);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persistent_ratchet_wrst_and_vault_v060_search_totp_export_import() {
    let dir = unique_tmp("persist_vault");

    // 1. Persistent encrypted PQ Ratchet State (WRST v1) across messages & PCS rekey
    let (mut alice_sign_sk, alice_vk) = SigningKey::generate(3).unwrap();
    let (bob_kem_sk, bob_kem_pk) = keygen().unwrap();
    let (mut alice, init) =
        PqRatchetSession::initiate_handshake(&mut alice_sign_sk, &bob_kem_pk, b"ctx").unwrap();
    let bob = PqRatchetSession::accept_handshake(&bob_kem_sk, &alice_vk, &init, b"ctx").unwrap();

    let pkt1 = alice.encrypt_next(b"msg-before-save", b"aad");
    let a_path = dir.join("alice.wrst");
    let b_path = dir.join("bob.wrst");
    save_pq_session(&a_path, &alice, b"state-pw", None, KdfParams::FAST_TEST).unwrap();
    save_pq_session(&b_path, &bob, b"state-pw", None, KdfParams::FAST_TEST).unwrap();

    // Reload from disk and verify continuity + PCS rekey
    let mut alice_re = load_pq_session(&a_path, b"state-pw", None).unwrap();
    let mut bob_re = load_pq_session(&b_path, b"state-pw", None).unwrap();
    assert_eq!(bob_re.decrypt_packet(&pkt1, b"aad").unwrap(), b"msg-before-save");

    let rekey = alice_re.initiate_rekey().unwrap();
    bob_re.accept_rekey(&rekey).unwrap();
    let pkt2 = alice_re.encrypt_next(b"msg-after-rekey", b"aad");
    assert_eq!(bob_re.decrypt_packet(&pkt2, b"aad").unwrap(), b"msg-after-rekey");
    assert!(load_pq_session(&a_path, b"wrong-pw", None).is_err());

    // 2. Vault search, TOTP (raw Base32 & otpauth:// URI), armored export/import/merge
    let mut v = Vault::new();
    v.set("github_token", "ghp_secret123").unwrap();
    v.set("github_totp", "JBSWY3DPEHPK3PXP").unwrap();
    v.set("aws_totp", "otpauth://totp/AWS:dev?secret=JBSWY3DPEHPK3PXP&issuer=AWS").unwrap();
    assert_eq!(v.search("GITHUB"), vec!["github_token", "github_totp"]);

    let (c1, _) = v.totp_at("github_totp", 1_700_000_000, 30, 6).unwrap();
    let (c2, _) = v.totp_at("aws_totp", 1_700_000_000, 30, 6).unwrap();
    assert_eq!(c1, c2);

    let armored = v.export_armored(b"export-pw", None, KdfParams::FAST_TEST).unwrap();
    assert!(armored.contains("-----BEGIN WILIS VAULT-----"));
    let imported = Vault::import_armored(&armored, b"export-pw", None).unwrap();
    assert_eq!(imported, v);
    assert!(Vault::import_armored(&armored, b"wrong-pw", None).is_err());

    let mut v2 = Vault::new();
    v2.set("local_only", "val").unwrap();
    assert_eq!(v2.merge_from(&imported).unwrap(), 3);
    assert_eq!(v2.len(), 4);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ffi_v060_siv_treehash_and_slh_exports_are_memory_safe() {
    unsafe {
        let key = [0x5Au8; 32];
        let msg = b"wilis-v060-ffi-test-message";

        // 1. In-place SIV seal & open
        let mut buf = msg.to_vec();
        let mut siv_tag = [0u8; SIV_TAG_BYTES];
        assert_eq!(
            wilis_siv_seal(
                key.as_ptr(),
                b"aad".as_ptr(),
                3,
                buf.as_ptr(),
                buf.len(),
                buf.as_mut_ptr(),
                siv_tag.as_mut_ptr()
            ),
            WILIS_OK
        );
        assert_ne!(buf.as_slice(), msg.as_slice());
        assert_eq!(
            wilis_siv_open(
                key.as_ptr(),
                b"aad".as_ptr(),
                3,
                buf.as_ptr(),
                buf.len(),
                siv_tag.as_ptr(),
                buf.as_mut_ptr()
            ),
            WILIS_OK
        );
        assert_eq!(buf.as_slice(), msg.as_slice());

        // Tampered tag returns WILIS_ERR_AUTH_FAILED and wipes output
        siv_tag[0] ^= 1;
        assert_eq!(
            wilis_siv_open(
                key.as_ptr(),
                b"aad".as_ptr(),
                3,
                buf.as_ptr(),
                buf.len(),
                siv_tag.as_ptr(),
                buf.as_mut_ptr()
            ),
            WILIS_ERR_AUTH_FAILED
        );
        assert!(buf.iter().all(|&b| b == 0));

        // 2. TreeHash FFI
        let mut th = [0u8; 32];
        assert_eq!(wilis_tree_hash_256(msg.as_ptr(), msg.len(), th.as_mut_ptr()), WILIS_OK);
        assert_eq!(th, tree_hash(msg));
        assert_eq!(wilis_tree_hash_256(msg.as_ptr(), usize::MAX, th.as_mut_ptr()), WILIS_ERR_INVALID_ARG);

        // 3. Stateless SLH FFI
        let mut lpk = [0u8; SLH_PK_BYTES];
        let mut lsk = [0u8; SLH_SK_BYTES];
        let mut lsig = vec![0u8; SLH_SIG_BYTES];
        assert_eq!(wilis_slh_keygen(lpk.as_mut_ptr(), lsk.as_mut_ptr()), WILIS_OK);
        assert_eq!(wilis_slh_sign(lsk.as_ptr(), msg.as_ptr(), msg.len(), lsig.as_mut_ptr()), WILIS_OK);
        assert_eq!(wilis_slh_verify(lpk.as_ptr(), msg.as_ptr(), msg.len(), lsig.as_ptr()), WILIS_OK);
        lsig[20] ^= 1;
        assert_eq!(
            wilis_slh_verify(lpk.as_ptr(), msg.as_ptr(), msg.len(), lsig.as_ptr()),
            WILIS_ERR_AUTH_FAILED
        );
    }
}
