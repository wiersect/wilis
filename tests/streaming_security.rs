//! Security tests for constant-memory `WILS` v2 chunked streaming encryption:
//! - Empty, 1-byte, exact chunk boundary, and multi-chunk round-trips
//! - Truncation attack rejection
//! - Trailing-chunk / append attack rejection
//! - Chunk reordering / swap attack rejection
//! - Middle-chunk 1-bit tamper rejection
//! - 2FA Passphrase + Keyfile round-trip & missing-keyfile rejection

use std::io::Cursor;

use wilis::error::WilisError;
use wilis::format::ContainerHeader;
use wilis::hash::hash;
use wilis::kdf::KdfParams;
use wilis::stream::{
    decrypt_stream_with_key, decrypt_stream_with_passphrase, encrypt_stream_with_key,
    encrypt_stream_with_passphrase,
};

#[test]
fn streaming_round_trip_across_boundaries() {
    let key = [0x77u8; 32];
    let chunk_size = 4096u32;

    for &len in &[0usize, 1, 16, 4095, 4096, 4097, 12_288, 25_000] {
        let plain: Vec<u8> = (0..len).map(|i| ((i * 53 + 11) & 0xFF) as u8).collect();
        let mut encrypted = Vec::new();
        let (in_b, _) = encrypt_stream_with_key(
            &key,
            &mut Cursor::new(&plain),
            &mut encrypted,
            b"stream-aad",
            chunk_size,
        )
        .unwrap();
        assert_eq!(in_b as usize, len);

        let mut decrypted = Vec::new();
        let out_b = decrypt_stream_with_key(
            &key,
            &mut Cursor::new(&encrypted),
            &mut decrypted,
            b"stream-aad",
        )
        .unwrap();
        assert_eq!(out_b as usize, len);
        assert_eq!(decrypted, plain, "stream mismatch for len={len}");
    }
}

#[test]
fn streaming_rejects_truncation_reordering_duplication_and_tampering() {
    let key = [0x99u8; 32];
    let chunk_size = 1024u32;
    let plain: Vec<u8> = (0..3500usize).map(|i| (i & 0xFF) as u8).collect();

    let mut encrypted = Vec::new();
    encrypt_stream_with_key(
        &key,
        &mut Cursor::new(&plain),
        &mut encrypted,
        b"ctx",
        chunk_size,
    )
    .unwrap();

    let (_hdr, hdr_len) = ContainerHeader::parse(&encrypted).unwrap();
    // Chunk 0 frame length = 4 (len) + 1 (flag) + 1024 (ct) + 32 (tag) = 1061 bytes
    let chunk_frame_len = 5 + 1024 + 32;
    let c0_start = hdr_len;
    let c1_start = c0_start + chunk_frame_len;
    let c2_start = c1_start + chunk_frame_len;

    // 1. Truncation attack: drop final chunk (keep only header + chunk 0 + chunk 1)
    let truncated = encrypted[..c2_start].to_vec();
    let mut out = Vec::new();
    assert!(matches!(
        decrypt_stream_with_key(&key, &mut Cursor::new(&truncated), &mut out, b"ctx"),
        Err(WilisError::AuthenticationFailed)
    ));

    // 2. Chunk reordering attack: swap chunk 0 and chunk 1
    let mut swapped = encrypted.clone();
    let chunk0 = encrypted[c0_start..c1_start].to_vec();
    let chunk1 = encrypted[c1_start..c2_start].to_vec();
    swapped[c0_start..c1_start].copy_from_slice(&chunk1);
    swapped[c1_start..c2_start].copy_from_slice(&chunk0);
    let mut out = Vec::new();
    assert!(matches!(
        decrypt_stream_with_key(&key, &mut Cursor::new(&swapped), &mut out, b"ctx"),
        Err(WilisError::AuthenticationFailed)
    ));

    // 3. Trailing garbage / appended duplicate chunk after final chunk
    let mut appended = encrypted.clone();
    appended.extend_from_slice(&chunk0);
    let mut out = Vec::new();
    assert!(matches!(
        decrypt_stream_with_key(&key, &mut Cursor::new(&appended), &mut out, b"ctx"),
        Err(WilisError::AuthenticationFailed)
    ));

    // 4. Single-bit flip in middle chunk
    let mut flipped = encrypted.clone();
    flipped[c1_start + 100] ^= 0x01;
    let mut out = Vec::new();
    assert!(matches!(
        decrypt_stream_with_key(&key, &mut Cursor::new(&flipped), &mut out, b"ctx"),
        Err(WilisError::AuthenticationFailed)
    ));
}

#[test]
fn streaming_2fa_passphrase_plus_keyfile_security() {
    let pass = b"wildan-elis-secret";
    let keyfile = hash(b"this-is-a-2fa-keyfile-contents");
    let plain = vec![0x5Au8; 5000];

    let mut encrypted = Vec::new();
    encrypt_stream_with_passphrase(
        pass,
        Some(&keyfile),
        &mut Cursor::new(&plain),
        &mut encrypted,
        b"2fa-test",
        KdfParams::FAST_TEST,
        2048,
    )
    .unwrap();

    // Correct passphrase + correct keyfile -> succeeds
    let mut decrypted = Vec::new();
    decrypt_stream_with_passphrase(
        pass,
        Some(&keyfile),
        &mut Cursor::new(&encrypted),
        &mut decrypted,
        b"2fa-test",
    )
    .unwrap();
    assert_eq!(decrypted, plain);

    // Correct passphrase WITHOUT keyfile -> MUST fail!
    let mut out = Vec::new();
    assert!(matches!(
        decrypt_stream_with_passphrase(
            pass,
            None,
            &mut Cursor::new(&encrypted),
            &mut out,
            b"2fa-test",
        ),
        Err(WilisError::AuthenticationFailed)
    ));
}
