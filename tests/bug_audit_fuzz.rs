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
