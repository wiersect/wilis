//! Security and correctness tests for `WilisAEAD`.

use wilis::aead::{open, seal};
use wilis::error::WilisError;

#[test]
fn aead_round_trip_various_lengths() {
    let key = [0x42u8; 32];
    let nonce = [0x19u8; 24];
    let aad = b"wilis-header-metadata";

    let lengths = [0usize, 1, 7, 15, 16, 17, 31, 32, 33, 64, 127, 255, 4096];
    for len in lengths {
        let pt: Vec<u8> = (0..len).map(|i| ((i * 73 + 19) & 0xFF) as u8).collect();
        let (ct, tag) = seal(&key, &nonce, aad, &pt);
        assert_eq!(ct.len(), pt.len());

        let recovered = open(&key, &nonce, aad, &ct, &tag)
            .unwrap_or_else(|e| panic!("round-trip failed for len={len}: {e}"));
        assert_eq!(recovered, pt, "plaintext mismatch for len={len}");
    }
}

#[test]
fn different_nonces_produce_completely_different_ciphertexts() {
    let key = [0xABu8; 32];
    let nonce_a = [0x01u8; 24];
    let mut nonce_b = nonce_a;
    nonce_b[23] ^= 1;

    let msg = b"Identical message encrypted under two distinct nonces!";
    let (ct_a, tag_a) = seal(&key, &nonce_a, b"", msg);
    let (ct_b, tag_b) = seal(&key, &nonce_b, b"", msg);

    assert_ne!(ct_a, ct_b);
    assert_ne!(tag_a, tag_b);
}

#[test]
fn single_bit_tamper_in_ciphertext_tag_nonce_key_or_aad_is_rejected() {
    let key = [0x7Eu8; 32];
    let nonce = [0x33u8; 24];
    let aad = b"authenticated-context";
    let pt = b"Top secret payload protected by WilisAEAD 256-bit authentication tag.";

    let (ct, tag) = seal(&key, &nonce, aad, pt);

    // 1. Flip 1 bit in ciphertext
    let mut bad_ct = ct.clone();
    bad_ct[ct.len() / 2] ^= 0x01;
    assert!(matches!(
        open(&key, &nonce, aad, &bad_ct, &tag),
        Err(WilisError::AuthenticationFailed)
    ));

    // 2. Flip 1 bit in tag
    let mut bad_tag = tag;
    bad_tag[31] ^= 0x80;
    assert!(matches!(
        open(&key, &nonce, aad, &ct, &bad_tag),
        Err(WilisError::AuthenticationFailed)
    ));

    // 3. Flip 1 bit in nonce
    let mut bad_nonce = nonce;
    bad_nonce[0] ^= 0x01;
    assert!(matches!(
        open(&key, &bad_nonce, aad, &ct, &tag),
        Err(WilisError::AuthenticationFailed)
    ));

    // 4. Flip 1 bit in key
    let mut bad_key = key;
    bad_key[15] ^= 0x04;
    assert!(matches!(
        open(&bad_key, &nonce, aad, &ct, &tag),
        Err(WilisError::AuthenticationFailed)
    ));

    // 5. Modify AAD
    assert!(matches!(
        open(&key, &nonce, b"authenticated-contexT", &ct, &tag),
        Err(WilisError::AuthenticationFailed)
    ));

    // 6. Empty vs non-empty AAD must not collide
    assert!(matches!(
        open(&key, &nonce, b"", &ct, &tag),
        Err(WilisError::AuthenticationFailed)
    ));
}
