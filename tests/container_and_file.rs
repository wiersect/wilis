//! End-to-end tests for the `WILS` v1 container format, Base64, Hex, and header authentication.

use wilis::error::WilisError;
use wilis::format::{
    decrypt_with_key, decrypt_with_passphrase, encrypt_with_key, encrypt_with_passphrase,
};
use wilis::kdf::KdfParams;
use wilis::utils::base64::{decode_base64, encode_base64};
use wilis::utils::hex::{decode_hex, encode_hex};
use wilis::utils::random::generate_key;

#[test]
fn container_passphrase_round_trip_and_header_tamper_detection() {
    let pass = b"strong-passphrase-2026!";
    let msg = b"Binary & UTF-8 payload: \x00\x01\xFF Hello Wilis!";
    let aad = b"file:report.bin";

    let container = encrypt_with_passphrase(pass, msg, aad, KdfParams::FAST_TEST).unwrap();
    let recovered = decrypt_with_passphrase(pass, &container, aad).unwrap();
    assert_eq!(recovered, msg);

    // Tampering with salt inside header must fail authentication
    let mut tampered_salt = container.clone();
    tampered_salt[15] ^= 0x01;
    assert!(matches!(
        decrypt_with_passphrase(pass, &tampered_salt, aad),
        Err(WilisError::AuthenticationFailed)
    ));

    // Tampering with nonce inside header must fail authentication
    let mut tampered_nonce = container.clone();
    tampered_nonce[40] ^= 0x01;
    assert!(matches!(
        decrypt_with_passphrase(pass, &tampered_nonce, aad),
        Err(WilisError::AuthenticationFailed)
    ));

    // Wrong passphrase must fail authentication
    assert!(matches!(
        decrypt_with_passphrase(b"wrong-passphrase", &container, aad),
        Err(WilisError::AuthenticationFailed)
    ));
}

#[test]
fn container_raw_key_round_trip_and_mode_mismatch() {
    let key = generate_key().unwrap();
    let msg = vec![0xCDu8; 4099];

    let container = encrypt_with_key(key.as_bytes(), &msg, b"").unwrap();
    let recovered = decrypt_with_key(key.as_bytes(), &container, b"").unwrap();
    assert_eq!(recovered, msg);

    // Attempting passphrase decryption on a raw-key container must report format error
    assert!(matches!(
        decrypt_with_passphrase(b"any-pass", &container, b""),
        Err(WilisError::InvalidFormat(_))
    ));
}

#[test]
fn pure_rust_base64_and_hex_round_trips() {
    for len in 0..=64 {
        let data: Vec<u8> = (0..len).map(|i| ((i * 37 + 5) & 0xFF) as u8).collect();

        let b64 = encode_base64(&data);
        assert_eq!(decode_base64(&b64).unwrap(), data);

        let hx = encode_hex(&data);
        assert_eq!(decode_hex(&hx).unwrap(), data);
    }
}
