//! Tests for hybrid memory-hard `WilisKDF` and `WilisHash-256`.

use wilis::hash::{hash, hash_hex, WilisHash};
use wilis::kdf::{derive_key, derive_key_with_keyfile, KdfParams};

#[test]
fn kdf_is_deterministic_and_sensitive_to_passphrase_salt_params_and_keyfile() {
    let salt_a = [0x11u8; 24];
    let mut salt_b = salt_a;
    salt_b[0] ^= 1;

    let k1 = derive_key(b"correct-horse-battery-staple", &salt_a, KdfParams::FAST_TEST).unwrap();
    let k2 = derive_key(b"correct-horse-battery-staple", &salt_a, KdfParams::FAST_TEST).unwrap();
    assert_eq!(k1.as_bytes(), k2.as_bytes());

    let k_diff_pass =
        derive_key(b"correct-horse-battery-staplE", &salt_a, KdfParams::FAST_TEST).unwrap();
    assert_ne!(k1.as_bytes(), k_diff_pass.as_bytes());

    let k_diff_salt =
        derive_key(b"correct-horse-battery-staple", &salt_b, KdfParams::FAST_TEST).unwrap();
    assert_ne!(k1.as_bytes(), k_diff_salt.as_bytes());

    let alt_params = KdfParams {
        memory_blocks: 64,
        passes: 3,
    };
    let k_diff_params = derive_key(b"correct-horse-battery-staple", &salt_a, alt_params).unwrap();
    assert_ne!(k1.as_bytes(), k_diff_params.as_bytes());

    // 2FA Keyfile mixing must produce a distinct key from passphrase-only derivation
    let keyfile_digest = hash(b"secret-keyfile-material-wildan-elis");
    let k_with_kf = derive_key_with_keyfile(
        b"correct-horse-battery-staple",
        Some(&keyfile_digest),
        &salt_a,
        KdfParams::FAST_TEST,
    )
    .unwrap();
    assert_ne!(k1.as_bytes(), k_with_kf.as_bytes());
}

#[test]
fn hash_streaming_matches_one_shot_and_exhibits_avalanche() {
    let data = b"The quick brown fox jumps over the lazy dog 0123456789 WilisHash-256!";
    let oneshot = hash(data);

    let mut streamed = WilisHash::new();
    for chunk in data.chunks(5) {
        streamed.update(chunk);
    }
    assert_eq!(oneshot, streamed.finalize());

    let mut altered = data.to_vec();
    altered[0] ^= 1;
    let altered_digest = hash(&altered);
    let flipped: u32 = oneshot
        .iter()
        .zip(altered_digest.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();
    assert!(
        (90..=166).contains(&flipped),
        "hash avalanche out of expected range: {flipped}/256"
    );

    assert_eq!(hash_hex(b"").len(), 64);
    assert_ne!(hash(b""), hash(b"\x00"));
}
