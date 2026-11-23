//! Comprehensive mathematical & IND-CCA2 security tests for `WilisKEM` (Module-LWE 768)
//! and Hybrid Post-Quantum Public-Key Encryption (`WPKE` v1).

use wilis::error::WilisError;
use wilis::kem::poly::{Poly, KEM_N, KEM_Q, POLY_BYTES};
use wilis::kem::{
    decapsulate, encapsulate, keygen, pub_decrypt, pub_encrypt, KemCiphertext, KemPublicKey,
    KemSecretKey,
};

#[test]
fn poly_ring_axioms_packing_and_non_canonical_rejection() {
    let seed = [0x42u8; 32];
    let a = Poly::sample_uniform(&seed, 0, 0);
    let b = Poly::sample_uniform(&seed, 0, 1);
    let c = Poly::sample_cbd2(&seed, 2);

    // Commutativity and distributivity in Z_7681[X] / (X^256 + 1)
    assert_eq!(a.mul(&b), b.mul(&a));
    assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)));
    assert_eq!(a.add(&b).sub(&b), a);

    // Exact 13-bit packing round-trip
    let packed = a.pack();
    assert_eq!(packed.len(), POLY_BYTES);
    assert_eq!(Poly::unpack(&packed).unwrap(), a);

    // Non-canonical coefficient (>= 7681) MUST be rejected by unpack
    let mut bad = [0xFFu8; POLY_BYTES]; // 0x1FFF = 8191 >= 7681
    assert!(Poly::unpack(&bad).is_err());
    bad[0] = 0;
    assert!(Poly::unpack(&bad).is_err());

    // Exact message bit encode/decode round-trip even with heavy +/- 1800 noise
    let msg: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(13));
    let mut noisy = Poly::from_msg_bits(&msg);
    for i in 0..KEM_N {
        let delta: i32 = if i % 2 == 0 { 1800 } else { -1800 };
        noisy.coeffs[i] = (noisy.coeffs[i] as i32 + delta).rem_euclid(KEM_Q as i32) as u16;
    }
    assert_eq!(noisy.to_msg_bits(), msg);
}

#[test]
fn kem_50_encapsulations_zero_failures_and_cca2_implicit_rejection() {
    let (sk, pk) = keygen().unwrap();

    // Serialization round-trip & corruption rejection
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();
    assert_eq!(KemPublicKey::from_bytes(&pk_bytes).unwrap(), pk);
    let sk2 = KemSecretKey::from_bytes(&sk_bytes).unwrap();
    assert_eq!(sk2.public_key(), &pk);

    let mut bad_sk = sk_bytes.clone();
    bad_sk[sk_bytes.len() - 40] ^= 0x01; // flip pk_hash
    assert!(KemSecretKey::from_bytes(&bad_sk).is_err());

    for _ in 0..50 {
        let (ct, ss_enc) = encapsulate(&pk).unwrap();
        let ct_parsed = KemCiphertext::from_bytes(&ct.to_bytes()).unwrap();
        let ss_dec = decapsulate(&sk2, &ct_parsed);
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    // CCA2 Implicit Rejection: tampered ciphertext returns deterministic unrelated secret
    let (mut ct, ss_real) = encapsulate(&pk).unwrap();
    ct.u[1].coeffs[42] = (ct.u[1].coeffs[42] + 1) % KEM_Q;
    let ss_rej_1 = decapsulate(&sk, &ct);
    let ss_rej_2 = decapsulate(&sk, &ct);
    assert_ne!(ss_rej_1.as_bytes(), ss_real.as_bytes());
    assert_eq!(ss_rej_1.as_bytes(), ss_rej_2.as_bytes());
}

#[test]
fn hybrid_public_key_encryption_round_trip_and_tamper_rejection() {
    let (sk, pk) = keygen().unwrap();
    let (other_sk, _) = keygen().unwrap();

    for &len in &[0usize, 1, 16, 255, 4096] {
        let msg: Vec<u8> = (0..len).map(|i| ((i * 29 + 7) & 0xFF) as u8).collect();
        let packet = pub_encrypt(&pk, &msg, b"pq-aad").unwrap();
        let plain = pub_decrypt(&sk, &packet, b"pq-aad").unwrap();
        assert_eq!(plain, msg);
    }

    let packet = pub_encrypt(&pk, b"Top secret for Wildan & Elis", b"ctx").unwrap();

    // 1. Wrong secret key
    assert!(matches!(
        pub_decrypt(&other_sk, &packet, b"ctx"),
        Err(WilisError::AuthenticationFailed)
    ));
    // 2. Wrong AAD
    assert!(matches!(
        pub_decrypt(&sk, &packet, b"wrong-ctx"),
        Err(WilisError::AuthenticationFailed)
    ));
    // 3. Flip 1 bit in AEAD ciphertext/tag
    let mut bad_tag = packet.clone();
    let last = bad_tag.len() - 1;
    bad_tag[last] ^= 0x01;
    assert!(matches!(
        pub_decrypt(&sk, &bad_tag, b"ctx"),
        Err(WilisError::AuthenticationFailed)
    ));
    // 4. Tamper KEM ciphertext header -> implicit rejection causes AEAD auth failure
    let mut bad_kem = packet.clone();
    bad_kem[10] ^= 0x01;
    assert!(pub_decrypt(&sk, &bad_kem, b"ctx").is_err());
}
