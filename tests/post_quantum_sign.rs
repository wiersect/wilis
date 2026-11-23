//! Security & correctness tests for `WilisSign` post-quantum WOTS+ Merkle signatures.

use wilis::sign::{Signature, SigningKey, VerifyingKey};

#[test]
fn sign_verify_round_trip_serialization_and_leaf_exhaustion() {
    // Height = 2 -> 2^2 = 4 one-time signatures
    let (mut sk, pk) = SigningKey::generate(2).unwrap();
    assert_eq!(sk.max_signatures(), 4);
    assert_eq!(sk.remaining_signatures(), 4);

    // Key serialization round-trip + tamper detection
    let sk_bytes = sk.to_bytes();
    let pk_bytes = pk.to_bytes();
    assert_eq!(VerifyingKey::from_bytes(&pk_bytes).unwrap(), pk);
    let mut bad_pk = pk_bytes.clone();
    bad_pk[10] ^= 0x01;
    assert!(VerifyingKey::from_bytes(&bad_pk).is_err());

    let mut bad_sk = sk_bytes.clone();
    bad_sk[20] ^= 0x01;
    assert!(SigningKey::from_bytes(&bad_sk).is_err());

    // Use all 4 one-time leaves on distinct messages
    for idx in 0..4u32 {
        let msg = format!("Post-quantum signed message #{idx}");
        let sig = sk.sign(msg.as_bytes()).unwrap();
        assert_eq!(sig.leaf_index, idx);
        assert_eq!(sk.remaining_signatures(), 3 - idx);

        let sig_bytes = sig.to_bytes();
        let parsed_sig = Signature::from_bytes(&sig_bytes).unwrap();
        assert_eq!(parsed_sig, sig);
        assert!(pk.verify(msg.as_bytes(), &parsed_sig));
    }

    // 5th signature MUST fail (strict stateful protection against WOTS+ key reuse)
    assert!(sk.sign(b"must-be-rejected").is_err());
}

#[test]
fn signature_rejects_any_single_bit_tamper_or_wrong_key() {
    let (mut sk, pk) = SigningKey::generate(3).unwrap();
    let (_, other_pk) = SigningKey::generate(3).unwrap();
    let msg = b"Authentic release binary digest";

    let sig = sk.sign(msg).unwrap();
    assert!(pk.verify(msg, &sig));

    // 1. Modified message (1 bit)
    let mut bad_msg = msg.to_vec();
    bad_msg[0] ^= 0x01;
    assert!(!pk.verify(&bad_msg, &sig));

    // 2. Wrong public key
    assert!(!other_pk.verify(msg, &sig));

    // 3. Modified randomizer
    let mut bad_rand = sig.clone();
    bad_rand.randomizer[15] ^= 0x80;
    assert!(!pk.verify(msg, &bad_rand));

    // 4. Modified WOTS+ chain element
    let mut bad_wots = sig.clone();
    bad_wots.wots_sig[33][7] ^= 0x04;
    assert!(!pk.verify(msg, &bad_wots));

    // 5. Modified Merkle authentication path node
    let mut bad_path = sig.clone();
    bad_path.auth_path[1][0] ^= 0x01;
    assert!(!pk.verify(msg, &bad_path));

    // 6. Modified leaf index
    let mut bad_idx = sig.clone();
    bad_idx.leaf_index ^= 1;
    assert!(!pk.verify(msg, &bad_idx));
}
