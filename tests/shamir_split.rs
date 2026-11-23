//! Mathematical and security tests for `WilisSplit` Shamir's Secret Sharing over `GF(2^8)`.

use wilis::error::WilisError;
use wilis::split::gf256::{gf_add, gf_div, gf_inv, gf_mul};
use wilis::split::{combine_shares, split_secret, Share};

#[test]
fn gf256_field_axioms_verified_exhaustively() {
    assert_eq!(gf_inv(0), 0);
    for a in 1..=255u8 {
        let inv = gf_inv(a);
        assert_eq!(gf_mul(a, inv), 1, "a * inv(a) != 1 for a={a}");
        assert_eq!(gf_div(a, a), 1, "a / a != 1 for a={a}");
    }

    // Check distributivity & commutativity on representative pairs
    for a in [0u8, 1, 2, 7, 53, 128, 211, 255] {
        for b in [0u8, 1, 3, 19, 87, 170, 254, 255] {
            assert_eq!(gf_mul(a, b), gf_mul(b, a));
            let c = 0x5Au8;
            assert_eq!(
                gf_mul(a, gf_add(b, c)),
                gf_add(gf_mul(a, b), gf_mul(a, c))
            );
        }
    }
}

#[test]
fn shamir_3_of_5_reconstructs_from_every_valid_subset() {
    let secret = b"Wildan-Elis-256bit-Master-Key-32";
    let shares = split_secret(secret, 5, 3).unwrap();
    assert_eq!(shares.len(), 5);

    // Every share encodes/decodes cleanly as text
    let decoded: Vec<Share> = shares
        .iter()
        .map(|s| Share::decode_string(&s.encode_string()).unwrap())
        .collect();

    // Test all C(5,3) = 10 subsets of 3 shares
    for i in 0..5 {
        for j in (i + 1)..5 {
            for k in (j + 1)..5 {
                let subset = [decoded[i].clone(), decoded[j].clone(), decoded[k].clone()];
                let recovered = combine_shares(&subset).unwrap();
                assert_eq!(recovered, secret);
            }
        }
    }

    // Passing more than K shares (all 5) also succeeds
    assert_eq!(combine_shares(&decoded).unwrap(), secret);
}

#[test]
fn shamir_rejects_insufficient_duplicate_tampered_and_mismatched_shares() {
    let secret_a = [0xAAu8; 32];
    let secret_b = [0xBBu8; 32];
    let shares_a = split_secret(&secret_a, 5, 3).unwrap();
    let shares_b = split_secret(&secret_b, 5, 3).unwrap();

    // 1. Fewer than threshold (2 of 3) -> rejected
    assert!(combine_shares(&shares_a[0..2]).is_err());

    // 2. Duplicate share indices -> rejected
    let dup = [shares_a[0].clone(), shares_a[0].clone(), shares_a[1].clone()];
    assert!(combine_shares(&dup).is_err());

    // 3. Single-bit tamper inside share payload -> caught by commitment check!
    let mut tampered = shares_a[2].clone();
    tampered.data[10] ^= 0x01;
    let bad_set = [shares_a[0].clone(), shares_a[1].clone(), tampered];
    assert!(matches!(
        combine_shares(&bad_set),
        Err(WilisError::AuthenticationFailed)
    ));

    // 4. Mixing shares from two different secrets -> caught immediately!
    let mixed = [shares_a[0].clone(), shares_a[1].clone(), shares_b[2].clone()];
    assert!(matches!(
        combine_shares(&mixed),
        Err(WilisError::AuthenticationFailed)
    ));
}
