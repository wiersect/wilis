//! Locked Known-Answer Test Vectors (KAT) & v0.4.3 Audit Regression Suite.
//!
//! These hardcoded golden vectors lock exact wire-format and mathematical
//! compatibility across versions and CPU architectures (x86_64, ARM64, 32-bit/64-bit)
//! for every cryptographic primitive in Wilis.

use wilis::aead::{open, seal};
use wilis::cli::args::parse_args;
use wilis::core::constants::{ROUNDS_DATA, ROUNDS_FULL};
use wilis::core::permute::{permute, permute_inverse};
use wilis::core::state::State;
use wilis::format::header::{ContainerHeader, KeyMode, FORMAT_VERSION_V2};
use wilis::hash::hash;
use wilis::kdf::{derive_key, derive_key_with_keyfile, KdfParams};
use wilis::kem::poly::Poly;
use wilis::mac::{derive_subkey, mac};
use wilis::ratchet::RatchetSession;
use wilis::sign::merkle::build_merkle_tree;
use wilis::sign::wots::{
    compute_leaf_pk_hash, wots_chain, wots_recover_leaf_pk_hash, wots_sign_digest,
};
use wilis::stream::chunk_nonce::DEFAULT_CHUNK_SIZE;
use wilis::utils::base64::{decode_base64, encode_base64};
use wilis::utils::hex::encode_hex;
use wilis::xof::WilisXof;

#[test]
fn kat_core_permutation_hash_xof_mac_aead_and_kdf_vectors() {
    // 1. WilisPerm-384 (16-round & 12-round + exact inverse bijection)
    let mut s16 = State::from_words([0, 1, 2, 3, 4, 5]);
    permute(&mut s16, ROUNDS_FULL);
    assert_eq!(
        encode_hex(&s16.to_bytes()),
        "77be099ac8cf1efeaac75b9c3b412670d1c3f1653e63521185ab6cfcadd0365ec2a660bd651f8e1e049b4762ef1044be"
    );
    permute_inverse(&mut s16, ROUNDS_FULL);
    assert_eq!(s16.words, [0, 1, 2, 3, 4, 5]);

    let mut s12 = State::from_words([0, 1, 2, 3, 4, 5]);
    permute(&mut s12, ROUNDS_DATA);
    assert_eq!(
        encode_hex(&s12.to_bytes()),
        "96b658ee278a5237547d93d5afa8c0122316a47a2dae995f8ea112a72c92fd92f71c827d3825faa9ced84c38c60ec2b9"
    );
    permute_inverse(&mut s12, ROUNDS_DATA);
    assert_eq!(s12.words, [0, 1, 2, 3, 4, 5]);

    // 2. WilisHash-256
    assert_eq!(
        encode_hex(&hash(b"")),
        "a7470288849756b2d5d1e43ffe3a97492aea9753bbcebfa2e974caa291f79c37"
    );
    assert_eq!(
        encode_hex(&hash(b"abc")),
        "6c3ec00ee93a5ed75470df77b51abc00a538db9e1801ff7697e5c33427ef70b3"
    );
    assert_eq!(
        encode_hex(&hash(b"0123456789abcdef")),
        "2b8089bf35ab0f4b01d84246c16cab328ea66b2b18bd0e86f19301073cf613c5"
    );

    // 3. WilisXOF (empty vs non-empty domain labels)
    assert_eq!(
        encode_hex(&WilisXof::derive(b"", b"wilis-kat-seed", 48)),
        "8815ff41ba940259b2709ee801aa3245832848677e66bab2702e7b302b61418a73727556d78e71490949d0fed184d50b"
    );
    assert_eq!(
        encode_hex(&WilisXof::derive(b"KAT_XOF_V1", b"wilis-kat-seed", 48)),
        "1cc448cd403cf9fe5cfc52bb7150013590485b05545e2d6c652a00cb46b668eb487beaa8e631da72055f198d40ef4e1b"
    );

    // 4. WilisMAC & derive_subkey
    let key = [0x2Au8; 32];
    assert_eq!(
        encode_hex(&mac(&key, b"Wilis KAT message")),
        "31a320a3d73c835f37234d7f362717e9e5cef7189027d75ebfdcbbb6a7164803"
    );
    assert_eq!(
        encode_hex(derive_subkey(&key, b"kat-context").as_bytes()),
        "1592dcd4049227aa53f76928561f615c51f34123879e3685e9b90f04f7416629"
    );

    // 5. WilisAEAD (empty & multi-block authenticated encryption)
    let nonce = [0x17u8; 24];
    let (e_ct, e_tag) = seal(&key, &nonce, b"", b"");
    assert!(e_ct.is_empty());
    assert_eq!(
        encode_hex(&e_tag),
        "fefab3e89d5b04452b8f211700f3e31edcf1e9d27b55158c6579d4b3be28fb4a"
    );

    let msg = b"Wilis deterministic AEAD KAT payload 0123456789!";
    let (ct, tag) = seal(&key, &nonce, b"kat-aad-header", msg);
    assert_eq!(
        encode_hex(&ct),
        "5ef3b1c26dd754d4c80e8a3a11c26b81b2851bf15d13d6c13862ee1c14573f2e33dbcaa54d8edffd028457b34cc63def"
    );
    assert_eq!(
        encode_hex(&tag),
        "2333aaba5bf1fbb19ed428ab294e4ba813f3ec04456155c47ac9f984221bf710"
    );
    assert_eq!(open(&key, &nonce, b"kat-aad-header", &ct, &tag).unwrap(), msg);

    // 6. WilisKDF v2 (locks 32-bit/64-bit cross-platform determinism with & without 2FA keyfile)
    let salt = [0x5Cu8; 24];
    let kf = [0x9Au8; 32];
    let k_plain = derive_key(b"wilis-kat-passphrase", &salt, KdfParams::FAST_TEST).unwrap();
    let k_2fa = derive_key_with_keyfile(b"wilis-kat-passphrase", Some(&kf), &salt, KdfParams::FAST_TEST).unwrap();
    assert_eq!(
        encode_hex(k_plain.as_bytes()),
        "f6a3a8e89fc57fc7138e19203093dc4c701f9b3107cb72ed5346ab9d535d856b"
    );
    assert_eq!(
        encode_hex(k_2fa.as_bytes()),
        "999f31801d9bc71b2786a1eb3d62ca8fc4acd1f5d335f929637a26d8f7885fa4"
    );
}

#[test]
fn kat_post_quantum_kem_sign_and_ratchet_vectors() {
    let key = [0x2Au8; 32];

    // 1. WilisKEM deterministic Module-LWE polynomial ring vector (Barrett + CBD_2 + 13-bit packing)
    let p_a = Poly::sample_uniform(&key, 1, 2);
    let p_s = Poly::sample_cbd2(&key, 0);
    let p_e = Poly::sample_cbd2(&key, 3);
    let p_t = p_a.mul(&p_s).add(&p_e);
    assert_eq!(
        encode_hex(&hash(&p_t.pack())),
        "8a4b934176f9a9bbb4eaa589a9ea40ea3e137edb2ce9760da09dbf71e9898bae"
    );

    // 2. WilisSign deterministic WOTS+ leaf, Merkle root & recovery vector
    let sk_seed = [0x33u8; 32];
    let pk_seed = [0x77u8; 32];
    let leaf0 = compute_leaf_pk_hash(&sk_seed, &pk_seed, 0);
    let levels = build_merkle_tree(&sk_seed, &pk_seed, 2);
    let root = levels[2][0];
    let digest = hash(b"wilis-sign-kat-digest");
    let wots_sig = wots_sign_digest(&sk_seed, &pk_seed, 0, &digest);
    assert_eq!(wots_recover_leaf_pk_hash(&wots_sig, &pk_seed, 0, &digest), leaf0);
    assert_eq!(
        encode_hex(&leaf0),
        "b98469f752f53e7da26ed14341b963d91af8279af17ded75881b00959c42bbde"
    );
    assert_eq!(
        encode_hex(&root),
        "ecaee9e20fb30894fe93aaa36307c6c3e0050913e183cc55baea53921aacfc47"
    );

    // 3. WilisRatchet deterministic wire packets & bidirectional round-trip
    let mut alice = RatchetSession::from_shared_secret(&key, true);
    let mut bob = RatchetSession::from_shared_secret(&key, false);
    let p0 = alice.encrypt_next(b"kat-msg-0", b"hdr");
    let p1 = alice.encrypt_next(b"kat-msg-1", b"hdr");
    assert_eq!(
        encode_hex(&p0.to_bytes()),
        "57524154010000000000000000c90c70e4389fc2e151cac68fb87e6933aa53321e82bbc633149ea1daa5543d322ea7b87342904209cd"
    );
    assert_eq!(
        encode_hex(&p1.to_bytes()),
        "5752415401010000000000000097d6b6c4846222d4853058401ce5fcdb75e917252b82ee30bd34fed3c03c56c4a090ecbcfc662734c7"
    );
    assert_eq!(bob.decrypt_packet(&p0, b"hdr").unwrap(), b"kat-msg-0");
    assert_eq!(bob.decrypt_packet(&p1, b"hdr").unwrap(), b"kat-msg-1");
}

#[test]
fn regression_v043_audit_fixes_verified() {
    // 1. wots_chain rejects out-of-range u8 wrapping step bounds instead of silently wrapping
    let overflow_caught = std::panic::catch_unwind(|| {
        wots_chain([0x11u8; 32], 200, 100, &[0x22u8; 32], 0, 0)
    });
    assert!(overflow_caught.is_err());

    // 2. ContainerHeader::to_bytes never panics when version == 2 and chunk_size is None
    let hdr = ContainerHeader {
        version: FORMAT_VERSION_V2,
        mode: KeyMode::RawKey,
        nonce: [0xABu8; 24],
        chunk_size: None,
    };
    let raw = hdr.to_bytes();
    let (parsed, _) = ContainerHeader::parse(&raw).unwrap();
    assert_eq!(parsed.chunk_size, Some(DEFAULT_CHUNK_SIZE));

    // 3. Base64 zeroizing decode rejects invalid symbols & preserves exact canonical round-trips
    let sample = b"\x00\xFFWilis v0.4.3 KAT";
    assert_eq!(decode_base64(&encode_base64(sample)).unwrap(), sample);
    assert!(decode_base64("AAAA!AAA").is_err());

    // 4. CLI ZeroizeStr cleanly handles early `?` failure after `--pass` without leaking/panicking
    let args: Vec<String> = [
        "encrypt-file",
        "--pass",
        "super-secret-pass",
        "--strength",
        "bogus-tier",
        "--in",
        "a",
        "--out",
        "b",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert!(parse_args(&args).is_err());
}
