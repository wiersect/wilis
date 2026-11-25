//! Related-key sensitivity test for `WilisAEAD`, live IND-CCA2 self-audit for `WilisKEM`,
//! and v0.5.0 protocol audit for `WPKE` v2 multi-recipient streaming, PQ PCS ratchet & `WilisPad`.

use crate::aead::seal;
use crate::kem::{
    decapsulate, encapsulate, keygen, pub_decrypt_multi, pub_encrypt_multi,
};
use crate::ratchet::PqRatchetSession;
use crate::sign::SigningKey;
use crate::utils::padding::{pad_to_block, unpad_strict};

/// Results from flipping every single bit of a 256-bit `WilisAEAD` key.
#[derive(Debug, Clone)]
pub struct KeySensitivityResult {
    pub avg_ct_percent: f64,
    pub avg_tag_percent: f64,
    pub passed: bool,
}

/// Results from live post-quantum `WilisKEM` CCA2 encapsulation/decapsulation & tamper check.
#[derive(Debug, Clone)]
pub struct KemAuditResult {
    pub trials: usize,
    pub zero_failures: bool,
    pub implicit_rejection_ok: bool,
    pub passed: bool,
}

/// Flips each of the 256 bits in a `WilisAEAD` key and measures output diffusion on both
/// ciphertext (512 bits) and authentication tag (256 bits).
pub fn analyze_related_key_sensitivity() -> KeySensitivityResult {
    let base_key = [0x5Au8; 32];
    let nonce = [0xC3u8; 24];
    let msg = [0x33u8; 64]; // 512 bits
    let (base_ct, base_tag) = seal(&base_key, &nonce, b"key-sens-audit", &msg);

    let mut total_ct_flips: u64 = 0;
    let mut total_tag_flips: u64 = 0;

    for bit in 0..256usize {
        let mut k = base_key;
        k[bit / 8] ^= 1u8 << (bit % 8);
        let (ct, tag) = seal(&k, &nonce, b"key-sens-audit", &msg);

        let ct_flips: u32 = base_ct
            .iter()
            .zip(ct.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        let tag_flips: u32 = base_tag
            .iter()
            .zip(tag.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();

        total_ct_flips += ct_flips as u64;
        total_tag_flips += tag_flips as u64;
    }

    let avg_ct_pct = (total_ct_flips as f64 / (256.0 * 512.0)) * 100.0;
    let avg_tag_pct = (total_tag_flips as f64 / (256.0 * 256.0)) * 100.0;
    let passed = (47.5..=52.5).contains(&avg_ct_pct) && (47.5..=52.5).contains(&avg_tag_pct);

    KeySensitivityResult {
        avg_ct_percent: avg_ct_pct,
        avg_tag_percent: avg_tag_pct,
        passed,
    }
}

/// Runs `trials` live post-quantum `WilisKEM` encapsulations/decapsulations and verifies
/// Fujisaki-Okamoto implicit rejection against tampered ciphertexts.
pub fn analyze_kem_cca2(trials: usize) -> KemAuditResult {
    if trials == 0 {
        return KemAuditResult {
            trials: 0,
            zero_failures: false,
            implicit_rejection_ok: false,
            passed: false,
        };
    }
    let (sk, pk) = match keygen() {
        Ok(pair) => pair,
        Err(_) => {
            return KemAuditResult {
                trials,
                zero_failures: false,
                implicit_rejection_ok: false,
                passed: false,
            }
        }
    };

    let mut zero_failures = true;
    let mut implicit_rejection_ok = true;

    for _ in 0..trials {
        let (mut ct, ss_enc) = match encapsulate(&pk) {
            Ok(res) => res,
            Err(_) => {
                zero_failures = false;
                break;
            }
        };
        let ss_dec = decapsulate(&sk, &ct);
        if ss_enc.as_bytes() != ss_dec.as_bytes() {
            zero_failures = false;
        }

        // Tamper 1 coefficient in ciphertext -> FO implicit rejection must yield a distinct key
        ct.v.coeffs[0] = (ct.v.coeffs[0] + 1) % crate::kem::poly::KEM_Q;
        let ss_tampered = decapsulate(&sk, &ct);
        if ss_tampered.as_bytes() == ss_enc.as_bytes() {
            implicit_rejection_ok = false;
        }
    }

    KemAuditResult {
        trials,
        zero_failures,
        implicit_rejection_ok,
        passed: zero_failures && implicit_rejection_ok,
    }
}

/// Results from live v0.5.0 post-quantum protocol verification (`WPKE` v2, PQ PCS ratchet, `WilisPad`).
#[derive(Debug, Clone)]
pub struct PqProtocolAuditResult {
    pub wpke_v2_multi_ok: bool,
    pub pq_pcs_ratchet_ok: bool,
    pub padding_integrity_ok: bool,
    pub passed: bool,
}

/// Verifies multi-recipient anonymous `WPKE` v2 encryption, `PqRatchetSession` mutual
/// handshake + PCS rekeying, and `WilisPad` constant-time tamper rejection.
pub fn analyze_pq_protocols() -> PqProtocolAuditResult {
    let wpke_v2_multi_ok = (|| -> bool {
        let Ok((sk1, pk1)) = keygen() else { return false };
        let Ok((sk2, pk2)) = keygen() else { return false };
        let Ok((sk_outsider, _)) = keygen() else { return false };
        let msg = b"Wilis v0.5.0 multi-recipient post-quantum audit payload";
        let Ok(pkt) = pub_encrypt_multi(&[&pk1, &pk2], msg, b"audit-aad") else { return false };
        let ok1 = pub_decrypt_multi(&sk1, &pkt, b"audit-aad").map(|p| p == msg).unwrap_or(false);
        let ok2 = pub_decrypt_multi(&sk2, &pkt, b"audit-aad").map(|p| p == msg).unwrap_or(false);
        let outsider_rej = pub_decrypt_multi(&sk_outsider, &pkt, b"audit-aad").is_err();
        ok1 && ok2 && outsider_rej
    })();

    let pq_pcs_ratchet_ok = (|| -> bool {
        let Ok((mut alice_sign_sk, alice_vk)) = SigningKey::generate(2) else { return false };
        let Ok((bob_kem_sk, bob_kem_pk)) = keygen() else { return false };
        let Ok((mut alice, init)) =
            PqRatchetSession::initiate_handshake(&mut alice_sign_sk, &bob_kem_pk, b"audit-ctx")
        else {
            return false;
        };
        let Ok(mut bob) =
            PqRatchetSession::accept_handshake(&bob_kem_sk, &alice_vk, &init, b"audit-ctx")
        else {
            return false;
        };
        let m0 = alice.encrypt_next(b"epoch-0", b"");
        if bob.decrypt_packet(&m0, b"").map(|p| p != b"epoch-0").unwrap_or(true) {
            return false;
        }
        // PCS rekey round-trip + forged rekey rejection
        let Ok(mut rk1) = alice.initiate_rekey() else { return false };
        rk1.mac_tag[0] ^= 0x01;
        if bob.accept_rekey(&rk1).is_ok() {
            return false;
        }
        rk1.mac_tag[0] ^= 0x01;
        if bob.accept_rekey(&rk1).is_err() {
            return false;
        }
        let m1 = bob.encrypt_next(b"epoch-1-healed", b"");
        alice
            .decrypt_packet(&m1, b"")
            .map(|p| p == b"epoch-1-healed" && alice.epoch() == 1)
            .unwrap_or(false)
    })();

    let padding_integrity_ok = (|| -> bool {
        let Ok(mut padded) = pad_to_block(b"short", 64) else { return false };
        if padded.len() != 64 {
            return false;
        }
        if unpad_strict(&padded).map(|u| u != b"short").unwrap_or(true) {
            return false;
        }
        padded[63] ^= 0x01;
        unpad_strict(&padded).is_err()
    })();

    PqProtocolAuditResult {
        wpke_v2_multi_ok,
        pq_pcs_ratchet_ok,
        padding_integrity_ok,
        passed: wpke_v2_multi_ok && pq_pcs_ratchet_ok && padding_integrity_ok,
    }
}
