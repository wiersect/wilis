//! Related-key sensitivity test for `WilisAEAD` and live IND-CCA2 self-audit for `WilisKEM`.

use crate::aead::seal;
use crate::kem::{decapsulate, encapsulate, keygen};

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
