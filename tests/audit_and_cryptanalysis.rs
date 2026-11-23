//! Scientific cryptanalysis audit & key-commitment security tests for `Wilis`.

use wilis::aead::{open, seal};
use wilis::audit::run_full_audit;
use wilis::error::WilisError;

#[test]
fn full_cryptanalysis_audit_passes_all_checks() {
    let summary = run_full_audit();

    assert!(
        summary.first_full_diffusion_round.unwrap_or(99) <= 4,
        "expected full 384-bit diffusion by round 4, got {:?}",
        summary.first_full_diffusion_round
    );
    assert!(summary.bic.passed, "BIC failed: {:?}", summary.bic);
    assert!(summary.sbox.passed, "S-Box DDT/LAT failed: {:?}", summary.sbox);
    assert!(
        summary.randomness.all_passed,
        "Randomness battery failed: {:?}",
        summary.randomness
    );
    assert!(summary.overall_pass, "Overall cryptographic audit failed");
}

#[test]
fn aead_enforces_key_commitment_across_distinct_keys() {
    let key_a = [0x11u8; 32];
    let mut key_b = [0x11u8; 32];
    key_b[31] ^= 0x01;
    let nonce = [0x22u8; 24];
    let msg = b"Key-commitment protected payload";

    let (ct, tag) = seal(&key_a, &nonce, b"aad", msg);

    // Distinct key must fail tag verification immediately
    assert!(matches!(
        open(&key_b, &nonce, b"aad", &ct, &tag),
        Err(WilisError::AuthenticationFailed)
    ));
}
