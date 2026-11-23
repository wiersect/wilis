//! Unified cryptanalysis audit runner and formatted scorecard reporter.

use crate::audit::avalanche::{analyze_avalanche_by_round, analyze_bic, BicResult, RoundAvalanche};
use crate::audit::randomness::{analyze_keystream_randomness, RandomnessMetrics};
use crate::audit::sbox_analysis::{analyze_chi5_sbox, SboxMetrics};

/// Complete scientific cryptanalysis summary for `Wilis`.
#[derive(Debug, Clone)]
pub struct AuditSummary {
    pub round_avalanche: Vec<RoundAvalanche>,
    pub first_full_diffusion_round: Option<usize>,
    pub bic: BicResult,
    pub sbox: SboxMetrics,
    pub randomness: RandomnessMetrics,
    pub overall_pass: bool,
}

/// Runs the complete cryptanalysis and statistical audit battery.
pub fn run_full_audit() -> AuditSummary {
    let round_avalanche = analyze_avalanche_by_round();
    let first_full_diffusion_round = round_avalanche
        .iter()
        .find(|r| r.full_diffusion)
        .map(|r| r.rounds);
    let bic = analyze_bic(512);
    let sbox = analyze_chi5_sbox();
    let randomness = analyze_keystream_randomness(131_072);

    let full_round_ok = round_avalanche
        .last()
        .map(|r| r.full_diffusion)
        .unwrap_or(false);
    let overall_pass = full_round_ok && bic.passed && sbox.passed && randomness.all_passed;

    AuditSummary {
        round_avalanche,
        first_full_diffusion_round,
        bic,
        sbox,
        randomness,
        overall_pass,
    }
}

/// Formats an [`AuditSummary`] into a readable terminal report.
pub fn format_audit_report(summary: &AuditSummary) -> String {
    let mut out = String::new();
    out.push_str("=== Wilis Cryptanalysis & Security Audit Report ===\n\n");

    out.push_str("[1/4] Round-by-Round Strict Avalanche Criterion (384-bit state)\n");
    for r in &summary.round_avalanche {
        if r.rounds <= 4 || r.rounds == 8 || r.rounds == 12 || r.rounds == 16 {
            out.push_str(&format!(
                "  Round {:2}: avg {:6.2}/384 bits ({:5.2}%), range [{:3}..{:3}] {}\n",
                r.rounds,
                r.avg_bits_flipped,
                r.avg_percent,
                r.min_bits,
                r.max_bits,
                if r.full_diffusion { "[FULL DIFFUSION]" } else { "" }
            ));
        }
    }
    if let Some(first_r) = summary.first_full_diffusion_round {
        out.push_str(&format!(
            "  -> Full diffusion achieved at Round {first_r} (security margin: {} extra rounds in data phase, {} in full phase)\n\n",
            12usize.saturating_sub(first_r),
            16usize.saturating_sub(first_r)
        ));
    }

    out.push_str("[2/4] Bit Independence Criterion (BIC, 512 trials x 2016 bit pairs)\n");
    out.push_str(&format!(
        "  Max |corr| : {:.4} | Avg |corr| : {:.4} -> {}\n\n",
        summary.bic.max_abs_correlation,
        summary.bic.avg_abs_correlation,
        if summary.bic.passed { "PASS" } else { "FAIL" }
    ));

    out.push_str("[3/4] Bitsliced Chi-5 S-Box Cryptanalysis (Exact DDT & LAT)\n");
    out.push_str(&format!(
        "  Bijective  : {} | Diff Uniformity : {} | Max Linear Bias : {} | Nonlinearity : {} -> {}\n",
        summary.sbox.is_bijective,
        summary.sbox.differential_uniformity,
        summary.sbox.max_linear_bias,
        summary.sbox.nonlinearity,
        if summary.sbox.passed { "PASS" } else { "FAIL" }
    ));
    out.push_str("  Note: Paired every round with 64-bit modular ARX carry chains (degree up to 63).\n\n");

    let rnd = &summary.randomness;
    out.push_str(&format!(
        "[4/4] Keystream Statistical Randomness Battery ({} bytes)\n",
        rnd.sample_bytes
    ));
    out.push_str(&format!(
        "  Monobit Ones Ratio : {:.5} (ideal 0.50000) -> {}\n",
        rnd.ones_ratio,
        if rnd.monobit_pass { "PASS" } else { "FAIL" }
    ));
    out.push_str(&format!(
        "  Runs Z-Score       : {:.4}  (< 3.29)       -> {}\n",
        rnd.runs_z_score,
        if rnd.runs_pass { "PASS" } else { "FAIL" }
    ));
    out.push_str(&format!(
        "  Shannon Entropy    : {:.5} bits/byte      -> {}\n",
        rnd.shannon_entropy_bits_per_byte,
        if rnd.entropy_pass { "PASS" } else { "FAIL" }
    ));
    out.push_str(&format!(
        "  Chi-Squared (255df): {:.2}  ([170..350])   -> {}\n",
        rnd.chi_squared,
        if rnd.chi_squared_pass { "PASS" } else { "FAIL" }
    ));
    out.push_str(&format!(
        "  Autocorr (lags1-16): {:.5} (< 0.025)      -> {}\n\n",
        rnd.max_autocorr_lag1_16,
        if rnd.autocorr_pass { "PASS" } else { "FAIL" }
    ));

    out.push_str(&format!(
        "OVERALL CRYPTOGRAPHIC AUDIT: {}\n",
        if summary.overall_pass { "ALL CHECKS PASSED" } else { "ATTENTION REQUIRED" }
    ));
    out
}
