//! Empirical constant-time timing verification (Welch's t-test, `dudect`-style)
//! and `v0.6.0` cryptographic engine self-verification (NTT, SIMD 4x, SIV, Stateless SLH).

use std::hint::black_box;
use std::time::Instant;

use crate::aead::{siv_open, siv_seal};
use crate::core::constants::{ROUNDS_FULL, STATE_WORDS};
use crate::core::permute::permute;
use crate::core::simd::{active_simd_backend, permute_4x};
use crate::core::state::State;
use crate::kem::poly::Poly;
use crate::sign::SlhSecretKey;
use crate::utils::constant_time::ct_eq;

/// Result of Check [8/8]: Empirical timing verification & v0.6.0 engine audit.
#[derive(Debug, Clone)]
pub struct TimingAndEngineAuditResult {
    pub simd_backend: &'static str,
    pub welch_t_stat: f64,
    pub timing_ok: bool,
    pub ntt_exact_ok: bool,
    pub simd_exact_ok: bool,
    pub siv_misuse_ok: bool,
    pub slh_stateless_ok: bool,
    pub passed: bool,
}

fn trimmed_welch_t(mut a: Vec<f64>, mut b: Vec<f64>) -> f64 {
    a.sort_by(|x, y| x.total_cmp(y));
    b.sort_by(|x, y| x.total_cmp(y));

    // Crop top/bottom 10% to remove OS scheduler preemption & frequency-scaling outliers
    let trim_a = a.len() / 10;
    let trim_b = b.len() / 10;
    let sa = &a[trim_a..a.len() - trim_a];
    let sb = &b[trim_b..b.len() - trim_b];

    let na = sa.len() as f64;
    let nb = sb.len() as f64;
    if na < 2.0 || nb < 2.0 {
        return 0.0;
    }

    let mean_a = sa.iter().sum::<f64>() / na;
    let mean_b = sb.iter().sum::<f64>() / nb;

    let var_a = sa.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (na - 1.0);
    let var_b = sb.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (nb - 1.0);

    let denom = (var_a / na + var_b / nb).sqrt();
    if denom <= 1e-12 {
        0.0
    } else {
        (mean_a - mean_b) / denom
    }
}

#[inline(never)]
fn time_ct_eq_batch(a: &[u8; 32], b: &[u8; 32], iters: usize) -> f64 {
    let t0 = Instant::now();
    let mut acc = false;
    for _ in 0..iters {
        acc ^= ct_eq(black_box(a), black_box(b));
    }
    black_box(acc);
    t0.elapsed().as_nanos() as f64
}

fn measure_ct_eq_welch_t() -> f64 {
    let base = [0xA5u8; 32];
    // Use a SINGLE stack buffer address mutated in-place and a SINGLE #[inline(never)]
    // timing function so both classes share identical cache-line alignment and code address.
    let mut probe = [0xA5u8; 32];

    const SAMPLES: usize = 300;
    const INNER_ITERS: usize = 512;

    // Warmup caches & CPU frequency governor
    for _ in 0..32 {
        probe[0] = 0xA5;
        let _ = time_ct_eq_batch(&base, &probe, 64);
        probe[0] = 0x5A;
        let _ = time_ct_eq_batch(&base, &probe, 64);
    }

    let mut class_a = Vec::with_capacity(SAMPLES);
    let mut class_b = Vec::with_capacity(SAMPLES);

    for i in 0..SAMPLES {
        // Interleave class order to cancel monotonic thermal/frequency drift
        if (i & 1) == 0 {
            probe[0] = 0xA5;
            class_a.push(time_ct_eq_batch(&base, &probe, INNER_ITERS));
            probe[0] = 0x5A;
            class_b.push(time_ct_eq_batch(&base, &probe, INNER_ITERS));
        } else {
            probe[0] = 0x5A;
            class_b.push(time_ct_eq_batch(&base, &probe, INNER_ITERS));
            probe[0] = 0xA5;
            class_a.push(time_ct_eq_batch(&base, &probe, INNER_ITERS));
        }
    }

    trimmed_welch_t(class_a, class_b)
}

fn check_ntt_exact() -> bool {
    let mut a = Poly::zero();
    let mut b = Poly::zero();
    for i in 0..256 {
        a.coeffs[i] = ((i * 137 + 41) % 7681) as u16;
        b.coeffs[i] = ((i * 251 + 19) % 7681) as u16;
    }
    let ntt_prod = a.mul(&b);
    let sb_prod = a.mul_schoolbook(&b);
    ntt_prod == sb_prod
}

fn check_simd_exact() -> bool {
    let mut states = [
        State::from_words([1, 2, 3, 4, 5, 6]),
        State::from_words([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        State::from_words([0xDEAD, 0xBEEF, 0xCAFE, 0xBABE, 0x1234, 0x5678]),
        State::from_words([u64::MAX, 0, 0xAAAA_5555, 0x5555_AAAA, 42, 99]),
    ];
    let mut expected = states.clone();
    permute_4x(&mut states, ROUNDS_FULL);
    for s in &mut expected {
        permute(s, ROUNDS_FULL);
    }
    for lane in 0..4 {
        for w in 0..STATE_WORDS {
            if states[lane].words[w] != expected[lane].words[w] {
                return false;
            }
        }
    }
    true
}

fn check_siv_misuse() -> bool {
    let key = [0x3Cu8; 32];
    let reused_nonce = [0x7Au8; 24];
    let aad = b"audit-siv-aad";
    let pt1 = b"nonce-misuse-resistant-message-alpha";
    let pt2 = b"nonce-misuse-resistant-message-beta!";
    let (ct1, tag1) = siv_seal(&key, &reused_nonce, aad, pt1);
    let (ct2, tag2) = siv_seal(&key, &reused_nonce, aad, pt2);
    let (ct1_dup, tag1_dup) = siv_seal(&key, &reused_nonce, aad, pt1);

    let det_ok = ct1 == ct1_dup && tag1 == tag1_dup && tag1 != tag2 && ct1 != ct2;
    let open_ok = siv_open(&key, &reused_nonce, aad, &ct1, &tag1)
        .map(|p| p == pt1)
        .unwrap_or(false);
    let mut bad_ct = ct1.clone();
    bad_ct[0] ^= 0x01;
    let tamper_rejected = siv_open(&key, &reused_nonce, aad, &bad_ct, &tag1).is_err();
    det_ok && open_ok && tamper_rejected
}

fn check_slh_stateless() -> bool {
    let Ok((sk, pk)) = SlhSecretKey::generate() else {
        return false;
    };
    let Ok(sig1) = sk.sign(b"wilis-slh-audit-msg-1") else {
        return false;
    };
    let Ok(sig2) = sk.sign(b"wilis-slh-audit-msg-2") else {
        return false;
    };
    pk.verify(b"wilis-slh-audit-msg-1", &sig1)
        && pk.verify(b"wilis-slh-audit-msg-2", &sig2)
        && !pk.verify(b"wilis-slh-audit-msg-1", &sig2)
}

/// Runs Check [8/8]: `dudect`-style Welch's t-test on `ct_eq` plus exact engine verification
/// for NTT (`q = 7681`), 4-way SIMD permutation, `WilisAEAD-SIV`, and stateless `WilisSLH`.
pub fn analyze_timing_and_engine() -> TimingAndEngineAuditResult {
    let welch_t_stat = measure_ct_eq_welch_t();
    // Generous threshold (|t| < 12.0) prevents false positives on noisy shared CI hypervisors
    // while catching gross non-constant-time branching leaks.
    let timing_ok = welch_t_stat.is_finite() && welch_t_stat.abs() < 12.0;
    let ntt_exact_ok = check_ntt_exact();
    let simd_exact_ok = check_simd_exact();
    let siv_misuse_ok = check_siv_misuse();
    let slh_stateless_ok = check_slh_stateless();
    let passed = timing_ok && ntt_exact_ok && simd_exact_ok && siv_misuse_ok && slh_stateless_ok;

    TimingAndEngineAuditResult {
        simd_backend: active_simd_backend(),
        welch_t_stat,
        timing_ok,
        ntt_exact_ok,
        simd_exact_ok,
        siv_misuse_ok,
        slh_stateless_ok,
        passed,
    }
}
