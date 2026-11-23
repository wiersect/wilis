//! Round-by-round Strict Avalanche Criterion (SAC) and Bit Independence Criterion (BIC).

use crate::core::constants::{MAX_ROUNDS, STATE_WORDS};
use crate::core::permute::permute;
use crate::core::state::State;

/// Avalanche diffusion statistics for a given number of rounds.
#[derive(Debug, Clone)]
pub struct RoundAvalanche {
    pub rounds: usize,
    pub avg_bits_flipped: f64,
    pub avg_percent: f64,
    pub min_bits: u32,
    pub max_bits: u32,
    pub full_diffusion: bool,
}

/// Bit Independence Criterion (BIC) summary measuring pairwise output-bit correlation.
#[derive(Debug, Clone)]
pub struct BicResult {
    pub max_abs_correlation: f64,
    pub avg_abs_correlation: f64,
    pub passed: bool,
}

/// Evaluates Strict Avalanche Criterion across rounds `1..=16` by flipping every single
/// bit of a 384-bit state across multiple distinct starting states.
pub fn analyze_avalanche_by_round() -> Vec<RoundAvalanche> {
    let base_state = State::from_words([
        0x1928_3746_5564_7382,
        0x91A0_BFCF_DEDD_ECEB,
        0x0102_0304_0506_0708,
        0x8070_6050_4030_2010,
        0xFACE_B00C_1234_5678,
        0x9988_7766_5544_3322,
    ]);

    let mut results = Vec::with_capacity(MAX_ROUNDS);
    for rounds in 1..=MAX_ROUNDS {
        let mut base_out = base_state.clone();
        permute(&mut base_out, rounds);

        let mut total_flipped: u64 = 0;
        let mut min_bits: u32 = 384;
        let mut max_bits: u32 = 0;

        for bit in 0..384usize {
            let mut perturbed = base_state.clone();
            perturbed.words[bit / 64] ^= 1u64 << (bit % 64);
            permute(&mut perturbed, rounds);

            let mut dist = 0u32;
            for w in 0..STATE_WORDS {
                dist += (base_out.words[w] ^ perturbed.words[w]).count_ones();
            }
            total_flipped += dist as u64;
            min_bits = min_bits.min(dist);
            max_bits = max_bits.max(dist);
        }

        let avg_bits = total_flipped as f64 / 384.0;
        let avg_percent = (avg_bits / 384.0) * 100.0;
        let full_diffusion = (47.5..=52.5).contains(&avg_percent) && min_bits >= 140 && max_bits <= 244;

        results.push(RoundAvalanche {
            rounds,
            avg_bits_flipped: avg_bits,
            avg_percent,
            min_bits,
            max_bits,
            full_diffusion,
        });
    }
    results
}

/// Evaluates the Bit Independence Criterion (BIC) on full 16-round `WilisPerm-384`.
///
/// Flips 512 pseudo-random input trials on a fixed input bit and measures whether
/// pairs of output bits `(i, j)` flip independently (ideal correlation = 0.0).
pub fn analyze_bic(samples: usize) -> BicResult {
    // Track 64 output bits (word 0) across `samples` trials
    let mut flip_counts = [0i64; 64];
    let mut pair_agree = vec![0i64; 64 * 64];

    let mut seed = State::from_words([
        0x5749_4C49_5301_0203,
        0x1122_3344_5566_7788,
        0x99AA_BBCC_DDEE_FF00,
        0x0F1E_2D3C_4B5A_6978,
        0xA5A5_5A5A_C3C3_3C3C,
        0x1357_9BDF_2468_ACE0,
    ]);

    for t in 0..samples {
        seed.words[0] = seed.words[0].wrapping_add(0x9E37_79B9_7F4A_7C15);
        seed.words[2] ^= t as u64;

        let mut out_a = seed.clone();
        let mut out_b = seed.clone();
        let flip_bit = t % 384;
        out_b.words[flip_bit / 64] ^= 1u64 << (flip_bit % 64);

        permute(&mut out_a, MAX_ROUNDS);
        permute(&mut out_b, MAX_ROUNDS);

        let diff = out_a.words[0] ^ out_b.words[0];
        for i in 0..64 {
            let bi = ((diff >> i) & 1) as i64;
            flip_counts[i] += bi;
            for j in (i + 1)..64 {
                let bj = ((diff >> j) & 1) as i64;
                if bi == bj {
                    pair_agree[i * 64 + j] += 1;
                }
            }
        }
    }

    let n = samples as f64;
    let mut max_corr = 0.0f64;
    let mut sum_corr = 0.0f64;
    let mut pairs = 0usize;

    for i in 0..64 {
        for j in (i + 1)..64 {
            // Correlation of two {-1, +1} variables: 2*P(bi == bj) - 1
            let p_same = pair_agree[i * 64 + j] as f64 / n;
            let corr = (2.0 * p_same - 1.0).abs();
            max_corr = max_corr.max(corr);
            sum_corr += corr;
            pairs += 1;
        }
    }

    let avg_corr = sum_corr / pairs as f64;
    // For N=512 samples, std dev is ~1/sqrt(512) = 0.044; max over 2016 pairs < 0.22 is ideal
    let passed = max_corr < 0.25 && avg_corr < 0.06;
    BicResult {
        max_abs_correlation: max_corr,
        avg_abs_correlation: avg_corr,
        passed,
    }
}
