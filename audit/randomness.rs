//! NIST SP 800-22 inspired statistical randomness battery for `WilisAEAD` keystream.

use crate::aead::seal;

/// Results from the keystream statistical randomness battery.
#[derive(Debug, Clone)]
pub struct RandomnessMetrics {
    pub sample_bytes: usize,
    pub ones_ratio: f64,
    pub monobit_pass: bool,
    pub runs_z_score: f64,
    pub runs_pass: bool,
    pub shannon_entropy_bits_per_byte: f64,
    pub entropy_pass: bool,
    pub chi_squared: f64,
    pub chi_squared_pass: bool,
    pub max_autocorr_lag1_16: f64,
    pub autocorr_pass: bool,
    pub all_passed: bool,
}

/// Generates `sample_bytes` of raw `WilisAEAD` keystream (encrypting all-zero plaintext)
/// and runs 5 independent statistical randomness tests.
pub fn analyze_keystream_randomness(sample_bytes: usize) -> RandomnessMetrics {
    if sample_bytes < 256 {
        return RandomnessMetrics {
            sample_bytes,
            ones_ratio: 0.0,
            monobit_pass: false,
            runs_z_score: f64::INFINITY,
            runs_pass: false,
            shannon_entropy_bits_per_byte: 0.0,
            entropy_pass: false,
            chi_squared: f64::INFINITY,
            chi_squared_pass: false,
            max_autocorr_lag1_16: 1.0,
            autocorr_pass: false,
            all_passed: false,
        };
    }

    let key = [0x3Cu8; 32];
    let nonce = [0x91u8; 24];
    let zeros = vec![0u8; sample_bytes];
    let (stream, _tag) = seal(&key, &nonce, b"wilis-randomness-audit", &zeros);

    let total_bits = (stream.len() * 8) as f64;
    let mut ones: u64 = 0;
    let mut byte_counts = [0u64; 256];

    for &b in &stream {
        ones += b.count_ones() as u64;
        byte_counts[b as usize] += 1;
    }

    // 1. Frequency (Monobit) test: Z = |2*ones - N| / sqrt(N) < 3.29 (p > 0.001)
    let ones_ratio = ones as f64 / total_bits;
    let monobit_z = ((2.0 * ones as f64 - total_bits).abs()) / total_bits.sqrt();
    let monobit_pass = monobit_z < 3.29;

    // 2. Runs test (bit transitions across stream)
    let mut runs: u64 = 1;
    let mut prev_bit = stream[0] & 1;
    for &b in &stream {
        for bit_idx in 0..8 {
            let cur = (b >> bit_idx) & 1;
            if cur != prev_bit {
                runs += 1;
                prev_bit = cur;
            }
        }
    }
    let pi = ones_ratio;
    let expected_runs = 2.0 * total_bits * pi * (1.0 - pi);
    let runs_denom = 2.0 * (2.0 * total_bits).sqrt() * pi * (1.0 - pi);
    let runs_z = ((runs as f64 - expected_runs).abs()) / runs_denom;
    let runs_pass = runs_z < 3.29;

    // 3. Shannon Entropy (bits per byte; ideal = 8.0000)
    let n_bytes = stream.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &byte_counts {
        if c > 0 {
            let p = c as f64 / n_bytes;
            entropy -= p * p.log2();
        }
    }
    let entropy_pass = entropy > 7.995;

    // 4. Chi-Squared byte uniformity test (df = 255; 99.9% CI ~ [170, 350])
    let expected_byte = n_bytes / 256.0;
    let chi_sq: f64 = byte_counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected_byte;
            (d * d) / expected_byte
        })
        .sum();
    let chi_squared_pass = (170.0..=350.0).contains(&chi_sq);

    // 5. Bit-level Autocorrelation across lags 1..=16
    let mut max_autocorr = 0.0f64;
    let bit_at = |idx: usize| -> u8 { (stream[idx / 8] >> (idx % 8)) & 1 };
    let bit_limit = (stream.len() * 8).min(65_536);
    for lag in 1..=16usize {
        let mut agree: u64 = 0;
        let count = bit_limit - lag;
        for i in 0..count {
            if bit_at(i) == bit_at(i + lag) {
                agree += 1;
            }
        }
        let corr = (2.0 * (agree as f64 / count as f64) - 1.0).abs();
        max_autocorr = max_autocorr.max(corr);
    }
    let autocorr_pass = max_autocorr < 0.025;

    let all_passed =
        monobit_pass && runs_pass && entropy_pass && chi_squared_pass && autocorr_pass;

    RandomnessMetrics {
        sample_bytes: stream.len(),
        ones_ratio,
        monobit_pass,
        runs_z_score: runs_z,
        runs_pass,
        shannon_entropy_bits_per_byte: entropy,
        entropy_pass,
        chi_squared: chi_sq,
        chi_squared_pass,
        max_autocorr_lag1_16: max_autocorr,
        autocorr_pass,
        all_passed,
    }
}
