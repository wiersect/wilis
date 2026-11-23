//! Cryptographic property tests for `WilisPerm-384`:
//! - Exhaustive 5-bit Chi bijection verification
//! - Full 384-bit permutation bijectivity (`P^-1(P(x)) == x`)
//! - Strict Avalanche Criterion (~50% bit flip per 1-bit input change)
//! - Keystream byte frequency uniformity (chi-squared test)

use wilis::core::constants::{ROUNDS_DATA, ROUNDS_FULL, STATE_WORDS};
use wilis::core::permute::{permute, permute_inverse};
use wilis::core::sbox::{apply_sbox, inverse_sbox};
use wilis::core::state::State;

#[test]
fn sbox_is_strictly_bijective_on_all_64_slices() {
    // Exhaustively check all 64 possible 6-bit slice inputs (2^6 = 64)
    let mut outputs = Vec::with_capacity(64);
    for input in 0u64..64 {
        let mut w = [
            (input >> 0) & 1,
            (input >> 1) & 1,
            (input >> 2) & 1,
            (input >> 3) & 1,
            (input >> 4) & 1,
            (input >> 5) & 1,
        ];
        // Note: Feistel-6 rotates w[3] by 7 bits, so test full 64-bit word round-trip
        let orig = w;
        apply_sbox(&mut w);
        let packed = (w[0] & 1)
            | ((w[1] & 1) << 1)
            | ((w[2] & 1) << 2)
            | ((w[3] & 1) << 3)
            | ((w[4] & 1) << 4)
            | ((w[5] & 1) << 5);
        outputs.push(packed);

        inverse_sbox(&mut w);
        assert_eq!(w, orig, "sbox inverse failed for input {input}");
    }

    // Verify all 32 values of Chi-5 (ignoring rotated w[3] on bit 7) produce unique outputs
    outputs.sort_unstable();
    outputs.dedup();
    assert_eq!(outputs.len(), 64, "6-bit slice projection must be bijective");
}

#[test]
fn permutation_is_strictly_bijective_full_and_data_rounds() {
    let samples = [
        [0u64; STATE_WORDS],
        [u64::MAX; STATE_WORDS],
        [
            0x0123_4567_89AB_CDEF,
            0xFEDC_BA98_7654_3210,
            0x0F0F_0F0F_0F0F_0F0F,
            0xAAAA_5555_AAAA_5555,
            0xDEAD_BEEF_CAFE_BABE,
            0x1357_9BDF_2468_ACE0,
        ],
        [1, 2, 3, 4, 5, 6],
    ];

    for &rounds in &[1usize, 4, ROUNDS_DATA, ROUNDS_FULL] {
        for &words in &samples {
            let orig = State::from_words(words);
            let mut s = orig.clone();
            permute(&mut s, rounds);
            assert_ne!(s, orig, "permutation must not be identity for {rounds} rounds");
            permute_inverse(&mut s, rounds);
            assert_eq!(
                s, orig,
                "exact inverse failed for rounds={rounds}, words={words:?}"
            );
        }
    }
}

#[test]
fn strict_avalanche_criterion_384_bits() {
    let base_in = State::from_words([
        0x1928_3746_5564_7382,
        0x91A0_BFCF_DEDD_ECEB,
        0x0102_0304_0506_0708,
        0x8070_6050_4030_2010,
        0xFACE_B00C_1234_5678,
        0x9988_7766_5544_3322,
    ]);
    let mut base_out = base_in.clone();
    permute(&mut base_out, ROUNDS_FULL);

    let mut total_flipped: u64 = 0;
    for bit in 0..384usize {
        let mut perturbed = base_in.clone();
        perturbed.words[bit / 64] ^= 1u64 << (bit % 64);
        permute(&mut perturbed, ROUNDS_FULL);

        let mut flipped = 0u32;
        for w in 0..STATE_WORDS {
            flipped += (base_out.words[w] ^ perturbed.words[w]).count_ones();
        }
        // Individual 1-bit flip distance should stay well inside normal binomial bounds
        assert!(
            (140..=244).contains(&flipped),
            "bit {bit} produced poor avalanche distance: {flipped}/384"
        );
        total_flipped += flipped as u64;
    }

    let avg = total_flipped as f64 / 384.0;
    assert!(
        (185.0..=199.0).contains(&avg),
        "average avalanche {avg:.2}/384 deviates too far from ideal 192.0"
    );
}

#[test]
fn output_byte_distribution_passes_chi_squared_uniformity() {
    // Generate 65,536 bytes from WilisPerm-384 in sponge-squeeze mode
    let mut state = State::from_words([
        0x5749_4C49_5300_0001,
        0x1111_2222_3333_4444,
        0x5555_6666_7777_8888,
        0x9999_AAAA_BBBB_CCCC,
        0xDDDD_EEEE_FFFF_0000,
        0x0123_4567_89AB_CDEF,
    ]);
    let mut counts = [0u64; 256];
    let total_bytes = 65_536usize;

    for _ in 0..(total_bytes / 16) {
        permute(&mut state, ROUNDS_DATA);
        for &b in &state.rate_bytes() {
            counts[b as usize] += 1;
        }
    }

    let expected = total_bytes as f64 / 256.0;
    let chi_sq: f64 = counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            (diff * diff) / expected
        })
        .sum();

    // For df = 255, 99.9% confidence interval is roughly [175, 345]
    assert!(
        (170.0..=350.0).contains(&chi_sq),
        "chi-squared statistic {chi_sq:.2} indicates non-uniform byte distribution"
    );
}
