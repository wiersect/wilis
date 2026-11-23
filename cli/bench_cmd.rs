//! CLI self-test and benchmark command (`wilis bench`).

use std::time::Instant;

use crate::aead::{open, seal};
use crate::core::constants::{ROUNDS_FULL, STATE_WORDS};
use crate::core::permute::{permute, permute_inverse};
use crate::core::state::State;
use crate::error::Result;

/// Runs a live diagnostic checking bijectivity, avalanche diffusion, and AEAD throughput.
pub fn run_bench() -> Result<()> {
    println!("=== Wilis Self-Test & Benchmark ===");

    // 1. Bijectivity check
    let original = State::from_words([
        0x0123_4567_89AB_CDEF,
        0xFEDC_BA98_7654_3210,
        0x1122_3344_5566_7788,
        0x99AA_BBCC_DDEE_FF00,
        0xCAFE_BABE_DEAD_BEEF,
        0x0F0E_0D0C_0B0A_0908,
    ]);
    let mut s = original.clone();
    permute(&mut s, ROUNDS_FULL);
    permute_inverse(&mut s, ROUNDS_FULL);
    println!(
        "[1/3] Bijectivity P^-1(P(x)) == x : {}",
        if s == original { "PASS" } else { "FAIL" }
    );

    // 2. Strict Avalanche Criterion (flip every single bit across the 384-bit state)
    let mut base_out = original.clone();
    permute(&mut base_out, ROUNDS_FULL);

    let mut total_flipped: u64 = 0;
    let mut min_flipped: u32 = 384;
    let mut max_flipped: u32 = 0;

    for bit in 0..384usize {
        let mut flipped = original.clone();
        flipped.words[bit / 64] ^= 1u64 << (bit % 64);
        permute(&mut flipped, ROUNDS_FULL);

        let mut dist: u32 = 0;
        for i in 0..STATE_WORDS {
            dist += (base_out.words[i] ^ flipped.words[i]).count_ones();
        }
        total_flipped += dist as u64;
        min_flipped = min_flipped.min(dist);
        max_flipped = max_flipped.max(dist);
    }

    let avg_bits = total_flipped as f64 / 384.0;
    let avg_pct = (avg_bits / 384.0) * 100.0;
    println!(
        "[2/3] Avalanche (384 1-bit flips) : avg {:.2}/384 bits ({:.2}%), range [{}..{}]",
        avg_bits, avg_pct, min_flipped, max_flipped
    );

    // 3. AEAD Throughput benchmark (8 MiB payload)
    let key = [0x5Au8; 32];
    let nonce = [0xA5u8; 24];
    let payload = vec![0x42u8; 8 * 1024 * 1024];

    let t0 = Instant::now();
    let (ct, tag) = seal(&key, &nonce, b"bench-aad", &payload);
    let enc_secs = t0.elapsed().as_secs_f64();

    let t1 = Instant::now();
    let pt = open(&key, &nonce, b"bench-aad", &ct, &tag)?;
    let dec_secs = t1.elapsed().as_secs_f64();

    assert_eq!(pt.len(), payload.len());
    let mib = payload.len() as f64 / (1024.0 * 1024.0);
    println!(
        "[3/3] WilisAEAD Throughput      : seal {:.2} MiB/s | open {:.2} MiB/s",
        mib / enc_secs,
        mib / dec_secs
    );

    Ok(())
}
