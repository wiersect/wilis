//! Hardware SIMD multi-lane `WilisPerm-384` acceleration (`AVX2` 4-way on x86_64,
//! `NEON` 2-way on aarch64) with automatic runtime dispatch and bit-exact scalar fallback.
//!
//! Used by parallel multi-block primitives (`WilisTreeHash`, `WilisKDF` v3) while
//! remaining 100% zero-dependency (`core::arch` only) and bit-for-bit identical to [`permute`].

use crate::core::constants::{MAX_ROUNDS, ROUND_CONSTANTS};
use crate::core::permute::permute;
use crate::core::state::State;

/// Reports the active hardware SIMD backend for multi-lane `WilisPerm-384`.
pub fn active_simd_backend() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            return "x86_64 AVX2 (4-way 256-bit SIMD)";
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        return "aarch64 NEON (2-way 128-bit SIMD)";
    }
    #[allow(unreachable_code)]
    "Portable Scalar Fallback"
}

/// Executes `rounds` rounds of `WilisPerm-384` simultaneously across 4 independent states.
///
/// Guaranteed bit-for-bit identical to calling [`permute`] on each state individually.
pub fn permute_4x(states: &mut [State; 4], rounds: usize) {
    assert!(
        rounds > 0 && rounds <= MAX_ROUNDS,
        "rounds must be within 1..={MAX_ROUNDS}"
    );

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 availability verified at runtime via `is_x86_feature_detected!`.
            unsafe {
                permute_4x_avx2(states, rounds);
            }
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON is mandatory on all AArch64 targets.
        unsafe {
            let (left, right) = states.split_at_mut(2);
            permute_2x_neon(&mut left[0], &mut left[1], rounds);
            permute_2x_neon(&mut right[0], &mut right[1], rounds);
        }
        return;
    }

    #[allow(unreachable_code)]
    for s in states.iter_mut() {
        permute(s, rounds);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn permute_4x_avx2(states: &mut [State; 4], rounds: usize) {
    use core::arch::x86_64::*;

    #[inline(always)]
    unsafe fn rotl<const L: i32, const R: i32>(v: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_slli_epi64::<L>(v), _mm256_srli_epi64::<R>(v))
    }

    #[inline(always)]
    unsafe fn rotr<const R: i32, const L: i32>(v: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_srli_epi64::<R>(v), _mm256_slli_epi64::<L>(v))
    }

    #[inline(always)]
    unsafe fn mix_pair<const L1: i32, const R1: i32, const L2: i32, const R2: i32>(
        a: &mut __m256i,
        b: &mut __m256i,
    ) {
        *a = _mm256_add_epi64(*a, *b);
        *b = _mm256_xor_si256(rotl::<L1, R1>(*b), *a);
        *a = _mm256_add_epi64(*a, *b);
        *b = _mm256_xor_si256(rotl::<L2, R2>(*b), *a);
    }

    #[inline(always)]
    unsafe fn diffuse<const A: i32, const LA: i32, const B: i32, const LB: i32>(
        x: __m256i,
    ) -> __m256i {
        _mm256_xor_si256(_mm256_xor_si256(x, rotr::<A, LA>(x)), rotr::<B, LB>(x))
    }

    let load_word = |idx: usize| -> __m256i {
        _mm256_set_epi64x(
            states[3].words[idx] as i64,
            states[2].words[idx] as i64,
            states[1].words[idx] as i64,
            states[0].words[idx] as i64,
        )
    };

    let mut w0 = load_word(0);
    let mut w1 = load_word(1);
    let mut w2 = load_word(2);
    let mut w3 = load_word(3);
    let mut w4 = load_word(4);
    let mut w5 = load_word(5);

    let start_round = MAX_ROUNDS - rounds;
    for r in start_round..MAX_ROUNDS {
        // 1. Asymmetric round constant injection
        let rc0 = _mm256_set1_epi64x(ROUND_CONSTANTS[r * 2] as i64);
        let rc1 = _mm256_set1_epi64x(ROUND_CONSTANTS[r * 2 + 1] as i64);
        w0 = _mm256_xor_si256(w0, rc0);
        w3 = _mm256_add_epi64(w3, rc1);

        // 2. Primary ARX: (0,1):(13,37), (2,3):(19,43), (4,5):(29,53)
        mix_pair::<13, 51, 37, 27>(&mut w0, &mut w1);
        mix_pair::<19, 45, 43, 21>(&mut w2, &mut w3);
        mix_pair::<29, 35, 53, 11>(&mut w4, &mut w5);

        // 3. Bitsliced Chi-5 + Feistel-6
        let (x0, x1, x2, x3, x4) = (w0, w1, w2, w3, w4);
        w0 = _mm256_xor_si256(x0, _mm256_andnot_si256(x1, x2));
        w1 = _mm256_xor_si256(x1, _mm256_andnot_si256(x2, x3));
        w2 = _mm256_xor_si256(x2, _mm256_andnot_si256(x3, x4));
        w3 = _mm256_xor_si256(x3, _mm256_andnot_si256(x4, x0));
        w4 = _mm256_xor_si256(x4, _mm256_andnot_si256(x0, x1));
        let f = _mm256_xor_si256(
            _mm256_xor_si256(_mm256_and_si256(w0, w2), _mm256_and_si256(w1, w4)),
            rotl::<7, 57>(w3),
        );
        w5 = _mm256_xor_si256(w5, f);

        // 4. Staggered ARX: (1,2):(17,41), (3,4):(23,47), (5,0):(31,59)
        mix_pair::<17, 47, 41, 23>(&mut w1, &mut w2);
        mix_pair::<23, 41, 47, 17>(&mut w3, &mut w4);
        mix_pair::<31, 33, 59, 5>(&mut w5, &mut w0);

        // 5. Intra-word 3-tap diffusion + rotate_left(1)
        let d0 = diffuse::<7, 57, 29, 35>(w0);
        let d1 = diffuse::<11, 53, 41, 23>(w1);
        let d2 = diffuse::<17, 47, 53, 11>(w2);
        let d3 = diffuse::<23, 41, 37, 27>(w3);
        let d4 = diffuse::<13, 51, 47, 17>(w4);
        let d5 = diffuse::<19, 45, 59, 5>(w5);
        w0 = d1;
        w1 = d2;
        w2 = d3;
        w3 = d4;
        w4 = d5;
        w5 = d0;
    }

    let mut tmp = [0i64; 4];
    for (word_idx, reg) in [w0, w1, w2, w3, w4, w5].into_iter().enumerate() {
        _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, reg);
        for lane in 0..4 {
            states[lane].words[word_idx] = tmp[lane] as u64;
        }
    }
    for v in &mut tmp {
        core::ptr::write_volatile(v as *mut i64, 0);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(target_arch = "aarch64")]
unsafe fn permute_2x_neon(s0: &mut State, s1: &mut State, rounds: usize) {
    use core::arch::aarch64::*;

    #[inline(always)]
    unsafe fn rotl<const L: i32, const R: i32>(v: uint64x2_t) -> uint64x2_t {
        vorrq_u64(vshlq_n_u64::<L>(v), vshrq_n_u64::<R>(v))
    }

    #[inline(always)]
    unsafe fn rotr<const R: i32, const L: i32>(v: uint64x2_t) -> uint64x2_t {
        vorrq_u64(vshrq_n_u64::<R>(v), vshlq_n_u64::<L>(v))
    }

    #[inline(always)]
    unsafe fn mix_pair<const L1: i32, const R1: i32, const L2: i32, const R2: i32>(
        a: &mut uint64x2_t,
        b: &mut uint64x2_t,
    ) {
        *a = vaddq_u64(*a, *b);
        *b = veorq_u64(rotl::<L1, R1>(*b), *a);
        *a = vaddq_u64(*a, *b);
        *b = veorq_u64(rotl::<L2, R2>(*b), *a);
    }

    #[inline(always)]
    unsafe fn diffuse<const A: i32, const LA: i32, const B: i32, const LB: i32>(
        x: uint64x2_t,
    ) -> uint64x2_t {
        veorq_u64(veorq_u64(x, rotr::<A, LA>(x)), rotr::<B, LB>(x))
    }

    let load_word = |idx: usize| -> uint64x2_t {
        let pair = [s0.words[idx], s1.words[idx]];
        vld1q_u64(pair.as_ptr())
    };

    let mut w0 = load_word(0);
    let mut w1 = load_word(1);
    let mut w2 = load_word(2);
    let mut w3 = load_word(3);
    let mut w4 = load_word(4);
    let mut w5 = load_word(5);

    let start_round = MAX_ROUNDS - rounds;
    for r in start_round..MAX_ROUNDS {
        w0 = veorq_u64(w0, vdupq_n_u64(ROUND_CONSTANTS[r * 2]));
        w3 = vaddq_u64(w3, vdupq_n_u64(ROUND_CONSTANTS[r * 2 + 1]));

        mix_pair::<13, 51, 37, 27>(&mut w0, &mut w1);
        mix_pair::<19, 45, 43, 21>(&mut w2, &mut w3);
        mix_pair::<29, 35, 53, 11>(&mut w4, &mut w5);

        let (x0, x1, x2, x3, x4) = (w0, w1, w2, w3, w4);
        w0 = veorq_u64(x0, vbicq_u64(x2, x1));
        w1 = veorq_u64(x1, vbicq_u64(x3, x2));
        w2 = veorq_u64(x2, vbicq_u64(x4, x3));
        w3 = veorq_u64(x3, vbicq_u64(x0, x4));
        w4 = veorq_u64(x4, vbicq_u64(x1, x0));
        let f = veorq_u64(
            veorq_u64(vandq_u64(w0, w2), vandq_u64(w1, w4)),
            rotl::<7, 57>(w3),
        );
        w5 = veorq_u64(w5, f);

        mix_pair::<17, 47, 41, 23>(&mut w1, &mut w2);
        mix_pair::<23, 41, 47, 17>(&mut w3, &mut w4);
        mix_pair::<31, 33, 59, 5>(&mut w5, &mut w0);

        let d0 = diffuse::<7, 57, 29, 35>(w0);
        let d1 = diffuse::<11, 53, 41, 23>(w1);
        let d2 = diffuse::<17, 47, 53, 11>(w2);
        let d3 = diffuse::<23, 41, 37, 27>(w3);
        let d4 = diffuse::<13, 51, 47, 17>(w4);
        let d5 = diffuse::<19, 45, 59, 5>(w5);
        w0 = d1;
        w1 = d2;
        w2 = d3;
        w3 = d4;
        w4 = d5;
        w5 = d0;
    }

    let mut tmp = [0u64; 2];
    for (word_idx, reg) in [w0, w1, w2, w3, w4, w5].into_iter().enumerate() {
        vst1q_u64(tmp.as_mut_ptr(), reg);
        s0.words[word_idx] = tmp[0];
        s1.words[word_idx] = tmp[1];
    }
    for v in &mut tmp {
        core::ptr::write_volatile(v as *mut u64, 0);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
