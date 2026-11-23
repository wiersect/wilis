//! Intra-word 3-tap linear diffusion and word-lane rotation.
//!
//! Each 64-bit word is transformed by `x ^ rotr(x, a) ^ rotr(x, b)`.
//! Over `GF(2)[t] / (t^64 + 1)`, every odd-weight polynomial satisfies
//! `f(t)^64 == 1`, guaranteeing strict invertibility with zero entropy loss.

use crate::core::constants::{DIFFUSION_TAPS, STATE_WORDS};

/// Applies one 3-tap rotation diffusion step to a 64-bit word.
#[inline(always)]
pub fn diffuse_word(x: u64, a: u32, b: u32) -> u64 {
    x ^ x.rotate_right(a) ^ x.rotate_right(b)
}

/// Exact inverse of [`diffuse_word`] using `f^64(x) == x` => `f^-1(y) == f^63(y)`.
#[inline]
pub fn inverse_diffuse_word(mut y: u64, a: u32, b: u32) -> u64 {
    for _ in 0..63 {
        y = diffuse_word(y, a, b);
    }
    y
}

/// Applies per-word 3-tap linear diffusion followed by a cyclic word rotation.
#[inline]
pub fn apply_diffusion(w: &mut [u64; STATE_WORDS]) {
    for (i, &(a, b)) in DIFFUSION_TAPS.iter().enumerate() {
        w[i] = diffuse_word(w[i], a, b);
    }
    w.rotate_left(1);
}

/// Exact mathematical inverse of [`apply_diffusion`].
#[inline]
pub fn inverse_diffusion(w: &mut [u64; STATE_WORDS]) {
    w.rotate_right(1);
    for (i, &(a, b)) in DIFFUSION_TAPS.iter().enumerate() {
        w[i] = inverse_diffuse_word(w[i], a, b);
    }
}
