//! Bitsliced nonlinear substitution layer (Chi-5 + nonlinear Feistel-6).
//!
//! Operates strictly with constant-time bitwise boolean instructions across all
//! 64 bit-slices in parallel — completely immune to cache-timing side channels.

use crate::core::constants::STATE_WORDS;

/// Applies one pass of the bijective 5-word Chi transformation on `w[0..5]`.
///
/// Over `{0, 1}^5`, this transformation is strictly bijective and has algebraic
/// order 4 (`chi5^4(x) == x`).
#[inline(always)]
fn chi5_step(w: &mut [u64; STATE_WORDS]) {
    let (x0, x1, x2, x3, x4) = (w[0], w[1], w[2], w[3], w[4]);
    w[0] = x0 ^ (!x1 & x2);
    w[1] = x1 ^ (!x2 & x3);
    w[2] = x2 ^ (!x3 & x4);
    w[3] = x3 ^ (!x4 & x0);
    w[4] = x4 ^ (!x0 & x1);
}

/// Applies the full 6-word bitsliced nonlinear layer:
/// 1. Bijective 5-word Chi on `w[0..5]`.
/// 2. Bijective nonlinear Feistel injection into `w[5]` using the updated `w[0..5]`.
#[inline]
pub fn apply_sbox(w: &mut [u64; STATE_WORDS]) {
    chi5_step(w);
    w[5] ^= (w[0] & w[2]) ^ (w[1] & w[4]) ^ w[3].rotate_left(7);
}

/// Exact mathematical inverse of [`apply_sbox`].
#[inline]
pub fn inverse_sbox(w: &mut [u64; STATE_WORDS]) {
    // Undo the Feistel injection on w[5] first (w[0..5] are still in post-Chi state).
    w[5] ^= (w[0] & w[2]) ^ (w[1] & w[4]) ^ w[3].rotate_left(7);
    // Because 5-bit Chi has exact order 4, applying it 3 more times yields its inverse.
    chi5_step(w);
    chi5_step(w);
    chi5_step(w);
}
