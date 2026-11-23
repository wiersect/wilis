//! Invertible ARX (Add-Rotate-XOR) cross-word mixing functions.
//!
//! Modular 64-bit addition propagates carries across bit positions, creating
//! high-degree arithmetic nonlinearity without any lookup tables.

use crate::core::constants::{ARX_PRIMARY_ROTS, ARX_STAGGERED_ROTS, STATE_WORDS};

/// Bijective 2-word ARX mixing gadget.
#[inline(always)]
pub fn mix_pair(a: &mut u64, b: &mut u64, r1: u32, r2: u32) {
    *a = a.wrapping_add(*b);
    *b = b.rotate_left(r1) ^ *a;
    *a = a.wrapping_add(*b);
    *b = b.rotate_left(r2) ^ *a;
}

/// Exact mathematical inverse of [`mix_pair`].
#[inline(always)]
pub fn unmix_pair(a: &mut u64, b: &mut u64, r1: u32, r2: u32) {
    *b = (*b ^ *a).rotate_right(r2);
    *a = a.wrapping_sub(*b);
    *b = (*b ^ *a).rotate_right(r1);
    *a = a.wrapping_sub(*b);
}

/// Primary ARX layer mixing disjoint adjacent word pairs: `(0,1)`, `(2,3)`, `(4,5)`.
#[inline]
pub fn apply_primary_arx(w: &mut [u64; STATE_WORDS]) {
    let (mut a, mut b) = (w[0], w[1]);
    mix_pair(&mut a, &mut b, ARX_PRIMARY_ROTS[0].0, ARX_PRIMARY_ROTS[0].1);
    w[0] = a;
    w[1] = b;

    let (mut c, mut d) = (w[2], w[3]);
    mix_pair(&mut c, &mut d, ARX_PRIMARY_ROTS[1].0, ARX_PRIMARY_ROTS[1].1);
    w[2] = c;
    w[3] = d;

    let (mut e, mut f) = (w[4], w[5]);
    mix_pair(&mut e, &mut f, ARX_PRIMARY_ROTS[2].0, ARX_PRIMARY_ROTS[2].1);
    w[4] = e;
    w[5] = f;
}

/// Exact inverse of [`apply_primary_arx`].
#[inline]
pub fn inverse_primary_arx(w: &mut [u64; STATE_WORDS]) {
    let (mut a, mut b) = (w[0], w[1]);
    unmix_pair(&mut a, &mut b, ARX_PRIMARY_ROTS[0].0, ARX_PRIMARY_ROTS[0].1);
    w[0] = a;
    w[1] = b;

    let (mut c, mut d) = (w[2], w[3]);
    unmix_pair(&mut c, &mut d, ARX_PRIMARY_ROTS[1].0, ARX_PRIMARY_ROTS[1].1);
    w[2] = c;
    w[3] = d;

    let (mut e, mut f) = (w[4], w[5]);
    unmix_pair(&mut e, &mut f, ARX_PRIMARY_ROTS[2].0, ARX_PRIMARY_ROTS[2].1);
    w[4] = e;
    w[5] = f;
}

/// Staggered ARX layer coupling pairs across primary boundaries: `(1,2)`, `(3,4)`, `(5,0)`.
#[inline]
pub fn apply_staggered_arx(w: &mut [u64; STATE_WORDS]) {
    let (mut a, mut b) = (w[1], w[2]);
    mix_pair(&mut a, &mut b, ARX_STAGGERED_ROTS[0].0, ARX_STAGGERED_ROTS[0].1);
    w[1] = a;
    w[2] = b;

    let (mut c, mut d) = (w[3], w[4]);
    mix_pair(&mut c, &mut d, ARX_STAGGERED_ROTS[1].0, ARX_STAGGERED_ROTS[1].1);
    w[3] = c;
    w[4] = d;

    let (mut e, mut f) = (w[5], w[0]);
    mix_pair(&mut e, &mut f, ARX_STAGGERED_ROTS[2].0, ARX_STAGGERED_ROTS[2].1);
    w[5] = e;
    w[0] = f;
}

/// Exact inverse of [`apply_staggered_arx`].
#[inline]
pub fn inverse_staggered_arx(w: &mut [u64; STATE_WORDS]) {
    let (mut a, mut b) = (w[1], w[2]);
    unmix_pair(&mut a, &mut b, ARX_STAGGERED_ROTS[0].0, ARX_STAGGERED_ROTS[0].1);
    w[1] = a;
    w[2] = b;

    let (mut c, mut d) = (w[3], w[4]);
    unmix_pair(&mut c, &mut d, ARX_STAGGERED_ROTS[1].0, ARX_STAGGERED_ROTS[1].1);
    w[3] = c;
    w[4] = d;

    let (mut e, mut f) = (w[5], w[0]);
    unmix_pair(&mut e, &mut f, ARX_STAGGERED_ROTS[2].0, ARX_STAGGERED_ROTS[2].1);
    w[5] = e;
    w[0] = f;
}
