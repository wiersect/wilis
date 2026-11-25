//! Constant-time Number-Theoretic Transform (`NTT` / `INTT`) over `R_q = Z_7681[X] / (X^256 + 1)`.
//!
//! Because `q = 7681 = 15 * 512 + 1`, `psi = 62` is a primitive 512-th root of unity mod `q`
//! (`psi^256 = -1 mod q`, `omega = psi^2 = 3844`, `psi^-1 = 1115`, `N^-1 = 7651`).
//! All reductions are strictly division-free and branchless using Barrett reduction
//! so polynomial multiplication runs in `O(N log N)` time with zero timing side channels
//! and bit-for-bit exact mathematical equivalence to schoolbook multiplication.

use crate::kem::poly::{KEM_N, KEM_Q};

const Q32: u32 = KEM_Q as u32;
const PSI: u16 = 62;
const PSI_INV: u16 = 1115;
const OMEGA: u16 = 3844;
const OMEGA_INV: u16 = 6584;
const N_INV: u16 = 7651;

/// Barrett multiplier `floor(2^32 / 7681) = 559_167` for exact reduction of `x < 2^26`.
const BARRETT_M32: u64 = (1u64 << 32) / (KEM_Q as u64);

/// Branchless, division-free reduction modulo `q = 7681` for any `x <= 60_000_000`.
#[inline(always)]
fn barrett_reduce(x: u32) -> u16 {
    let k = ((x as u64 * BARRETT_M32) >> 32) as u32;
    let r = x - k * Q32; // Guaranteed 0 <= r < 2 * Q32
    let diff = r.wrapping_sub(Q32);
    let borrow = core::hint::black_box(0u32.wrapping_sub(diff >> 31));
    ((r & borrow) | (diff & !borrow)) as u16
}

#[inline(always)]
fn add_mod(a: u16, b: u16) -> u16 {
    let s = a as u32 + b as u32;
    let diff = s.wrapping_sub(Q32);
    let borrow = core::hint::black_box(0u32.wrapping_sub(diff >> 31));
    ((s & borrow) | (diff & !borrow)) as u16
}

#[inline(always)]
fn sub_mod(a: u16, b: u16) -> u16 {
    let d = a as i32 - b as i32;
    let mask = core::hint::black_box((d >> 31) as u32);
    ((d as u32).wrapping_add(Q32 & mask)) as u16
}

#[inline(always)]
fn mul_mod(a: u16, b: u16) -> u16 {
    barrett_reduce((a as u32) * (b as u32))
}

const fn pow_mod_const(mut base: u32, mut exp: u32) -> u16 {
    let mut acc: u32 = 1;
    while exp > 0 {
        if (exp & 1) != 0 {
            acc = (acc * base) % Q32;
        }
        base = (base * base) % Q32;
        exp >>= 1;
    }
    acc as u16
}

const fn build_bitrev_table() -> [u8; KEM_N] {
    let mut out = [0u8; KEM_N];
    let mut i = 0usize;
    while i < KEM_N {
        out[i] = (i as u8).reverse_bits();
        i += 1;
    }
    out
}

const fn build_pows(root: u16, scale: u16) -> [u16; KEM_N] {
    let mut out = [0u16; KEM_N];
    let mut cur = scale as u32;
    let r = root as u32;
    let mut i = 0usize;
    while i < KEM_N {
        out[i] = cur as u16;
        cur = (cur * r) % Q32;
        i += 1;
    }
    out
}

const fn build_stage_twiddles(root: u16) -> [[u16; 128]; 8] {
    let mut table = [[0u16; 128]; 8];
    let mut stage = 0usize;
    while stage < 8 {
        let len = 2usize << stage;
        let half = len / 2;
        let step_root = pow_mod_const(root as u32, (KEM_N / len) as u32) as u32;
        let mut w: u32 = 1;
        let mut j = 0usize;
        while j < half {
            table[stage][j] = w as u16;
            w = (w * step_root) % Q32;
            j += 1;
        }
        stage += 1;
    }
    table
}

const BITREV: [u8; KEM_N] = build_bitrev_table();
const PSI_POWS: [u16; KEM_N] = build_pows(PSI, 1);
const PSI_INV_SCALED: [u16; KEM_N] = build_pows(PSI_INV, N_INV);
const FWD_TWIDDLES: [[u16; 128]; 8] = build_stage_twiddles(OMEGA);
const INV_TWIDDLES: [[u16; 128]; 8] = build_stage_twiddles(OMEGA_INV);

fn zeroize_u16_array(buf: &mut [u16; KEM_N]) {
    for c in buf.iter_mut() {
        // SAFETY: `c` is a valid, aligned mutable `u16` reference within `buf`.
        unsafe {
            core::ptr::write_volatile(c as *mut u16, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn ntt_core(input: &[u16; KEM_N], twiddles: &[[u16; 128]; 8]) -> [u16; KEM_N] {
    let mut a = [0u16; KEM_N];
    for i in 0..KEM_N {
        a[i] = input[BITREV[i] as usize];
    }

    for (stage, stage_tw) in twiddles.iter().enumerate() {
        let len = 2usize << stage;
        let half = len / 2;
        let mut start = 0usize;
        while start < KEM_N {
            for j in 0..half {
                let u = a[start + j];
                let v = mul_mod(a[start + j + half], stage_tw[j]);
                a[start + j] = add_mod(u, v);
                a[start + j + half] = sub_mod(u, v);
            }
            start += len;
        }
    }
    a
}

/// Computes the exact constant-time negacyclic product `a * b mod (X^256 + 1, 7681)`
/// in `O(N log N)` time via twisted Cooley-Tukey NTT, wiping all stack intermediates.
pub fn poly_mul_ntt(a: &[u16; KEM_N], b: &[u16; KEM_N]) -> [u16; KEM_N] {
    let mut ta = [0u16; KEM_N];
    let mut tb = [0u16; KEM_N];
    for i in 0..KEM_N {
        ta[i] = mul_mod(a[i], PSI_POWS[i]);
        tb[i] = mul_mod(b[i], PSI_POWS[i]);
    }

    let mut fa = ntt_core(&ta, &FWD_TWIDDLES);
    let mut fb = ntt_core(&tb, &FWD_TWIDDLES);
    zeroize_u16_array(&mut ta);
    zeroize_u16_array(&mut tb);

    let mut fc = [0u16; KEM_N];
    for i in 0..KEM_N {
        fc[i] = mul_mod(fa[i], fb[i]);
    }
    zeroize_u16_array(&mut fa);
    zeroize_u16_array(&mut fb);

    let mut tc = ntt_core(&fc, &INV_TWIDDLES);
    zeroize_u16_array(&mut fc);

    let mut out = [0u16; KEM_N];
    for i in 0..KEM_N {
        out[i] = mul_mod(tc[i], PSI_INV_SCALED[i]);
    }
    zeroize_u16_array(&mut tc);
    out
}
