//! Constant-time finite-field arithmetic over `GF(2^8)` modulo `x^8 + x^4 + x^3 + x + 1` (`0x11B`).
//!
//! Uses bit-by-bit Russian peasant multiplication with zero lookup tables so secret
//! byte operations never leak through CPU cache timing.

/// Irreducible reduction polynomial `x^8 + x^4 + x^3 + x + 1` (low 8 bits = `0x1B`).
const GF_POLY: u8 = 0x1B;

/// Constant-time addition/subtraction in `GF(2^8)` (XOR).
#[inline(always)]
pub fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Constant-time multiplication in `GF(2^8)` using branchless bitmasking.
#[inline]
pub fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut prod: u8 = 0;
    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(b & 1);
        prod ^= a & mask;
        let high_bit = 0u8.wrapping_sub((a >> 7) & 1);
        a = (a << 1) ^ (GF_POLY & high_bit);
        b >>= 1;
    }
    prod
}

/// Constant-time multiplicative inverse in `GF(2^8)` via Fermat's Little Theorem (`a^254`).
///
/// Returns `0` for `a == 0`.
pub fn gf_inv(a: u8) -> u8 {
    // 254 = 0b1111_1110 = 2 + 4 + 8 + 16 + 32 + 64 + 128
    let mut base = gf_mul(a, a); // a^2
    let mut result = 1u8;
    for _ in 0..7 {
        result = gf_mul(result, base);
        base = gf_mul(base, base);
    }
    // If a == 0, base and result are already 0
    result
}

/// Division `a / b` in `GF(2^8)`. Caller must ensure `b != 0`.
#[inline]
pub fn gf_div(a: u8, b: u8) -> u8 {
    debug_assert!(b != 0, "division by zero in GF(2^8)");
    gf_mul(a, gf_inv(b))
}
