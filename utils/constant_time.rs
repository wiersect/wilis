//! Constant-time comparison primitives to mitigate timing side-channel attacks.

use std::hint::black_box;

/// Compares two byte slices in constant time with respect to their contents.
///
/// Returns `true` if and only if both slices have equal length and identical bytes.
/// Uses bitwise accumulation and `black_box` to prevent early-exit branch optimization.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= black_box(x ^ y);
    }

    black_box(diff) == 0
}
