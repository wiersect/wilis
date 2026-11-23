//! Polynomial ring arithmetic over `R_q = Z_q[X] / (X^256 + 1)` with `q = 7681`.
//!
//! All serialization uses exact 13-bit packing (416 bytes per polynomial, zero compression
//! distortion) and validates every decoded coefficient strictly `< Q` to prevent
//! non-canonical ciphertext malleability.

use crate::error::{Result, WilisError};
use crate::utils::zeroize::zeroize_bytes;
use crate::xof::WilisXof;

/// Polynomial degree `N = 256`.
pub const KEM_N: usize = 256;

/// Prime modulus `q = 7681` (`7681 = 15 * 512 + 1`, fits cleanly in 13 bits).
pub const KEM_Q: u16 = 7681;

/// Module rank `k = 3` (768-dimensional Module-LWE lattice).
pub const KEM_K: usize = 3;

/// Exact packed byte size of one 256-coefficient 13-bit polynomial (`256 * 13 / 8 = 416`).
pub const POLY_BYTES: usize = 416;

/// Element of `R_q = Z_7681[X] / (X^256 + 1)` with canonical coefficients in `0..7681`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [u16; KEM_N],
}

impl Poly {
    /// Returns the zero polynomial.
    pub fn zero() -> Self {
        Self {
            coeffs: [0u16; KEM_N],
        }
    }

    /// Securely wipes all polynomial coefficients using volatile writes.
    pub fn zeroize(&mut self) {
        for c in &mut self.coeffs {
            // SAFETY: `c` is a valid, aligned mutable `u16` reference within `self.coeffs`.
            unsafe {
                core::ptr::write_volatile(c as *mut u16, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Coefficient-wise addition modulo `q`.
    pub fn add(&self, rhs: &Self) -> Self {
        let mut out = Self::zero();
        for i in 0..KEM_N {
            let s = self.coeffs[i] as u32 + rhs.coeffs[i] as u32;
            out.coeffs[i] = if s >= KEM_Q as u32 {
                (s - KEM_Q as u32) as u16
            } else {
                s as u16
            };
        }
        out
    }

    /// Coefficient-wise subtraction modulo `q`.
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut out = Self::zero();
        for i in 0..KEM_N {
            let a = self.coeffs[i] as i32;
            let b = rhs.coeffs[i] as i32;
            let d = a - b;
            out.coeffs[i] = if d < 0 {
                (d + KEM_Q as i32) as u16
            } else {
                d as u16
            };
        }
        out
    }

    /// Exact negacyclic polynomial multiplication modulo `(X^256 + 1, q)`.
    ///
    /// Uses `i64` accumulators (max magnitude `256 * 7680^2 ≈ 1.5e10 << 2^63`)
    /// so intermediate overflow is mathematically impossible.
    pub fn mul(&self, rhs: &Self) -> Self {
        let mut acc = [0i64; KEM_N];
        for i in 0..KEM_N {
            let ai = self.coeffs[i] as i64;
            for j in 0..KEM_N {
                let prod = ai * (rhs.coeffs[j] as i64);
                let idx = i + j;
                if idx < KEM_N {
                    acc[idx] += prod;
                } else {
                    acc[idx - KEM_N] -= prod;
                }
            }
        }

        let mut out = Self::zero();
        let q64 = KEM_Q as i64;
        for i in 0..KEM_N {
            out.coeffs[i] = acc[i].rem_euclid(q64) as u16;
        }
        out
    }

    /// Encodes a 32-byte (256-bit) message into a polynomial by mapping bit `b` to `b * 3840`.
    pub fn from_msg_bits(msg: &[u8; 32]) -> Self {
        let half_q = KEM_Q / 2; // 3840
        let mut out = Self::zero();
        for (byte_idx, &byte) in msg.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = ((byte >> bit_idx) & 1) as u16;
                // Constant-time selection: 0 -> 0, 1 -> 3840
                let mask = 0u16.wrapping_sub(bit);
                out.coeffs[byte_idx * 8 + bit_idx] = half_q & mask;
            }
        }
        out
    }

    /// Decodes a noisy polynomial back into 32 message bytes (threshold at `q/4 = 1920`).
    pub fn to_msg_bits(&self) -> [u8; 32] {
        let mut msg = [0u8; 32];
        for (i, &c) in self.coeffs.iter().enumerate() {
            // Maps [1920..=5760] -> 1, and [0..1920) U (5760..7681) -> 0
            let shifted = (c as u32 + 1920) % (KEM_Q as u32);
            let bit = if shifted >= 3840 { 1u8 } else { 0u8 };
            msg[i / 8] |= bit << (i % 8);
        }
        msg
    }

    /// Samples a uniform random polynomial over `R_q` from `WilisXOF` via rejection sampling.
    pub fn sample_uniform(seed: &[u8; 32], row: u8, col: u8) -> Self {
        let mut xof = WilisXof::new(b"WKEM_MAT_V1");
        xof.absorb(seed);
        xof.absorb(&[row, col]);

        let mut out = Self::zero();
        let mut idx = 0usize;
        let mut buf = [0u8; 64];

        while idx < KEM_N {
            xof.squeeze(&mut buf);
            for pair in buf.chunks_exact(2) {
                let cand = u16::from_le_bytes([pair[0], pair[1]]) & 0x1FFF; // 13 bits: 0..8191
                if cand < KEM_Q {
                    out.coeffs[idx] = cand;
                    idx += 1;
                    if idx == KEM_N {
                        break;
                    }
                }
            }
        }
        out
    }

    /// Samples a small error/secret polynomial from Centered Binomial Distribution `CBD_2`
    /// (coefficients in `{-2, -1, 0, 1, 2}` reduced modulo `q`).
    pub fn sample_cbd2(seed: &[u8; 32], nonce: u8) -> Self {
        let mut xof = WilisXof::new(b"WKEM_CBD_V1");
        xof.absorb(seed);
        xof.absorb(&[nonce]);

        // 4 bits per coefficient (2 pos + 2 neg) => 256 * 4 / 8 = 128 bytes
        let mut raw = [0u8; 128];
        xof.squeeze(&mut raw);

        let mut out = Self::zero();
        for (i, &byte) in raw.iter().enumerate() {
            // Low nibble -> coeff 2*i
            let a0 = (byte & 1) + ((byte >> 1) & 1);
            let b0 = ((byte >> 2) & 1) + ((byte >> 3) & 1);
            let d0 = a0 as i32 - b0 as i32;
            out.coeffs[i * 2] = if d0 < 0 {
                (d0 + KEM_Q as i32) as u16
            } else {
                d0 as u16
            };

            // High nibble -> coeff 2*i + 1
            let a1 = ((byte >> 4) & 1) + ((byte >> 5) & 1);
            let b1 = ((byte >> 6) & 1) + ((byte >> 7) & 1);
            let d1 = a1 as i32 - b1 as i32;
            out.coeffs[i * 2 + 1] = if d1 < 0 {
                (d1 + KEM_Q as i32) as u16
            } else {
                d1 as u16
            };
        }
        zeroize_bytes(&mut raw);
        out
    }

    /// Packs 256 13-bit coefficients into exactly 416 bytes (8 coeffs -> 13 bytes).
    pub fn pack(&self) -> [u8; POLY_BYTES] {
        let mut out = [0u8; POLY_BYTES];
        for g in 0..(KEM_N / 8) {
            let c = &self.coeffs[g * 8..(g + 1) * 8];
            let mut bits: u128 = 0;
            for (k, &val) in c.iter().enumerate() {
                debug_assert!(val < KEM_Q);
                bits |= (val as u128) << (k * 13);
            }
            let raw = bits.to_le_bytes();
            out[g * 13..(g + 1) * 13].copy_from_slice(&raw[..13]);
        }
        out
    }

    /// Unpacks 416 bytes into a canonical polynomial, rejecting any coefficient `>= Q`.
    pub fn unpack(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != POLY_BYTES {
            return Err(WilisError::InvalidFormat(format!(
                "invalid polynomial length: expected {POLY_BYTES}, got {}",
                bytes.len()
            )));
        }
        let mut out = Self::zero();
        for g in 0..(KEM_N / 8) {
            let mut raw = [0u8; 16];
            raw[..13].copy_from_slice(&bytes[g * 13..(g + 1) * 13]);
            let bits = u128::from_le_bytes(raw);
            for k in 0..8 {
                let val = ((bits >> (k * 13)) & 0x1FFF) as u16;
                if val >= KEM_Q {
                    return Err(WilisError::InvalidFormat(format!(
                        "non-canonical KEM polynomial coefficient {val} >= {KEM_Q}"
                    )));
                }
                out.coeffs[g * 8 + k] = val;
            }
        }
        Ok(out)
    }
}

/// Computes the inner product `sum_i a[i] * b[i]` of two `k`-element polynomial vectors.
pub fn vec_dot(a: &[Poly; KEM_K], b: &[Poly; KEM_K]) -> Poly {
    let mut sum = Poly::zero();
    for i in 0..KEM_K {
        let prod = a[i].mul(&b[i]);
        sum = sum.add(&prod);
    }
    sum
}
