//! Shamir's Secret Sharing (`K`-of-`N` threshold) with built-in `WilisHash-256`
//! secret commitment verification and canonical string serialization.

use crate::error::{Result, WilisError};
use crate::hash::hash;
use crate::split::gf256::{gf_add, gf_div, gf_mul};
use crate::utils::base64::{decode_base64, encode_base64};
use crate::utils::constant_time::ct_eq;
use crate::utils::random::fill_random;
use crate::utils::zeroize::zeroize_bytes;

const SHARE_MAGIC: [u8; 4] = *b"WSHR";
const SHARE_PREFIX: &str = "wilis-share-v1:";

/// A single Shamir secret share carrying its threshold metadata and secret commitment.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    /// Non-zero x-coordinate (`1..=255`).
    pub index: u8,
    /// Minimum shares required to reconstruct (`2..=total`).
    pub threshold: u8,
    /// Total shares originally issued (`threshold..=255`).
    pub total: u8,
    /// 8-byte truncated `WilisHash-256` commitment of the original secret for tamper detection.
    pub commitment: [u8; 8],
    /// Evaluated y-values for each byte of the secret.
    pub data: Vec<u8>,
}

impl Share {
    /// Serializes the share to canonical `WSHR` binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 3 + 8 + self.data.len());
        out.extend_from_slice(&SHARE_MAGIC);
        out.push(1u8); // version
        out.push(self.index);
        out.push(self.threshold);
        out.push(self.total);
        out.extend_from_slice(&self.commitment);
        out.extend_from_slice(&self.data);
        out
    }

    /// Parses a canonical `WSHR` binary share.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() <= 16 || raw[0..4] != SHARE_MAGIC || raw[4] != 1 {
            return Err(WilisError::InvalidFormat(
                "invalid or corrupted WilisSplit share".into(),
            ));
        }
        let index = raw[5];
        let threshold = raw[6];
        let total = raw[7];
        if index == 0 || threshold < 2 || total < threshold {
            return Err(WilisError::InvalidFormat(
                "invalid threshold/index metadata in share".into(),
            ));
        }
        let mut commitment = [0u8; 8];
        commitment.copy_from_slice(&raw[8..16]);
        let data = raw[16..].to_vec();
        Ok(Self {
            index,
            threshold,
            total,
            commitment,
            data,
        })
    }

    /// Encodes the share as a portable text token (`wilis-share-v1:<base64>`).
    pub fn encode_string(&self) -> String {
        format!("{SHARE_PREFIX}{}", encode_base64(&self.to_bytes()))
    }

    /// Decodes a portable share token (`wilis-share-v1:<base64>`).
    pub fn decode_string(text: &str) -> Result<Self> {
        let trimmed = text.trim();
        let b64 = trimmed.strip_prefix(SHARE_PREFIX).ok_or_else(|| {
            WilisError::InvalidEncoding(format!("share must begin with '{SHARE_PREFIX}'"))
        })?;
        let raw = decode_base64(b64)?;
        Self::from_bytes(&raw)
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.data);
    }
}

fn secret_commitment(secret: &[u8]) -> [u8; 8] {
    let mut tagged = Vec::with_capacity(8 + secret.len());
    tagged.extend_from_slice(b"WSHR_CMT");
    tagged.extend_from_slice(secret);
    let digest = hash(&tagged);
    zeroize_bytes(&mut tagged);
    digest[0..8].try_into().expect("8 bytes")
}

/// Splits `secret` into `total` (`n`) shares requiring any `threshold` (`k`) shares to recover.
pub fn split_secret(secret: &[u8], total: u8, threshold: u8) -> Result<Vec<Share>> {
    if secret.is_empty() {
        return Err(WilisError::InvalidParameters(
            "secret to split must not be empty".into(),
        ));
    }
    if threshold < 2 {
        return Err(WilisError::InvalidParameters(
            "threshold k must be at least 2".into(),
        ));
    }
    if total < threshold {
        return Err(WilisError::InvalidParameters(format!(
            "total shares n ({total}) must be >= threshold k ({threshold})"
        )));
    }

    let commitment = secret_commitment(secret);
    let secret_len = secret.len();
    let degree = (threshold - 1) as usize;

    // Generate all random polynomial coefficients in one OS CSPRNG read
    let mut coeffs = vec![0u8; secret_len * degree];
    fill_random(&mut coeffs)?;

    let mut shares = Vec::with_capacity(total as usize);
    for share_idx in 1..=total {
        let mut y_vals = Vec::with_capacity(secret_len);
        for (byte_pos, &secret_byte) in secret.iter().enumerate() {
            // Evaluate f(x) = secret_byte + c_1*x + c_2*x^2 + ... + c_{k-1}*x^{k-1} via Horner
            let mut acc = 0u8;
            let base = byte_pos * degree;
            for c_idx in (0..degree).rev() {
                acc = gf_add(gf_mul(acc, share_idx), coeffs[base + c_idx]);
            }
            acc = gf_add(gf_mul(acc, share_idx), secret_byte);
            y_vals.push(acc);
        }
        shares.push(Share {
            index: share_idx,
            threshold,
            total,
            commitment,
            data: y_vals,
        });
    }

    zeroize_bytes(&mut coeffs);
    Ok(shares)
}

/// Reconstructs the original secret from `shares` using exact Lagrange interpolation at `x = 0`.
///
/// Rejects insufficient shares, duplicate indices, mismatched lengths/commitments, or tampered data.
pub fn combine_shares(shares: &[Share]) -> Result<Vec<u8>> {
    if shares.is_empty() {
        return Err(WilisError::InvalidParameters(
            "at least 2 shares are required".into(),
        ));
    }

    let threshold = shares[0].threshold;
    let secret_len = shares[0].data.len();
    let expected_cmt = shares[0].commitment;

    if threshold < 2 || secret_len == 0 {
        return Err(WilisError::InvalidFormat(
            "invalid share threshold or empty share payload".into(),
        ));
    }

    if shares.len() < threshold as usize {
        return Err(WilisError::InvalidParameters(format!(
            "insufficient shares: need at least {threshold}, got {}",
            shares.len()
        )));
    }

    // Validate compatibility and uniqueness of x-coordinates
    let mut seen_x = [false; 256];
    for s in shares {
        if s.index == 0 {
            return Err(WilisError::InvalidFormat("share index 0 is invalid".into()));
        }
        if seen_x[s.index as usize] {
            return Err(WilisError::InvalidFormat(format!(
                "duplicate share index: {}",
                s.index
            )));
        }
        seen_x[s.index as usize] = true;

        if s.threshold != threshold
            || s.data.len() != secret_len
            || !ct_eq(&s.commitment, &expected_cmt)
        {
            return Err(WilisError::AuthenticationFailed);
        }
    }

    // Use the first `threshold` shares for Lagrange interpolation at x = 0
    let subset = &shares[..threshold as usize];
    let k = subset.len();

    // Precompute Lagrange basis weights L_i(0) = prod_{j != i} (x_j / (x_j ^ x_i))
    let mut weights = vec![0u8; k];
    for i in 0..k {
        let xi = subset[i].index;
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, sj) in subset.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = sj.index;
            num = gf_mul(num, xj);
            den = gf_mul(den, gf_add(xj, xi));
        }
        weights[i] = gf_div(num, den);
    }

    let mut recovered = vec![0u8; secret_len];
    for byte_pos in 0..secret_len {
        let mut val = 0u8;
        for i in 0..k {
            val = gf_add(val, gf_mul(subset[i].data[byte_pos], weights[i]));
        }
        recovered[byte_pos] = val;
    }

    // Verify reconstructed secret against the embedded WilisHash-256 commitment
    let actual_cmt = secret_commitment(&recovered);
    if !ct_eq(&actual_cmt, &expected_cmt) {
        zeroize_bytes(&mut recovered);
        return Err(WilisError::AuthenticationFailed);
    }

    Ok(recovered)
}
