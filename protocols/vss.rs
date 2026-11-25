//! Verifiable Secret Sharing (`WilisVSS`) & Proactive Share Refresh built on `WilisSplit`
//! and `WilisHash-256` blinded share commitments.
//!
//! - **Public Share Verification:** Each share carries a blinded 256-bit nonce and Merkle
//!   inclusion proof against the dealer's public 32-byte `VssCommitment`, letting any holder
//!   verify their share is authentic without revealing the share or reconstructing the secret.
//! - **Proactive Share Refresh:** Adds a fresh random zero-intercept polynomial `g(x)` with
//!   `g(0) = 0` to every share, invalidating any previously leaked epoch shares while preserving
//!   the exact underlying secret!

use crate::core::constants::HASH_BYTES;
use crate::error::{Result, WilisError};
use crate::hash::WilisHash;
use crate::split::gf256::{gf_add, gf_mul};
use crate::split::{combine_shares, split_secret, Share};
use crate::utils::constant_time::ct_eq;
use crate::utils::random::fill_random;
use crate::utils::zeroize::zeroize_bytes;

/// Public 32-byte dealer commitment binding all issued VSS shares without leaking them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VssCommitment {
    pub epoch: u32,
    pub total: u8,
    pub threshold: u8,
    pub merkle_root: [u8; HASH_BYTES],
}

/// A verifiable Shamir share carrying its blinding salt and Merkle proof against [`VssCommitment`].
#[derive(Clone)]
pub struct VssShare {
    pub share: Share,
    pub blinding: [u8; HASH_BYTES],
    pub proof: Vec<([u8; HASH_BYTES], bool)>,
}

impl Drop for VssShare {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.blinding);
    }
}

fn commit_share_leaf(epoch: u32, share: &Share, blinding: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    let mut raw = share.to_bytes();
    let mut h = WilisHash::new();
    h.update(b"WVSS_LF1");
    h.update(&epoch.to_le_bytes());
    h.update(blinding);
    h.update(&raw);
    zeroize_bytes(&mut raw);
    h.finalize()
}

fn hash_vss_pair(level: u32, left: &[u8; HASH_BYTES], right: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    let mut h = WilisHash::new();
    h.update(b"WVSS_ND1");
    h.update(&level.to_le_bytes());
    h.update(left);
    h.update(right);
    h.finalize()
}

fn build_vss_bundle(epoch: u32, shares: Vec<Share>) -> Result<(VssCommitment, Vec<VssShare>)> {
    let n = shares.len();
    let threshold = shares[0].threshold;
    let total = shares[0].total;

    let mut blindings = vec![[0u8; HASH_BYTES]; n];
    for b in &mut blindings {
        fill_random(b)?;
    }

    let leaves: Vec<[u8; HASH_BYTES]> = shares
        .iter()
        .zip(blindings.iter())
        .map(|(s, b)| commit_share_leaf(epoch, s, b))
        .collect();

    // Build full binary tree levels to extract per-share Merkle proofs
    let mut levels: Vec<Vec<[u8; HASH_BYTES]>> = vec![leaves];
    let mut lvl: u32 = 0;
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity(prev.len().div_ceil(2));
        let mut i = 0;
        while i < prev.len() {
            if i + 1 < prev.len() {
                next.push(hash_vss_pair(lvl, &prev[i], &prev[i + 1]));
            } else {
                next.push(prev[i]);
            }
            i += 2;
        }
        levels.push(next);
        lvl += 1;
    }

    let merkle_root = levels.last().unwrap()[0];
    let mut out_shares = Vec::with_capacity(n);
    for (orig_idx, (share, blinding)) in shares.into_iter().zip(blindings.into_iter()).enumerate() {
        let mut proof = Vec::new();
        let mut idx = orig_idx;
        for level in levels.iter().take(levels.len() - 1) {
            if (idx & 1) == 0 {
                if idx + 1 < level.len() {
                    proof.push((level[idx + 1], true));
                }
            } else {
                proof.push((level[idx - 1], false));
            }
            idx >>= 1;
        }
        out_shares.push(VssShare {
            share,
            blinding,
            proof,
        });
    }

    Ok((
        VssCommitment {
            epoch,
            total,
            threshold,
            merkle_root,
        },
        out_shares,
    ))
}

/// Splits `secret` into `total` verifiable shares requiring `threshold` shares to reconstruct.
pub fn vss_split(secret: &[u8], total: u8, threshold: u8) -> Result<(VssCommitment, Vec<VssShare>)> {
    let shares = split_secret(secret, total, threshold)?;
    build_vss_bundle(0, shares)
}

/// Verifies a single [`VssShare`] against the dealer's public [`VssCommitment`] without reconstructing.
pub fn vss_verify_share(commitment: &VssCommitment, vss_share: &VssShare) -> bool {
    if vss_share.share.total != commitment.total
        || vss_share.share.threshold != commitment.threshold
        || vss_share.share.index == 0
        || vss_share.share.index > commitment.total
    {
        return false;
    }
    let mut cur = commit_share_leaf(commitment.epoch, &vss_share.share, &vss_share.blinding);
    let mut idx = (vss_share.share.index - 1) as usize;
    let mut level_len = commitment.total as usize;
    let mut lvl: u32 = 0;
    let mut iter = vss_share.proof.iter();

    while level_len > 1 {
        if (idx & 1) == 0 {
            if idx + 1 < level_len {
                let Some(&(sib, is_right)) = iter.next() else { return false };
                if !is_right {
                    return false;
                }
                cur = hash_vss_pair(lvl, &cur, &sib);
            }
        } else {
            let Some(&(sib, is_right)) = iter.next() else { return false };
            if is_right {
                return false;
            }
            cur = hash_vss_pair(lvl, &sib, &cur);
        }
        idx >>= 1;
        level_len = level_len.div_ceil(2);
        lvl += 1;
    }
    if iter.next().is_some() {
        return false;
    }
    ct_eq(&cur, &commitment.merkle_root)
}

/// Reconstructs the secret after verifying every supplied [`VssShare`] against `commitment`.
pub fn vss_combine(commitment: &VssCommitment, shares: &[VssShare]) -> Result<Vec<u8>> {
    for s in shares {
        if !vss_verify_share(commitment, s) {
            return Err(WilisError::AuthenticationFailed);
        }
    }
    let mut raw: Vec<Share> = shares.iter().map(|s| s.share.clone()).collect();
    let res = combine_shares(&raw);
    for s in &mut raw {
        zeroize_bytes(&mut s.data);
    }
    res
}

/// Proactively refreshes a full set of `N` shares by adding a random degree-`(K-1)` polynomial
/// `g(x)` with `g(0) = 0` in `GF(2^8)`, advancing `epoch + 1` and invalidating old epoch shares
/// while keeping the exact same underlying secret!
pub fn vss_proactive_refresh(
    commitment: &VssCommitment,
    all_shares: &[VssShare],
) -> Result<(VssCommitment, Vec<VssShare>)> {
    if commitment.threshold < 2
        || commitment.total < commitment.threshold
        || all_shares.is_empty()
        || all_shares.len() != commitment.total as usize
    {
        return Err(WilisError::InvalidParameters(
            "proactive refresh requires valid threshold >= 2 and all N shares".into(),
        ));
    }
    for (i, s) in all_shares.iter().enumerate() {
        if s.share.index != (i + 1) as u8 || !vss_verify_share(commitment, s) {
            return Err(WilisError::AuthenticationFailed);
        }
    }
    let new_epoch = commitment
        .epoch
        .checked_add(1)
        .ok_or_else(|| WilisError::InvalidParameters("VSS epoch overflow".into()))?;
    let secret_len = all_shares[0].share.data.len();
    let degree = (commitment.threshold - 1) as usize;

    let mut delta_coeffs = vec![0u8; secret_len * degree];
    fill_random(&mut delta_coeffs)?;

    let mut refreshed = Vec::with_capacity(all_shares.len());
    for s in all_shares {
        let x = s.share.index;
        let mut new_data = Vec::with_capacity(secret_len);
        for pos in 0..secret_len {
            // Evaluate g(x) = c_1*x + c_2*x^2 + ... + c_{k-1}*x^{k-1} (strictly g(0) = 0!)
            let mut g_val = 0u8;
            let base = pos * degree;
            for c_idx in (0..degree).rev() {
                g_val = gf_add(gf_mul(g_val, x), delta_coeffs[base + c_idx]);
            }
            g_val = gf_mul(g_val, x);
            new_data.push(gf_add(s.share.data[pos], g_val));
        }
        refreshed.push(Share {
            index: s.share.index,
            threshold: s.share.threshold,
            total: s.share.total,
            commitment: s.share.commitment,
            data: new_data,
        });
    }
    zeroize_bytes(&mut delta_coeffs);
    build_vss_bundle(new_epoch, refreshed)
}
