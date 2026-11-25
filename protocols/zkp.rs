//! Non-Interactive Post-Quantum Hash-Based One-Time Proof of Knowledge (`WilisZKP`)
//! built strictly on `WilisHash-256` & `WilisXOF` (Fiat-Shamir Lamport/Sigma commitment).
//!
//! Proves knowledge of a 256-bit secret seed behind a public [`ZkpStatement`] of 64 committed
//! one-way hash pairs `(H(s_{i,0}), H(s_{i,1}))` bound to an arbitrary verifier `context`.
//!
//! ## Security Note (Single-Use Statement)
//! Like Lamport / WOTS+ one-time hash proofs, each [`ZkpStatement`] MUST be used for at most
//! ONE proof generation (`zkp_prove`), as generating multiple proofs under different Fiat-Shamir
//! challenges would reveal both halves of overlapping pairs. Generate a fresh seed/statement
//! per identification event.

use crate::core::constants::HASH_BYTES;
use crate::error::{Result, WilisError};
use crate::hash::{hash, WilisHash};
use crate::utils::constant_time::ct_eq;
use crate::utils::random::fill_random;
use crate::utils::zeroize::zeroize_bytes;
use crate::xof::WilisXof;

const ZKP_ROUNDS: usize = 64;
const ZKP_PROOF_MAGIC: [u8; 4] = *b"WZKP";
const ZKP_PROOF_VER: u8 = 1;

/// Exact serialized size of a `WZKP` v1 proof (`4 + 1 + 32 + 64 * 32 = 2085` bytes).
pub const ZKP_PROOF_BYTES: usize = 4 + 1 + HASH_BYTES + ZKP_ROUNDS * HASH_BYTES;

/// Public commitment statement of 64 one-way hash pairs and their binding digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkpStatement {
    pub pair_hashes: [([u8; HASH_BYTES], [u8; HASH_BYTES]); ZKP_ROUNDS],
    pub statement_id: [u8; HASH_BYTES],
}

/// Non-interactive Fiat-Shamir proof revealing strictly ONE preimage per pair (`WZKP` v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkpProof {
    pub nonce: [u8; HASH_BYTES],
    pub openings: [[u8; HASH_BYTES]; ZKP_ROUNDS],
}

impl ZkpProof {
    /// Serializes the proof into canonical `WZKP` v1 bytes (`2,085` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ZKP_PROOF_BYTES);
        out.extend_from_slice(&ZKP_PROOF_MAGIC);
        out.push(ZKP_PROOF_VER);
        out.extend_from_slice(&self.nonce);
        for o in &self.openings {
            out.extend_from_slice(o);
        }
        out
    }

    /// Parses a canonical `WZKP` v1 proof.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != ZKP_PROOF_BYTES
            || data[0..4] != ZKP_PROOF_MAGIC
            || data[4] != ZKP_PROOF_VER
        {
            return Err(WilisError::InvalidFormat(format!(
                "invalid WilisZKP proof (expected WZKP v1, {ZKP_PROOF_BYTES} bytes)"
            )));
        }
        let nonce: [u8; HASH_BYTES] = data[5..5 + HASH_BYTES].try_into().expect("32 bytes");
        let mut openings = [[0u8; HASH_BYTES]; ZKP_ROUNDS];
        let mut pos = 5 + HASH_BYTES;
        for o in &mut openings {
            o.copy_from_slice(&data[pos..pos + HASH_BYTES]);
            pos += HASH_BYTES;
        }
        Ok(Self { nonce, openings })
    }
}

/// Generates a fresh 256-bit ZKP secret witness and its public [`ZkpStatement`].
pub fn zkp_keygen(secret_seed: &[u8; HASH_BYTES]) -> ZkpStatement {
    let mut pair_hashes = [([0u8; HASH_BYTES], [0u8; HASH_BYTES]); ZKP_ROUNDS];
    let mut h_stmt = WilisHash::new();
    h_stmt.update(b"WZKP_STMT_V1");

    for (i, slot) in pair_hashes.iter_mut().enumerate() {
        let mut s0 = derive_pair_secret(secret_seed, i as u16, 0);
        let mut s1 = derive_pair_secret(secret_seed, i as u16, 1);
        let h0 = hash(&s0);
        let h1 = hash(&s1);
        zeroize_bytes(&mut s0);
        zeroize_bytes(&mut s1);
        *slot = (h0, h1);
        h_stmt.update(&h0);
        h_stmt.update(&h1);
    }

    ZkpStatement {
        pair_hashes,
        statement_id: h_stmt.finalize(),
    }
}

fn derive_pair_secret(seed: &[u8; HASH_BYTES], idx: u16, side: u8) -> [u8; HASH_BYTES] {
    let mut h = WilisHash::new();
    h.update(b"WZKP_WIT_V1");
    h.update(seed);
    h.update(&idx.to_le_bytes());
    h.update(&[side]);
    h.finalize()
}

fn fiat_shamir_challenge(
    statement_id: &[u8; HASH_BYTES],
    nonce: &[u8; HASH_BYTES],
    context: &[u8],
) -> [u8; ZKP_ROUNDS / 8] {
    let mut xof = WilisXof::new(b"WZKP_FS_V1");
    xof.absorb(statement_id);
    xof.absorb(nonce);
    xof.absorb(&(context.len() as u64).to_le_bytes());
    xof.absorb(context);
    let mut bits = [0u8; ZKP_ROUNDS / 8];
    xof.squeeze(&mut bits);
    bits
}

/// Produces a non-interactive Fiat-Shamir proof of knowledge of `secret_seed` bound to `context`,
/// revealing zero bits of `secret_seed` itself (each opening is a one-way derived leaf).
pub fn zkp_prove(
    secret_seed: &[u8; HASH_BYTES],
    statement: &ZkpStatement,
    context: &[u8],
) -> Result<ZkpProof> {
    let mut nonce = [0u8; HASH_BYTES];
    fill_random(&mut nonce)?;
    let chal = fiat_shamir_challenge(&statement.statement_id, &nonce, context);

    let mut openings = [[0u8; HASH_BYTES]; ZKP_ROUNDS];
    for i in 0..ZKP_ROUNDS {
        let bit = (chal[i / 8] >> (i % 8)) & 1;
        openings[i] = derive_pair_secret(secret_seed, i as u16, bit);
    }
    Ok(ZkpProof { nonce, openings })
}

/// Verifies a [`ZkpProof`] against [`ZkpStatement`] and `context` in constant time.
pub fn zkp_verify(statement: &ZkpStatement, proof: &ZkpProof, context: &[u8]) -> bool {
    let mut h_stmt = WilisHash::new();
    h_stmt.update(b"WZKP_STMT_V1");
    for (h0, h1) in &statement.pair_hashes {
        h_stmt.update(h0);
        h_stmt.update(h1);
    }
    if !ct_eq(&h_stmt.finalize(), &statement.statement_id) {
        return false;
    }

    let chal = fiat_shamir_challenge(&statement.statement_id, &proof.nonce, context);
    let mut ok = true;
    for i in 0..ZKP_ROUNDS {
        let bit = (chal[i / 8] >> (i % 8)) & 1;
        let expected = if bit == 0 {
            &statement.pair_hashes[i].0
        } else {
            &statement.pair_hashes[i].1
        };
        let actual = hash(&proof.openings[i]);
        if !ct_eq(&actual, expected) {
            ok = false;
        }
    }
    ok
}
