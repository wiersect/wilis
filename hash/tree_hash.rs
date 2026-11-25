//! Parallel Multi-Core Merkle Tree Hash (`WilisTreeHash`) & Verified Range Streaming
//! Inclusion Proofs (`TreeProof`) built strictly on `WilisHash-256` + `std::thread::scope`.
//!
//! Splits input into 4 KiB leaves hashed in parallel across CPU cores, combines nodes into a
//! domain-separated binary Merkle tree, and supports `O(log N)` chunk verification without
//! reading the rest of a multi-GB file.

use crate::core::constants::HASH_BYTES;
use crate::error::{Result, WilisError};
use crate::hash::WilisHash;
use crate::utils::constant_time::ct_eq;

/// Leaf chunk size for `WilisTreeHash` (4 KiB).
pub const TREE_CHUNK_BYTES: usize = 4096;

/// Merkle inclusion proof authenticating one 4 KiB chunk against a 256-bit `WilisTreeHash` root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeProof {
    pub total_len: u64,
    pub chunk_index: u64,
    /// Sibling hashes from bottom to top, paired with `is_right_sibling` flag.
    pub siblings: Vec<([u8; HASH_BYTES], bool)>,
}

fn hash_leaf(chunk_index: u64, chunk: &[u8]) -> [u8; HASH_BYTES] {
    let mut h = WilisHash::new();
    h.update(b"WTRE_LF1");
    h.update(&chunk_index.to_le_bytes());
    h.update(&(chunk.len() as u64).to_le_bytes());
    h.update(chunk);
    h.finalize()
}

fn hash_parent(level: u32, left: &[u8; HASH_BYTES], right: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    let mut h = WilisHash::new();
    h.update(b"WTRE_ND1");
    h.update(&level.to_le_bytes());
    h.update(left);
    h.update(right);
    h.finalize()
}

fn finalize_root(root_node: &[u8; HASH_BYTES], total_len: u64) -> [u8; HASH_BYTES] {
    let mut h = WilisHash::new();
    h.update(b"WTRE_RT1");
    h.update(&total_len.to_le_bytes());
    h.update(root_node);
    h.finalize()
}

fn compute_leaf_hashes(data: &[u8]) -> Vec<[u8; HASH_BYTES]> {
    if data.is_empty() {
        return vec![hash_leaf(0, &[])];
    }

    let chunks: Vec<&[u8]> = data.chunks(TREE_CHUNK_BYTES).collect();
    let num_chunks = chunks.len();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(8);

    // Parallelize via pure-std scoped threads when payload spans >= 8 chunks (32 KiB+)
    if threads > 1 && num_chunks >= 8 {
        let mut leaves = vec![[0u8; HASH_BYTES]; num_chunks];
        let per_thread = num_chunks.div_ceil(threads);
        std::thread::scope(|scope| {
            let mut offset = 0usize;
            for slice in leaves.chunks_mut(per_thread) {
                let start = offset;
                let end = start + slice.len();
                let chunk_slice = &chunks[start..end];
                scope.spawn(move || {
                    for (local_i, &chunk) in chunk_slice.iter().enumerate() {
                        slice[local_i] = hash_leaf((start + local_i) as u64, chunk);
                    }
                });
                offset = end;
            }
        });
        leaves
    } else {
        chunks
            .iter()
            .enumerate()
            .map(|(i, &c)| hash_leaf(i as u64, c))
            .collect()
    }
}

/// Computes the 256-bit parallel `WilisTreeHash` root digest of `data`.
pub fn tree_hash(data: &[u8]) -> [u8; HASH_BYTES] {
    let mut level_nodes = compute_leaf_hashes(data);
    let mut level: u32 = 0;

    while level_nodes.len() > 1 {
        let mut next = Vec::with_capacity(level_nodes.len().div_ceil(2));
        let mut i = 0;
        while i < level_nodes.len() {
            if i + 1 < level_nodes.len() {
                next.push(hash_parent(level, &level_nodes[i], &level_nodes[i + 1]));
            } else {
                // Odd trailing node promoted deterministically without duplicating leaf hashes
                next.push(level_nodes[i]);
            }
            i += 2;
        }
        level_nodes = next;
        level += 1;
    }

    finalize_root(&level_nodes[0], data.len() as u64)
}

/// Generates a compact `O(log N)` Merkle inclusion proof for chunk `chunk_index` of `data`,
/// returning `(root_hash, chunk_bytes, TreeProof)`.
pub fn build_chunk_proof(
    data: &[u8],
    chunk_index: u64,
) -> Result<([u8; HASH_BYTES], Vec<u8>, TreeProof)> {
    let mut level_nodes = compute_leaf_hashes(data);
    let total_chunks = level_nodes.len() as u64;
    if chunk_index >= total_chunks {
        return Err(WilisError::InvalidParameters(format!(
            "chunk_index {chunk_index} out of range (total chunks: {total_chunks})"
        )));
    }

    let chunk_bytes = if data.is_empty() {
        Vec::new()
    } else {
        let start = (chunk_index as usize) * TREE_CHUNK_BYTES;
        let end = (start + TREE_CHUNK_BYTES).min(data.len());
        data[start..end].to_vec()
    };

    let mut siblings = Vec::new();
    let mut idx = chunk_index as usize;
    let mut level: u32 = 0;

    while level_nodes.len() > 1 {
        let is_left = (idx & 1) == 0;
        if is_left {
            if idx + 1 < level_nodes.len() {
                siblings.push((level_nodes[idx + 1], true));
            }
        } else {
            siblings.push((level_nodes[idx - 1], false));
        }

        let mut next = Vec::with_capacity(level_nodes.len().div_ceil(2));
        let mut i = 0;
        while i < level_nodes.len() {
            if i + 1 < level_nodes.len() {
                next.push(hash_parent(level, &level_nodes[i], &level_nodes[i + 1]));
            } else {
                next.push(level_nodes[i]);
            }
            i += 2;
        }
        level_nodes = next;
        idx >>= 1;
        level += 1;
    }

    let root = finalize_root(&level_nodes[0], data.len() as u64);
    Ok((
        root,
        chunk_bytes,
        TreeProof {
            total_len: data.len() as u64,
            chunk_index,
            siblings,
        },
    ))
}

/// Verifies a single 4 KiB chunk and its [`TreeProof`] against `expected_root` in constant time.
pub fn verify_chunk_proof(
    expected_root: &[u8; HASH_BYTES],
    chunk: &[u8],
    proof: &TreeProof,
) -> bool {
    if chunk.len() > TREE_CHUNK_BYTES {
        return false;
    }
    let total_chunks = if proof.total_len == 0 {
        1u64
    } else {
        proof.total_len.div_ceil(TREE_CHUNK_BYTES as u64)
    };
    if proof.chunk_index >= total_chunks {
        return false;
    }

    let mut cur = hash_leaf(proof.chunk_index, chunk);
    let mut idx = proof.chunk_index;
    let mut level_count = total_chunks;
    let mut level: u32 = 0;
    let mut sib_iter = proof.siblings.iter();

    while level_count > 1 {
        let is_left = (idx & 1) == 0;
        if is_left {
            if idx + 1 < level_count {
                let Some(&(sib, is_right_sib)) = sib_iter.next() else {
                    return false;
                };
                if !is_right_sib {
                    return false;
                }
                cur = hash_parent(level, &cur, &sib);
            }
        } else {
            let Some(&(sib, is_right_sib)) = sib_iter.next() else {
                return false;
            };
            if is_right_sib {
                return false;
            }
            cur = hash_parent(level, &sib, &cur);
        }
        idx >>= 1;
        level_count = level_count.div_ceil(2);
        level += 1;
    }

    if sib_iter.next().is_some() {
        return false;
    }

    let computed_root = finalize_root(&cur, proof.total_len);
    ct_eq(&computed_root, expected_root)
}
