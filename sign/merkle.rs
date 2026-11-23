//! Merkle hash tree construction, authentication path extraction, and root verification
//! for `WilisSign` stateful hash-based signatures.

use crate::core::constants::HASH_BYTES;
use crate::hash::WilisHash;
use crate::sign::wots::compute_leaf_pk_hash;

/// Domain-separated internal Merkle node hash combining left and right children.
pub fn hash_internal_node(
    pub_seed: &[u8; HASH_BYTES],
    level: u8,
    node_idx: u32,
    left: &[u8; HASH_BYTES],
    right: &[u8; HASH_BYTES],
) -> [u8; HASH_BYTES] {
    let mut h = WilisHash::new();
    h.update(b"WSIG_ND1");
    h.update(pub_seed);
    h.update(&[level]);
    h.update(&node_idx.to_le_bytes());
    h.update(left);
    h.update(right);
    h.finalize()
}

/// Computes the full Merkle tree levels from leaves up to the root.
///
/// Level 0 contains `2^height` leaves; level `height` contains the single 256-bit root.
pub fn build_merkle_tree(
    secret_seed: &[u8; HASH_BYTES],
    pub_seed: &[u8; HASH_BYTES],
    height: u8,
) -> Vec<Vec<[u8; HASH_BYTES]>> {
    let leaf_count = 1usize << height;
    let mut levels: Vec<Vec<[u8; HASH_BYTES]>> = Vec::with_capacity(height as usize + 1);

    let mut leaves = Vec::with_capacity(leaf_count);
    for idx in 0..leaf_count {
        leaves.push(compute_leaf_pk_hash(secret_seed, pub_seed, idx as u32));
    }
    levels.push(leaves);

    for lvl in 0..height {
        let prev = &levels[lvl as usize];
        let next_len = prev.len() / 2;
        let mut next = Vec::with_capacity(next_len);
        for i in 0..next_len {
            next.push(hash_internal_node(
                pub_seed,
                lvl + 1,
                i as u32,
                &prev[i * 2],
                &prev[i * 2 + 1],
            ));
        }
        levels.push(next);
    }

    levels
}

/// Extracts the Merkle authentication path (`height` sibling nodes) for `leaf_idx`.
pub fn extract_auth_path(
    levels: &[Vec<[u8; HASH_BYTES]>],
    leaf_idx: u32,
) -> Vec<[u8; HASH_BYTES]> {
    let height = levels.len() - 1;
    let mut path = Vec::with_capacity(height);
    let mut idx = leaf_idx as usize;

    for level in levels.iter().take(height) {
        let sibling = idx ^ 1;
        path.push(level[sibling]);
        idx >>= 1;
    }

    path
}

/// Climbs from a recovered `leaf_hash` to the Merkle root using `auth_path`.
pub fn compute_root_from_path(
    pub_seed: &[u8; HASH_BYTES],
    mut current: [u8; HASH_BYTES],
    leaf_idx: u32,
    auth_path: &[[u8; HASH_BYTES]],
) -> [u8; HASH_BYTES] {
    let mut idx = leaf_idx;
    for (lvl, sibling) in auth_path.iter().enumerate() {
        let parent_idx = idx >> 1;
        current = if (idx & 1) == 0 {
            hash_internal_node(pub_seed, (lvl + 1) as u8, parent_idx, &current, sibling)
        } else {
            hash_internal_node(pub_seed, (lvl + 1) as u8, parent_idx, sibling, &current)
        };
        idx = parent_idx;
    }
    current
}
