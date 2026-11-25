//! Stateless Post-Quantum Hash-Based Digital Signatures (`WilisSLH` — FORS + WOTS+ Hypertree)
//! built strictly from `WilisHash-256` & `WilisXOF` (zero external dependencies).
//!
//! Unlike stateful [`crate::sign::SigningKey`], `WilisSLH` requires NO mutable signature
//! counter, can be safely cloned across distributed servers, and supports unlimited signatures:
//! - **FORS (Forest of Random Subsets):** `K = 16` Merkle trees of height `A = 6` (64 leaves/tree)
//! - **Hypertree:** `D = 2` layers of WOTS+ Merkle subtrees (`H' = 4`, total height `H = 8`)
//! - **Hedged Randomization:** Mixes `sk_prf` with fresh OS CSPRNG bytes for deterministic fallback safety.
//! - **Compact Wire Formats:** `WLP1` (`100` B pk), `WLS1` (`164` B sk), `WLSG` (`8,165` B sig).

use crate::core::constants::HASH_BYTES;
use crate::error::{Result, WilisError};
use crate::hash::{hash, WilisHash};
use crate::mac::WilisMac;
use crate::sign::wots::{wots_recover_leaf_pk_hash, wots_sign_digest, WOTS_LEN, WOTS_MAX_STEP, wots_chain};
use crate::utils::constant_time::ct_eq;
use crate::utils::random::fill_random;
use crate::utils::zeroize::zeroize_bytes;
use crate::xof::WilisXof;

const SLH_PK_MAGIC: [u8; 4] = *b"WLP1";
const SLH_SK_MAGIC: [u8; 4] = *b"WLS1";
const SLH_SIG_MAGIC: [u8; 4] = *b"WLSG";
const SLH_SIG_VER: u8 = 1;

const FORS_TREES: usize = 16;
const FORS_HEIGHT: usize = 6;
const FORS_LEAVES: usize = 1 << FORS_HEIGHT; // 64
const HT_LAYERS: usize = 2;
const SUBTREE_HEIGHT: usize = 4;
const SUBTREE_LEAVES: usize = 1 << SUBTREE_HEIGHT; // 16

/// Serialized `WLP1` stateless public key size (`4 + 32 + 32 + 32 = 100` bytes).
pub const SLH_PK_BYTES: usize = 4 + HASH_BYTES * 3;

/// Serialized `WLS1` stateless secret key size (`4 + 32*5 = 164` bytes).
pub const SLH_SK_BYTES: usize = 4 + HASH_BYTES * 5;

/// Serialized `WLSG` stateless signature size (`8,165` bytes).
pub const SLH_SIG_BYTES: usize =
    4 + 1 + HASH_BYTES + FORS_TREES * (1 + FORS_HEIGHT) * HASH_BYTES + HT_LAYERS * (WOTS_LEN + SUBTREE_HEIGHT) * HASH_BYTES;

/// Public verifying key for stateless `WilisSLH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlhPublicKey {
    pub pub_seed: [u8; HASH_BYTES],
    pub root: [u8; HASH_BYTES],
}

/// Stateless secret signing key for `WilisSLH` (auto-zeroizes on drop; safe to clone).
#[derive(Clone)]
pub struct SlhSecretKey {
    sk_seed: [u8; HASH_BYTES],
    sk_prf: [u8; HASH_BYTES],
    pub_seed: [u8; HASH_BYTES],
    root: [u8; HASH_BYTES],
}

impl Drop for SlhSecretKey {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.sk_seed);
        zeroize_bytes(&mut self.sk_prf);
    }
}

/// Stateless post-quantum signature (`WLSG` v1, `8,165` bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlhSignature {
    pub randomizer: [u8; HASH_BYTES],
    pub fors_secrets: [[u8; HASH_BYTES]; FORS_TREES],
    pub fors_paths: [[[u8; HASH_BYTES]; FORS_HEIGHT]; FORS_TREES],
    pub ht_wots: [[[u8; HASH_BYTES]; WOTS_LEN]; HT_LAYERS],
    pub ht_paths: [[[u8; HASH_BYTES]; SUBTREE_HEIGHT]; HT_LAYERS],
}

fn slh_leaf_addr(layer: u8, tree_idx: u32, leaf_idx: u32) -> u32 {
    ((layer as u32) << 24) ^ ((tree_idx & 0xFFFF) << 8) ^ (leaf_idx & 0xFF)
}

fn slh_node_hash(
    pub_seed: &[u8; HASH_BYTES],
    domain: &[u8; 8],
    tag_a: u32,
    tag_b: u32,
    left: &[u8; HASH_BYTES],
    right: &[u8; HASH_BYTES],
) -> [u8; HASH_BYTES] {
    let mut h = WilisHash::new();
    h.update(domain);
    h.update(pub_seed);
    h.update(&tag_a.to_le_bytes());
    h.update(&tag_b.to_le_bytes());
    h.update(left);
    h.update(right);
    h.finalize()
}

fn fors_secret_val(
    sk_seed: &[u8; HASH_BYTES],
    pub_seed: &[u8; HASH_BYTES],
    tree_addr: u32,
    fors_tree: usize,
    leaf: usize,
) -> [u8; HASH_BYTES] {
    let mut h = WilisHash::new();
    h.update(b"WSLH_FSK");
    h.update(sk_seed);
    h.update(pub_seed);
    h.update(&tree_addr.to_le_bytes());
    h.update(&(fors_tree as u16).to_le_bytes());
    h.update(&(leaf as u16).to_le_bytes());
    h.finalize()
}

fn fors_leaf_hash(
    pub_seed: &[u8; HASH_BYTES],
    tree_addr: u32,
    fors_tree: usize,
    leaf: usize,
    secret_val: &[u8; HASH_BYTES],
) -> [u8; HASH_BYTES] {
    let mut h = WilisHash::new();
    h.update(b"WSLH_FLF");
    h.update(pub_seed);
    h.update(&tree_addr.to_le_bytes());
    h.update(&(fors_tree as u16).to_le_bytes());
    h.update(&(leaf as u16).to_le_bytes());
    h.update(secret_val);
    h.finalize()
}

fn fors_sign_and_pk(
    sk_seed: &[u8; HASH_BYTES],
    pub_seed: &[u8; HASH_BYTES],
    tree_addr: u32,
    indices: &[usize; FORS_TREES],
) -> (
    [[u8; HASH_BYTES]; FORS_TREES],
    [[[u8; HASH_BYTES]; FORS_HEIGHT]; FORS_TREES],
    [u8; HASH_BYTES],
) {
    let mut secrets = [[0u8; HASH_BYTES]; FORS_TREES];
    let mut paths = [[[0u8; HASH_BYTES]; FORS_HEIGHT]; FORS_TREES];
    let mut roots = [[0u8; HASH_BYTES]; FORS_TREES];

    for t in 0..FORS_TREES {
        let mut level = [[0u8; HASH_BYTES]; FORS_LEAVES];
        for l in 0..FORS_LEAVES {
            let mut s = fors_secret_val(sk_seed, pub_seed, tree_addr, t, l);
            level[l] = fors_leaf_hash(pub_seed, tree_addr, t, l, &s);
            if l == indices[t] {
                secrets[t] = s;
            }
            zeroize_bytes(&mut s);
        }

        let mut idx = indices[t];
        let mut cur_len = FORS_LEAVES;
        for h_lvl in 0..FORS_HEIGHT {
            paths[t][h_lvl] = level[idx ^ 1];
            let next_len = cur_len / 2;
            for i in 0..next_len {
                level[i] = slh_node_hash(
                    pub_seed,
                    b"WSLH_FND",
                    (tree_addr << 8) ^ (t as u32),
                    ((h_lvl as u32) << 16) ^ (i as u32),
                    &level[i * 2],
                    &level[i * 2 + 1],
                );
            }
            idx >>= 1;
            cur_len = next_len;
        }
        roots[t] = level[0];
    }

    let mut h_pk = WilisHash::new();
    h_pk.update(b"WSLH_FPK");
    h_pk.update(pub_seed);
    h_pk.update(&tree_addr.to_le_bytes());
    for r in &roots {
        h_pk.update(r);
    }
    (secrets, paths, h_pk.finalize())
}

fn fors_pk_from_sig(
    pub_seed: &[u8; HASH_BYTES],
    tree_addr: u32,
    indices: &[usize; FORS_TREES],
    secrets: &[[u8; HASH_BYTES]; FORS_TREES],
    paths: &[[[u8; HASH_BYTES]; FORS_HEIGHT]; FORS_TREES],
) -> [u8; HASH_BYTES] {
    let mut h_pk = WilisHash::new();
    h_pk.update(b"WSLH_FPK");
    h_pk.update(pub_seed);
    h_pk.update(&tree_addr.to_le_bytes());

    for t in 0..FORS_TREES {
        let mut cur = fors_leaf_hash(pub_seed, tree_addr, t, indices[t], &secrets[t]);
        let mut idx = indices[t];
        for h_lvl in 0..FORS_HEIGHT {
            let parent = idx >> 1;
            let sib = &paths[t][h_lvl];
            cur = if (idx & 1) == 0 {
                slh_node_hash(
                    pub_seed,
                    b"WSLH_FND",
                    (tree_addr << 8) ^ (t as u32),
                    ((h_lvl as u32) << 16) ^ (parent as u32),
                    &cur,
                    sib,
                )
            } else {
                slh_node_hash(
                    pub_seed,
                    b"WSLH_FND",
                    (tree_addr << 8) ^ (t as u32),
                    ((h_lvl as u32) << 16) ^ (parent as u32),
                    sib,
                    &cur,
                )
            };
            idx = parent;
        }
        h_pk.update(&cur);
    }
    h_pk.finalize()
}

fn ht_leaf_pk(
    sk_seed: &[u8; HASH_BYTES],
    pub_seed: &[u8; HASH_BYTES],
    layer: u8,
    tree_idx: u32,
    leaf_idx: u32,
) -> [u8; HASH_BYTES] {
    let addr = slh_leaf_addr(layer, tree_idx, leaf_idx);
    let mut h_leaf = WilisHash::new();
    h_leaf.update(b"WSIG_LF1");
    h_leaf.update(pub_seed);
    h_leaf.update(&addr.to_le_bytes());

    for c in 0..WOTS_LEN {
        let mut sk_c = crate::sign::wots::derive_wots_secret_elem(sk_seed, pub_seed, addr, c as u16);
        let pk_c = wots_chain(sk_c, 0, WOTS_MAX_STEP, pub_seed, addr, c as u16);
        zeroize_bytes(&mut sk_c);
        h_leaf.update(&pk_c);
    }
    h_leaf.finalize()
}

fn ht_subtree_sign(
    sk_seed: &[u8; HASH_BYTES],
    pub_seed: &[u8; HASH_BYTES],
    layer: u8,
    tree_idx: u32,
    leaf_idx: u32,
    msg_digest: &[u8; HASH_BYTES],
) -> ([[u8; HASH_BYTES]; WOTS_LEN], [[u8; HASH_BYTES]; SUBTREE_HEIGHT], [u8; HASH_BYTES]) {
    let addr = slh_leaf_addr(layer, tree_idx, leaf_idx);
    let wots_sig = wots_sign_digest(sk_seed, pub_seed, addr, msg_digest);

    let mut level = [[0u8; HASH_BYTES]; SUBTREE_LEAVES];
    for l in 0..SUBTREE_LEAVES {
        level[l] = ht_leaf_pk(sk_seed, pub_seed, layer, tree_idx, l as u32);
    }

    let mut path = [[0u8; HASH_BYTES]; SUBTREE_HEIGHT];
    let mut idx = leaf_idx as usize;
    let mut cur_len = SUBTREE_LEAVES;
    for h_lvl in 0..SUBTREE_HEIGHT {
        path[h_lvl] = level[idx ^ 1];
        let next_len = cur_len / 2;
        for i in 0..next_len {
            level[i] = slh_node_hash(
                pub_seed,
                b"WSLH_HND",
                ((layer as u32) << 16) ^ tree_idx,
                ((h_lvl as u32) << 16) ^ (i as u32),
                &level[i * 2],
                &level[i * 2 + 1],
            );
        }
        idx >>= 1;
        cur_len = next_len;
    }

    (wots_sig, path, level[0])
}

fn ht_subtree_root(
    sk_seed: &[u8; HASH_BYTES],
    pub_seed: &[u8; HASH_BYTES],
    layer: u8,
    tree_idx: u32,
) -> [u8; HASH_BYTES] {
    let mut level = [[0u8; HASH_BYTES]; SUBTREE_LEAVES];
    for l in 0..SUBTREE_LEAVES {
        level[l] = ht_leaf_pk(sk_seed, pub_seed, layer, tree_idx, l as u32);
    }
    let mut cur_len = SUBTREE_LEAVES;
    for h_lvl in 0..SUBTREE_HEIGHT {
        let next_len = cur_len / 2;
        for i in 0..next_len {
            level[i] = slh_node_hash(
                pub_seed,
                b"WSLH_HND",
                ((layer as u32) << 16) ^ tree_idx,
                ((h_lvl as u32) << 16) ^ (i as u32),
                &level[i * 2],
                &level[i * 2 + 1],
            );
        }
        cur_len = next_len;
    }
    level[0]
}

fn ht_subtree_verify_root(
    pub_seed: &[u8; HASH_BYTES],
    layer: u8,
    tree_idx: u32,
    leaf_idx: u32,
    msg_digest: &[u8; HASH_BYTES],
    wots_sig: &[[u8; HASH_BYTES]; WOTS_LEN],
    path: &[[u8; HASH_BYTES]; SUBTREE_HEIGHT],
) -> [u8; HASH_BYTES] {
    let addr = slh_leaf_addr(layer, tree_idx, leaf_idx);
    let mut cur = wots_recover_leaf_pk_hash(wots_sig, pub_seed, addr, msg_digest);
    let mut idx = leaf_idx as usize;
    for h_lvl in 0..SUBTREE_HEIGHT {
        let parent = idx >> 1;
        let sib = &path[h_lvl];
        cur = if (idx & 1) == 0 {
            slh_node_hash(
                pub_seed,
                b"WSLH_HND",
                ((layer as u32) << 16) ^ tree_idx,
                ((h_lvl as u32) << 16) ^ (parent as u32),
                &cur,
                sib,
            )
        } else {
            slh_node_hash(
                pub_seed,
                b"WSLH_HND",
                ((layer as u32) << 16) ^ tree_idx,
                ((h_lvl as u32) << 16) ^ (parent as u32),
                sib,
                &cur,
            )
        };
        idx = parent;
    }
    cur
}

fn expand_msg_indices(
    randomizer: &[u8; HASH_BYTES],
    pub_seed: &[u8; HASH_BYTES],
    root: &[u8; HASH_BYTES],
    message: &[u8],
) -> ([usize; FORS_TREES], u32, u32) {
    let mut xof = WilisXof::new(b"WSLH_HMSG_V1");
    xof.absorb(randomizer);
    xof.absorb(pub_seed);
    xof.absorb(root);
    xof.absorb(&(message.len() as u64).to_le_bytes());
    xof.absorb(message);

    // 16 bytes for FORS indices (6 bits each) + 2 bytes for (tree_idx: 4b, leaf_idx: 4b)
    let mut raw = [0u8; FORS_TREES + 2];
    xof.squeeze(&mut raw);
    let mut fors_idx = [0usize; FORS_TREES];
    for i in 0..FORS_TREES {
        fors_idx[i] = (raw[i] as usize) & (FORS_LEAVES - 1);
    }
    let tree_idx = (raw[FORS_TREES] as u32) & ((SUBTREE_LEAVES as u32) - 1);
    let leaf_idx = (raw[FORS_TREES + 1] as u32) & ((SUBTREE_LEAVES as u32) - 1);
    (fors_idx, tree_idx, leaf_idx)
}

impl SlhSecretKey {
    /// Generates a fresh stateless post-quantum `WilisSLH` keypair (unlimited signatures).
    pub fn generate() -> Result<(Self, SlhPublicKey)> {
        let mut sk_seed = [0u8; HASH_BYTES];
        let mut sk_prf = [0u8; HASH_BYTES];
        let mut pub_seed = [0u8; HASH_BYTES];
        fill_random(&mut sk_seed)?;
        if let Err(e) = fill_random(&mut sk_prf) {
            zeroize_bytes(&mut sk_seed);
            return Err(e);
        }
        if let Err(e) = fill_random(&mut pub_seed) {
            zeroize_bytes(&mut sk_seed);
            zeroize_bytes(&mut sk_prf);
            return Err(e);
        }

        let root = ht_subtree_root(&sk_seed, &pub_seed, (HT_LAYERS - 1) as u8, 0);
        let pk = SlhPublicKey { pub_seed, root };
        let sk = Self {
            sk_seed,
            sk_prf,
            pub_seed,
            root,
        };
        zeroize_bytes(&mut sk_seed);
        zeroize_bytes(&mut sk_prf);
        Ok((sk, pk))
    }

    /// Returns the public verifying key corresponding to this secret key.
    pub fn public_key(&self) -> SlhPublicKey {
        SlhPublicKey {
            pub_seed: self.pub_seed,
            root: self.root,
        }
    }

    /// Statelessly signs `message` using hedged randomization (does NOT mutate `self`!).
    pub fn sign(&self, message: &[u8]) -> Result<SlhSignature> {
        let mut opt_rand = [0u8; HASH_BYTES];
        fill_random(&mut opt_rand)?;
        let mut prf = WilisMac::new(&self.sk_prf);
        prf.update(b"WSLH_PRF_V1:");
        prf.update(&opt_rand);
        prf.update(&(message.len() as u64).to_le_bytes());
        prf.update(message);
        let randomizer = prf.finalize();
        zeroize_bytes(&mut opt_rand);

        let (fors_idx, tree_idx, leaf_idx) =
            expand_msg_indices(&randomizer, &self.pub_seed, &self.root, message);
        let tree_addr = (tree_idx << 4) | leaf_idx;

        let (fors_secrets, fors_paths, fors_pk) =
            fors_sign_and_pk(&self.sk_seed, &self.pub_seed, tree_addr, &fors_idx);

        // Layer 0 signs FORS public key at (tree_idx, leaf_idx)
        let (wots0, path0, root0) =
            ht_subtree_sign(&self.sk_seed, &self.pub_seed, 0, tree_idx, leaf_idx, &fors_pk);
        // Layer 1 (top) signs Layer-0 root at (0, tree_idx)
        let (wots1, path1, _top_root) =
            ht_subtree_sign(&self.sk_seed, &self.pub_seed, 1, 0, tree_idx, &root0);

        Ok(SlhSignature {
            randomizer,
            fors_secrets,
            fors_paths,
            ht_wots: [wots0, wots1],
            ht_paths: [path0, path1],
        })
    }

    /// Serializes to canonical `WLS1` bytes (`164` bytes with 32-byte checksum).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SLH_SK_BYTES);
        out.extend_from_slice(&SLH_SK_MAGIC);
        out.extend_from_slice(&self.sk_seed);
        out.extend_from_slice(&self.sk_prf);
        out.extend_from_slice(&self.pub_seed);
        out.extend_from_slice(&self.root);
        let chk = hash(&out);
        out.extend_from_slice(&chk);
        out
    }

    /// Parses and mathematically verifies a `WLS1` stateless secret key (including root recomputation).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != SLH_SK_BYTES || data[0..4] != SLH_SK_MAGIC {
            return Err(WilisError::InvalidKey(format!(
                "invalid WilisSLH secret key (expected WLS1, {SLH_SK_BYTES} bytes)"
            )));
        }
        let body = &data[..SLH_SK_BYTES - HASH_BYTES];
        let chk = &data[SLH_SK_BYTES - HASH_BYTES..];
        if !ct_eq(chk, &hash(body)) {
            return Err(WilisError::InvalidKey(
                "WilisSLH secret key failed integrity checksum".into(),
            ));
        }

        let mut sk_seed: [u8; HASH_BYTES] = body[4..36].try_into().expect("32 bytes");
        let mut sk_prf: [u8; HASH_BYTES] = body[36..68].try_into().expect("32 bytes");
        let pub_seed: [u8; HASH_BYTES] = body[68..100].try_into().expect("32 bytes");
        let root: [u8; HASH_BYTES] = body[100..132].try_into().expect("32 bytes");

        let expected_root = ht_subtree_root(&sk_seed, &pub_seed, (HT_LAYERS - 1) as u8, 0);
        if !ct_eq(&root, &expected_root) {
            zeroize_bytes(&mut sk_seed);
            zeroize_bytes(&mut sk_prf);
            return Err(WilisError::InvalidKey(
                "WilisSLH secret key failed hypertree root consistency check".into(),
            ));
        }

        let sk = Self {
            sk_seed,
            sk_prf,
            pub_seed,
            root,
        };
        zeroize_bytes(&mut sk_seed);
        zeroize_bytes(&mut sk_prf);
        Ok(sk)
    }
}

impl SlhPublicKey {
    /// Verifies a stateless `WLSG` signature over `message` in constant time.
    pub fn verify(&self, message: &[u8], sig: &SlhSignature) -> bool {
        let (fors_idx, tree_idx, leaf_idx) =
            expand_msg_indices(&sig.randomizer, &self.pub_seed, &self.root, message);
        let tree_addr = (tree_idx << 4) | leaf_idx;

        let fors_pk = fors_pk_from_sig(
            &self.pub_seed,
            tree_addr,
            &fors_idx,
            &sig.fors_secrets,
            &sig.fors_paths,
        );
        let root0 = ht_subtree_verify_root(
            &self.pub_seed,
            0,
            tree_idx,
            leaf_idx,
            &fors_pk,
            &sig.ht_wots[0],
            &sig.ht_paths[0],
        );
        let recovered_top = ht_subtree_verify_root(
            &self.pub_seed,
            1,
            0,
            tree_idx,
            &root0,
            &sig.ht_wots[1],
            &sig.ht_paths[1],
        );
        ct_eq(&recovered_top, &self.root)
    }

    /// Serializes to canonical `WLP1` bytes (`100` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SLH_PK_BYTES);
        out.extend_from_slice(&SLH_PK_MAGIC);
        out.extend_from_slice(&self.pub_seed);
        out.extend_from_slice(&self.root);
        let chk = hash(&out);
        out.extend_from_slice(&chk);
        out
    }

    /// Parses and checksum-verifies a `WLP1` stateless public key.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != SLH_PK_BYTES || data[0..4] != SLH_PK_MAGIC {
            return Err(WilisError::InvalidKey(format!(
                "invalid WilisSLH public key (expected WLP1, {SLH_PK_BYTES} bytes)"
            )));
        }
        let body = &data[..SLH_PK_BYTES - HASH_BYTES];
        let chk = &data[SLH_PK_BYTES - HASH_BYTES..];
        if !ct_eq(chk, &hash(body)) {
            return Err(WilisError::InvalidKey(
                "WilisSLH public key failed integrity checksum".into(),
            ));
        }
        Ok(Self {
            pub_seed: body[4..36].try_into().expect("32 bytes"),
            root: body[36..68].try_into().expect("32 bytes"),
        })
    }
}

impl SlhSignature {
    /// Serializes the signature to canonical `WLSG` v1 bytes (`8,165` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SLH_SIG_BYTES);
        out.extend_from_slice(&SLH_SIG_MAGIC);
        out.push(SLH_SIG_VER);
        out.extend_from_slice(&self.randomizer);
        for s in &self.fors_secrets {
            out.extend_from_slice(s);
        }
        for p in &self.fors_paths {
            for node in p {
                out.extend_from_slice(node);
            }
        }
        for layer in 0..HT_LAYERS {
            for elem in &self.ht_wots[layer] {
                out.extend_from_slice(elem);
            }
            for node in &self.ht_paths[layer] {
                out.extend_from_slice(node);
            }
        }
        out
    }

    /// Parses a canonical `WLSG` v1 stateless signature.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != SLH_SIG_BYTES
            || data[0..4] != SLH_SIG_MAGIC
            || data[4] != SLH_SIG_VER
        {
            return Err(WilisError::InvalidFormat(format!(
                "invalid WilisSLH signature (expected WLSG v1, {SLH_SIG_BYTES} bytes)"
            )));
        }
        let mut pos = 5;
        let randomizer: [u8; HASH_BYTES] = data[pos..pos + HASH_BYTES].try_into().expect("32 bytes");
        pos += HASH_BYTES;

        let mut fors_secrets = [[0u8; HASH_BYTES]; FORS_TREES];
        for s in &mut fors_secrets {
            s.copy_from_slice(&data[pos..pos + HASH_BYTES]);
            pos += HASH_BYTES;
        }
        let mut fors_paths = [[[0u8; HASH_BYTES]; FORS_HEIGHT]; FORS_TREES];
        for p in &mut fors_paths {
            for node in p {
                node.copy_from_slice(&data[pos..pos + HASH_BYTES]);
                pos += HASH_BYTES;
            }
        }
        let mut ht_wots = [[[0u8; HASH_BYTES]; WOTS_LEN]; HT_LAYERS];
        let mut ht_paths = [[[0u8; HASH_BYTES]; SUBTREE_HEIGHT]; HT_LAYERS];
        for layer in 0..HT_LAYERS {
            for elem in &mut ht_wots[layer] {
                elem.copy_from_slice(&data[pos..pos + HASH_BYTES]);
                pos += HASH_BYTES;
            }
            for node in &mut ht_paths[layer] {
                node.copy_from_slice(&data[pos..pos + HASH_BYTES]);
                pos += HASH_BYTES;
            }
        }

        Ok(Self {
            randomizer,
            fors_secrets,
            fors_paths,
            ht_wots,
            ht_paths,
        })
    }
}
