//! `WilisSign` keypair generation, signing, verification, and binary serialization.

use crate::core::constants::HASH_BYTES;
use crate::error::{Result, WilisError};
use crate::hash::WilisHash;
use crate::sign::merkle::{build_merkle_tree, compute_root_from_path, extract_auth_path};
use crate::sign::wots::{wots_recover_leaf_pk_hash, wots_sign_digest, WOTS_LEN};
use crate::utils::constant_time::ct_eq;
use crate::utils::random::fill_random;
use crate::utils::zeroize::zeroize_bytes;

/// Default Merkle tree height (`2^6 = 64` one-time signatures per keypair).
pub const DEFAULT_TREE_HEIGHT: u8 = 6;

/// Minimum supported Merkle tree height (`2^2 = 4` signatures).
pub const MIN_TREE_HEIGHT: u8 = 2;

/// Maximum supported Merkle tree height (`2^10 = 1024` signatures).
pub const MAX_TREE_HEIGHT: u8 = 10;

const SK_MAGIC: [u8; 4] = *b"WSK1";
const PK_MAGIC: [u8; 4] = *b"WPK1";
const SIG_MAGIC: [u8; 4] = *b"WSIG";

/// Public verifying key for `WilisSign` (compact: 65 payload bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    pub height: u8,
    pub pub_seed: [u8; HASH_BYTES],
    pub root: [u8; HASH_BYTES],
}

/// Stateful secret signing key for `WilisSign`. Automatically zeroizes on drop.
#[derive(Clone)]
pub struct SigningKey {
    secret_seed: [u8; HASH_BYTES],
    pub_seed: [u8; HASH_BYTES],
    root: [u8; HASH_BYTES],
    height: u8,
    next_index: u32,
}

/// Post-quantum `WilisSign` signature containing WOTS+ chains and Merkle auth path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub height: u8,
    pub leaf_index: u32,
    pub randomizer: [u8; HASH_BYTES],
    pub wots_sig: [[u8; HASH_BYTES]; WOTS_LEN],
    pub auth_path: Vec<[u8; HASH_BYTES]>,
}

fn hash_randomized_message(
    randomizer: &[u8; HASH_BYTES],
    pub_seed: &[u8; HASH_BYTES],
    root: &[u8; HASH_BYTES],
    leaf_index: u32,
    message: &[u8],
) -> [u8; HASH_BYTES] {
    let mut h = WilisHash::new();
    h.update(b"WSIG_MG1");
    h.update(randomizer);
    h.update(pub_seed);
    h.update(root);
    h.update(&leaf_index.to_le_bytes());
    h.update(&(message.len() as u64).to_le_bytes());
    h.update(message);
    h.finalize()
}

impl SigningKey {
    /// Generates a fresh post-quantum `WilisSign` keypair with Merkle tree height `height`.
    pub fn generate(height: u8) -> Result<(Self, VerifyingKey)> {
        if !(MIN_TREE_HEIGHT..=MAX_TREE_HEIGHT).contains(&height) {
            return Err(WilisError::InvalidParameters(format!(
                "Merkle tree height {height} out of range [{MIN_TREE_HEIGHT}..={MAX_TREE_HEIGHT}]"
            )));
        }

        let mut secret_seed = [0u8; HASH_BYTES];
        let mut pub_seed = [0u8; HASH_BYTES];
        fill_random(&mut secret_seed)?;
        if let Err(e) = fill_random(&mut pub_seed) {
            zeroize_bytes(&mut secret_seed);
            return Err(e);
        }

        let levels = build_merkle_tree(&secret_seed, &pub_seed, height);
        let root = levels[height as usize][0];

        let sk = Self {
            secret_seed,
            pub_seed,
            root,
            height,
            next_index: 0,
        };
        zeroize_bytes(&mut secret_seed);
        let pk = sk.verifying_key();
        Ok((sk, pk))
    }

    /// Returns the corresponding public [`VerifyingKey`].
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            height: self.height,
            pub_seed: self.pub_seed,
            root: self.root,
        }
    }

    /// Returns total signatures supported by this keypair (`2^height`).
    pub fn max_signatures(&self) -> u32 {
        1u32 << self.height
    }

    /// Returns how many unused one-time signatures remain in this Merkle tree.
    pub fn remaining_signatures(&self) -> u32 {
        self.max_signatures().saturating_sub(self.next_index)
    }

    /// Signs `message` using the next unused Merkle leaf and advances `next_index`.
    ///
    /// Fails if all `2^height` one-time keys have been consumed, preventing catastrophic
    /// WOTS+ leaf reuse.
    pub fn sign(&mut self, message: &[u8]) -> Result<Signature> {
        let max_sigs = self.max_signatures();
        if self.next_index >= max_sigs {
            return Err(WilisError::InvalidKey(format!(
                "signing key exhausted: all {max_sigs} one-time signatures have been used; generate a new keypair"
            )));
        }

        // Draw OS randomness BEFORE advancing next_index so RNG failure never burns a leaf
        let mut randomizer = [0u8; HASH_BYTES];
        fill_random(&mut randomizer)?;

        let leaf_index = self.next_index;
        self.next_index += 1;

        let digest = hash_randomized_message(
            &randomizer,
            &self.pub_seed,
            &self.root,
            leaf_index,
            message,
        );

        let wots_sig = wots_sign_digest(&self.secret_seed, &self.pub_seed, leaf_index, &digest);
        let levels = build_merkle_tree(&self.secret_seed, &self.pub_seed, self.height);
        let auth_path = extract_auth_path(&levels, leaf_index);

        Ok(Signature {
            height: self.height,
            leaf_index,
            randomizer,
            wots_sig,
            auth_path,
        })
    }

    /// Serializes the secret key with a `WSK1` magic header and 32-byte integrity digest.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 4 + HASH_BYTES * 3 + HASH_BYTES);
        out.extend_from_slice(&SK_MAGIC);
        out.push(self.height);
        out.extend_from_slice(&self.next_index.to_le_bytes());
        out.extend_from_slice(&self.secret_seed);
        out.extend_from_slice(&self.pub_seed);
        out.extend_from_slice(&self.root);
        let checksum = crate::hash::hash(&out);
        out.extend_from_slice(&checksum);
        out
    }

    /// Parses and integrity-checks a serialized `WSK1` secret key.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let expected_len = 4 + 1 + 4 + HASH_BYTES * 4;
        if data.len() != expected_len || data[0..4] != SK_MAGIC {
            return Err(WilisError::InvalidKey(
                "invalid or corrupted WilisSign secret key (expected WSK1)".into(),
            ));
        }

        let body = &data[..expected_len - HASH_BYTES];
        let stored_chk = &data[expected_len - HASH_BYTES..];
        let computed_chk = crate::hash::hash(body);
        if !ct_eq(stored_chk, &computed_chk) {
            return Err(WilisError::InvalidKey(
                "WilisSign secret key failed integrity verification".into(),
            ));
        }

        let height = body[4];
        if !(MIN_TREE_HEIGHT..=MAX_TREE_HEIGHT).contains(&height) {
            return Err(WilisError::InvalidKey(format!(
                "invalid Merkle height in secret key: {height}"
            )));
        }
        let next_index = u32::from_le_bytes(body[5..9].try_into().expect("4 bytes"));
        if next_index > (1u32 << height) {
            return Err(WilisError::InvalidKey(format!(
                "corrupted next_index {next_index} exceeds tree capacity {}",
                1u32 << height
            )));
        }
        let mut secret_seed = [0u8; HASH_BYTES];
        let mut pub_seed = [0u8; HASH_BYTES];
        let mut root = [0u8; HASH_BYTES];
        secret_seed.copy_from_slice(&body[9..9 + HASH_BYTES]);
        pub_seed.copy_from_slice(&body[9 + HASH_BYTES..9 + HASH_BYTES * 2]);
        root.copy_from_slice(&body[9 + HASH_BYTES * 2..9 + HASH_BYTES * 3]);

        let sk = Self {
            secret_seed,
            pub_seed,
            root,
            height,
            next_index,
        };
        zeroize_bytes(&mut secret_seed);
        Ok(sk)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.secret_seed);
    }
}

impl VerifyingKey {
    /// Verifies `signature` over `message` in constant time.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        if !(MIN_TREE_HEIGHT..=MAX_TREE_HEIGHT).contains(&self.height) {
            return false;
        }
        if signature.height != self.height {
            return false;
        }
        if signature.auth_path.len() != self.height as usize {
            return false;
        }
        if signature.leaf_index >= (1u32 << self.height) {
            return false;
        }

        let digest = hash_randomized_message(
            &signature.randomizer,
            &self.pub_seed,
            &self.root,
            signature.leaf_index,
            message,
        );

        let leaf_hash = wots_recover_leaf_pk_hash(
            &signature.wots_sig,
            &self.pub_seed,
            signature.leaf_index,
            &digest,
        );
        let recovered_root = compute_root_from_path(
            &self.pub_seed,
            leaf_hash,
            signature.leaf_index,
            &signature.auth_path,
        );

        ct_eq(&recovered_root, &self.root)
    }

    /// Serializes the public key (`WPK1` header + height + pub_seed + root + checksum).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + HASH_BYTES * 3);
        out.extend_from_slice(&PK_MAGIC);
        out.push(self.height);
        out.extend_from_slice(&self.pub_seed);
        out.extend_from_slice(&self.root);
        let checksum = crate::hash::hash(&out);
        out.extend_from_slice(&checksum);
        out
    }

    /// Parses and integrity-checks a serialized `WPK1` public key.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let expected_len = 4 + 1 + HASH_BYTES * 3;
        if data.len() != expected_len || data[0..4] != PK_MAGIC {
            return Err(WilisError::InvalidKey(
                "invalid or corrupted WilisSign public key (expected WPK1)".into(),
            ));
        }

        let body = &data[..expected_len - HASH_BYTES];
        let stored_chk = &data[expected_len - HASH_BYTES..];
        let computed_chk = crate::hash::hash(body);
        if !ct_eq(stored_chk, &computed_chk) {
            return Err(WilisError::InvalidKey(
                "WilisSign public key failed integrity verification".into(),
            ));
        }

        let height = body[4];
        if !(MIN_TREE_HEIGHT..=MAX_TREE_HEIGHT).contains(&height) {
            return Err(WilisError::InvalidKey(format!(
                "invalid Merkle height in public key: {height}"
            )));
        }

        let mut pub_seed = [0u8; HASH_BYTES];
        let mut root = [0u8; HASH_BYTES];
        pub_seed.copy_from_slice(&body[5..5 + HASH_BYTES]);
        root.copy_from_slice(&body[5 + HASH_BYTES..5 + HASH_BYTES * 2]);

        Ok(Self {
            height,
            pub_seed,
            root,
        })
    }
}

impl Signature {
    /// Serializes the signature into canonical `WSIG` v1 binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let total = 4 + 1 + 1 + 4 + HASH_BYTES + (WOTS_LEN + self.auth_path.len()) * HASH_BYTES;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&SIG_MAGIC);
        out.push(1u8); // version
        out.push(self.height);
        out.extend_from_slice(&self.leaf_index.to_le_bytes());
        out.extend_from_slice(&self.randomizer);
        for elem in &self.wots_sig {
            out.extend_from_slice(elem);
        }
        for node in &self.auth_path {
            out.extend_from_slice(node);
        }
        out
    }

    /// Parses a `WSIG` v1 binary signature.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 10 + HASH_BYTES || data[0..4] != SIG_MAGIC || data[4] != 1 {
            return Err(WilisError::InvalidFormat(
                "invalid or unsupported WilisSign signature format".into(),
            ));
        }

        let height = data[5];
        if !(MIN_TREE_HEIGHT..=MAX_TREE_HEIGHT).contains(&height) {
            return Err(WilisError::InvalidFormat(format!(
                "invalid signature Merkle height: {height}"
            )));
        }
        let expected_len = 10 + HASH_BYTES + (WOTS_LEN + height as usize) * HASH_BYTES;
        if data.len() != expected_len {
            return Err(WilisError::InvalidFormat(format!(
                "invalid signature length: expected {expected_len}, got {}",
                data.len()
            )));
        }

        let leaf_index = u32::from_le_bytes(data[6..10].try_into().expect("4 bytes"));
        if leaf_index >= (1u32 << height) {
            return Err(WilisError::InvalidFormat(format!(
                "signature leaf_index {leaf_index} out of range for height {height}"
            )));
        }
        let mut pos = 10;

        let mut randomizer = [0u8; HASH_BYTES];
        randomizer.copy_from_slice(&data[pos..pos + HASH_BYTES]);
        pos += HASH_BYTES;

        let mut wots_sig = [[0u8; HASH_BYTES]; WOTS_LEN];
        for elem in &mut wots_sig {
            elem.copy_from_slice(&data[pos..pos + HASH_BYTES]);
            pos += HASH_BYTES;
        }

        let mut auth_path = Vec::with_capacity(height as usize);
        for _ in 0..height {
            let mut node = [0u8; HASH_BYTES];
            node.copy_from_slice(&data[pos..pos + HASH_BYTES]);
            auth_path.push(node);
            pos += HASH_BYTES;
        }

        Ok(Self {
            height,
            leaf_index,
            randomizer,
            wots_sig,
            auth_path,
        })
    }
}
