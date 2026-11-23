//! `WilisKDF` — Hybrid memory-hard Key Derivation Function built exclusively
//! on `WilisPerm-384`.
//!
//! Security model (inspired by hybrid memory-hard constructions, 100% custom):
//! - **Pass 0 (Data-Independent Indexing):** Populates the multi-megabyte scratchpad
//!   using deterministic non-secret indices, resisting cache-timing side channels.
//! - **Passes 1..T (Data-Dependent Indexing):** Sweeps the entire scratchpad using
//!   state-derived pseudo-random lookups with XOR-accumulation, resisting time-memory
//!   tradeoff (TMTO) and GPU/ASIC parallel brute-force attacks.
//! - **Optional 2FA Keyfile Mixing:** Cryptographically binds an external keyfile's
//!   `WilisHash-256` digest alongside the passphrase.
//! - **Volatile Zeroization:** Wipes the entire multi-megabyte scratchpad before returning.

use crate::core::constants::{
    DOMAIN_KDF, HASH_BYTES, KEY_BYTES, RATE_BYTES, ROUNDS_DATA, ROUNDS_FULL, SALT_BYTES,
    STATE_WORDS,
};
use crate::core::permute::permute;
use crate::core::state::State;
use crate::error::Result;
use crate::kdf::params::KdfParams;
use crate::utils::zeroize::{zeroize_bytes, zeroize_u64_slice, SecretKey};

/// Deterministic non-secret index mixer for Pass 0 (avoids secret-dependent memory access).
#[inline]
fn independent_ref_index(idx: usize) -> usize {
    if idx <= 1 {
        return 0;
    }
    // Weyl-mixed quadratic hash strictly over the public slot index `idx`.
    // Compute modulo in u64 before casting to usize for 32-bit/64-bit determinism.
    let mut x = (idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    (x % (idx as u64)) as usize
}

/// Derives a 256-bit [`SecretKey`] from a passphrase and 192-bit salt.
pub fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_BYTES],
    params: KdfParams,
) -> Result<SecretKey> {
    derive_key_with_keyfile(passphrase, None, salt, params)
}

/// Derives a 256-bit [`SecretKey`] from a passphrase, optional 256-bit keyfile hash,
/// and 192-bit salt using the hybrid memory-hard `WilisKDF`.
pub fn derive_key_with_keyfile(
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    salt: &[u8; SALT_BYTES],
    params: KdfParams,
) -> Result<SecretKey> {
    params.validate()?;

    let s0 = u64::from_le_bytes(salt[0..8].try_into().expect("8 bytes"));
    let s1 = u64::from_le_bytes(salt[8..16].try_into().expect("8 bytes"));
    let s2 = u64::from_le_bytes(salt[16..24].try_into().expect("8 bytes"));
    let param_word = ((params.memory_blocks as u64) << 32) | (params.passes as u64);
    let keyfile_flag: u64 = if keyfile_hash.is_some() { 1 } else { 0 };

    // Phase 1: Absorb domain, work parameters, keyfile flag, passphrase length, and salt
    let mut acc = State::from_words([
        DOMAIN_KDF ^ keyfile_flag,
        param_word,
        passphrase.len() as u64,
        s0,
        s1,
        s2,
    ]);
    permute(&mut acc, ROUNDS_FULL);

    // Absorb passphrase
    let mut chunks = passphrase.chunks_exact(RATE_BYTES);
    for chunk in chunks.by_ref() {
        let block: &[u8; RATE_BYTES] = chunk.try_into().expect("16-byte chunk");
        acc.xor_rate_block(block);
        permute(&mut acc, ROUNDS_DATA);
    }
    let rem = chunks.remainder();
    let mut padded = [0u8; RATE_BYTES];
    padded[..rem.len()].copy_from_slice(rem);
    padded[rem.len()] = 0x80;
    acc.xor_rate_block(&padded);
    zeroize_bytes(&mut padded);
    permute(&mut acc, ROUNDS_FULL);

    // Optionally absorb 256-bit keyfile digest with domain separator
    if let Some(kf) = keyfile_hash {
        acc.words[5] ^= 0x4B46_5F32_4641_0001; // "KF_2FA\0\x01"
        acc.xor_rate_block(kf[0..16].try_into().expect("16 bytes"));
        permute(&mut acc, ROUNDS_DATA);
        acc.xor_rate_block(kf[16..32].try_into().expect("16 bytes"));
        permute(&mut acc, ROUNDS_FULL);
    }

    // Phase 2 (Pass 0): Data-independent memory fill (resists cache-timing side channels)
    let mem_len = params.memory_blocks as usize;
    let mut table: Vec<[u64; STATE_WORDS]> = Vec::with_capacity(mem_len);

    permute(&mut acc, ROUNDS_DATA);
    table.push(acc.words);

    for idx in 1..mem_len {
        let ref_idx = independent_ref_index(idx);
        let prev = table[idx - 1];
        let ref_block = table[ref_idx];
        for i in 0..STATE_WORDS {
            acc.words[i] ^= prev[i] ^ ref_block[i];
        }
        acc.words[0] = acc.words[0].wrapping_add(idx as u64);
        permute(&mut acc, ROUNDS_DATA);
        table.push(acc.words);
    }

    // Phase 3 (Passes 1..passes): Data-dependent memory sweeps (resists TMTO & GPU cracking)
    let mem_len_u64 = mem_len as u64;
    for pass in 1..params.passes {
        for idx in 0..mem_len {
            // Compute modulo in u64 before casting to usize for exact 32-bit/64-bit determinism
            let pick_idx = ((acc.words[0] ^ acc.words[3].rotate_left(17)) % mem_len_u64) as usize;
            let picked = table[pick_idx];
            let current = table[idx];
            for i in 0..STATE_WORDS {
                acc.words[i] ^= picked[i] ^ current[i];
            }
            acc.words[1] = acc.words[1].wrapping_add(((pass as u64) << 32) | (idx as u64));
            permute(&mut acc, ROUNDS_DATA);
            for i in 0..STATE_WORDS {
                table[idx][i] ^= acc.words[i];
            }
        }
    }

    // Phase 4: Strided final fold across the scratchpad & squeeze 256-bit SecretKey
    let stride = (mem_len / 16).max(1);
    let mut pos = mem_len - 1;
    for _ in 0..16 {
        for i in 0..STATE_WORDS {
            acc.words[i] ^= table[pos][i];
        }
        permute(&mut acc, ROUNDS_DATA);
        pos = pos.saturating_sub(stride);
    }
    permute(&mut acc, ROUNDS_FULL);

    let mut key_bytes = [0u8; KEY_BYTES];
    key_bytes[0..RATE_BYTES].copy_from_slice(&acc.rate_bytes());
    permute(&mut acc, ROUNDS_FULL);
    key_bytes[RATE_BYTES..KEY_BYTES].copy_from_slice(&acc.rate_bytes());

    // Zeroize the entire memory-hard scratchpad and stack key copy before releasing
    for slot in table.iter_mut() {
        zeroize_u64_slice(slot);
    }

    let secret_key = SecretKey::from_bytes(key_bytes);
    zeroize_bytes(&mut key_bytes);
    Ok(secret_key)
}
