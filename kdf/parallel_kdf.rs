//! Parallel Multi-Lane Memory-Hard KDF (`WilisKDF` v3 Parallel) using pure-`std` scoped threads.
//!
//! Splits the scratchpad across `lanes` (`1..=16`) independent parallel lanes synchronized
//! at deterministic cross-lane folding barriers between every pass. Output is 100% deterministic
//! regardless of OS thread scheduling, and every lane scratchpad is volatile-zeroized on exit.

use crate::core::constants::{
    DOMAIN_KDF, HASH_BYTES, KEY_BYTES, RATE_BYTES, ROUNDS_DATA, ROUNDS_FULL, SALT_BYTES,
    STATE_WORDS,
};
use crate::core::permute::permute;
use crate::core::state::State;
use crate::error::{Result, WilisError};
use crate::kdf::params::{KdfParams, BLOCKS_PER_MIB};
use crate::utils::zeroize::{zeroize_bytes, zeroize_u64_slice, SecretKey};

/// Configurable work-factor & lane-parallelism parameters for `WilisKDF` v3 Parallel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParallelKdfParams {
    pub memory_blocks: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl ParallelKdfParams {
    /// Interactive 4-lane parallel preset (~16 MiB RAM, 3 passes, 4 lanes).
    pub const INTERACTIVE_4LANE: Self = Self {
        memory_blocks: 16 * BLOCKS_PER_MIB,
        passes: 3,
        lanes: 4,
    };

    /// Fast 4-lane preset for unit tests.
    pub const FAST_TEST: Self = Self {
        memory_blocks: 128,
        passes: 2,
        lanes: 4,
    };

    /// Validates bounds for memory, passes, and parallel lanes (`1..=16`).
    pub fn validate(&self) -> Result<()> {
        KdfParams {
            memory_blocks: self.memory_blocks,
            passes: self.passes,
        }
        .validate()?;
        if self.lanes == 0 || self.lanes > 16 {
            return Err(WilisError::InvalidParameters(format!(
                "KDF parallel lanes {} out of range [1..=16]",
                self.lanes
            )));
        }
        if (self.memory_blocks / self.lanes) < 4 {
            return Err(WilisError::InvalidParameters(
                "KDF memory_blocks must allocate at least 4 blocks per lane".into(),
            ));
        }
        Ok(())
    }
}

#[inline]
fn lane_independent_ref(idx: usize) -> usize {
    if idx <= 1 {
        return 0;
    }
    let mut x = (idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    (x % (idx as u64)) as usize
}

/// Derives a 256-bit [`SecretKey`] using multi-lane parallel memory-hard `WilisKDF` v3.
pub fn derive_key_parallel(
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    salt: &[u8; SALT_BYTES],
    params: ParallelKdfParams,
) -> Result<SecretKey> {
    params.validate()?;

    let s0 = u64::from_le_bytes(salt[0..8].try_into().expect("8 bytes"));
    let s1 = u64::from_le_bytes(salt[8..16].try_into().expect("8 bytes"));
    let s2 = u64::from_le_bytes(salt[16..24].try_into().expect("8 bytes"));
    let param_word = ((params.memory_blocks as u64) << 32)
        | ((params.passes as u64) << 8)
        | (params.lanes as u64);
    let keyfile_flag: u64 = if keyfile_hash.is_some() { 1 } else { 0 };

    // Distinct domain tag `WKDF_P3` mixed into DOMAIN_KDF
    let mut base = State::from_words([
        DOMAIN_KDF ^ 0x5033_0000_0000_0000 ^ keyfile_flag,
        param_word,
        passphrase.len() as u64,
        s0,
        s1,
        s2,
    ]);
    permute(&mut base, ROUNDS_FULL);

    let mut chunks = passphrase.chunks_exact(RATE_BYTES);
    for chunk in chunks.by_ref() {
        let block: &[u8; RATE_BYTES] = chunk.try_into().expect("16 bytes");
        base.xor_rate_block(block);
        permute(&mut base, ROUNDS_DATA);
    }
    let rem = chunks.remainder();
    let mut padded = [0u8; RATE_BYTES];
    padded[..rem.len()].copy_from_slice(rem);
    padded[rem.len()] = 0x80;
    base.xor_rate_block(&padded);
    zeroize_bytes(&mut padded);
    permute(&mut base, ROUNDS_FULL);

    if let Some(kf) = keyfile_hash {
        base.words[5] ^= 0x4B46_5F32_4641_0003;
        base.xor_rate_block(kf[0..16].try_into().expect("16 bytes"));
        permute(&mut base, ROUNDS_DATA);
        base.xor_rate_block(kf[16..32].try_into().expect("16 bytes"));
        permute(&mut base, ROUNDS_FULL);
    }

    let lanes = params.lanes as usize;
    let blocks_per_lane = (params.memory_blocks as usize) / lanes;
    let mut lane_tables: Vec<Vec<[u64; STATE_WORDS]>> = (0..lanes)
        .map(|_| vec![[0u64; STATE_WORDS]; blocks_per_lane])
        .collect();
    let mut lane_heads: Vec<[u64; STATE_WORDS]> = (0..lanes)
        .map(|lane_id| {
            let mut st = base.clone();
            st.words[4] ^= (lane_id as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            permute(&mut st, ROUNDS_DATA);
            st.words
        })
        .collect();

    // Pass 0: Parallel data-independent memory fill across all lanes
    std::thread::scope(|scope| {
        for (lane_id, (table, head)) in lane_tables
            .iter_mut()
            .zip(lane_heads.iter_mut())
            .enumerate()
        {
            scope.spawn(move || {
                let mut acc = State::from_words(*head);
                table[0] = acc.words;
                for idx in 1..blocks_per_lane {
                    let ref_idx = lane_independent_ref(idx);
                    let prev = table[idx - 1];
                    let rblk = table[ref_idx];
                    for i in 0..STATE_WORDS {
                        acc.words[i] ^= prev[i] ^ rblk[i];
                    }
                    acc.words[0] = acc.words[0].wrapping_add(((lane_id as u64) << 32) | (idx as u64));
                    permute(&mut acc, ROUNDS_DATA);
                    table[idx] = acc.words;
                }
                *head = acc.words;
            });
        }
    });

    // Passes 1..T: Deterministic cross-lane barrier fold followed by parallel data-dependent sweeps
    let len_u64 = blocks_per_lane as u64;
    for pass in 1..params.passes {
        // Cross-lane fold: each lane mixes the previous pass's terminal state of its neighbor
        let mut snapshot = lane_heads.clone();
        for lane_id in 0..lanes {
            let neighbor = snapshot[(lane_id + 1) % lanes];
            for i in 0..STATE_WORDS {
                lane_heads[lane_id][i] ^= neighbor[i];
            }
        }
        for s in &mut snapshot {
            zeroize_u64_slice(s);
        }
        std::thread::scope(|scope| {
            for (lane_id, (table, head)) in lane_tables
                .iter_mut()
                .zip(lane_heads.iter_mut())
                .enumerate()
            {
                scope.spawn(move || {
                    let mut acc = State::from_words(*head);
                    for idx in 0..blocks_per_lane {
                        let pick = ((acc.words[0] ^ acc.words[3].rotate_left(17)) % len_u64) as usize;
                        let picked = table[pick];
                        let current = table[idx];
                        for i in 0..STATE_WORDS {
                            acc.words[i] ^= picked[i] ^ current[i];
                        }
                        acc.words[1] = acc.words[1].wrapping_add(
                            ((pass as u64) << 40) | ((lane_id as u64) << 32) | (idx as u64),
                        );
                        permute(&mut acc, ROUNDS_DATA);
                        for i in 0..STATE_WORDS {
                            table[idx][i] ^= acc.words[i];
                        }
                    }
                    *head = acc.words;
                });
            }
        });
    }

    // Final cross-lane fold & squeeze 256-bit SecretKey
    let mut final_acc = base;
    for (lane_id, table) in lane_tables.iter().enumerate() {
        let last = table[blocks_per_lane - 1];
        for i in 0..STATE_WORDS {
            final_acc.words[i] ^= last[i] ^ lane_heads[lane_id][i];
        }
        permute(&mut final_acc, ROUNDS_DATA);
    }
    permute(&mut final_acc, ROUNDS_FULL);

    let mut key_bytes = [0u8; KEY_BYTES];
    key_bytes[0..RATE_BYTES].copy_from_slice(&final_acc.rate_bytes());
    permute(&mut final_acc, ROUNDS_FULL);
    key_bytes[RATE_BYTES..KEY_BYTES].copy_from_slice(&final_acc.rate_bytes());

    // Zeroize every lane scratchpad and lane head before returning
    for table in &mut lane_tables {
        for slot in table.iter_mut() {
            zeroize_u64_slice(slot);
        }
    }
    for head in &mut lane_heads {
        zeroize_u64_slice(head);
    }

    let sk = SecretKey::from_bytes(key_bytes);
    zeroize_bytes(&mut key_bytes);
    Ok(sk)
}
