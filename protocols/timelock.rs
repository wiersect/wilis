//! Sequential Iterated-Permutation Time-Lock Puzzle (`WilisTimeLock`).
//!
//! Locks a plaintext payload behind `iterations` strictly sequential `WilisPerm-384`
//! evaluations (`P^T(seed)`). Because every iteration depends serially on the previous
//! state, solving the puzzle cannot be parallelized across CPU/GPU cores.

use crate::aead::{open, seal};
use crate::core::constants::{KEY_BYTES, NONCE_BYTES, ROUNDS_DATA, ROUNDS_FULL, TAG_BYTES};
use crate::core::permute::permute;
use crate::core::state::State;
use crate::error::{Result, WilisError};
use crate::utils::random::{fill_random, generate_nonce};
use crate::utils::zeroize::zeroize_bytes;

const TIMELOCK_MAGIC: [u8; 4] = *b"WTLK";
const TIMELOCK_VERSION: u8 = 1;

/// Maximum iterations allowed per puzzle call to prevent accidental infinite locks (`100M`).
pub const MAX_TIMELOCK_ITERATIONS: u64 = 100_000_000;

/// Self-contained `WTLK` v1 time-lock puzzle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeLockPuzzle {
    pub iterations: u64,
    pub seed: [u8; 32],
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_BYTES],
}

fn evaluate_sequential_delay(seed: &[u8; 32], iterations: u64) -> [u8; KEY_BYTES] {
    let mut state = State::zero();
    state.words[0] = 0x5754_4C4B_5F56_3031; // "WTLK_V01"
    state.words[1] = iterations;
    state.xor_capacity_key(seed);
    permute(&mut state, ROUNDS_FULL);

    for step in 0..iterations {
        state.words[0] ^= step;
        permute(&mut state, ROUNDS_DATA);
    }
    permute(&mut state, ROUNDS_FULL);

    let mut key = [0u8; KEY_BYTES];
    key[0..16].copy_from_slice(&state.rate_bytes());
    permute(&mut state, ROUNDS_FULL);
    key[16..32].copy_from_slice(&state.rate_bytes());
    key
}

fn timelock_aad(iterations: u64, seed: &[u8; 32], nonce: &[u8; NONCE_BYTES], user_aad: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity((8 + 8 + 32 + NONCE_BYTES + 8).saturating_add(user_aad.len()));
    aad.extend_from_slice(b"WTLK_V1:");
    aad.extend_from_slice(&iterations.to_le_bytes());
    aad.extend_from_slice(seed);
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(&(user_aad.len() as u64).to_le_bytes());
    aad.extend_from_slice(user_aad);
    aad
}

impl TimeLockPuzzle {
    /// Seals `plaintext` behind `iterations` (`1..=MAX_TIMELOCK_ITERATIONS`) sequential steps.
    pub fn lock(plaintext: &[u8], user_aad: &[u8], iterations: u64) -> Result<Self> {
        if iterations == 0 || iterations > MAX_TIMELOCK_ITERATIONS {
            return Err(WilisError::InvalidParameters(format!(
                "timelock iterations {iterations} out of range [1..={MAX_TIMELOCK_ITERATIONS}]"
            )));
        }
        let mut seed = [0u8; 32];
        fill_random(&mut seed)?;
        let nonce = generate_nonce()?;
        let mut key = evaluate_sequential_delay(&seed, iterations);
        let aad = timelock_aad(iterations, &seed, &nonce, user_aad);
        let (ciphertext, tag) = seal(&key, &nonce, &aad, plaintext);
        zeroize_bytes(&mut key);
        Ok(Self {
            iterations,
            seed,
            nonce,
            ciphertext,
            tag,
        })
    }

    /// Evaluates the sequential delay function and decrypts/verifies the puzzle payload.
    pub fn unlock(&self, user_aad: &[u8]) -> Result<Vec<u8>> {
        if self.iterations == 0 || self.iterations > MAX_TIMELOCK_ITERATIONS {
            return Err(WilisError::InvalidFormat("invalid timelock iteration count".into()));
        }
        let mut key = evaluate_sequential_delay(&self.seed, self.iterations);
        let aad = timelock_aad(self.iterations, &self.seed, &self.nonce, user_aad);
        let res = open(&key, &self.nonce, &aad, &self.ciphertext, &self.tag);
        zeroize_bytes(&mut key);
        res
    }

    /// Serializes to canonical `WTLK` v1 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 8 + 32 + NONCE_BYTES + self.ciphertext.len() + TAG_BYTES);
        out.extend_from_slice(&TIMELOCK_MAGIC);
        out.push(TIMELOCK_VERSION);
        out.extend_from_slice(&self.iterations.to_le_bytes());
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out
    }

    /// Parses a canonical `WTLK` v1 puzzle.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let hdr = 4 + 1 + 8 + 32 + NONCE_BYTES;
        if data.len() < hdr + TAG_BYTES
            || data[0..4] != TIMELOCK_MAGIC
            || data[4] != TIMELOCK_VERSION
        {
            return Err(WilisError::InvalidFormat(
                "invalid or truncated WilisTimeLock (WTLK) puzzle".into(),
            ));
        }
        let iterations = u64::from_le_bytes(data[5..13].try_into().expect("8 bytes"));
        if iterations == 0 || iterations > MAX_TIMELOCK_ITERATIONS {
            return Err(WilisError::InvalidFormat(
                "WTLK iteration count out of safe bounds".into(),
            ));
        }
        let seed: [u8; 32] = data[13..45].try_into().expect("32 bytes");
        let nonce: [u8; NONCE_BYTES] = data[45..45 + NONCE_BYTES].try_into().expect("24 bytes");
        let tag_start = data.len() - TAG_BYTES;
        let ciphertext = data[hdr..tag_start].to_vec();
        let tag: [u8; TAG_BYTES] = data[tag_start..].try_into().expect("32 bytes");
        Ok(Self {
            iterations,
            seed,
            nonce,
            ciphertext,
            tag,
        })
    }
}
