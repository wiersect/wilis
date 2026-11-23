//! 384-bit internal sponge state representation (`6 x u64`).
//!
//! Layout:
//! - Words `0..2` (16 bytes / 128 bits): **Rate** — interacts with external data.
//! - Words `2..6` (32 bytes / 256 bits): **Capacity** — hidden security core.
//!
//! The state automatically zeroizes its contents when dropped.

use crate::core::constants::{RATE_BYTES, STATE_BYTES, STATE_WORDS};
use crate::utils::zeroize::zeroize_u64_slice;

/// Internal 384-bit permutation state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub words: [u64; STATE_WORDS],
}

impl State {
    /// Creates an all-zero 384-bit state.
    pub fn zero() -> Self {
        Self {
            words: [0u64; STATE_WORDS],
        }
    }

    /// Creates a state directly from 6 little-endian 64-bit words.
    pub fn from_words(words: [u64; STATE_WORDS]) -> Self {
        Self { words }
    }

    /// Parses a 48-byte little-endian array into a 384-bit state.
    pub fn from_bytes(bytes: &[u8; STATE_BYTES]) -> Self {
        let mut words = [0u64; STATE_WORDS];
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            words[i] = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        }
        Self { words }
    }

    /// Serializes the full 384-bit state to 48 little-endian bytes.
    pub fn to_bytes(&self) -> [u8; STATE_BYTES] {
        let mut out = [0u8; STATE_BYTES];
        for (i, word) in self.words.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Reads the 16-byte (128-bit) rate portion of the state in little-endian order.
    #[inline]
    pub fn rate_bytes(&self) -> [u8; RATE_BYTES] {
        let mut out = [0u8; RATE_BYTES];
        out[0..8].copy_from_slice(&self.words[0].to_le_bytes());
        out[8..16].copy_from_slice(&self.words[1].to_le_bytes());
        out
    }

    /// Overwrites the 16-byte rate portion of the state from little-endian bytes.
    #[inline]
    pub fn set_rate_bytes(&mut self, rate: &[u8; RATE_BYTES]) {
        self.words[0] = u64::from_le_bytes(rate[0..8].try_into().expect("8-byte slice"));
        self.words[1] = u64::from_le_bytes(rate[8..16].try_into().expect("8-byte slice"));
    }

    /// XORs a full 16-byte block into the rate words.
    #[inline]
    pub fn xor_rate_block(&mut self, block: &[u8; RATE_BYTES]) {
        let w0 = u64::from_le_bytes(block[0..8].try_into().expect("8-byte slice"));
        let w1 = u64::from_le_bytes(block[8..16].try_into().expect("8-byte slice"));
        self.words[0] ^= w0;
        self.words[1] ^= w1;
    }

    /// XORs a 32-byte (256-bit) key into the four capacity words (`words[2..6]`).
    #[inline]
    pub fn xor_capacity_key(&mut self, key: &[u8; 32]) {
        for i in 0..4 {
            let word = u64::from_le_bytes(key[i * 8..(i + 1) * 8].try_into().expect("8-byte slice"));
            self.words[2 + i] ^= word;
        }
    }

    /// Explicitly clears all words in memory.
    pub fn clear(&mut self) {
        zeroize_u64_slice(&mut self.words);
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.clear();
    }
}
