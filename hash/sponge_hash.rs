//! Streaming and one-shot 256-bit cryptographic sponge hash (`WilisHash-256`).
//!
//! Uses a 128-bit rate and 256-bit capacity (`WilisPerm-384`) for a 128-bit
//! collision-resistance margin and 256-bit preimage-resistance target.

use crate::core::constants::{DOMAIN_HASH, HASH_BYTES, RATE_BYTES, ROUNDS_DATA, ROUNDS_FULL};
use crate::core::permute::permute;
use crate::core::state::State;
use crate::utils::hex::encode_hex;

/// Incremental sponge hasher producing a 256-bit (32-byte) digest.
#[derive(Clone)]
pub struct WilisHash {
    state: State,
    buffer: [u8; RATE_BYTES],
    buf_len: usize,
}

impl WilisHash {
    /// Creates a new `WilisHash-256` hasher initialized with its unique domain separator.
    pub fn new() -> Self {
        let mut state = State::zero();
        state.words[5] = DOMAIN_HASH;
        permute(&mut state, ROUNDS_FULL);
        Self {
            state,
            buffer: [0u8; RATE_BYTES],
            buf_len: 0,
        }
    }

    /// Absorbs arbitrary input bytes into the running hash state.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let needed = RATE_BYTES - self.buf_len;
            let take = needed.min(data.len());
            self.buffer[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];

            if self.buf_len == RATE_BYTES {
                let block = self.buffer;
                self.state.xor_rate_block(&block);
                permute(&mut self.state, ROUNDS_DATA);
                self.buf_len = 0;
            }
        }

        let mut chunks = data.chunks_exact(RATE_BYTES);
        for chunk in chunks.by_ref() {
            let block: &[u8; RATE_BYTES] = chunk.try_into().expect("16-byte hash block");
            self.state.xor_rate_block(block);
            permute(&mut self.state, ROUNDS_DATA);
        }

        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.buffer[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
    }

    /// Finalizes absorption with `0x80` padding and squeezes a 32-byte digest.
    pub fn finalize(mut self) -> [u8; HASH_BYTES] {
        let mut padded = [0u8; RATE_BYTES];
        padded[..self.buf_len].copy_from_slice(&self.buffer[..self.buf_len]);
        padded[self.buf_len] = 0x80;
        self.state.xor_rate_block(&padded);
        permute(&mut self.state, ROUNDS_FULL);

        let mut digest = [0u8; HASH_BYTES];
        digest[0..RATE_BYTES].copy_from_slice(&self.state.rate_bytes());
        permute(&mut self.state, ROUNDS_FULL);
        digest[RATE_BYTES..HASH_BYTES].copy_from_slice(&self.state.rate_bytes());
        digest
    }
}

impl Default for WilisHash {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the 256-bit `WilisHash-256` digest of `data` in one call.
pub fn hash(data: &[u8]) -> [u8; HASH_BYTES] {
    let mut hasher = WilisHash::new();
    hasher.update(data);
    hasher.finalize()
}

/// Computes the 256-bit `WilisHash-256` digest of `data` as a 64-char hex string.
pub fn hash_hex(data: &[u8]) -> String {
    encode_hex(&hash(data))
}
