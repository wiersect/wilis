//! Streaming keyed 256-bit MAC (`WilisMAC`) and domain-separated subkey derivation.
//!
//! Because `WilisPerm-384` uses a 256-bit capacity and keys both initialization
//! and finalization (keyed-sponge / KMAC paradigm), `WilisMAC` is immune to
//! length-extension attacks without needing double-hash HMAC wrapping.

use crate::core::constants::{DOMAIN_MAC, KEY_BYTES, RATE_BYTES, ROUNDS_DATA, ROUNDS_FULL, TAG_BYTES};
use crate::core::permute::permute;
use crate::core::state::State;
use crate::utils::constant_time::ct_eq;
use crate::utils::zeroize::{zeroize_bytes, SecretKey};

/// Streaming 256-bit keyed Message Authentication Code.
#[derive(Clone)]
pub struct WilisMac {
    state: State,
    key: [u8; KEY_BYTES],
    buf: [u8; RATE_BYTES],
    buf_len: usize,
}

impl WilisMac {
    /// Creates a new `WilisMAC` instance initialized with a 256-bit key.
    pub fn new(key: &[u8; KEY_BYTES]) -> Self {
        let mut state = State::zero();
        state.words[0] = DOMAIN_MAC;
        state.xor_capacity_key(key);
        permute(&mut state, ROUNDS_FULL);
        // Post-init key whitening
        state.xor_capacity_key(key);

        Self {
            state,
            key: *key,
            buf: [0u8; RATE_BYTES],
            buf_len: 0,
        }
    }

    /// Feeds message bytes into the running MAC state.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (RATE_BYTES - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];

            if self.buf_len == RATE_BYTES {
                let block = self.buf;
                self.state.xor_rate_block(&block);
                permute(&mut self.state, ROUNDS_DATA);
                self.buf_len = 0;
            }
        }

        let mut chunks = data.chunks_exact(RATE_BYTES);
        for chunk in chunks.by_ref() {
            let block: &[u8; RATE_BYTES] = chunk.try_into().expect("16-byte MAC block");
            self.state.xor_rate_block(block);
            permute(&mut self.state, ROUNDS_DATA);
        }

        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
    }

    /// Finalizes the MAC and outputs a keyed 256-bit authentication tag.
    pub fn finalize(mut self) -> [u8; TAG_BYTES] {
        let mut padded = [0u8; RATE_BYTES];
        padded[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        padded[self.buf_len] = 0x80;
        self.state.xor_rate_block(&padded);
        zeroize_bytes(&mut padded);
        self.state.words[5] ^= 0x01;
        self.state.xor_capacity_key(&self.key);
        permute(&mut self.state, ROUNDS_FULL);

        let mut tag = [0u8; TAG_BYTES];
        let mut h1 = self.state.rate_bytes();
        for i in 0..RATE_BYTES {
            tag[i] = h1[i] ^ self.key[i];
        }
        zeroize_bytes(&mut h1);
        permute(&mut self.state, ROUNDS_DATA);
        let mut h2 = self.state.rate_bytes();
        for i in 0..RATE_BYTES {
            tag[RATE_BYTES + i] = h2[i] ^ self.key[RATE_BYTES + i];
        }
        zeroize_bytes(&mut h2);
        tag
    }
}

impl Drop for WilisMac {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.key);
        zeroize_bytes(&mut self.buf);
    }
}

/// Computes a 256-bit `WilisMAC` tag over `message` under `key`.
pub fn mac(key: &[u8; KEY_BYTES], message: &[u8]) -> [u8; TAG_BYTES] {
    let mut m = WilisMac::new(key);
    m.update(message);
    m.finalize()
}

/// Verifies `expected_tag` against `mac(key, message)` in constant time.
pub fn verify_mac(key: &[u8; KEY_BYTES], message: &[u8], expected_tag: &[u8; TAG_BYTES]) -> bool {
    let actual = mac(key, message);
    ct_eq(&actual, expected_tag)
}

/// Derives an independent, domain-separated 256-bit [`SecretKey`] from `master_key` and `context`.
pub fn derive_subkey(master_key: &[u8; KEY_BYTES], context: &[u8]) -> SecretKey {
    let mut m = WilisMac::new(master_key);
    m.update(b"WILS_SUBKEY_V1:");
    m.update(&(context.len() as u64).to_le_bytes());
    m.update(context);
    SecretKey::from_bytes(m.finalize())
}
