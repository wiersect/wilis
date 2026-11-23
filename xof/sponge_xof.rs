//! Streaming Extendable-Output Function (`WilisXOF`) powered by `WilisPerm-384`.

use crate::core::constants::{DOMAIN_XOF, RATE_BYTES, ROUNDS_DATA, ROUNDS_FULL};
use crate::core::permute::permute;
use crate::core::state::State;
use crate::utils::zeroize::zeroize_bytes;

/// Arbitrary-length cryptographic sponge XOF (`WilisXOF`).
///
/// Call [`WilisXof::absorb`] any number of times, then call [`WilisXof::squeeze`]
/// as many times as needed to extract an arbitrary-length pseudorandom byte stream.
#[derive(Clone)]
pub struct WilisXof {
    state: State,
    buf: [u8; RATE_BYTES],
    buf_pos: usize,
    squeezing: bool,
}

impl WilisXof {
    /// Creates a new `WilisXOF` initialized with its unique domain separator and optional label.
    pub fn new(domain_label: &[u8]) -> Self {
        let mut state = State::zero();
        state.words[5] = DOMAIN_XOF;
        permute(&mut state, ROUNDS_FULL);

        let mut xof = Self {
            state,
            buf: [0u8; RATE_BYTES],
            buf_pos: 0,
            squeezing: false,
        };
        // Always length-prefix the domain label (even when empty -> 0u64) so
        // ("", seed) can never collide with (non_empty_label, seed2).
        xof.absorb(&(domain_label.len() as u64).to_le_bytes());
        if !domain_label.is_empty() {
            xof.absorb(domain_label);
        }
        xof
    }

    /// Absorbs arbitrary input bytes into the sponge.
    ///
    /// # Panics
    /// Panics if called after [`Self::squeeze`] has already started.
    pub fn absorb(&mut self, mut data: &[u8]) {
        assert!(!self.squeezing, "cannot absorb into WilisXof after squeezing");

        if self.buf_pos > 0 {
            let take = (RATE_BYTES - self.buf_pos).min(data.len());
            self.buf[self.buf_pos..self.buf_pos + take].copy_from_slice(&data[..take]);
            self.buf_pos += take;
            data = &data[take..];

            if self.buf_pos == RATE_BYTES {
                let block = self.buf;
                self.state.xor_rate_block(&block);
                permute(&mut self.state, ROUNDS_DATA);
                self.buf_pos = 0;
            }
        }

        let mut chunks = data.chunks_exact(RATE_BYTES);
        for chunk in chunks.by_ref() {
            let block: &[u8; RATE_BYTES] = chunk.try_into().expect("16-byte XOF block");
            self.state.xor_rate_block(block);
            permute(&mut self.state, ROUNDS_DATA);
        }

        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buf_pos = rem.len();
        }
    }

    /// Transitions from absorption to squeezing mode (idempotent).
    fn finish_absorb(&mut self) {
        if self.squeezing {
            return;
        }
        let mut padded = [0u8; RATE_BYTES];
        padded[..self.buf_pos].copy_from_slice(&self.buf[..self.buf_pos]);
        padded[self.buf_pos] = 0x80;
        self.state.xor_rate_block(&padded);
        self.state.words[5] ^= 0xFF;
        permute(&mut self.state, ROUNDS_FULL);

        self.buf = self.state.rate_bytes();
        self.buf_pos = 0;
        self.squeezing = true;
    }

    /// Squeezes `out.len()` pseudorandom bytes from the sponge into `out`.
    pub fn squeeze(&mut self, mut out: &mut [u8]) {
        self.finish_absorb();

        while !out.is_empty() {
            if self.buf_pos == RATE_BYTES {
                permute(&mut self.state, ROUNDS_DATA);
                self.buf = self.state.rate_bytes();
                self.buf_pos = 0;
            }
            let avail = RATE_BYTES - self.buf_pos;
            let take = avail.min(out.len());
            out[..take].copy_from_slice(&self.buf[self.buf_pos..self.buf_pos + take]);
            self.buf_pos += take;
            out = &mut out[take..];
        }
    }

    /// Convenience helper returning a freshly allocated `len`-byte vector.
    pub fn squeeze_vec(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.squeeze(&mut out);
        out
    }

    /// One-shot helper deriving `len` bytes from `(label, seed)`.
    pub fn derive(domain_label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
        let mut xof = Self::new(domain_label);
        xof.absorb(seed);
        xof.squeeze_vec(len)
    }
}

impl Drop for WilisXof {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.buf);
    }
}
