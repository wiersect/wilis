//! Forward-secret symmetric chain ratchet (`WilisRatchet`) with replay & out-of-order protection.

use std::collections::BTreeMap;

use crate::aead::{open, seal};
use crate::core::constants::{DOMAIN_RATCHET, KEY_BYTES, NONCE_BYTES, TAG_BYTES};
use crate::error::{Result, WilisError};
use crate::utils::zeroize::{zeroize_bytes, SecretKey};
use crate::xof::WilisXof;

/// Maximum number of skipped out-of-order message keys cached before rejecting a jump (DoS bound).
pub const MAX_SKIP_WINDOW: u64 = 64;

const PACKET_MAGIC: [u8; 4] = *b"WRAT";

/// Authenticated ratcheted message packet (`WRAT` v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetPacket {
    pub counter: u64,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_BYTES],
}

impl RatchetPacket {
    /// Serializes the packet into canonical `WRAT` binary bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 8 + self.ciphertext.len() + TAG_BYTES);
        out.extend_from_slice(&PACKET_MAGIC);
        out.push(1u8);
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out
    }

    /// Parses a canonical `WRAT` binary packet.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 13 + TAG_BYTES || data[0..4] != PACKET_MAGIC || data[4] != 1 {
            return Err(WilisError::InvalidFormat(
                "invalid or truncated WilisRatchet packet".into(),
            ));
        }
        let counter = u64::from_le_bytes(data[5..13].try_into().expect("8 bytes"));
        let tag_start = data.len() - TAG_BYTES;
        let ciphertext = data[13..tag_start].to_vec();
        let tag: [u8; TAG_BYTES] = data[tag_start..].try_into().expect("32-byte tag");
        Ok(Self {
            counter,
            ciphertext,
            tag,
        })
    }
}

/// One-time `(key, nonce)` derived from advancing a chain key once.
struct MessageKeyMaterial {
    key: SecretKey,
    nonce: [u8; NONCE_BYTES],
}

impl Drop for MessageKeyMaterial {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.nonce);
    }
}

/// Advances `chain_key` one step forward in place, returning the one-time message key & nonce.
/// The previous `chain_key` is immediately overwritten (forward secrecy).
fn ratchet_step(chain_key: &mut [u8; KEY_BYTES], counter: u64) -> MessageKeyMaterial {
    let mut xof = WilisXof::new(b"WRAT_STEP_V1");
    xof.absorb(&DOMAIN_RATCHET.to_le_bytes());
    xof.absorb(chain_key);
    xof.absorb(&counter.to_le_bytes());

    let mut material = [0u8; KEY_BYTES + KEY_BYTES + NONCE_BYTES];
    xof.squeeze(&mut material);

    // Overwrite chain key immediately so past states cannot be recovered
    chain_key.copy_from_slice(&material[0..KEY_BYTES]);
    let mut msg_key: [u8; KEY_BYTES] = material[KEY_BYTES..KEY_BYTES * 2]
        .try_into()
        .expect("32 bytes");
    let nonce: [u8; NONCE_BYTES] = material[KEY_BYTES * 2..KEY_BYTES * 2 + NONCE_BYTES]
        .try_into()
        .expect("24 bytes");
    zeroize_bytes(&mut material);

    let key = SecretKey::from_bytes(msg_key);
    zeroize_bytes(&mut msg_key);
    MessageKeyMaterial { key, nonce }
}

fn build_ratchet_aad(counter: u64, user_aad: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(28usize.saturating_add(user_aad.len()));
    aad.extend_from_slice(b"WRAT_MSG_V1:");
    aad.extend_from_slice(&counter.to_le_bytes());
    aad.extend_from_slice(&(user_aad.len() as u64).to_le_bytes());
    aad.extend_from_slice(user_aad);
    aad
}

/// Bidirectional forward-secret symmetric session between an initiator and a responder.
pub struct RatchetSession {
    send_chain: [u8; KEY_BYTES],
    recv_chain: [u8; KEY_BYTES],
    send_counter: u64,
    recv_counter: u64,
    skipped: BTreeMap<u64, MessageKeyMaterial>,
}

impl RatchetSession {
    /// Initializes a session from a shared 256-bit root secret (e.g. from `WilisKEM`).
    ///
    /// Pass `is_initiator = true` on one peer and `is_initiator = false` on the other so
    /// their send/receive chains pair cleanly with distinct keys in each direction.
    pub fn from_shared_secret(root_secret: &[u8; KEY_BYTES], is_initiator: bool) -> Self {
        let mut xof = WilisXof::new(b"WRAT_INIT_V1");
        xof.absorb(&DOMAIN_RATCHET.to_le_bytes());
        xof.absorb(root_secret);

        let mut chains = [0u8; KEY_BYTES * 2];
        xof.squeeze(&mut chains);

        let mut c_a = [0u8; KEY_BYTES];
        let mut c_b = [0u8; KEY_BYTES];
        c_a.copy_from_slice(&chains[0..KEY_BYTES]);
        c_b.copy_from_slice(&chains[KEY_BYTES..KEY_BYTES * 2]);
        zeroize_bytes(&mut chains);

        let (send_chain, recv_chain) = if is_initiator { (c_a, c_b) } else { (c_b, c_a) };
        zeroize_bytes(&mut c_a);
        zeroize_bytes(&mut c_b);
        Self {
            send_chain,
            recv_chain,
            send_counter: 0,
            recv_counter: 0,
            skipped: BTreeMap::new(),
        }
    }

    /// Encrypts the next outgoing message, advancing and zeroizing the previous send chain key.
    ///
    /// # Panics
    /// Panics only if `send_counter` reaches `u64::MAX` (2^64 - 1 messages in one session).
    pub fn encrypt_next(&mut self, plaintext: &[u8], user_aad: &[u8]) -> RatchetPacket {
        let counter = self.send_counter;
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .expect("ratchet send counter exhausted");

        let mk = ratchet_step(&mut self.send_chain, counter);
        let aad = build_ratchet_aad(counter, user_aad);
        let (ciphertext, tag) = seal(mk.key.as_bytes(), &mk.nonce, &aad, plaintext);

        RatchetPacket {
            counter,
            ciphertext,
            tag,
        }
    }

    /// Authenticates and decrypts an incoming [`RatchetPacket`], supporting bounded
    /// out-of-order delivery while rejecting replayed, overflow, or tampered messages.
    pub fn decrypt_packet(&mut self, packet: &RatchetPacket, user_aad: &[u8]) -> Result<Vec<u8>> {
        if packet.counter == u64::MAX {
            return Err(WilisError::AuthenticationFailed);
        }

        let aad = build_ratchet_aad(packet.counter, user_aad);

        // Case 1: Packet arrived out of order and its key is in the skipped cache
        if let Some(mk) = self.skipped.get(&packet.counter) {
            let pt = open(mk.key.as_bytes(), &mk.nonce, &aad, &packet.ciphertext, &packet.tag)?;
            // Consume key only AFTER successful authentication (prevents forged DoS eviction!)
            self.skipped.remove(&packet.counter);
            return Ok(pt);
        }

        // Case 2: Replay of an already-consumed message counter -> reject!
        if packet.counter < self.recv_counter {
            return Err(WilisError::AuthenticationFailed);
        }

        // Case 3: Excessive forward jump -> reject to prevent memory/CPU DoS
        let gap = packet.counter - self.recv_counter;
        if gap > MAX_SKIP_WINDOW || (self.skipped.len() as u64 + gap) > MAX_SKIP_WINDOW * 2 {
            return Err(WilisError::AuthenticationFailed);
        }

        // Speculatively derive keys on a cloned chain so forged packets CANNOT corrupt session state!
        let mut temp_chain = self.recv_chain;
        let mut pending_skipped: Vec<(u64, MessageKeyMaterial)> = Vec::with_capacity(gap as usize);

        for c in self.recv_counter..packet.counter {
            let mk = ratchet_step(&mut temp_chain, c);
            pending_skipped.push((c, mk));
        }
        let target_mk = ratchet_step(&mut temp_chain, packet.counter);

        let res = open(
            target_mk.key.as_bytes(),
            &target_mk.nonce,
            &aad,
            &packet.ciphertext,
            &packet.tag,
        );

        let plaintext = match res {
            Ok(pt) => pt,
            Err(e) => {
                zeroize_bytes(&mut temp_chain);
                return Err(e);
            }
        };

        // Commit state advancement ONLY after authentication succeeds!
        self.recv_chain = temp_chain;
        zeroize_bytes(&mut temp_chain);
        self.recv_counter = packet.counter + 1;
        for (c, mk) in pending_skipped {
            self.skipped.insert(c, mk);
        }

        Ok(plaintext)
    }

    /// Returns the number of outgoing messages sent so far.
    pub fn send_count(&self) -> u64 {
        self.send_counter
    }

    /// Returns the expected next incoming message counter.
    pub fn recv_count(&self) -> u64 {
        self.recv_counter
    }

    /// Serializes the full sensitive symmetric ratchet state (caller MUST encrypt & zeroize).
    pub(crate) fn to_state_bytes(&self) -> Vec<u8> {
        let cap = KEY_BYTES * 2 + 8 + 8 + 4 + self.skipped.len() * (8 + KEY_BYTES + NONCE_BYTES);
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(&self.send_chain);
        out.extend_from_slice(&self.recv_chain);
        out.extend_from_slice(&self.send_counter.to_le_bytes());
        out.extend_from_slice(&self.recv_counter.to_le_bytes());
        out.extend_from_slice(&(self.skipped.len() as u32).to_le_bytes());
        for (&counter, mk) in &self.skipped {
            out.extend_from_slice(&counter.to_le_bytes());
            out.extend_from_slice(mk.key.as_bytes());
            out.extend_from_slice(&mk.nonce);
        }
        out
    }

    /// Deserializes a symmetric ratchet state produced by [`Self::to_state_bytes`].
    pub(crate) fn from_state_bytes(data: &[u8]) -> Result<Self> {
        let fixed = KEY_BYTES * 2 + 8 + 8 + 4;
        if data.len() < fixed {
            return Err(WilisError::InvalidFormat(
                "truncated inner ratchet session state".into(),
            ));
        }
        let mut send_chain = [0u8; KEY_BYTES];
        let mut recv_chain = [0u8; KEY_BYTES];
        send_chain.copy_from_slice(&data[0..KEY_BYTES]);
        recv_chain.copy_from_slice(&data[KEY_BYTES..KEY_BYTES * 2]);
        let send_counter = u64::from_le_bytes(data[64..72].try_into().expect("8 bytes"));
        let recv_counter = u64::from_le_bytes(data[72..80].try_into().expect("8 bytes"));
        let skipped_len = u32::from_le_bytes(data[80..84].try_into().expect("4 bytes")) as usize;
        if skipped_len > (MAX_SKIP_WINDOW as usize) * 2 {
            zeroize_bytes(&mut send_chain);
            zeroize_bytes(&mut recv_chain);
            return Err(WilisError::InvalidFormat(
                "ratchet skipped key cache exceeds safety window".into(),
            ));
        }
        let entry_sz = 8 + KEY_BYTES + NONCE_BYTES;
        let expected_len = fixed + skipped_len * entry_sz;
        if data.len() != expected_len {
            zeroize_bytes(&mut send_chain);
            zeroize_bytes(&mut recv_chain);
            return Err(WilisError::InvalidFormat(
                "non-canonical inner ratchet session state length".into(),
            ));
        }

        let mut skipped = BTreeMap::new();
        let mut pos = fixed;
        for _ in 0..skipped_len {
            let counter = u64::from_le_bytes(data[pos..pos + 8].try_into().expect("8 bytes"));
            pos += 8;
            let mut k = [0u8; KEY_BYTES];
            k.copy_from_slice(&data[pos..pos + KEY_BYTES]);
            pos += KEY_BYTES;
            let mut nonce = [0u8; NONCE_BYTES];
            nonce.copy_from_slice(&data[pos..pos + NONCE_BYTES]);
            pos += NONCE_BYTES;
            let mk = MessageKeyMaterial {
                key: SecretKey::from_bytes(k),
                nonce,
            };
            zeroize_bytes(&mut k);
            if skipped.insert(counter, mk).is_some() {
                zeroize_bytes(&mut send_chain);
                zeroize_bytes(&mut recv_chain);
                return Err(WilisError::InvalidFormat(
                    "duplicate skipped counter in ratchet state".into(),
                ));
            }
        }

        Ok(Self {
            send_chain,
            recv_chain,
            send_counter,
            recv_counter,
            skipped,
        })
    }
}

impl Drop for RatchetSession {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.send_chain);
        zeroize_bytes(&mut self.recv_chain);
        self.skipped.clear();
    }
}
