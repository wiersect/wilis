//! Post-Quantum Authenticated Key Exchange (`WilisHandshake` — `WilisKEM` + `WilisSign`)
//! and Hybrid Post-Compromise-Secure Messaging Ratchet (`PqRatchetSession`).
//!
//! Combines:
//! - **Mutual Post-Quantum Authentication (`WHSH` v1):** Initiator encapsulates a fresh
//!   `WilisKEM` secret to the responder's public key and signs the full handshake transcript
//!   (binding context, responder public key, KEM ciphertext, and initiator's ephemeral ratchet
//!   public key) with `WilisSign`.
//! - **Forward Secrecy (per-message):** Each epoch runs a full `RatchetSession` (`WRAT` v1).
//! - **Post-Compromise Security / Break-In Recovery (`WPRK` v1):** Any peer can trigger a
//!   `WilisKEM` ratchet rekey that mixes fresh post-quantum entropy into the session root key
//!   and advertises a freshly generated ephemeral `KemPublicKey`. After one full round-trip,
//!   even an adversary who previously compromised the entire session state cannot derive new keys.

use crate::core::constants::{DOMAIN_RATCHET, HASH_BYTES, KEY_BYTES, TAG_BYTES};
use crate::error::{Result, WilisError};
use crate::hash::WilisHash;
use crate::kem::{
    decapsulate, encapsulate, keygen, KemCiphertext, KemPublicKey, KemSecretKey, KEM_CT_BYTES,
    KEM_PK_BYTES,
};
use crate::mac::{mac, verify_mac};
use crate::ratchet::session::{RatchetPacket, RatchetSession};
use crate::sign::{Signature, SigningKey, VerifyingKey};
use crate::utils::zeroize::zeroize_bytes;
use crate::xof::WilisXof;

const HANDSHAKE_MAGIC: [u8; 4] = *b"WHSH";
const HANDSHAKE_VERSION: u8 = 1;

const PQ_MSG_MAGIC: [u8; 4] = *b"WRP2";
const PQ_MSG_VERSION: u8 = 1;

const PQ_REKEY_MAGIC: [u8; 4] = *b"WPRK";
const PQ_REKEY_VERSION: u8 = 1;

/// Exact serialized size of a `WPRK` v1 post-quantum rekey packet (`2997` bytes).
pub const PQ_REKEY_BYTES: usize = 4 + 1 + 8 + KEM_CT_BYTES + KEM_PK_BYTES + TAG_BYTES;

/// Authenticated post-quantum handshake initiation message (`WHSH` v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeInit {
    pub kem_ct: KemCiphertext,
    pub initiator_next_pk: KemPublicKey,
    pub signature: Signature,
}

impl HandshakeInit {
    /// Serializes the handshake packet into canonical `WHSH` v1 binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig_bytes = self.signature.to_bytes();
        let mut out = Vec::with_capacity(4 + 1 + KEM_CT_BYTES + KEM_PK_BYTES + 4 + sig_bytes.len());
        out.extend_from_slice(&HANDSHAKE_MAGIC);
        out.push(HANDSHAKE_VERSION);
        out.extend_from_slice(&self.kem_ct.to_bytes());
        out.extend_from_slice(&self.initiator_next_pk.to_bytes());
        out.extend_from_slice(&(sig_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&sig_bytes);
        out
    }

    /// Parses a canonical `WHSH` v1 handshake message.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let fixed = 4 + 1 + KEM_CT_BYTES + KEM_PK_BYTES + 4;
        if data.len() < fixed || data[0..4] != HANDSHAKE_MAGIC || data[4] != HANDSHAKE_VERSION {
            return Err(WilisError::InvalidFormat(
                "invalid or truncated WilisHandshake (WHSH) packet".into(),
            ));
        }
        let mut pos = 5;
        let kem_ct = KemCiphertext::from_bytes(&data[pos..pos + KEM_CT_BYTES])?;
        pos += KEM_CT_BYTES;
        let initiator_next_pk = KemPublicKey::from_bytes(&data[pos..pos + KEM_PK_BYTES])?;
        pos += KEM_PK_BYTES;
        let sig_len = u32::from_le_bytes(data[pos..pos + 4].try_into().expect("4 bytes")) as usize;
        pos += 4;
        if sig_len == 0 || sig_len > 4096 || data.len() - pos != sig_len {
            return Err(WilisError::InvalidFormat(
                "invalid or non-canonical signature length in WHSH packet".into(),
            ));
        }
        let signature = Signature::from_bytes(&data[pos..pos + sig_len])?;
        Ok(Self {
            kem_ct,
            initiator_next_pk,
            signature,
        })
    }
}

/// Authenticated post-quantum ratchet message packet carrying its PCS epoch (`WRP2` v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqMessagePacket {
    pub epoch: u64,
    pub inner: RatchetPacket,
}

impl PqMessagePacket {
    /// Serializes the packet into canonical `WRP2` v1 binary bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let inner_bytes = self.inner.to_bytes();
        let mut out = Vec::with_capacity(4 + 1 + 8 + inner_bytes.len());
        out.extend_from_slice(&PQ_MSG_MAGIC);
        out.push(PQ_MSG_VERSION);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&inner_bytes);
        out
    }

    /// Parses a canonical `WRP2` v1 message packet.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 13 || data[0..4] != PQ_MSG_MAGIC || data[4] != PQ_MSG_VERSION {
            return Err(WilisError::InvalidFormat(
                "invalid or truncated PqMessagePacket (WRP2)".into(),
            ));
        }
        let epoch = u64::from_le_bytes(data[5..13].try_into().expect("8 bytes"));
        let inner = RatchetPacket::from_bytes(&data[13..])?;
        Ok(Self { epoch, inner })
    }
}

/// Authenticated post-quantum KEM rekey packet advancing a session to `new_epoch` (`WPRK` v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqRekeyPacket {
    pub new_epoch: u64,
    pub kem_ct: KemCiphertext,
    pub next_kem_pk: KemPublicKey,
    pub mac_tag: [u8; TAG_BYTES],
}

impl PqRekeyPacket {
    /// Serializes the rekey packet into canonical `WPRK` v1 bytes (`2997` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PQ_REKEY_BYTES);
        out.extend_from_slice(&PQ_REKEY_MAGIC);
        out.push(PQ_REKEY_VERSION);
        out.extend_from_slice(&self.new_epoch.to_le_bytes());
        out.extend_from_slice(&self.kem_ct.to_bytes());
        out.extend_from_slice(&self.next_kem_pk.to_bytes());
        out.extend_from_slice(&self.mac_tag);
        out
    }

    /// Parses a canonical `WPRK` v1 post-quantum rekey packet.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != PQ_REKEY_BYTES
            || data[0..4] != PQ_REKEY_MAGIC
            || data[4] != PQ_REKEY_VERSION
        {
            return Err(WilisError::InvalidFormat(format!(
                "invalid PqRekeyPacket (expected WPRK v1, {PQ_REKEY_BYTES} bytes)"
            )));
        }
        let new_epoch = u64::from_le_bytes(data[5..13].try_into().expect("8 bytes"));
        let mut pos = 13;
        let kem_ct = KemCiphertext::from_bytes(&data[pos..pos + KEM_CT_BYTES])?;
        pos += KEM_CT_BYTES;
        let next_kem_pk = KemPublicKey::from_bytes(&data[pos..pos + KEM_PK_BYTES])?;
        pos += KEM_PK_BYTES;
        let mac_tag: [u8; TAG_BYTES] = data[pos..pos + TAG_BYTES]
            .try_into()
            .expect("32-byte MAC tag");
        Ok(Self {
            new_epoch,
            kem_ct,
            next_kem_pk,
            mac_tag,
        })
    }
}

fn handshake_transcript_hash(
    context: &[u8],
    responder_pk: &KemPublicKey,
    kem_ct: &KemCiphertext,
    initiator_next_pk: &KemPublicKey,
) -> [u8; HASH_BYTES] {
    let mut h = WilisHash::new();
    h.update(b"WHSH_V1");
    h.update(&(context.len() as u64).to_le_bytes());
    h.update(context);
    h.update(&responder_pk.to_bytes());
    h.update(&kem_ct.to_bytes());
    h.update(&initiator_next_pk.to_bytes());
    h.finalize()
}

fn derive_initial_root_and_session(
    pq_ss: &[u8; KEY_BYTES],
    transcript_hash: &[u8; HASH_BYTES],
) -> ([u8; KEY_BYTES], [u8; KEY_BYTES]) {
    let mut xof = WilisXof::new(b"WHSH_ROOT_V1");
    xof.absorb(&DOMAIN_RATCHET.to_le_bytes());
    xof.absorb(pq_ss);
    xof.absorb(transcript_hash);
    let mut out = [0u8; KEY_BYTES * 2];
    xof.squeeze(&mut out);
    let root: [u8; KEY_BYTES] = out[0..KEY_BYTES].try_into().expect("32 bytes");
    let sess: [u8; KEY_BYTES] = out[KEY_BYTES..KEY_BYTES * 2].try_into().expect("32 bytes");
    zeroize_bytes(&mut out);
    (root, sess)
}

fn derive_rekey_material(
    old_root: &[u8; KEY_BYTES],
    pq_ss: &[u8; KEY_BYTES],
    new_epoch: u64,
    kem_ct_bytes: &[u8],
    next_pk_bytes: &[u8],
) -> ([u8; KEY_BYTES], [u8; KEY_BYTES], [u8; KEY_BYTES]) {
    let mut xof = WilisXof::new(b"WRAT_PQ_PCS_V1");
    xof.absorb(&DOMAIN_RATCHET.to_le_bytes());
    xof.absorb(old_root);
    xof.absorb(pq_ss);
    xof.absorb(&new_epoch.to_le_bytes());
    xof.absorb(kem_ct_bytes);
    xof.absorb(next_pk_bytes);
    let mut out = [0u8; KEY_BYTES * 3];
    xof.squeeze(&mut out);
    let mac_key: [u8; KEY_BYTES] = out[0..KEY_BYTES].try_into().expect("32 bytes");
    let new_root: [u8; KEY_BYTES] = out[KEY_BYTES..KEY_BYTES * 2].try_into().expect("32 bytes");
    let new_sess: [u8; KEY_BYTES] = out[KEY_BYTES * 2..KEY_BYTES * 3]
        .try_into()
        .expect("32 bytes");
    zeroize_bytes(&mut out);
    (mac_key, new_root, new_sess)
}

fn build_rekey_mac_input(new_epoch: u64, kem_ct_bytes: &[u8], next_pk_bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(11 + 8 + kem_ct_bytes.len() + next_pk_bytes.len());
    buf.extend_from_slice(b"WPRK_TAG_V1");
    buf.extend_from_slice(&new_epoch.to_le_bytes());
    buf.extend_from_slice(kem_ct_bytes);
    buf.extend_from_slice(next_pk_bytes);
    buf
}

fn build_epoch_aad(epoch: u64, user_aad: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(15usize.saturating_add(user_aad.len()));
    aad.extend_from_slice(b"WRP2_E:");
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.extend_from_slice(user_aad);
    aad
}

/// Post-Quantum Hybrid Ratchet Session providing BOTH per-message Forward Secrecy
/// and Post-Compromise Security (break-in recovery) via ephemeral `WilisKEM` ratcheting.
pub struct PqRatchetSession {
    root_key: [u8; KEY_BYTES],
    epoch: u64,
    is_initiator: bool,
    local_kem_sk: KemSecretKey,
    peer_kem_pk: KemPublicKey,
    inner: RatchetSession,
}

impl PqRatchetSession {
    /// Initiates a mutually authenticated post-quantum handshake with `responder_kem_pk`,
    /// signing the transcript with `initiator_sign_sk` and returning `(session, HandshakeInit)`.
    pub fn initiate_handshake(
        initiator_sign_sk: &mut SigningKey,
        responder_kem_pk: &KemPublicKey,
        context: &[u8],
    ) -> Result<(Self, HandshakeInit)> {
        let (kem_ct, pq_ss) = encapsulate(responder_kem_pk)?;
        let (local_kem_sk, initiator_next_pk) = keygen()?;

        let transcript =
            handshake_transcript_hash(context, responder_kem_pk, &kem_ct, &initiator_next_pk);
        let signature = initiator_sign_sk.sign(&transcript)?;

        let (root_key, mut sess_secret) =
            derive_initial_root_and_session(pq_ss.as_bytes(), &transcript);
        let inner = RatchetSession::from_shared_secret(&sess_secret, true);
        zeroize_bytes(&mut sess_secret);

        let init = HandshakeInit {
            kem_ct,
            initiator_next_pk,
            signature,
        };
        let session = Self {
            root_key,
            epoch: 0,
            is_initiator: true,
            local_kem_sk,
            peer_kem_pk: responder_kem_pk.clone(),
            inner,
        };
        Ok((session, init))
    }

    /// Verifies an incoming [`HandshakeInit`] against `initiator_vk`, decapsulates the
    /// post-quantum shared secret with `responder_kem_sk`, and establishes the responder session.
    pub fn accept_handshake(
        responder_kem_sk: &KemSecretKey,
        initiator_vk: &VerifyingKey,
        init: &HandshakeInit,
        context: &[u8],
    ) -> Result<Self> {
        let transcript = handshake_transcript_hash(
            context,
            responder_kem_sk.public_key(),
            &init.kem_ct,
            &init.initiator_next_pk,
        );
        if !initiator_vk.verify(&transcript, &init.signature) {
            return Err(WilisError::AuthenticationFailed);
        }

        let pq_ss = decapsulate(responder_kem_sk, &init.kem_ct);
        let (root_key, mut sess_secret) =
            derive_initial_root_and_session(pq_ss.as_bytes(), &transcript);
        let inner = RatchetSession::from_shared_secret(&sess_secret, false);
        zeroize_bytes(&mut sess_secret);

        Ok(Self {
            root_key,
            epoch: 0,
            is_initiator: false,
            local_kem_sk: responder_kem_sk.clone(),
            peer_kem_pk: init.initiator_next_pk.clone(),
            inner,
        })
    }

    /// Returns the current Post-Compromise Security (PCS) ratchet epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Encrypts the next outgoing message within the current PCS epoch.
    pub fn encrypt_next(&mut self, plaintext: &[u8], user_aad: &[u8]) -> PqMessagePacket {
        let bound_aad = build_epoch_aad(self.epoch, user_aad);
        let inner = self.inner.encrypt_next(plaintext, &bound_aad);
        PqMessagePacket {
            epoch: self.epoch,
            inner,
        }
    }

    /// Authenticates and decrypts an incoming [`PqMessagePacket`], rejecting cross-epoch,
    /// replayed, or tampered packets.
    pub fn decrypt_packet(&mut self, packet: &PqMessagePacket, user_aad: &[u8]) -> Result<Vec<u8>> {
        if packet.epoch != self.epoch {
            return Err(WilisError::AuthenticationFailed);
        }
        let bound_aad = build_epoch_aad(self.epoch, user_aad);
        self.inner.decrypt_packet(&packet.inner, &bound_aad)
    }

    /// Performs a post-quantum `WilisKEM` ratchet step: mixes fresh Module-LWE entropy into
    /// `root_key`, rotates the local ephemeral KEM keypair, resets the inner symmetric ratchet,
    /// and returns an authenticated [`PqRekeyPacket`] to send to the peer.
    pub fn initiate_rekey(&mut self) -> Result<PqRekeyPacket> {
        let new_epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| WilisError::InvalidParameters("PQ ratchet epoch exhausted".into()))?;

        let (kem_ct, pq_ss) = encapsulate(&self.peer_kem_pk)?;
        let (new_local_sk, next_kem_pk) = keygen()?;

        let kem_ct_bytes = kem_ct.to_bytes();
        let next_pk_bytes = next_kem_pk.to_bytes();

        let (mut mac_key, mut new_root, mut new_sess) = derive_rekey_material(
            &self.root_key,
            pq_ss.as_bytes(),
            new_epoch,
            &kem_ct_bytes,
            &next_pk_bytes,
        );
        let mac_input = build_rekey_mac_input(new_epoch, &kem_ct_bytes, &next_pk_bytes);
        let mac_tag = mac(&mac_key, &mac_input);
        zeroize_bytes(&mut mac_key);

        // Commit state advancement and destroy previous epoch secrets
        zeroize_bytes(&mut self.root_key);
        self.root_key = new_root;
        zeroize_bytes(&mut new_root);
        self.epoch = new_epoch;
        self.local_kem_sk = new_local_sk;
        self.inner = RatchetSession::from_shared_secret(&new_sess, self.is_initiator);
        zeroize_bytes(&mut new_sess);

        Ok(PqRekeyPacket {
            new_epoch,
            kem_ct,
            next_kem_pk,
            mac_tag,
        })
    }

    /// Authenticates and applies an incoming [`PqRekeyPacket`] transactionally:
    /// forged or out-of-order rekey packets are rejected without mutating session state.
    pub fn accept_rekey(&mut self, rekey: &PqRekeyPacket) -> Result<()> {
        let expected_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(WilisError::AuthenticationFailed)?;
        if rekey.new_epoch != expected_epoch {
            return Err(WilisError::AuthenticationFailed);
        }

        let pq_ss = decapsulate(&self.local_kem_sk, &rekey.kem_ct);
        let kem_ct_bytes = rekey.kem_ct.to_bytes();
        let next_pk_bytes = rekey.next_kem_pk.to_bytes();

        let (mut mac_key, mut new_root, mut new_sess) = derive_rekey_material(
            &self.root_key,
            pq_ss.as_bytes(),
            rekey.new_epoch,
            &kem_ct_bytes,
            &next_pk_bytes,
        );
        let mac_input = build_rekey_mac_input(rekey.new_epoch, &kem_ct_bytes, &next_pk_bytes);
        let ok = verify_mac(&mac_key, &mac_input, &rekey.mac_tag);
        zeroize_bytes(&mut mac_key);

        if !ok {
            zeroize_bytes(&mut new_root);
            zeroize_bytes(&mut new_sess);
            return Err(WilisError::AuthenticationFailed);
        }

        // Commit ONLY after MAC verification passes
        zeroize_bytes(&mut self.root_key);
        self.root_key = new_root;
        zeroize_bytes(&mut new_root);
        self.epoch = rekey.new_epoch;
        self.peer_kem_pk = rekey.next_kem_pk.clone();
        self.inner = RatchetSession::from_shared_secret(&new_sess, self.is_initiator);
        zeroize_bytes(&mut new_sess);
        Ok(())
    }
}

impl Drop for PqRatchetSession {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.root_key);
    }
}
