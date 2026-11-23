//! `WilisRatchet` — Forward-Secret Symmetric Messaging Ratchet built on `WilisPerm-384`.
//!
//! Every message derives a unique one-time key + nonce, immediately destroys the prior
//! chain key (forward secrecy), supports out-of-order delivery up to a bounded window,
//! and rejects replayed or forged packets.

pub mod session;

pub use session::{RatchetPacket, RatchetSession, MAX_SKIP_WINDOW};
