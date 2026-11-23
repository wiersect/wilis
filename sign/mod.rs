//! `WilisSign` — Post-Quantum Hash-Based Digital Signatures (WOTS+ & Merkle Tree)
//! built 100% from `WilisHash-256` (`WilisPerm-384`), with zero external crypto.
//!
//! Security highlights:
//! - Relies exclusively on the preimage/second-preimage resistance of `WilisHash-256`.
//! - Structurally resistant to Shor's quantum algorithm (no RSA / ECC / discrete log).
//! - Randomized message hashing (`R || pub_seed || root || leaf_idx || message`) resists
//!   collision-based forgery attacks.
//! - Enforces strict stateful leaf-index exhaustion checks to prevent WOTS+ key reuse.

pub mod keypair;
pub mod merkle;
pub mod wots;

pub use keypair::{Signature, SigningKey, VerifyingKey, DEFAULT_TREE_HEIGHT};
