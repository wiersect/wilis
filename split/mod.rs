//! `WilisSplit` — Information-theoretic Shamir's Secret Sharing over `GF(2^8)`.
//!
//! Splits any secret (e.g., a 256-bit key) into `N` shares requiring any `K` shares
//! to reconstruct. Possessing `K - 1` or fewer shares reveals mathematically zero
//! information about the secret.

pub mod gf256;
pub mod shamir;

pub use shamir::{combine_shares, split_secret, Share};
