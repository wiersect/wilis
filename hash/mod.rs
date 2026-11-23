//! `WilisHash-256` — 256-bit sponge hash function built strictly on `WilisPerm-384`.

pub mod sponge_hash;

pub use sponge_hash::{hash, hash_hex, WilisHash};
