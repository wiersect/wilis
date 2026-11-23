//! `WilisKDF` — Hybrid memory-hard Key Derivation Function built exclusively on `WilisPerm-384`.

pub mod memory_kdf;
pub mod params;

pub use memory_kdf::{derive_key, derive_key_with_keyfile};
pub use params::{KdfParams, KdfStrength, BLOCKS_PER_MIB};
