//! `WilisHash-256` — 256-bit sponge hash function built strictly on `WilisPerm-384`.

pub mod sponge_hash;
pub mod tree_hash;

pub use sponge_hash::{hash, hash_hex, WilisHash};
pub use tree_hash::{build_chunk_proof, tree_hash, verify_chunk_proof, TreeProof, TREE_CHUNK_BYTES};
