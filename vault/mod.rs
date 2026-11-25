//! `WilisVault` — Authenticated local secret & password vault backed by `WilisAEAD`
//! and hybrid memory-hard `WilisKDF` v2.

pub mod deniable;
pub mod store;

pub use deniable::{create_deniable_container, open_deniable_container};
pub use store::Vault;
