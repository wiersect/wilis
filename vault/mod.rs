//! `WilisVault` — Authenticated local secret & password vault backed by `WilisAEAD`
//! and hybrid memory-hard `WilisKDF` v2.

pub mod store;

pub use store::Vault;
