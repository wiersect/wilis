//! `WilisAEAD` — Authenticated Encryption with Associated Data built on `WilisPerm-384`.
//!
//! Parameters:
//! - Key: 256 bits (32 bytes)
//! - Nonce: 192 bits (24 bytes)
//! - Authentication Tag: 256 bits (32 bytes)
//! - Rate: 128 bits (16 bytes), Capacity: 256 bits (32 bytes)

pub mod absorb;
pub mod cipher;
pub mod decrypt;
pub mod encrypt;
pub mod finalize;
pub mod init;
pub mod siv;

pub use cipher::{open, seal};
pub use siv::{siv_open, siv_seal, SIV_TAG_BYTES};
