//! # Wilis
//!
//! A standalone, zero-dependency custom cryptographic suite written in pure Rust.
//! Every primitive is built strictly from a single original 384-bit cryptographic
//! permutation (`WilisPerm-384`), without mixing in any external encryption,
//! hash, or key-derivation algorithms.
//!
//! ## Modules
//! - [`core`] — `WilisPerm-384` permutation (ARX, bitsliced Chi-5 + Feistel-6, 3-tap diffusion)
//! - [`aead`] — `WilisAEAD` duplex sponge authenticated encryption (256-bit key, 192-bit nonce, 256-bit tag)
//! - [`kdf`] — `WilisKDF` hybrid memory-hard password KDF (up to 64 MiB + optional 2FA keyfile)
//! - [`hash`] — `WilisHash-256` incremental cryptographic sponge hash
//! - [`format`] — Self-contained `WILS` v1 & v2 binary container formats
//! - [`stream`] — Constant-memory chunked streaming AEAD (`WILS` v2)
//! - [`audit`] — Scientific cryptanalysis & statistical randomness audit suite
//! - [`utils`] — Constant-time comparison, volatile zeroization, OS CSPRNG, secure prompt, Hex, Base64
//! - [`cli`] — Command-line application handlers

pub mod aead;
pub mod audit;
pub mod cli;
pub mod core;
pub mod error;
pub mod format;
pub mod hash;
pub mod kdf;
pub mod stream;
pub mod utils;

pub use error::{Result, WilisError};
