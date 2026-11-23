//! # Wilis
//!
//! A standalone, zero-dependency custom cryptographic suite written in pure Rust.
//! Every primitive is built strictly from a single original 384-bit cryptographic
//! permutation (`WilisPerm-384`), without mixing in any external encryption,
//! hash, signature, KEM, or key-derivation algorithms.
//!
//! ## Modules
//! - [`core`] — `WilisPerm-384` permutation (ARX, bitsliced Chi-5 + Feistel-6, 3-tap diffusion)
//! - [`aead`] — `WilisAEAD` duplex sponge authenticated encryption (256-bit key, 192-bit nonce, 256-bit tag)
//! - [`kdf`] — `WilisKDF` v2 hybrid memory-hard password KDF (16–64 MiB + optional 2FA keyfile)
//! - [`hash`] — `WilisHash-256` incremental cryptographic sponge hash
//! - [`xof`] — `WilisXOF` extendable-output sponge function & deterministic PRNG
//! - [`mac`] — `WilisMAC` keyed 256-bit MAC & domain-separated subkey derivation
//! - [`kem`] — `WilisKEM` post-quantum Module-LWE IND-CCA2 KEM & hybrid public-key encryption
//! - [`ratchet`] — `WilisRatchet` forward-secret symmetric messaging ratchet
//! - [`sign`] — `WilisSign` post-quantum hash-based digital signatures (WOTS+ Merkle tree)
//! - [`split`] — `WilisSplit` Shamir's Secret Sharing over constant-time `GF(2^8)`
//! - [`format`] — Self-contained `WILS` v1 & v2 binary container formats
//! - [`stream`] — Constant-memory chunked streaming AEAD (`WILS` v2)
//! - [`archive`] — `WilisDir` full-directory encrypted archiving with Zip-Slip protection
//! - [`vault`] — `WilisVault` encrypted local secret & password store
//! - [`audit`] — 6-part scientific cryptanalysis & statistical randomness audit suite
//! - [`ffi`] — Stable C-ABI exports (`libwilis`) for C/C++/Python/Node.js bindings
//! - [`utils`] — Constant-time comparison, volatile zeroization, cross-platform CSPRNG, secure prompt, Hex, Base64
//! - [`cli`] — Command-line application handlers

pub mod aead;
pub mod archive;
pub mod audit;
pub mod cli;
pub mod core;
pub mod error;
pub mod ffi;
pub mod format;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod mac;
pub mod ratchet;
pub mod sign;
pub mod split;
pub mod stream;
pub mod utils;
pub mod vault;
pub mod xof;

pub use error::{Result, WilisError};
