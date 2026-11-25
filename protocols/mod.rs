//! Advanced Zero-Dependency Cryptographic Protocols built exclusively on `WilisPerm-384`:
//! - [`totp`] — RFC 4226 / 6238-style HOTP & TOTP 2FA generator + Base32 codec
//! - [`fpe`] — Format-Preserving Encryption (`WilisFPE`) over arbitrary alphabets
//! - [`vss`] — Verifiable Secret Sharing (`WilisVSS`) & Proactive Share Refresh
//! - [`zkp`] — Non-Interactive Hash-Based Zero-Knowledge Proof of Knowledge (`WilisZKP`)
//! - [`timelock`] — Sequential Iterated-Permutation Time-Lock Puzzles (`WilisTimeLock`)
//! - [`pake`] — Post-Quantum Password-Authenticated Key Exchange (`WilisPAKE`)

pub mod fpe;
pub mod pake;
pub mod timelock;
pub mod totp;
pub mod vss;
pub mod zkp;
