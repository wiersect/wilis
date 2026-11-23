//! `WilisXOF` — Extendable-Output Sponge Function & Deterministic CSPRNG
//! built exclusively on `WilisPerm-384`.
//!
//! Absorbs arbitrary domain-separated input and squeezes an unbounded stream of
//! cryptographically uniform bytes with a 256-bit security capacity.

pub mod sponge_xof;

pub use sponge_xof::WilisXof;
