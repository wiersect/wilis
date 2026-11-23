//! Core 384-bit cryptographic permutation (`WilisPerm-384`).
//!
//! Every high-level primitive in Wilis (AEAD, KDF, and Hash) is built
//! strictly on top of the components in this module, with no external crypto.

pub mod arx;
pub mod constants;
pub mod diffusion;
pub mod permute;
pub mod sbox;
pub mod state;

pub use permute::{permute, permute_inverse};
pub use state::State;
