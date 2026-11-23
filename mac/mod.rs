//! `WilisMAC` — Keyed 256-bit Message Authentication Code & Subkey Derivation
//! built strictly on `WilisPerm-384`.

pub mod keyed_mac;

pub use keyed_mac::{derive_subkey, mac, verify_mac, WilisMac};
