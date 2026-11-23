//! `WilisDir` — Custom zero-dependency directory archiver (`WDIR` v1) paired with
//! `WILS` v2 constant-memory chunked encryption to hide file names, hierarchy, and contents.

pub mod pack;
pub mod unpack;

pub use pack::{encrypt_directory_with_key, encrypt_directory_with_passphrase, pack_directory};
pub use unpack::{decrypt_directory_with_key, decrypt_directory_with_passphrase, unpack_directory};
