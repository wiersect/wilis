//! Self-contained encrypted container formats (`WILS` v1 single-shot & `WILS` v2 streaming).

pub mod container;
pub mod header;

pub use container::{
    decrypt_with_key, decrypt_with_passphrase, decrypt_with_passphrase_and_keyfile,
    encrypt_with_key, encrypt_with_passphrase, encrypt_with_passphrase_and_keyfile,
};
pub use header::{ContainerHeader, KeyMode, FORMAT_VERSION, FORMAT_VERSION_V2, MAGIC_BYTES};
