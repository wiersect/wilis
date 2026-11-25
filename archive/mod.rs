//! `WilisDir` — Custom zero-dependency directory archiver (`WDIR` v1 & constant-memory streaming
//! `WDIR` v2) paired with `WILS` v2 chunked encryption to hide file names, hierarchy, and contents.

pub mod pack;
pub mod stream_dir;
pub mod unpack;

pub use pack::{encrypt_directory_with_key, encrypt_directory_with_passphrase, pack_directory};
pub use stream_dir::{
    decrypt_directory_v2_with_key, decrypt_directory_v2_with_passphrase,
    encrypt_directory_v2_with_key, encrypt_directory_v2_with_passphrase, pack_directory_v2,
    unpack_directory_v2, WDIR_V2_VERSION,
};
pub use unpack::{decrypt_directory_with_key, decrypt_directory_with_passphrase, unpack_directory};
