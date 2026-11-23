//! CLI handlers for `WilisDir` full-directory encryption (`encrypt-dir` & `decrypt-dir`).

use std::path::Path;

use crate::archive::{
    decrypt_directory_with_key, decrypt_directory_with_passphrase, encrypt_directory_with_key,
    encrypt_directory_with_passphrase,
};
use crate::cli::args::AuthInput;
use crate::error::Result;

/// Packs and encrypts an entire folder recursively into a single `WILS` v2 `.wils` file.
pub fn run_encrypt_dir(
    auth: AuthInput,
    aad: &str,
    dir_path: &str,
    output_file: &str,
) -> Result<()> {
    let src = Path::new(dir_path);
    let dst = Path::new(output_file);

    let (files, out_bytes) = match &auth {
        AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            strength,
        } => encrypt_directory_with_passphrase(
            passphrase.as_bytes(),
            keyfile_hash.as_ref(),
            src,
            dst,
            aad.as_bytes(),
            strength.to_params(),
        )?,
        AuthInput::RawKey(key) => {
            encrypt_directory_with_key(key.as_bytes(), src, dst, aad.as_bytes())?
        }
    };

    println!(
        "Encrypted directory '{}' ({files} files) -> '{}' ({out_bytes} bytes)",
        dir_path, output_file
    );
    Ok(())
}

/// Verifies, decrypts, and safely extracts a `.wils` directory archive into `out_dir`.
pub fn run_decrypt_dir(
    auth: AuthInput,
    aad: &str,
    input_file: &str,
    out_dir: &str,
) -> Result<()> {
    let src = Path::new(input_file);
    let dst = Path::new(out_dir);

    let files = match &auth {
        AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            ..
        } => decrypt_directory_with_passphrase(
            passphrase.as_bytes(),
            keyfile_hash.as_ref(),
            src,
            dst,
            aad.as_bytes(),
        )?,
        AuthInput::RawKey(key) => {
            decrypt_directory_with_key(key.as_bytes(), src, dst, aad.as_bytes())?
        }
    };

    println!(
        "Decrypted & verified directory archive '{}' -> '{}' ({files} files restored)",
        input_file, out_dir
    );
    Ok(())
}
