//! CLI handlers for `WilisDir` full-directory encryption (`encrypt-dir` & `decrypt-dir`).
//!
//! Uses true constant-memory streaming `WDIR` v2 (preserving empty directories, Unix
//! executable permissions, and optional per-file `WilisLZ` compression) while automatically
//! decoding both legacy `WDIR` v1 and streaming `WDIR` v2 archives on decryption.

use std::fs;
use std::path::Path;

use crate::archive::{
    decrypt_directory_v2_with_key, decrypt_directory_v2_with_passphrase,
    encrypt_directory_v2_with_key, encrypt_directory_v2_with_passphrase,
};
use crate::cli::args::AuthInput;
use crate::error::{Result, WilisError};
use crate::utils::zeroize::paths_refer_to_same_file;

/// Packs and encrypts an entire folder recursively in constant memory (`WDIR` v2 -> `WILS` v2).
pub fn run_encrypt_dir(
    auth: AuthInput,
    aad: &str,
    dir_path: &str,
    output_file: &str,
    enable_compress: bool,
) -> Result<()> {
    let src = Path::new(dir_path);
    let dst = Path::new(output_file);

    let (entries, out_bytes) = match &auth {
        AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            strength,
        } => encrypt_directory_v2_with_passphrase(
            passphrase.as_bytes(),
            keyfile_hash.as_ref(),
            src,
            dst,
            aad.as_bytes(),
            strength.to_params(),
            enable_compress,
        )?,
        AuthInput::RawKey(key) => encrypt_directory_v2_with_key(
            key.as_bytes(),
            src,
            dst,
            aad.as_bytes(),
            enable_compress,
        )?,
    };

    println!(
        "Encrypted directory '{}' (WDIR v2 stream{}, {entries} entries) -> '{}' ({out_bytes} bytes)",
        dir_path,
        if enable_compress { " + LZSS" } else { "" },
        output_file
    );
    Ok(())
}

/// Verifies, decrypts in constant memory, and safely extracts a `WDIR` v1/v2 directory archive.
pub fn run_decrypt_dir(
    auth: AuthInput,
    aad: &str,
    input_file: &str,
    out_dir: &str,
) -> Result<()> {
    let src = Path::new(input_file);
    let dst = Path::new(out_dir);
    if paths_refer_to_same_file(src, dst) {
        return Err(WilisError::InvalidParameters(
            "destination directory must not refer to the input archive".into(),
        ));
    }
    if let Ok(meta) = fs::symlink_metadata(dst) {
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return Err(WilisError::InvalidFormat(
                "destination path exists and is a symlink or non-directory".into(),
            ));
        }
    }

    let entries = match &auth {
        AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            ..
        } => decrypt_directory_v2_with_passphrase(
            passphrase.as_bytes(),
            keyfile_hash.as_ref(),
            src,
            dst,
            aad.as_bytes(),
        )?,
        AuthInput::RawKey(key) => {
            decrypt_directory_v2_with_key(key.as_bytes(), src, dst, aad.as_bytes())?
        }
    };

    println!(
        "Decrypted & verified directory archive '{}' -> '{}' ({entries} entries restored)",
        input_file, out_dir
    );
    Ok(())
}
