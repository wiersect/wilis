//! CLI handlers for `encrypt-file` and `decrypt-file`.
//!
//! Safety guarantees:
//! - Refuses in-place `--in == --out` (including symlinks & Unix hard links) to prevent data loss.
//! - Uses constant-memory `WILS` v2 chunked streaming for encryption and supports
//!   both `WILS` v1 and `WILS` v2 on decryption.
//! - Writes to a CSPRNG-named `O_EXCL` sibling `.tmp` file (never following symlinks),
//!   calls `sync_all()`, and atomically renames onto `output_path` ONLY after full
//!   authentication succeeds (preserving pre-existing files on authentication failure).

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read};
use std::path::Path;

use crate::cli::args::AuthInput;
use crate::error::{Result, WilisError};
use crate::format::{
    decrypt_with_key, decrypt_with_passphrase_and_keyfile, FORMAT_VERSION, FORMAT_VERSION_V2,
    MAGIC_BYTES,
};
use crate::stream::{
    decrypt_stream_with_key, decrypt_stream_with_passphrase, encrypt_stream_with_key,
    encrypt_stream_with_passphrase, DEFAULT_CHUNK_SIZE,
};
use crate::utils::zeroize::{
    create_unique_temp_file, paths_refer_to_same_file, write_atomic_file, zeroize_bytes,
};

/// Stream-encrypts an arbitrary file into a `WILS` v2 chunked container.
pub fn run_encrypt(
    auth: AuthInput,
    aad: &str,
    input_path: &str,
    output_path: &str,
) -> Result<()> {
    let in_p = Path::new(input_path);
    let out_p = Path::new(output_path);
    if paths_refer_to_same_file(in_p, out_p) {
        return Err(WilisError::InvalidParameters(
            "input and output paths must not refer to the same file".into(),
        ));
    }

    let (tmp_path, tmp_file) = create_unique_temp_file(out_p, false)?;
    let res = (|| -> Result<(u64, u64)> {
        let mut reader = BufReader::new(File::open(in_p)?);
        let mut writer = BufWriter::new(tmp_file);
        let counts = match &auth {
            AuthInput::Passphrase {
                passphrase,
                keyfile_hash,
                strength,
            } => encrypt_stream_with_passphrase(
                passphrase.as_bytes(),
                keyfile_hash.as_ref(),
                &mut reader,
                &mut writer,
                aad.as_bytes(),
                strength.to_params(),
                DEFAULT_CHUNK_SIZE,
            )?,
            AuthInput::RawKey(key) => encrypt_stream_with_key(
                key.as_bytes(),
                &mut reader,
                &mut writer,
                aad.as_bytes(),
                DEFAULT_CHUNK_SIZE,
            )?,
        };
        let file = writer.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        Ok(counts)
    })();

    match res {
        Ok((in_bytes, out_bytes)) => {
            if let Err(e) = fs::rename(&tmp_path, out_p) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e.into());
            }
            println!(
                "Encrypted (WILS v2 stream) '{}' ({in_bytes} bytes) -> '{}' ({out_bytes} bytes)",
                input_path, output_path
            );
            Ok(())
        }
        Err(err) => {
            let _ = fs::remove_file(&tmp_path);
            Err(err)
        }
    }
}

/// Verifies and decrypts either a `WILS` v1 or `WILS` v2 container file.
pub fn run_decrypt(
    auth: AuthInput,
    aad: &str,
    input_path: &str,
    output_path: &str,
) -> Result<()> {
    let in_p = Path::new(input_path);
    let out_p = Path::new(output_path);
    if paths_refer_to_same_file(in_p, out_p) {
        return Err(WilisError::InvalidParameters(
            "input and output paths must not refer to the same file".into(),
        ));
    }

    // Peek first 5 bytes to detect v1 vs v2 container version (preserving real OS I/O errors)
    let mut peek_file = File::open(in_p)?;
    let mut prefix = [0u8; 5];
    peek_file.read_exact(&mut prefix).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            WilisError::InvalidFormat("input file is too short to be a WILS container".into())
        } else {
            WilisError::Io(e)
        }
    })?;
    drop(peek_file);

    if prefix[0..4] != MAGIC_BYTES {
        return Err(WilisError::InvalidFormat(
            "invalid magic bytes (expected 'WILS')".into(),
        ));
    }

    match prefix[4] {
        FORMAT_VERSION => {
            let container = fs::read(in_p)?;
            let mut plaintext = match &auth {
                AuthInput::Passphrase {
                    passphrase,
                    keyfile_hash,
                    ..
                } => decrypt_with_passphrase_and_keyfile(
                    passphrase.as_bytes(),
                    keyfile_hash.as_ref(),
                    &container,
                    aad.as_bytes(),
                )?,
                AuthInput::RawKey(key) => {
                    decrypt_with_key(key.as_bytes(), &container, aad.as_bytes())?
                }
            };
            let plain_len = plaintext.len();
            let write_res = write_atomic_file(out_p, &plaintext, true);
            zeroize_bytes(&mut plaintext);
            write_res?;
            println!(
                "Decrypted & verified (WILS v1) '{}' ({} bytes) -> '{}' ({plain_len} bytes)",
                input_path,
                container.len(),
                output_path,
            );
            Ok(())
        }
        FORMAT_VERSION_V2 => {
            let in_len = fs::metadata(in_p)?.len();
            if let Ok(meta) = fs::symlink_metadata(out_p) {
                if meta.file_type().is_symlink() {
                    return Err(WilisError::InvalidFormat(format!(
                        "refusing to write decrypted plaintext onto symlink '{}'",
                        out_p.display()
                    )));
                }
            }
            let (tmp_path, tmp_file) = create_unique_temp_file(out_p, true)?;
            let res = (|| -> Result<u64> {
                let mut reader = BufReader::new(File::open(in_p)?);
                let mut writer = BufWriter::new(tmp_file);
                let out_bytes = match &auth {
                    AuthInput::Passphrase {
                        passphrase,
                        keyfile_hash,
                        ..
                    } => decrypt_stream_with_passphrase(
                        passphrase.as_bytes(),
                        keyfile_hash.as_ref(),
                        &mut reader,
                        &mut writer,
                        aad.as_bytes(),
                    )?,
                    AuthInput::RawKey(key) => decrypt_stream_with_key(
                        key.as_bytes(),
                        &mut reader,
                        &mut writer,
                        aad.as_bytes(),
                    )?,
                };
                let file = writer.into_inner().map_err(|e| e.into_error())?;
                file.sync_all()?;
                Ok(out_bytes)
            })();

            match res {
                Ok(out_bytes) => {
                    if let Err(e) = fs::rename(&tmp_path, out_p) {
                        let _ = fs::remove_file(&tmp_path);
                        return Err(e.into());
                    }
                    println!(
                        "Decrypted & verified (WILS v2 stream) '{}' ({in_len} bytes) -> '{}' ({out_bytes} bytes)",
                        input_path, output_path
                    );
                    Ok(())
                }
                Err(err) => {
                    // Remove unauthenticated temp file; any pre-existing file at output_path stays intact!
                    let _ = fs::remove_file(&tmp_path);
                    Err(err)
                }
            }
        }
        other => Err(WilisError::InvalidFormat(format!(
            "unsupported container version: {other}"
        ))),
    }
}
