//! CLI handlers for `encrypt-file` and `decrypt-file`.
//!
//! Uses constant-memory `WILS` v2 chunked streaming for encryption and automatically
//! supports both `WILS` v1 and `WILS` v2 containers on decryption. If decryption
//! fails authentication on any chunk, the partial output file is deleted immediately.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read};

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

/// Stream-encrypts an arbitrary file into a `WILS` v2 chunked container.
pub fn run_encrypt(
    auth: AuthInput,
    aad: &str,
    input_path: &str,
    output_path: &str,
) -> Result<()> {
    let mut reader = BufReader::new(File::open(input_path)?);
    let mut writer = BufWriter::new(File::create(output_path)?);

    let (in_bytes, out_bytes) = match auth {
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

    println!(
        "Encrypted (WILS v2 stream) '{}' ({in_bytes} bytes) -> '{}' ({out_bytes} bytes)",
        input_path, output_path
    );
    Ok(())
}

/// Verifies and decrypts either a `WILS` v1 or `WILS` v2 container file.
pub fn run_decrypt(
    auth: AuthInput,
    aad: &str,
    input_path: &str,
    output_path: &str,
) -> Result<()> {
    // Peek first 5 bytes to detect v1 vs v2 container version
    let mut peek_file = File::open(input_path)?;
    let mut prefix = [0u8; 5];
    peek_file.read_exact(&mut prefix).map_err(|_| {
        WilisError::InvalidFormat("input file is too short to be a WILS container".into())
    })?;
    drop(peek_file);

    if prefix[0..4] != MAGIC_BYTES {
        return Err(WilisError::InvalidFormat(
            "invalid magic bytes (expected 'WILS')".into(),
        ));
    }

    match prefix[4] {
        FORMAT_VERSION => {
            let container = fs::read(input_path)?;
            let plaintext = match auth {
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
            fs::write(output_path, &plaintext)?;
            println!(
                "Decrypted & verified (WILS v1) '{}' ({} bytes) -> '{}' ({} bytes)",
                input_path,
                container.len(),
                output_path,
                plaintext.len()
            );
            Ok(())
        }
        FORMAT_VERSION_V2 => {
            let in_len = fs::metadata(input_path)?.len();
            let mut reader = BufReader::new(File::open(input_path)?);
            let mut writer = BufWriter::new(File::create(output_path)?);

            let res = match auth {
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
                ),
                AuthInput::RawKey(key) => {
                    decrypt_stream_with_key(key.as_bytes(), &mut reader, &mut writer, aad.as_bytes())
                }
            };

            drop(writer);
            match res {
                Ok(out_bytes) => {
                    println!(
                        "Decrypted & verified (WILS v2 stream) '{}' ({in_len} bytes) -> '{}' ({out_bytes} bytes)",
                        input_path, output_path
                    );
                    Ok(())
                }
                Err(err) => {
                    // Never leave unauthenticated partial plaintext on disk
                    let _ = fs::remove_file(output_path);
                    Err(err)
                }
            }
        }
        other => Err(WilisError::InvalidFormat(format!(
            "unsupported container version: {other}"
        ))),
    }
}
