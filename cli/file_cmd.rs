//! CLI handlers for `encrypt-file` and `decrypt-file` with UNIX stdin/stdout pipe (`-`) support.
//!
//! Safety guarantees:
//! - Refuses in-place `--in == --out` (including symlinks & Unix hard links) to prevent data loss.
//! - Uses constant-memory `WILS` v2 chunked streaming for encryption and supports
//!   both `WILS` v1 and `WILS` v2 on decryption.
//! - Supports `--in -` (stdin) and `--out -` (stdout) for seamless UNIX pipelines; when writing
//!   to stdout, human status messages are emitted on stderr so binary streams stay clean.
//! - File outputs write to a CSPRNG-named `O_EXCL` sibling `.tmp` file (never following symlinks),
//!   call `sync_all()`, and atomically rename onto `output_path` ONLY after full authentication succeeds.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
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

fn encrypt_reader_to_writer<R: Read, W: Write>(
    auth: &AuthInput,
    aad: &str,
    reader: &mut R,
    writer: &mut W,
) -> Result<(u64, u64)> {
    match auth {
        AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            strength,
        } => encrypt_stream_with_passphrase(
            passphrase.as_bytes(),
            keyfile_hash.as_ref(),
            reader,
            writer,
            aad.as_bytes(),
            strength.to_params(),
            DEFAULT_CHUNK_SIZE,
        ),
        AuthInput::RawKey(key) => encrypt_stream_with_key(
            key.as_bytes(),
            reader,
            writer,
            aad.as_bytes(),
            DEFAULT_CHUNK_SIZE,
        ),
    }
}

fn decrypt_v2_reader_to_writer<R: Read, W: Write>(
    auth: &AuthInput,
    aad: &str,
    reader: &mut R,
    writer: &mut W,
) -> Result<u64> {
    match auth {
        AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            ..
        } => decrypt_stream_with_passphrase(
            passphrase.as_bytes(),
            keyfile_hash.as_ref(),
            reader,
            writer,
            aad.as_bytes(),
        ),
        AuthInput::RawKey(key) => {
            decrypt_stream_with_key(key.as_bytes(), reader, writer, aad.as_bytes())
        }
    }
}

/// Stream-encrypts an arbitrary file or stdin (`-`) into a `WILS` v2 chunked container
/// (written to a file or stdout `-`).
pub fn run_encrypt(
    auth: AuthInput,
    aad: &str,
    input_path: &str,
    output_path: &str,
) -> Result<()> {
    let in_is_stdin = input_path == "-";
    let out_is_stdout = output_path == "-";

    if !in_is_stdin && !out_is_stdout {
        let in_p = Path::new(input_path);
        let out_p = Path::new(output_path);
        if paths_refer_to_same_file(in_p, out_p) {
            return Err(WilisError::InvalidParameters(
                "input and output paths must not refer to the same file".into(),
            ));
        }
    }

    if out_is_stdout {
        let stdout = io::stdout();
        let mut writer = BufWriter::new(stdout.lock());
        let (in_bytes, out_bytes) = if in_is_stdin {
            let stdin = io::stdin();
            let mut reader = BufReader::new(stdin.lock());
            encrypt_reader_to_writer(&auth, aad, &mut reader, &mut writer)?
        } else {
            let mut reader = BufReader::new(File::open(input_path)?);
            encrypt_reader_to_writer(&auth, aad, &mut reader, &mut writer)?
        };
        writer.flush()?;
        eprintln!(
            "Encrypted (WILS v2 stream) '{}' ({in_bytes} bytes) -> stdout ({out_bytes} bytes)",
            input_path
        );
        return Ok(());
    }

    let out_p = Path::new(output_path);
    if out_p.is_dir() {
        return Err(WilisError::InvalidParameters(format!(
            "output path '{}' is an existing directory",
            output_path
        )));
    }

    let (tmp_path, tmp_file) = create_unique_temp_file(out_p, false)?;
    let res = (|| -> Result<(u64, u64)> {
        let mut writer = BufWriter::new(tmp_file);
        let counts = if in_is_stdin {
            let stdin = io::stdin();
            let mut reader = BufReader::new(stdin.lock());
            encrypt_reader_to_writer(&auth, aad, &mut reader, &mut writer)?
        } else {
            let mut reader = BufReader::new(File::open(input_path)?);
            encrypt_reader_to_writer(&auth, aad, &mut reader, &mut writer)?
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

/// Verifies and decrypts either a `WILS` v1 or `WILS` v2 container from a file or stdin (`-`),
/// writing decrypted plaintext to a file or stdout (`-`).
pub fn run_decrypt(
    auth: AuthInput,
    aad: &str,
    input_path: &str,
    output_path: &str,
) -> Result<()> {
    let in_is_stdin = input_path == "-";
    let out_is_stdout = output_path == "-";

    if !in_is_stdin && !out_is_stdout {
        let in_p = Path::new(input_path);
        let out_p = Path::new(output_path);
        if paths_refer_to_same_file(in_p, out_p) {
            return Err(WilisError::InvalidParameters(
                "input and output paths must not refer to the same file".into(),
            ));
        }
    }

    if !out_is_stdout && Path::new(output_path).is_dir() {
        return Err(WilisError::InvalidParameters(format!(
            "output path '{}' is an existing directory",
            output_path
        )));
    }

    if in_is_stdin {
        let stdin = io::stdin();
        let mut locked_in = stdin.lock();
        let mut prefix = [0u8; 5];
        locked_in.read_exact(&mut prefix).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                WilisError::InvalidFormat("stdin stream is too short to be a WILS container".into())
            } else {
                WilisError::Io(e)
            }
        })?;
        if prefix[0..4] != MAGIC_BYTES {
            return Err(WilisError::InvalidFormat(
                "invalid magic bytes (expected 'WILS')".into(),
            ));
        }
        let mut chained = Cursor::new(prefix).chain(locked_in);
        return decrypt_from_source(&auth, aad, prefix[4], &mut chained, input_path, output_path);
    }

    let in_p = Path::new(input_path);
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

    let mut file_reader = BufReader::new(File::open(in_p)?);
    decrypt_from_source(
        &auth,
        aad,
        prefix[4],
        &mut file_reader,
        input_path,
        output_path,
    )
}

fn decrypt_from_source<R: Read>(
    auth: &AuthInput,
    aad: &str,
    version: u8,
    reader: &mut R,
    input_label: &str,
    output_path: &str,
) -> Result<()> {
    let out_is_stdout = output_path == "-";

    match version {
        FORMAT_VERSION => {
            let mut container = Vec::new();
            reader.read_to_end(&mut container)?;
            let mut plaintext = match auth {
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
            if out_is_stdout {
                let stdout = io::stdout();
                let mut out = stdout.lock();
                let write_res = out.write_all(&plaintext).and_then(|_| out.flush());
                zeroize_bytes(&mut plaintext);
                write_res?;
                eprintln!(
                    "Decrypted & verified (WILS v1) '{}' ({} bytes) -> stdout ({plain_len} bytes)",
                    input_label,
                    container.len(),
                );
            } else {
                let write_res = write_atomic_file(Path::new(output_path), &plaintext, true);
                zeroize_bytes(&mut plaintext);
                write_res?;
                println!(
                    "Decrypted & verified (WILS v1) '{}' ({} bytes) -> '{}' ({plain_len} bytes)",
                    input_label,
                    container.len(),
                    output_path,
                );
            }
            Ok(())
        }
        FORMAT_VERSION_V2 => {
            if out_is_stdout {
                let stdout = io::stdout();
                let mut writer = BufWriter::new(stdout.lock());
                let out_bytes = decrypt_v2_reader_to_writer(auth, aad, reader, &mut writer)?;
                writer.flush()?;
                eprintln!(
                    "Decrypted & verified (WILS v2 stream) '{}' -> stdout ({out_bytes} bytes)",
                    input_label,
                );
                return Ok(());
            }

            let out_p = Path::new(output_path);
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
                let mut writer = BufWriter::new(tmp_file);
                let out_bytes = decrypt_v2_reader_to_writer(auth, aad, reader, &mut writer)?;
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
                        "Decrypted & verified (WILS v2 stream) '{}' -> '{}' ({out_bytes} bytes)",
                        input_label, output_path
                    );
                    Ok(())
                }
                Err(err) => {
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
