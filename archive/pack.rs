//! Recursive directory packing (`WDIR` v1) and encrypted folder sealing.

use std::fs::{self, File};
use std::io::{BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};

use crate::core::constants::{HASH_BYTES, KEY_BYTES};
use crate::error::{Result, WilisError};
use crate::kdf::KdfParams;
use crate::stream::{
    encrypt_stream_with_key, encrypt_stream_with_passphrase, DEFAULT_CHUNK_SIZE,
};

/// Magic header for the custom Wilis directory archive format.
pub const WDIR_MAGIC: [u8; 4] = *b"WDIR";
pub const WDIR_VERSION: u8 = 1;

/// Recursively collects and serializes all files inside `root_dir` into a canonical `WDIR` stream.
///
/// Symlinks are skipped to avoid unintended escape outside the source directory.
/// Returns the total number of files archived.
pub fn pack_directory<W: Write>(root_dir: &Path, writer: &mut W) -> Result<u64> {
    if !root_dir.is_dir() {
        return Err(WilisError::InvalidFormat(format!(
            "'{}' is not a directory",
            root_dir.display()
        )));
    }

    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    collect_files(root_dir, root_dir, &mut entries)?;
    // Deterministic lexicographical ordering
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    writer.write_all(&WDIR_MAGIC)?;
    writer.write_all(&[WDIR_VERSION])?;
    writer.write_all(&(entries.len() as u64).to_le_bytes())?;

    let mut copy_buf = [0u8; 64 * 1024];
    for (rel_path, full_path) in &entries {
        let path_bytes = rel_path.as_bytes();
        if path_bytes.len() > u32::MAX as usize {
            return Err(WilisError::InvalidFormat("file path too long".into()));
        }
        let meta = fs::metadata(full_path)?;
        let file_len = meta.len();

        writer.write_all(&(path_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(path_bytes)?;
        writer.write_all(&file_len.to_le_bytes())?;

        let mut f = File::open(full_path)?;
        let mut remaining = file_len;
        while remaining > 0 {
            let to_read = (remaining as usize).min(copy_buf.len());
            let n = f.read(&mut copy_buf[..to_read])?;
            if n == 0 {
                return Err(WilisError::InvalidFormat(format!(
                    "file '{}' changed size during archiving",
                    full_path.display()
                )));
            }
            writer.write_all(&copy_buf[..n])?;
            remaining -= n as u64;
        }
    }

    writer.flush()?;
    Ok(entries.len() as u64)
}

fn collect_files(
    root: &Path,
    current: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    for entry_res in fs::read_dir(current)? {
        let entry = entry_res?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            collect_files(root, &path, out)?;
        } else if file_type.is_file() {
            let rel = path.strip_prefix(root).map_err(|_| {
                WilisError::InvalidFormat("failed to compute relative path".into())
            })?;
            // Normalize path separators to forward slashes for cross-platform archives
            let normalized = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((normalized, path));
        }
    }
    Ok(())
}

/// Packs and encrypts an entire directory using a raw 256-bit key into a `WILS` v2 file.
pub fn encrypt_directory_with_key(
    key: &[u8; KEY_BYTES],
    source_dir: &Path,
    output_file: &Path,
    user_aad: &[u8],
) -> Result<(u64, u64)> {
    let mut packed = Vec::new();
    let file_count = pack_directory(source_dir, &mut packed)?;
    let mut writer = BufWriter::new(File::create(output_file)?);
    let (_, out_bytes) = encrypt_stream_with_key(
        key,
        &mut Cursor::new(&packed),
        &mut writer,
        user_aad,
        DEFAULT_CHUNK_SIZE,
    )?;
    Ok((file_count, out_bytes))
}

/// Packs and encrypts an entire directory using a passphrase (+ optional 2FA keyfile).
pub fn encrypt_directory_with_passphrase(
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    source_dir: &Path,
    output_file: &Path,
    user_aad: &[u8],
    params: KdfParams,
) -> Result<(u64, u64)> {
    let mut packed = Vec::new();
    let file_count = pack_directory(source_dir, &mut packed)?;
    let mut writer = BufWriter::new(File::create(output_file)?);
    let (_, out_bytes) = encrypt_stream_with_passphrase(
        passphrase,
        keyfile_hash,
        &mut Cursor::new(&packed),
        &mut writer,
        user_aad,
        params,
        DEFAULT_CHUNK_SIZE,
    )?;
    Ok((file_count, out_bytes))
}
