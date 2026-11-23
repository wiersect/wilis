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
use crate::utils::zeroize::zeroize_bytes;

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
    let copy_res = (|| -> Result<()> {
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
                let to_read = remaining.min(copy_buf.len() as u64) as usize;
                let n = match f.read(&mut copy_buf[..to_read]) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                };
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
        Ok(())
    })();
    zeroize_bytes(&mut copy_buf);
    copy_res?;

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

fn validate_output_outside_source(source_dir: &Path, output_file: &Path) -> Result<()> {
    if let Ok(canon_src) = fs::canonicalize(source_dir) {
        if let Some(parent) = output_file.parent() {
            let check_parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            if let Ok(canon_parent) = fs::canonicalize(check_parent) {
                if canon_parent.starts_with(&canon_src) {
                    return Err(WilisError::InvalidFormat(
                        "output archive must not be placed inside the source directory".into(),
                    ));
                }
            }
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
    validate_output_outside_source(source_dir, output_file)?;
    let mut packed = Vec::new();
    let pack_res = pack_directory(source_dir, &mut packed);
    let file_count = match pack_res {
        Ok(n) => n,
        Err(e) => {
            zeroize_bytes(&mut packed);
            return Err(e);
        }
    };
    let mut tmp_os = output_file.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);

    let enc_res = (|| -> Result<u64> {
        let mut writer = BufWriter::new(File::create(&tmp_path)?);
        let (_, out_bytes) = encrypt_stream_with_key(
            key,
            &mut Cursor::new(&packed),
            &mut writer,
            user_aad,
            DEFAULT_CHUNK_SIZE,
        )?;
        Ok(out_bytes)
    })();
    zeroize_bytes(&mut packed);

    match enc_res {
        Ok(out_bytes) => {
            if let Err(e) = fs::rename(&tmp_path, output_file) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e.into());
            }
            Ok((file_count, out_bytes))
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
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
    validate_output_outside_source(source_dir, output_file)?;
    let mut packed = Vec::new();
    let pack_res = pack_directory(source_dir, &mut packed);
    let file_count = match pack_res {
        Ok(n) => n,
        Err(e) => {
            zeroize_bytes(&mut packed);
            return Err(e);
        }
    };
    let mut tmp_os = output_file.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);

    let enc_res = (|| -> Result<u64> {
        let mut writer = BufWriter::new(File::create(&tmp_path)?);
        let (_, out_bytes) = encrypt_stream_with_passphrase(
            passphrase,
            keyfile_hash,
            &mut Cursor::new(&packed),
            &mut writer,
            user_aad,
            params,
            DEFAULT_CHUNK_SIZE,
        )?;
        Ok(out_bytes)
    })();
    zeroize_bytes(&mut packed);

    match enc_res {
        Ok(out_bytes) => {
            if let Err(e) = fs::rename(&tmp_path, output_file) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e.into());
            }
            Ok((file_count, out_bytes))
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}
