//! Recursive directory packing (`WDIR` v1) and encrypted folder sealing.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};

use crate::archive::unpack::sanitize_archive_path;
use crate::core::constants::{HASH_BYTES, KEY_BYTES};
use crate::error::{Result, WilisError};
use crate::kdf::KdfParams;
use crate::stream::{
    encrypt_stream_with_key, encrypt_stream_with_passphrase, DEFAULT_CHUNK_SIZE,
};
use crate::utils::zeroize::{create_unique_temp_file, paths_refer_to_same_file, zeroize_bytes};

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

    // Validate all paths & reject case-folding collisions at pack time so we never
    // produce an archive that decrypt-dir would later refuse to extract.
    let mut seen_ci: HashSet<String> = HashSet::with_capacity(entries.len());
    for (rel_path, _) in &entries {
        sanitize_archive_path(Path::new("."), rel_path)?;
        if !seen_ci.insert(rel_path.to_ascii_lowercase()) {
            return Err(WilisError::InvalidFormat(format!(
                "case-insensitive path collision in source directory: '{rel_path}'"
            )));
        }
    }

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
            let sym_meta = fs::symlink_metadata(full_path)?;
            if sym_meta.file_type().is_symlink() || !sym_meta.file_type().is_file() {
                return Err(WilisError::InvalidFormat(format!(
                    "file '{}' became a symlink or non-regular file during archiving",
                    full_path.display()
                )));
            }
            let mut f = File::open(full_path)?;
            let f_meta = f.metadata()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if sym_meta.dev() != f_meta.dev() || sym_meta.ino() != f_meta.ino() {
                    return Err(WilisError::InvalidFormat(format!(
                        "file '{}' was replaced during archiving (TOCTOU detected)",
                        full_path.display()
                    )));
                }
            }
            let file_len = f_meta.len();

            writer.write_all(&(path_bytes.len() as u32).to_le_bytes())?;
            writer.write_all(path_bytes)?;
            writer.write_all(&file_len.to_le_bytes())?;

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
                        "file '{}' shrank during archiving",
                        full_path.display()
                    )));
                }
                writer.write_all(&copy_buf[..n])?;
                remaining -= n as u64;
            }

            // Detect concurrent file growth after reading `file_len` bytes
            let mut extra = [0u8; 1];
            loop {
                match f.read(&mut extra) {
                    Ok(0) => break,
                    Ok(_) => {
                        return Err(WilisError::InvalidFormat(format!(
                            "file '{}' grew during archiving",
                            full_path.display()
                        )));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                }
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
            // Reject non-UTF-8 filenames strictly rather than silently corrupting via lossy replacement
            let mut parts = Vec::new();
            for comp in rel.components() {
                let s = comp.as_os_str().to_str().ok_or_else(|| {
                    WilisError::InvalidEncoding(format!(
                        "non-UTF-8 filename cannot be archived safely: '{}'",
                        path.display()
                    ))
                })?;
                parts.push(s);
            }
            out.push((parts.join("/"), path));
        }
    }
    Ok(())
}

fn validate_output_outside_source(source_dir: &Path, output_file: &Path) -> Result<()> {
    if output_file.is_dir() || paths_refer_to_same_file(source_dir, output_file) {
        return Err(WilisError::InvalidParameters(
            "output archive path must not be an existing directory or the source directory".into(),
        ));
    }
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
    let (tmp_path, tmp_file) = create_unique_temp_file(output_file, false)?;

    let enc_res = (|| -> Result<u64> {
        let mut writer = BufWriter::new(tmp_file);
        let (_, out_bytes) = encrypt_stream_with_key(
            key,
            &mut Cursor::new(&packed),
            &mut writer,
            user_aad,
            DEFAULT_CHUNK_SIZE,
        )?;
        let file = writer.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
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
    let (tmp_path, tmp_file) = create_unique_temp_file(output_file, false)?;

    let enc_res = (|| -> Result<u64> {
        let mut writer = BufWriter::new(tmp_file);
        let (_, out_bytes) = encrypt_stream_with_passphrase(
            passphrase,
            keyfile_hash,
            &mut Cursor::new(&packed),
            &mut writer,
            user_aad,
            params,
            DEFAULT_CHUNK_SIZE,
        )?;
        let file = writer.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
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
