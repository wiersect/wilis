//! Safe `WDIR` v1 unpacking with strict Zip-Slip, symlink-escape, duplicate-entry,
//! and cross-platform path-traversal protection.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::archive::pack::{WDIR_MAGIC, WDIR_VERSION};
use crate::core::constants::{HASH_BYTES, KEY_BYTES};
use crate::error::{Result, WilisError};
use crate::stream::{decrypt_stream_with_key, decrypt_stream_with_passphrase};
use crate::utils::zeroize::{create_unique_temp_file, zeroize_bytes};

/// Returns `true` if `part` is a Windows reserved DOS device name (e.g. `CON`, `NUL.txt`, `COM1`).
fn is_windows_reserved_name(part: &str) -> bool {
    let stem = part.split('.').next().unwrap_or(part);
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// Validates a relative archive path to completely block path traversal (`..`, absolute
/// paths, drive prefixes, colons/ADS, backslashes, control chars, trailing dots/spaces,
/// and Windows reserved device names).
pub fn sanitize_archive_path(dest_root: &Path, rel_path: &str) -> Result<PathBuf> {
    if rel_path.is_empty()
        || rel_path.contains('\0')
        || rel_path.contains('\\')
        || rel_path.contains(':')
        || rel_path.starts_with('/')
        || rel_path.bytes().any(|b| b < 0x20 || b == 0x7F)
    {
        return Err(WilisError::InvalidFormat(format!(
            "unsafe path rejected in archive: '{rel_path}'"
        )));
    }

    let mut clean = dest_root.to_path_buf();
    let mut component_count = 0usize;

    for comp in Path::new(rel_path).components() {
        match comp {
            Component::Normal(part) => {
                let s = part.to_str().ok_or_else(|| {
                    WilisError::InvalidEncoding("non-UTF-8 path component in archive".into())
                })?;
                if s.is_empty()
                    || s.ends_with('.')
                    || s.ends_with(' ')
                    || is_windows_reserved_name(s)
                {
                    return Err(WilisError::InvalidFormat(format!(
                        "unsafe or reserved path component rejected in archive: '{rel_path}'"
                    )));
                }
                clean.push(part);
                component_count += 1;
            }
            _ => {
                return Err(WilisError::InvalidFormat(format!(
                    "path traversal component rejected in archive: '{rel_path}'"
                )));
            }
        }
    }

    if component_count == 0 {
        return Err(WilisError::InvalidFormat(
            "empty normalized archive path rejected".into(),
        ));
    }

    Ok(clean)
}

/// Verifies that neither `dest_root` nor any intermediate directory component or target
/// file under `dest_root` is a symbolic link (prevents symlink-escape writes).
fn ensure_no_symlink_components(dest_root: &Path, rel_path: &str) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(dest_root) {
        if meta.file_type().is_symlink() {
            return Err(WilisError::InvalidFormat(
                "destination root directory must not be a symlink".into(),
            ));
        }
    }
    let mut cur = dest_root.to_path_buf();
    for comp in Path::new(rel_path).components() {
        if let Component::Normal(part) = comp {
            cur.push(part);
            if let Ok(meta) = fs::symlink_metadata(&cur) {
                if meta.file_type().is_symlink() {
                    return Err(WilisError::InvalidFormat(format!(
                        "refusing to extract through existing symlink at '{}'",
                        cur.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

fn create_secure_dir_all(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    Ok(())
}

fn read_exact_or_fmt<R: Read>(reader: &mut R, buf: &mut [u8], eof_msg: &str) -> Result<()> {
    reader.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            WilisError::InvalidFormat(eof_msg.to_string())
        } else {
            WilisError::Io(e)
        }
    })
}

/// Unpacks a verified `WDIR` v1 byte stream into `dest_dir`, returning extracted file count.
pub fn unpack_directory<R: Read>(reader: &mut R, dest_dir: &Path) -> Result<u64> {
    let mut hdr = [0u8; 13];
    read_exact_or_fmt(reader, &mut hdr, "truncated WDIR archive header")?;

    if hdr[0..4] != WDIR_MAGIC || hdr[4] != WDIR_VERSION {
        return Err(WilisError::InvalidFormat(
            "invalid WDIR archive magic or unsupported version".into(),
        ));
    }

    let file_count = u64::from_le_bytes(hdr[5..13].try_into().expect("8 bytes"));
    const MAX_ARCHIVE_FILES: u64 = 1_000_000;
    if file_count > MAX_ARCHIVE_FILES {
        return Err(WilisError::InvalidFormat(format!(
            "WDIR file_count {file_count} exceeds safety limit ({MAX_ARCHIVE_FILES})"
        )));
    }
    if let Ok(meta) = fs::symlink_metadata(dest_dir) {
        if meta.file_type().is_symlink() {
            return Err(WilisError::InvalidFormat(
                "destination directory must not be a symlink".into(),
            ));
        }
        if !meta.file_type().is_dir() {
            return Err(WilisError::InvalidFormat(
                "destination path exists and is not a directory".into(),
            ));
        }
    }
    create_secure_dir_all(dest_dir)?;

    let mut copy_buf = [0u8; 64 * 1024];
    // Track case-folded file and directory paths to prevent case-insensitive overwrites
    // (macOS APFS / Windows NTFS) and file-vs-directory prefix collisions.
    let mut seen_files_ci: HashSet<String> = HashSet::new();
    let mut seen_dirs_ci: HashSet<String> = HashSet::new();

    let extract_res = (|| -> Result<()> {
        for _ in 0..file_count {
            let mut len_buf = [0u8; 4];
            read_exact_or_fmt(reader, &mut len_buf, "truncated WDIR path length")?;
            let path_len = u32::from_le_bytes(len_buf) as usize;
            if path_len == 0 || path_len > 4096 {
                return Err(WilisError::InvalidFormat(
                    "invalid WDIR entry path length".into(),
                ));
            }

            let mut path_bytes = vec![0u8; path_len];
            read_exact_or_fmt(reader, &mut path_bytes, "truncated WDIR entry path")?;
            let rel_path = String::from_utf8(path_bytes).map_err(|_| {
                WilisError::InvalidEncoding("non-UTF-8 path in WDIR archive".into())
            })?;

            let target_path = sanitize_archive_path(dest_dir, &rel_path)?;
            let norm_ci = Path::new(&rel_path)
                .components()
                .filter_map(|c| match c {
                    Component::Normal(p) => p.to_str().map(|s| s.to_ascii_lowercase()),
                    _ => None,
                })
                .collect::<Vec<_>>();

            let full_ci = norm_ci.join("/");
            if seen_dirs_ci.contains(&full_ci) || !seen_files_ci.insert(full_ci) {
                return Err(WilisError::InvalidFormat(format!(
                    "duplicate or conflicting entry path rejected in WDIR archive: '{rel_path}'"
                )));
            }
            for depth in 1..norm_ci.len() {
                let prefix_ci = norm_ci[..depth].join("/");
                if seen_files_ci.contains(&prefix_ci) {
                    return Err(WilisError::InvalidFormat(format!(
                        "file-vs-directory path conflict rejected in WDIR archive: '{rel_path}'"
                    )));
                }
                seen_dirs_ci.insert(prefix_ci);
            }

            ensure_no_symlink_components(dest_dir, &rel_path)?;

            let mut size_buf = [0u8; 8];
            read_exact_or_fmt(reader, &mut size_buf, "truncated WDIR file size")?;
            let mut remaining = u64::from_le_bytes(size_buf);

            if let Some(parent) = target_path.parent() {
                create_secure_dir_all(parent)?;
            }

            // Extract atomically via CSPRNG O_EXCL sibling temp file (mode 0600 on Unix)
            // so extraction can never follow a raced symlink or leave half-written files.
            let (tmp_path, mut out_file) = create_unique_temp_file(&target_path, true)?;
            let write_res = (|| -> Result<()> {
                while remaining > 0 {
                    let to_read = remaining.min(copy_buf.len() as u64) as usize;
                    read_exact_or_fmt(reader, &mut copy_buf[..to_read], "truncated WDIR file payload")?;
                    out_file.write_all(&copy_buf[..to_read])?;
                    remaining -= to_read as u64;
                }
                out_file.sync_all()?;
                Ok(())
            })();
            drop(out_file);
            if let Err(e) = write_res {
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
            if let Err(e) = ensure_no_symlink_components(dest_dir, &rel_path) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
            if let Err(e) = fs::rename(&tmp_path, &target_path) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e.into());
            }
        }

        // Strict canonical check: reject unexpected trailing garbage bytes (retrying EINTR)
        let mut trailing = [0u8; 1];
        loop {
            match reader.read(&mut trailing) {
                Ok(0) => break,
                Ok(_) => {
                    return Err(WilisError::InvalidFormat(
                        "unexpected trailing bytes after WDIR archive end".into(),
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    })();
    zeroize_bytes(&mut copy_buf);
    extract_res?;

    Ok(file_count)
}

/// Performs a full read-only dry-run validation of an in-memory `WDIR` v1 archive
/// against `dest_dir` BEFORE creating any directories or files on disk.
///
/// Rejects truncated headers/payloads, trailing garbage, traversal/reserved paths,
/// case-folding/file-vs-dir collisions, and existing symlinks without touching the filesystem.
pub fn validate_wdir_buffer(data: &[u8], dest_dir: &Path) -> Result<u64> {
    if data.len() < 13 || data[0..4] != WDIR_MAGIC || data[4] != WDIR_VERSION {
        return Err(WilisError::InvalidFormat(
            "invalid or truncated WDIR archive header".into(),
        ));
    }
    let file_count = u64::from_le_bytes(data[5..13].try_into().expect("8 bytes"));
    const MAX_ARCHIVE_FILES: u64 = 1_000_000;
    if file_count > MAX_ARCHIVE_FILES {
        return Err(WilisError::InvalidFormat(format!(
            "WDIR file_count {file_count} exceeds safety limit ({MAX_ARCHIVE_FILES})"
        )));
    }
    if let Ok(meta) = fs::symlink_metadata(dest_dir) {
        if meta.file_type().is_symlink() {
            return Err(WilisError::InvalidFormat(
                "destination directory must not be a symlink".into(),
            ));
        }
        if !meta.file_type().is_dir() {
            return Err(WilisError::InvalidFormat(
                "destination path exists and is not a directory".into(),
            ));
        }
    }

    let mut pos = 13usize;
    let mut seen_files_ci: HashSet<String> = HashSet::new();
    let mut seen_dirs_ci: HashSet<String> = HashSet::new();

    for _ in 0..file_count {
        if data.len().saturating_sub(pos) < 4 {
            return Err(WilisError::InvalidFormat("truncated WDIR path length".into()));
        }
        let path_len = u32::from_le_bytes(data[pos..pos + 4].try_into().expect("4 bytes")) as usize;
        pos += 4;
        if path_len == 0 || path_len > 4096 || data.len().saturating_sub(pos) < path_len {
            return Err(WilisError::InvalidFormat(
                "invalid or truncated WDIR entry path".into(),
            ));
        }
        let rel_path = core::str::from_utf8(&data[pos..pos + path_len])
            .map_err(|_| WilisError::InvalidEncoding("non-UTF-8 path in WDIR archive".into()))?;
        pos += path_len;

        sanitize_archive_path(dest_dir, rel_path)?;
        let norm_ci = Path::new(rel_path)
            .components()
            .filter_map(|c| match c {
                Component::Normal(p) => p.to_str().map(|s| s.to_ascii_lowercase()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let full_ci = norm_ci.join("/");
        if seen_dirs_ci.contains(&full_ci) || !seen_files_ci.insert(full_ci) {
            return Err(WilisError::InvalidFormat(format!(
                "duplicate or conflicting entry path rejected in WDIR archive: '{rel_path}'"
            )));
        }
        for depth in 1..norm_ci.len() {
            let prefix_ci = norm_ci[..depth].join("/");
            if seen_files_ci.contains(&prefix_ci) {
                return Err(WilisError::InvalidFormat(format!(
                    "file-vs-directory path conflict rejected in WDIR archive: '{rel_path}'"
                )));
            }
            seen_dirs_ci.insert(prefix_ci);
        }
        ensure_no_symlink_components(dest_dir, rel_path)?;

        if data.len().saturating_sub(pos) < 8 {
            return Err(WilisError::InvalidFormat("truncated WDIR file size".into()));
        }
        let file_len = u64::from_le_bytes(data[pos..pos + 8].try_into().expect("8 bytes"));
        pos += 8;
        if (data.len().saturating_sub(pos) as u64) < file_len {
            return Err(WilisError::InvalidFormat("truncated WDIR file payload".into()));
        }
        pos += file_len as usize;
    }

    if pos != data.len() {
        return Err(WilisError::InvalidFormat(
            "unexpected trailing bytes after WDIR archive end".into(),
        ));
    }
    Ok(file_count)
}

/// Authenticates, decrypts, and safely unpacks a `WILS` v2 directory archive using a raw key.
pub fn decrypt_directory_with_key(
    key: &[u8; KEY_BYTES],
    input_file: &Path,
    dest_dir: &Path,
    user_aad: &[u8],
) -> Result<u64> {
    let mut reader = BufReader::new(File::open(input_file)?);
    let mut decrypted = Vec::new();
    let dec_res = decrypt_stream_with_key(key, &mut reader, &mut decrypted, user_aad);
    if let Err(e) = dec_res {
        zeroize_bytes(&mut decrypted);
        return Err(e);
    }
    // Auto-dispatch WDIR v2 cleanly if archive was created with constant-memory WDIR v2
    if decrypted.len() >= 5 && decrypted[0..4] == WDIR_MAGIC && decrypted[4] == 2 {
        let unpack_res =
            crate::archive::stream_dir::unpack_directory_v2(&mut Cursor::new(&decrypted), dest_dir);
        zeroize_bytes(&mut decrypted);
        return unpack_res;
    }
    // Dry-run validate the entire archive before creating any files/dirs on disk
    let unpack_res = validate_wdir_buffer(&decrypted, dest_dir)
        .and_then(|_| unpack_directory(&mut Cursor::new(&decrypted), dest_dir));
    zeroize_bytes(&mut decrypted);
    unpack_res
}

/// Authenticates, decrypts, and safely unpacks a `WILS` v2 directory archive using a passphrase.
pub fn decrypt_directory_with_passphrase(
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    input_file: &Path,
    dest_dir: &Path,
    user_aad: &[u8],
) -> Result<u64> {
    let mut reader = BufReader::new(File::open(input_file)?);
    let mut decrypted = Vec::new();
    let dec_res = decrypt_stream_with_passphrase(
        passphrase,
        keyfile_hash,
        &mut reader,
        &mut decrypted,
        user_aad,
    );
    if let Err(e) = dec_res {
        zeroize_bytes(&mut decrypted);
        return Err(e);
    }
    if decrypted.len() >= 5 && decrypted[0..4] == WDIR_MAGIC && decrypted[4] == 2 {
        let unpack_res =
            crate::archive::stream_dir::unpack_directory_v2(&mut Cursor::new(&decrypted), dest_dir);
        zeroize_bytes(&mut decrypted);
        return unpack_res;
    }
    // Dry-run validate the entire archive before creating any files/dirs on disk
    let unpack_res = validate_wdir_buffer(&decrypted, dest_dir)
        .and_then(|_| unpack_directory(&mut Cursor::new(&decrypted), dest_dir));
    zeroize_bytes(&mut decrypted);
    unpack_res
}
