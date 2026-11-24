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
use crate::utils::zeroize::zeroize_bytes;

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
    }
    fs::create_dir_all(dest_dir)?;

    let mut copy_buf = [0u8; 64 * 1024];
    let mut seen_paths: HashSet<String> = HashSet::new();

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
            if !seen_paths.insert(rel_path.clone()) {
                return Err(WilisError::InvalidFormat(format!(
                    "duplicate entry path rejected in WDIR archive: '{rel_path}'"
                )));
            }
            ensure_no_symlink_components(dest_dir, &rel_path)?;

            let mut size_buf = [0u8; 8];
            read_exact_or_fmt(reader, &mut size_buf, "truncated WDIR file size")?;
            let mut remaining = u64::from_le_bytes(size_buf);

            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut out_file = File::create(&target_path)?;
            while remaining > 0 {
                let to_read = remaining.min(copy_buf.len() as u64) as usize;
                read_exact_or_fmt(reader, &mut copy_buf[..to_read], "truncated WDIR file payload")?;
                out_file.write_all(&copy_buf[..to_read])?;
                remaining -= to_read as u64;
            }
        }

        // Strict canonical check: reject unexpected trailing garbage bytes
        let mut trailing = [0u8; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err(WilisError::InvalidFormat(
                "unexpected trailing bytes after WDIR archive end".into(),
            ));
        }
        Ok(())
    })();
    zeroize_bytes(&mut copy_buf);
    extract_res?;

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
    let unpack_res = unpack_directory(&mut Cursor::new(&decrypted), dest_dir);
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
    let unpack_res = unpack_directory(&mut Cursor::new(&decrypted), dest_dir);
    zeroize_bytes(&mut decrypted);
    unpack_res
}
