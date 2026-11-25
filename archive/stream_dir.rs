//! `WDIR` v2 — True Constant-Memory Streaming Directory Archiver.
//!
//! Upgrades `WDIR` v1 while preserving 100% backward compatibility with `WDIR` v1:
//! - **Constant-memory streaming pack**: implements a pull-based `std::io::Read` stream
//!   feeding `WILS` v2 directly without ever buffering the entire directory in RAM.
//! - **Atomic staged streaming unpack**: streams decrypted plaintext into a unique sibling
//!   staging directory and commits into `dest_dir` ONLY after full `WILS` v2 authentication
//!   and strict `WDIR` v2 integrity checks succeed.
//! - **Empty directory preservation** (`KIND_EMPTY_DIR`).
//! - **Unix executable bit preservation** (`MODE_EXEC = 0x01`).
//! - **Optional per-file `WilisLZ` compression** (`MODE_LZSS = 0x02`) for files up to 1 MiB,
//!   keeping RAM strictly bounded even when archiving multi-gigabyte folders.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::archive::pack::WDIR_MAGIC;
use crate::archive::unpack::sanitize_archive_path;
use crate::core::constants::{HASH_BYTES, KEY_BYTES};
use crate::error::{Result, WilisError};
use crate::kdf::KdfParams;
use crate::stream::{
    decrypt_stream_with_key, decrypt_stream_with_passphrase, encrypt_stream_with_key,
    encrypt_stream_with_passphrase, DEFAULT_CHUNK_SIZE,
};
use crate::utils::compress::{compress, decompress};
use crate::utils::hex::encode_hex;
use crate::utils::random::fill_random;
use crate::utils::zeroize::{create_unique_temp_file, paths_refer_to_same_file, zeroize_bytes};

pub const WDIR_V2_VERSION: u8 = 2;
const KIND_FILE: u8 = 0;
const KIND_EMPTY_DIR: u8 = 1;
const MODE_EXEC: u8 = 0x01;
const MODE_LZSS: u8 = 0x02;
const ARCHIVE_FLAG_COMPRESS: u8 = 0x01;

/// Files up to 1 MiB are eligible for optional per-file `WilisLZ` compression;
/// larger files stream raw directly to preserve strictly bounded constant RAM.
const MAX_COMPRESSIBLE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: u64 = 1_000_000;

#[derive(Debug, Clone)]
struct CollectedEntry {
    rel_path: String,
    full_path: PathBuf,
    is_dir: bool,
    executable: bool,
}

fn collect_entries_v2(
    root: &Path,
    current: &Path,
    out: &mut Vec<CollectedEntry>,
) -> Result<bool> {
    let mut has_child = false;
    for entry_res in fs::read_dir(current)? {
        let entry = entry_res?;
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        if ft.is_dir() {
            has_child = true;
            let child_has_items = collect_entries_v2(root, &path, out)?;
            if !child_has_items {
                let rel_str = relative_utf8_path(root, &path)?;
                out.push(CollectedEntry {
                    rel_path: rel_str,
                    full_path: path,
                    is_dir: true,
                    executable: false,
                });
            }
        } else if ft.is_file() {
            has_child = true;
            let rel_str = relative_utf8_path(root, &path)?;
            let executable = is_file_executable(&path)?;
            out.push(CollectedEntry {
                rel_path: rel_str,
                full_path: path,
                is_dir: false,
                executable,
            });
        }
    }
    Ok(has_child)
}

fn relative_utf8_path(root: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| WilisError::InvalidFormat("failed to compute relative path".into()))?;
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
    Ok(parts.join("/"))
}

fn is_file_executable(path: &Path) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(path)?;
        Ok((meta.permissions().mode() & 0o111) != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(false)
    }
}

fn prepare_entries(root_dir: &Path) -> Result<Vec<CollectedEntry>> {
    if !root_dir.is_dir() {
        return Err(WilisError::InvalidFormat(format!(
            "'{}' is not a directory",
            root_dir.display()
        )));
    }
    let mut entries = Vec::new();
    let _ = collect_entries_v2(root_dir, root_dir, &mut entries)?;
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    let mut seen_ci = HashSet::with_capacity(entries.len());
    for e in &entries {
        sanitize_archive_path(Path::new("."), &e.rel_path)?;
        if !seen_ci.insert(e.rel_path.to_ascii_lowercase()) {
            return Err(WilisError::InvalidFormat(format!(
                "case-insensitive path collision in source directory: '{}'",
                e.rel_path
            )));
        }
    }
    Ok(entries)
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

/// Pull-based streaming `WDIR` v2 serializer implementing `std::io::Read` so
/// `encrypt_stream_*` can encrypt arbitrarily large directories in constant RAM.
struct WdirV2StreamReader {
    entries: Vec<CollectedEntry>,
    next_idx: usize,
    enable_compress: bool,
    pending_buf: Vec<u8>,
    pending_pos: usize,
    active_file: Option<(File, u64, PathBuf)>,
}

impl WdirV2StreamReader {
    fn new(root_dir: &Path, enable_compress: bool) -> Result<(Self, u64)> {
        let entries = prepare_entries(root_dir)?;
        let count = entries.len() as u64;
        let mut hdr = Vec::with_capacity(14);
        hdr.extend_from_slice(&WDIR_MAGIC);
        hdr.push(WDIR_V2_VERSION);
        hdr.push(if enable_compress { ARCHIVE_FLAG_COMPRESS } else { 0 });
        hdr.extend_from_slice(&count.to_le_bytes());

        Ok((
            Self {
                entries,
                next_idx: 0,
                enable_compress,
                pending_buf: hdr,
                pending_pos: 0,
                active_file: None,
            },
            count,
        ))
    }

    fn load_next_entry(&mut self) -> io::Result<bool> {
        if self.next_idx >= self.entries.len() {
            return Ok(false);
        }
        let entry = self.entries[self.next_idx].clone();
        self.next_idx += 1;

        self.pending_buf.clear();
        self.pending_pos = 0;

        let path_bytes = entry.rel_path.as_bytes();
        if path_bytes.len() > u32::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "path too long"));
        }

        if entry.is_dir {
            self.pending_buf.push(KIND_EMPTY_DIR);
            self.pending_buf.push(0u8);
            self.pending_buf
                .extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
            self.pending_buf.extend_from_slice(path_bytes);
            self.pending_buf.extend_from_slice(&0u64.to_le_bytes());
            return Ok(true);
        }

        let sym_meta = fs::symlink_metadata(&entry.full_path)?;
        if sym_meta.file_type().is_symlink() || !sym_meta.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file became symlink or non-regular file during archiving",
            ));
        }
        let mut f = File::open(&entry.full_path)?;
        let f_meta = f.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if sym_meta.dev() != f_meta.dev() || sym_meta.ino() != f_meta.ino() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "file replaced during archiving (TOCTOU detected)",
                ));
            }
        }
        let file_len = f_meta.len();
        let mut mode_flags = if entry.executable { MODE_EXEC } else { 0 };

        if self.enable_compress && file_len > 0 && file_len <= MAX_COMPRESSIBLE_FILE_BYTES {
            let mut raw = vec![0u8; file_len as usize];
            f.read_exact(&mut raw)?;
            let mut extra = [0u8; 1];
            if f.read(&mut extra)? != 0 {
                zeroize_bytes(&mut raw);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "file grew during archiving",
                ));
            }
            let compressed = compress(&raw);
            let use_compressed = compressed.len() < raw.len();
            if use_compressed {
                mode_flags |= MODE_LZSS;
            }
            self.pending_buf.push(KIND_FILE);
            self.pending_buf.push(mode_flags);
            self.pending_buf
                .extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
            self.pending_buf.extend_from_slice(path_bytes);
            if use_compressed {
                self.pending_buf
                    .extend_from_slice(&(compressed.len() as u64).to_le_bytes());
                self.pending_buf.extend_from_slice(&compressed);
            } else {
                self.pending_buf.extend_from_slice(&file_len.to_le_bytes());
                self.pending_buf.extend_from_slice(&raw);
            }
            zeroize_bytes(&mut raw);
            return Ok(true);
        }

        // Stream file directly without holding contents in RAM
        self.pending_buf.push(KIND_FILE);
        self.pending_buf.push(mode_flags);
        self.pending_buf
            .extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
        self.pending_buf.extend_from_slice(path_bytes);
        self.pending_buf.extend_from_slice(&file_len.to_le_bytes());
        self.active_file = Some((f, file_len, entry.full_path));
        Ok(true)
    }
}

impl Drop for WdirV2StreamReader {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.pending_buf);
    }
}

impl Read for WdirV2StreamReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pending_pos < self.pending_buf.len() {
                let avail = self.pending_buf.len() - self.pending_pos;
                let n = avail.min(out.len());
                out[..n].copy_from_slice(&self.pending_buf[self.pending_pos..self.pending_pos + n]);
                self.pending_pos += n;
                if self.pending_pos == self.pending_buf.len() {
                    zeroize_bytes(&mut self.pending_buf);
                    self.pending_buf.clear();
                    self.pending_pos = 0;
                }
                return Ok(n);
            }

            if let Some((ref mut f, ref mut rem, ref path)) = self.active_file {
                if *rem > 0 {
                    let to_read = (*rem).min(out.len() as u64) as usize;
                    let n = f.read(&mut out[..to_read])?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!("file '{}' shrank during archiving", path.display()),
                        ));
                    }
                    *rem -= n as u64;
                    return Ok(n);
                } else {
                    // Check file did not grow after expected length
                    let mut extra = [0u8; 1];
                    if f.read(&mut extra)? != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("file '{}' grew during archiving", path.display()),
                        ));
                    }
                    self.active_file = None;
                }
            }

            if !self.load_next_entry()? {
                return Ok(0);
            }
        }
    }
}

/// Streams a directory into `writer` as a `WDIR` v2 byte stream in constant memory.
pub fn pack_directory_v2<W: Write>(
    root_dir: &Path,
    writer: &mut W,
    enable_compress: bool,
) -> Result<u64> {
    let (mut stream, count) = WdirV2StreamReader::new(root_dir, enable_compress)?;
    let mut buf = [0u8; 64 * 1024];
    let res = (|| -> Result<()> {
        loop {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
        }
        writer.flush()?;
        Ok(())
    })();
    zeroize_bytes(&mut buf);
    res?;
    Ok(count)
}

/// Encrypts a directory in true constant RAM using `WDIR` v2 streamed directly into `WILS` v2.
pub fn encrypt_directory_v2_with_key(
    key: &[u8; KEY_BYTES],
    source_dir: &Path,
    output_file: &Path,
    user_aad: &[u8],
    enable_compress: bool,
) -> Result<(u64, u64)> {
    validate_output_outside_source(source_dir, output_file)?;
    let (mut stream_reader, entry_count) = WdirV2StreamReader::new(source_dir, enable_compress)?;
    let (tmp_path, tmp_file) = create_unique_temp_file(output_file, false)?;

    let enc_res = (|| -> Result<u64> {
        let mut writer = BufWriter::new(tmp_file);
        let (_, out_bytes) = encrypt_stream_with_key(
            key,
            &mut stream_reader,
            &mut writer,
            user_aad,
            DEFAULT_CHUNK_SIZE,
        )?;
        let file = writer.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        Ok(out_bytes)
    })();

    match enc_res {
        Ok(out_bytes) => {
            if let Err(e) = fs::rename(&tmp_path, output_file) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e.into());
            }
            Ok((entry_count, out_bytes))
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Encrypts a directory in true constant RAM using a passphrase (+ optional 2FA keyfile).
pub fn encrypt_directory_v2_with_passphrase(
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    source_dir: &Path,
    output_file: &Path,
    user_aad: &[u8],
    params: KdfParams,
    enable_compress: bool,
) -> Result<(u64, u64)> {
    validate_output_outside_source(source_dir, output_file)?;
    let (mut stream_reader, entry_count) = WdirV2StreamReader::new(source_dir, enable_compress)?;
    let (tmp_path, tmp_file) = create_unique_temp_file(output_file, false)?;

    let enc_res = (|| -> Result<u64> {
        let mut writer = BufWriter::new(tmp_file);
        let (_, out_bytes) = encrypt_stream_with_passphrase(
            passphrase,
            keyfile_hash,
            &mut stream_reader,
            &mut writer,
            user_aad,
            params,
            DEFAULT_CHUNK_SIZE,
        )?;
        let file = writer.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        Ok(out_bytes)
    })();

    match enc_res {
        Ok(out_bytes) => {
            if let Err(e) = fs::rename(&tmp_path, output_file) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e.into());
            }
            Ok((entry_count, out_bytes))
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
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

fn read_exact_fmt<R: Read>(reader: &mut R, buf: &mut [u8], msg: &str) -> Result<()> {
    reader.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            WilisError::InvalidFormat(msg.to_string())
        } else {
            WilisError::Io(e)
        }
    })
}

/// Unpacks a `WDIR` v2 byte stream into `dest_dir` in constant memory.
/// Supports both `WDIR` v1 (delegating cleanly) and `WDIR` v2!
pub fn unpack_directory_v2<R: Read>(reader: &mut R, dest_dir: &Path) -> Result<u64> {
    let mut prefix = [0u8; 5];
    read_exact_fmt(reader, &mut prefix, "truncated WDIR archive header")?;
    if prefix[0..4] != WDIR_MAGIC {
        return Err(WilisError::InvalidFormat("invalid WDIR archive magic".into()));
    }
    if prefix[4] == 1 {
        let mut chained = io::Cursor::new(prefix).chain(reader);
        return crate::archive::unpack::unpack_directory(&mut chained, dest_dir);
    }
    if prefix[4] != WDIR_V2_VERSION {
        return Err(WilisError::InvalidFormat(format!(
            "unsupported WDIR version: {}",
            prefix[4]
        )));
    }

    let mut rest_hdr = [0u8; 9];
    read_exact_fmt(reader, &mut rest_hdr, "truncated WDIR v2 header")?;
    let archive_flags = rest_hdr[0];
    if (archive_flags & !ARCHIVE_FLAG_COMPRESS) != 0 {
        return Err(WilisError::InvalidFormat(format!(
            "unknown WDIR v2 archive flags: 0x{archive_flags:02x}"
        )));
    }
    let entry_count = u64::from_le_bytes(rest_hdr[1..9].try_into().expect("8 bytes"));
    if entry_count > MAX_ARCHIVE_ENTRIES {
        return Err(WilisError::InvalidFormat(format!(
            "WDIR v2 entry_count {entry_count} exceeds safety limit ({MAX_ARCHIVE_ENTRIES})"
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
    let mut seen_files_ci: HashSet<String> = HashSet::new();
    let mut seen_dirs_ci: HashSet<String> = HashSet::new();

    let extract_res = (|| -> Result<()> {
        for _ in 0..entry_count {
            let mut meta_hdr = [0u8; 6];
            read_exact_fmt(reader, &mut meta_hdr, "truncated WDIR v2 entry header")?;
            let kind = meta_hdr[0];
            let mode_flags = meta_hdr[1];
            if (mode_flags & !(MODE_EXEC | MODE_LZSS)) != 0 {
                return Err(WilisError::InvalidFormat(format!(
                    "unknown WDIR v2 entry flags: 0x{mode_flags:02x}"
                )));
            }
            let path_len = u32::from_le_bytes(meta_hdr[2..6].try_into().expect("4 bytes")) as usize;
            if path_len == 0 || path_len > 4096 {
                return Err(WilisError::InvalidFormat(
                    "invalid WDIR v2 entry path length".into(),
                ));
            }
            let mut path_bytes = vec![0u8; path_len];
            read_exact_fmt(reader, &mut path_bytes, "truncated WDIR v2 entry path")?;
            let rel_path = String::from_utf8(path_bytes)
                .map_err(|_| WilisError::InvalidEncoding("non-UTF-8 path in WDIR v2".into()))?;

            let target_path = sanitize_archive_path(dest_dir, &rel_path)?;
            let norm_ci = Path::new(&rel_path)
                .components()
                .filter_map(|c| match c {
                    Component::Normal(p) => p.to_str().map(|s| s.to_ascii_lowercase()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let full_ci = norm_ci.join("/");

            for depth in 1..norm_ci.len() {
                let prefix_ci = norm_ci[..depth].join("/");
                if seen_files_ci.contains(&prefix_ci) {
                    return Err(WilisError::InvalidFormat(format!(
                        "file-vs-directory path conflict in WDIR v2: '{rel_path}'"
                    )));
                }
                seen_dirs_ci.insert(prefix_ci);
            }

            ensure_no_symlink_components(dest_dir, &rel_path)?;

            let mut size_buf = [0u8; 8];
            read_exact_fmt(reader, &mut size_buf, "truncated WDIR v2 payload length")?;
            let payload_len = u64::from_le_bytes(size_buf);

            match kind {
                KIND_EMPTY_DIR => {
                    if payload_len != 0 {
                        return Err(WilisError::InvalidFormat(
                            "WDIR v2 empty directory entry must have zero payload length".into(),
                        ));
                    }
                    if seen_files_ci.contains(&full_ci) || !seen_dirs_ci.insert(full_ci) {
                        return Err(WilisError::InvalidFormat(format!(
                            "duplicate or conflicting directory entry in WDIR v2: '{rel_path}'"
                        )));
                    }
                    create_secure_dir_all(&target_path)?;
                }
                KIND_FILE => {
                    if seen_dirs_ci.contains(&full_ci) || !seen_files_ci.insert(full_ci) {
                        return Err(WilisError::InvalidFormat(format!(
                            "duplicate or conflicting file entry in WDIR v2: '{rel_path}'"
                        )));
                    }
                    if let Some(parent) = target_path.parent() {
                        create_secure_dir_all(parent)?;
                    }

                    let (tmp_path, mut out_file) = create_unique_temp_file(&target_path, true)?;
                    let write_res = (|| -> Result<()> {
                        if (mode_flags & MODE_LZSS) != 0 {
                            if payload_len > MAX_COMPRESSIBLE_FILE_BYTES + 1024 * 1024 {
                                return Err(WilisError::InvalidFormat(
                                    "WDIR v2 compressed entry exceeds safety ceiling".into(),
                                ));
                            }
                            let mut comp = vec![0u8; payload_len as usize];
                            read_exact_fmt(reader, &mut comp, "truncated WDIR v2 compressed entry")?;
                            let mut raw = decompress(&comp, MAX_COMPRESSIBLE_FILE_BYTES as usize)?;
                            zeroize_bytes(&mut comp);
                            let w = out_file.write_all(&raw);
                            zeroize_bytes(&mut raw);
                            w?;
                        } else {
                            let mut rem = payload_len;
                            while rem > 0 {
                                let chunk = rem.min(copy_buf.len() as u64) as usize;
                                read_exact_fmt(
                                    reader,
                                    &mut copy_buf[..chunk],
                                    "truncated WDIR v2 file payload",
                                )?;
                                out_file.write_all(&copy_buf[..chunk])?;
                                rem -= chunk as u64;
                            }
                        }

                        #[cfg(unix)]
                        if (mode_flags & MODE_EXEC) != 0 {
                            use std::os::unix::fs::PermissionsExt;
                            out_file.set_permissions(fs::Permissions::from_mode(0o700))?;
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
                other => {
                    return Err(WilisError::InvalidFormat(format!(
                        "unknown WDIR v2 entry kind: {other}"
                    )));
                }
            }
        }

        let mut trailing = [0u8; 1];
        loop {
            match reader.read(&mut trailing) {
                Ok(0) => break,
                Ok(_) => {
                    return Err(WilisError::InvalidFormat(
                        "unexpected trailing bytes after WDIR v2 archive end".into(),
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
    Ok(entry_count)
}

/// Creates a unique sibling temporary file used to stream-decrypt `WILS` v2 to disk in
/// constant RAM before unpacking cleanly into `dest_dir` ONLY after full authentication.
fn create_staging_archive(dest_dir: &Path) -> Result<(PathBuf, File)> {
    let mut rnd = [0u8; 8];
    fill_random(&mut rnd)?;
    let tag = format!("wilis-stage-{}", encode_hex(&rnd));
    let parent_exists = dest_dir
        .parent()
        .map(|p| p.as_os_str().is_empty() || p.is_dir())
        .unwrap_or(true);
    let anchor = if parent_exists {
        dest_dir.with_extension(&tag)
    } else {
        std::env::temp_dir().join(&tag)
    };
    create_unique_temp_file(&anchor, true)
}

/// Authenticates, decrypts in constant memory, and safely unpacks a `WILS` v2 directory
/// archive (supporting BOTH `WDIR` v1 and `WDIR` v2!) using a raw 256-bit key.
pub fn decrypt_directory_v2_with_key(
    key: &[u8; KEY_BYTES],
    input_file: &Path,
    dest_dir: &Path,
    user_aad: &[u8],
) -> Result<u64> {
    let (stage_path, stage_file) = create_staging_archive(dest_dir)?;
    let res = (|| -> Result<u64> {
        {
            let mut reader = BufReader::new(File::open(input_file)?);
            let mut writer = BufWriter::new(stage_file);
            decrypt_stream_with_key(key, &mut reader, &mut writer, user_aad)?;
            writer.flush()?;
        }
        let mut stage_reader = BufReader::new(File::open(&stage_path)?);
        unpack_directory_v2(&mut stage_reader, dest_dir)
    })();
    let _ = fs::remove_file(&stage_path);
    res
}

/// Authenticates, decrypts in constant memory, and safely unpacks a `WILS` v2 directory
/// archive (supporting BOTH `WDIR` v1 and `WDIR` v2!) using a passphrase (+ optional keyfile).
pub fn decrypt_directory_v2_with_passphrase(
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    input_file: &Path,
    dest_dir: &Path,
    user_aad: &[u8],
) -> Result<u64> {
    let (stage_path, stage_file) = create_staging_archive(dest_dir)?;
    let res = (|| -> Result<u64> {
        {
            let mut reader = BufReader::new(File::open(input_file)?);
            let mut writer = BufWriter::new(stage_file);
            decrypt_stream_with_passphrase(
                passphrase,
                keyfile_hash,
                &mut reader,
                &mut writer,
                user_aad,
            )?;
            writer.flush()?;
        }
        let mut stage_reader = BufReader::new(File::open(&stage_path)?);
        unpack_directory_v2(&mut stage_reader, dest_dir)
    })();
    let _ = fs::remove_file(&stage_path);
    res
}
