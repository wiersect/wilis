//! `WSEK` v1 — Random-Access Seekable Encrypted Container (`O(1)` range decryption).
//!
//! Unlike sequential `WILS` v2 (which uses variable-length framed chunks), `WSEK` v1
//! places every fixed-size encrypted chunk at an exact predictable byte offset:
//! ```text
//! chunk_offset(i) = header_len + i * (chunk_size + TAG_BYTES)
//! ```
//!
//! Security guarantees:
//! - Every chunk uses a unique 192-bit nonce derived from `(base_nonce, chunk_index, is_final)`.
//! - Every chunk's AAD binds `WilisHash-256(header)` (covering `total_plain_len`, `chunk_size`,
//!   KDF params, salt, and `base_nonce`), `chunk_index`, `is_final`, and `user_aad`.
//! - Truncating, extending, swapping, or tampering with any chunk or header field is
//!   immediately detected upon authenticating the affected chunk.
//! - Reading any byte range `[offset, offset + len)` decrypts and authenticates ONLY
//!   the overlapping chunks in `O(1)` seeks.

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::aead::{open, seal};
use crate::core::constants::{HASH_BYTES, KEY_BYTES, NONCE_BYTES, SALT_BYTES, TAG_BYTES};
use crate::error::{Result, WilisError};
use crate::hash::hash;
use crate::kdf::{derive_key_with_keyfile, KdfParams};
use crate::stream::chunk_nonce::{
    derive_chunk_nonce, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
};
use crate::utils::random::{generate_nonce, generate_salt};
use crate::utils::zeroize::{zeroize_bytes, SecretKey};

pub const WSEK_MAGIC: [u8; 4] = *b"WSEK";
pub const WSEK_VERSION: u8 = 1;
const MODE_RAW_KEY: u8 = 0;
const MODE_PASSPHRASE: u8 = 1;

const RAW_HEADER_BYTES: usize = 4 + 1 + 1 + 4 + 8 + NONCE_BYTES; // 42
const PASS_HEADER_BYTES: usize = RAW_HEADER_BYTES + 4 + 4 + SALT_BYTES; // 82

#[derive(Debug, Clone)]
enum SeekableMode {
    RawKey,
    Passphrase {
        params: KdfParams,
        salt: [u8; SALT_BYTES],
    },
}

#[derive(Debug, Clone)]
struct SeekableHeader {
    mode: SeekableMode,
    chunk_size: u32,
    total_plain_len: u64,
    base_nonce: [u8; NONCE_BYTES],
}

impl SeekableHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let cap = match self.mode {
            SeekableMode::RawKey => RAW_HEADER_BYTES,
            SeekableMode::Passphrase { .. } => PASS_HEADER_BYTES,
        };
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(&WSEK_MAGIC);
        out.push(WSEK_VERSION);
        match self.mode {
            SeekableMode::RawKey => out.push(MODE_RAW_KEY),
            SeekableMode::Passphrase { .. } => out.push(MODE_PASSPHRASE),
        }
        out.extend_from_slice(&self.chunk_size.to_le_bytes());
        out.extend_from_slice(&self.total_plain_len.to_le_bytes());
        out.extend_from_slice(&self.base_nonce);
        if let SeekableMode::Passphrase { params, salt } = self.mode {
            out.extend_from_slice(&params.memory_blocks.to_le_bytes());
            out.extend_from_slice(&params.passes.to_le_bytes());
            out.extend_from_slice(&salt);
        }
        out
    }

    fn read_from<R: Read>(reader: &mut R) -> Result<(Self, Vec<u8>)> {
        let mut fixed = [0u8; RAW_HEADER_BYTES];
        read_exact_fmt(reader, &mut fixed, "truncated WSEK header")?;

        if fixed[0..4] != WSEK_MAGIC {
            return Err(WilisError::InvalidFormat(
                "invalid magic bytes (expected 'WSEK')".into(),
            ));
        }
        if fixed[4] != WSEK_VERSION {
            return Err(WilisError::InvalidFormat(format!(
                "unsupported WSEK version: {}",
                fixed[4]
            )));
        }
        let mode_flag = fixed[5];
        let chunk_size = u32::from_le_bytes(fixed[6..10].try_into().expect("4 bytes"));
        validate_chunk_size(chunk_size)?;
        let total_plain_len = u64::from_le_bytes(fixed[10..18].try_into().expect("8 bytes"));
        let mut base_nonce = [0u8; NONCE_BYTES];
        base_nonce.copy_from_slice(&fixed[18..42]);

        let mut raw = fixed.to_vec();
        let mode = match mode_flag {
            MODE_RAW_KEY => SeekableMode::RawKey,
            MODE_PASSPHRASE => {
                let mut ext = [0u8; 4 + 4 + SALT_BYTES];
                read_exact_fmt(reader, &mut ext, "truncated WSEK KDF header")?;
                let memory_blocks = u32::from_le_bytes(ext[0..4].try_into().expect("4 bytes"));
                let passes = u32::from_le_bytes(ext[4..8].try_into().expect("4 bytes"));
                let params = KdfParams {
                    memory_blocks,
                    passes,
                };
                params.validate()?;
                let mut salt = [0u8; SALT_BYTES];
                salt.copy_from_slice(&ext[8..8 + SALT_BYTES]);
                raw.extend_from_slice(&ext);
                SeekableMode::Passphrase { params, salt }
            }
            other => {
                return Err(WilisError::InvalidFormat(format!(
                    "unknown WSEK key mode flag: {other}"
                )));
            }
        };

        Ok((
            Self {
                mode,
                chunk_size,
                total_plain_len,
                base_nonce,
            },
            raw,
        ))
    }

    fn num_chunks(&self) -> u64 {
        if self.total_plain_len == 0 {
            1
        } else {
            self.total_plain_len.div_ceil(self.chunk_size as u64)
        }
    }

    fn expected_container_len(&self, header_len: usize) -> Result<u64> {
        let chunks = self.num_chunks();
        let tags_bytes = chunks
            .checked_mul(TAG_BYTES as u64)
            .ok_or_else(|| WilisError::InvalidFormat("WSEK container size overflow".into()))?;
        (header_len as u64)
            .checked_add(self.total_plain_len)
            .and_then(|v| v.checked_add(tags_bytes))
            .ok_or_else(|| WilisError::InvalidFormat("WSEK container size overflow".into()))
    }
}

fn validate_chunk_size(chunk_size: u32) -> Result<()> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(WilisError::InvalidParameters(format!(
            "WSEK chunk_size {chunk_size} out of range [{MIN_CHUNK_SIZE}..={MAX_CHUNK_SIZE}] (default {DEFAULT_CHUNK_SIZE})"
        )));
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

fn build_seekable_aad(
    header_digest: &[u8; HASH_BYTES],
    chunk_index: u64,
    is_final: bool,
    user_aad: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(13 + HASH_BYTES + 8 + 1 + 8 + user_aad.len());
    aad.extend_from_slice(b"WILIS-WSEK-v1");
    aad.extend_from_slice(header_digest);
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.push(if is_final { 1 } else { 0 });
    aad.extend_from_slice(&(user_aad.len() as u64).to_le_bytes());
    aad.extend_from_slice(user_aad);
    aad
}

/// Streams a seekable input into a `WSEK` v1 random-access encrypted container using a raw key.
/// Returns total container bytes written.
pub fn encrypt_seekable_with_key<R: Read + Seek, W: Write>(
    key: &[u8; KEY_BYTES],
    reader: &mut R,
    writer: &mut W,
    user_aad: &[u8],
    chunk_size: u32,
) -> Result<u64> {
    validate_chunk_size(chunk_size)?;
    let start_pos = reader.stream_position()?;
    let end_pos = reader.seek(SeekFrom::End(0))?;
    let total_plain_len = end_pos.checked_sub(start_pos).ok_or_else(|| {
        WilisError::InvalidFormat("seekable reader end position precedes start".into())
    })?;
    reader.seek(SeekFrom::Start(start_pos))?;

    let header = SeekableHeader {
        mode: SeekableMode::RawKey,
        chunk_size,
        total_plain_len,
        base_nonce: generate_nonce()?,
    };
    encrypt_seekable_core(key, &header, reader, writer, user_aad)
}

/// Streams a seekable input into a `WSEK` v1 container using a passphrase (+ optional 2FA keyfile).
pub fn encrypt_seekable_with_passphrase<R: Read + Seek, W: Write>(
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    reader: &mut R,
    writer: &mut W,
    user_aad: &[u8],
    params: KdfParams,
    chunk_size: u32,
) -> Result<u64> {
    validate_chunk_size(chunk_size)?;
    let start_pos = reader.stream_position()?;
    let end_pos = reader.seek(SeekFrom::End(0))?;
    let total_plain_len = end_pos.checked_sub(start_pos).ok_or_else(|| {
        WilisError::InvalidFormat("seekable reader end position precedes start".into())
    })?;
    reader.seek(SeekFrom::Start(start_pos))?;

    let salt = generate_salt()?;
    let derived = derive_key_with_keyfile(passphrase, keyfile_hash, &salt, params)?;
    let header = SeekableHeader {
        mode: SeekableMode::Passphrase { params, salt },
        chunk_size,
        total_plain_len,
        base_nonce: generate_nonce()?,
    };
    encrypt_seekable_core(derived.as_bytes(), &header, reader, writer, user_aad)
}

fn encrypt_seekable_core<R: Read, W: Write>(
    key: &[u8; KEY_BYTES],
    header: &SeekableHeader,
    reader: &mut R,
    writer: &mut W,
    user_aad: &[u8],
) -> Result<u64> {
    let header_bytes = header.to_bytes();
    let header_digest = hash(&header_bytes);
    writer.write_all(&header_bytes)?;

    let num_chunks = header.num_chunks();
    let cs = header.chunk_size as usize;
    let mut buf = vec![0u8; cs];
    let mut total_written = header_bytes.len() as u64;

    let res = (|| -> Result<u64> {
        let mut remaining = header.total_plain_len;
        for chunk_index in 0..num_chunks {
            let is_final = chunk_index + 1 == num_chunks;
            let expected_len = if header.total_plain_len == 0 {
                0
            } else {
                remaining.min(cs as u64) as usize
            };

            if expected_len > 0 {
                read_exact_fmt(
                    reader,
                    &mut buf[..expected_len],
                    "input shrank while writing WSEK container",
                )?;
                remaining -= expected_len as u64;
            }

            let nonce = derive_chunk_nonce(&header.base_nonce, chunk_index, is_final);
            let aad = build_seekable_aad(&header_digest, chunk_index, is_final, user_aad);
            let (ct, tag) = seal(key, &nonce, &aad, &buf[..expected_len]);
            writer.write_all(&ct)?;
            writer.write_all(&tag)?;
            total_written = total_written
                .checked_add((ct.len() + tag.len()) as u64)
                .ok_or_else(|| WilisError::InvalidFormat("WSEK output counter overflow".into()))?;
        }
        writer.flush()?;
        Ok(total_written)
    })();

    zeroize_bytes(&mut buf);
    res
}

/// Random-access authenticated reader over a `WSEK` v1 container.
pub struct SeekableReader<R: Read + Seek> {
    reader: R,
    key: SecretKey,
    header: SeekableHeader,
    header_len: u64,
    header_digest: [u8; HASH_BYTES],
    user_aad: Vec<u8>,
}

impl<R: Read + Seek> SeekableReader<R> {
    /// Opens a raw-key `WSEK` v1 container and verifies exact container length against header.
    pub fn open_with_key(
        mut reader: R,
        key: &[u8; KEY_BYTES],
        user_aad: &[u8],
    ) -> Result<Self> {
        reader.seek(SeekFrom::Start(0))?;
        let (header, header_bytes) = SeekableHeader::read_from(&mut reader)?;
        if !matches!(header.mode, SeekableMode::RawKey) {
            return Err(WilisError::InvalidFormat(
                "WSEK container requires a passphrase, not a raw key".into(),
            ));
        }
        Self::finish_open(reader, SecretKey::from_bytes(*key), header, header_bytes, user_aad)
    }

    /// Opens a passphrase-protected `WSEK` v1 container (+ optional 2FA keyfile hash).
    pub fn open_with_passphrase(
        mut reader: R,
        passphrase: &[u8],
        keyfile_hash: Option<&[u8; HASH_BYTES]>,
        user_aad: &[u8],
    ) -> Result<Self> {
        reader.seek(SeekFrom::Start(0))?;
        let (header, header_bytes) = SeekableHeader::read_from(&mut reader)?;
        let (params, salt) = match header.mode {
            SeekableMode::Passphrase { params, salt } => (params, salt),
            SeekableMode::RawKey => {
                return Err(WilisError::InvalidFormat(
                    "WSEK container requires a raw 256-bit key, not a passphrase".into(),
                ));
            }
        };
        let key = derive_key_with_keyfile(passphrase, keyfile_hash, &salt, params)?;
        Self::finish_open(reader, key, header, header_bytes, user_aad)
    }

    fn finish_open(
        mut reader: R,
        key: SecretKey,
        header: SeekableHeader,
        header_bytes: Vec<u8>,
        user_aad: &[u8],
    ) -> Result<Self> {
        let header_len = header_bytes.len();
        let expected_len = header.expected_container_len(header_len)?;
        let actual_len = reader.seek(SeekFrom::End(0))?;
        if actual_len != expected_len {
            return Err(WilisError::InvalidFormat(format!(
                "WSEK container length mismatch: expected {expected_len} bytes, found {actual_len}"
            )));
        }
        let header_digest = hash(&header_bytes);
        Ok(Self {
            reader,
            key,
            header,
            header_len: header_len as u64,
            header_digest,
            user_aad: user_aad.to_vec(),
        })
    }

    /// Total plaintext length in bytes.
    #[inline]
    pub fn len(&self) -> u64 {
        self.header.total_plain_len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.header.total_plain_len == 0
    }

    #[inline]
    pub fn chunk_size(&self) -> u32 {
        self.header.chunk_size
    }

    #[inline]
    pub fn num_chunks(&self) -> u64 {
        self.header.num_chunks()
    }

    fn decrypt_chunk(&mut self, chunk_index: u64) -> Result<Vec<u8>> {
        let num_chunks = self.header.num_chunks();
        if chunk_index >= num_chunks {
            return Err(WilisError::InvalidParameters(
                "WSEK chunk index out of bounds".into(),
            ));
        }
        let cs = self.header.chunk_size as u64;
        let is_final = chunk_index + 1 == num_chunks;
        let plain_len = if self.header.total_plain_len == 0 {
            0usize
        } else if is_final {
            (self.header.total_plain_len - chunk_index * cs) as usize
        } else {
            cs as usize
        };

        let stride = cs + TAG_BYTES as u64;
        let file_offset = self
            .header_len
            .checked_add(
                chunk_index
                    .checked_mul(stride)
                    .ok_or_else(|| WilisError::InvalidFormat("WSEK seek offset overflow".into()))?,
            )
            .ok_or_else(|| WilisError::InvalidFormat("WSEK seek offset overflow".into()))?;

        self.reader.seek(SeekFrom::Start(file_offset))?;
        let mut ct = vec![0u8; plain_len];
        if plain_len > 0 {
            read_exact_fmt(&mut self.reader, &mut ct, "truncated WSEK chunk ciphertext")?;
        }
        let mut tag = [0u8; TAG_BYTES];
        read_exact_fmt(&mut self.reader, &mut tag, "truncated WSEK chunk tag")?;

        let nonce = derive_chunk_nonce(&self.header.base_nonce, chunk_index, is_final);
        let aad = build_seekable_aad(&self.header_digest, chunk_index, is_final, &self.user_aad);
        open(self.key.as_bytes(), &nonce, &aad, &ct, &tag)
    }

    /// Authenticates and reads `len` plaintext bytes starting at `offset` in `O(1)` seeks,
    /// decrypting ONLY the chunks overlapping `[offset, offset + len)`.
    pub fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| WilisError::InvalidParameters("read_at range overflow".into()))?;
        if end > self.header.total_plain_len {
            return Err(WilisError::InvalidParameters(format!(
                "read_at range [{offset}..{end}) exceeds plaintext length {}",
                self.header.total_plain_len
            )));
        }
        if len == 0 {
            // Still authenticate chunk 0 when empty container is read at (0, 0) so wrong keys fail
            if self.header.total_plain_len == 0 {
                let _ = self.decrypt_chunk(0)?;
            }
            return Ok(Vec::new());
        }

        let cs = self.header.chunk_size as u64;
        let first_chunk = offset / cs;
        let last_chunk = (end - 1) / cs;

        let mut out = Vec::with_capacity(len);
        for chunk_idx in first_chunk..=last_chunk {
            let mut chunk_pt = match self.decrypt_chunk(chunk_idx) {
                Ok(pt) => pt,
                Err(e) => {
                    zeroize_bytes(&mut out);
                    return Err(e);
                }
            };
            let chunk_start = chunk_idx * cs;
            let slice_start = offset.saturating_sub(chunk_start) as usize;
            let slice_end = (end - chunk_start).min(chunk_pt.len() as u64) as usize;
            out.extend_from_slice(&chunk_pt[slice_start..slice_end]);
            zeroize_bytes(&mut chunk_pt);
        }
        Ok(out)
    }

    /// Authenticates every chunk in the container without retaining plaintext in RAM.
    pub fn verify_all(&mut self) -> Result<()> {
        let n = self.header.num_chunks();
        for i in 0..n {
            let mut pt = self.decrypt_chunk(i)?;
            zeroize_bytes(&mut pt);
        }
        Ok(())
    }
}
