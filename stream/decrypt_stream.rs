//! Constant-memory chunked streaming file decryption (`WILS` v2) with strict
//! anti-truncation, anti-reordering, and trailing-garbage rejection.

use std::io::{Read, Write};

use crate::aead::open;
use crate::core::constants::{HASH_BYTES, KEY_BYTES, TAG_BYTES};
use crate::error::{Result, WilisError};
use crate::format::header::{ContainerHeader, KeyMode, FORMAT_VERSION_V2};
use crate::hash::hash;
use crate::kdf::derive_key_with_keyfile;
use crate::stream::chunk_nonce::{build_chunk_aad, derive_chunk_nonce, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};
use crate::utils::zeroize::zeroize_bytes;

/// Decrypts a `WILS` v2 stream using a raw 256-bit key.
///
/// Returns total verified plaintext bytes written.
pub fn decrypt_stream_with_key<R: Read, W: Write>(
    key: &[u8; KEY_BYTES],
    reader: &mut R,
    writer: &mut W,
    user_aad: &[u8],
) -> Result<u64> {
    let (header, header_bytes) = ContainerHeader::read_from(reader)?;
    if header.version != FORMAT_VERSION_V2 {
        return Err(WilisError::InvalidFormat(format!(
            "expected streaming container v2, got v{}",
            header.version
        )));
    }
    if header.mode != KeyMode::RawKey {
        return Err(WilisError::InvalidFormat(
            "stream was encrypted with a passphrase, not a raw key".into(),
        ));
    }
    decrypt_stream_core(key, &header, &header_bytes, reader, writer, user_aad)
}

/// Decrypts a `WILS` v2 stream using a passphrase (+ optional 2FA keyfile hash).
pub fn decrypt_stream_with_passphrase<R: Read, W: Write>(
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    reader: &mut R,
    writer: &mut W,
    user_aad: &[u8],
) -> Result<u64> {
    let (header, header_bytes) = ContainerHeader::read_from(reader)?;
    if header.version != FORMAT_VERSION_V2 {
        return Err(WilisError::InvalidFormat(format!(
            "expected streaming container v2, got v{}",
            header.version
        )));
    }
    let (params, salt) = match header.mode {
        KeyMode::Passphrase { params, salt } => (params, salt),
        KeyMode::RawKey => {
            return Err(WilisError::InvalidFormat(
                "stream was encrypted with a raw key, not a passphrase".into(),
            ));
        }
    };
    let derived_key = derive_key_with_keyfile(passphrase, keyfile_hash, &salt, params)?;
    decrypt_stream_core(
        derived_key.as_bytes(),
        &header,
        &header_bytes,
        reader,
        writer,
        user_aad,
    )
}

fn decrypt_stream_core<R: Read, W: Write>(
    key: &[u8; KEY_BYTES],
    header: &ContainerHeader,
    header_bytes: &[u8],
    reader: &mut R,
    writer: &mut W,
    user_aad: &[u8],
) -> Result<u64> {
    let chunk_size = header.chunk_size.ok_or_else(|| {
        WilisError::InvalidFormat("missing chunk_size in streaming header".into())
    })?;
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(WilisError::InvalidFormat(format!(
            "chunk_size {chunk_size} out of safe range [{MIN_CHUNK_SIZE}..={MAX_CHUNK_SIZE}]"
        )));
    }

    let header_digest = hash(header_bytes);
    let mut chunk_index: u64 = 0;
    let mut total_plain: u64 = 0;
    let mut ct_buf = Vec::new();
    let mut seen_final = false;

    loop {
        // Read 5-byte chunk frame prefix: [len: u32 LE][is_final: u8]
        let mut frame_hdr = [0u8; 5];
        match read_exact_or_clean_eof(reader, &mut frame_hdr)? {
            ReadOutcome::Eof => break,
            ReadOutcome::Truncated => return Err(WilisError::AuthenticationFailed),
            ReadOutcome::Full => {}
        }

        if seen_final {
            // Trailing data appended after authenticated final chunk -> tamper!
            return Err(WilisError::AuthenticationFailed);
        }

        let ct_len = u32::from_le_bytes(frame_hdr[0..4].try_into().expect("4 bytes"));
        let is_final = match frame_hdr[4] {
            0 => false,
            1 => true,
            _ => return Err(WilisError::AuthenticationFailed),
        };

        // Canonical WILS v2 framing: non-final chunks must equal `chunk_size` exactly,
        // and final chunks must satisfy `0 <= ct_len <= chunk_size`.
        if (!is_final && ct_len != chunk_size) || ct_len > chunk_size {
            return Err(WilisError::AuthenticationFailed);
        }

        ct_buf.resize(ct_len as usize, 0);
        if reader.read_exact(&mut ct_buf).is_err() {
            return Err(WilisError::AuthenticationFailed);
        }

        let mut tag = [0u8; TAG_BYTES];
        if reader.read_exact(&mut tag).is_err() {
            return Err(WilisError::AuthenticationFailed);
        }

        let chunk_nonce = derive_chunk_nonce(&header.nonce, chunk_index, is_final);
        let chunk_aad = build_chunk_aad(&header_digest, chunk_index, is_final, user_aad);
        let mut pt = open(key, &chunk_nonce, &chunk_aad, &ct_buf, &tag)?;

        let write_res = writer.write_all(&pt);
        let pt_len = pt.len() as u64;
        zeroize_bytes(&mut pt);
        write_res?;
        total_plain = total_plain
            .checked_add(pt_len)
            .ok_or_else(|| WilisError::InvalidFormat("stream plaintext counter overflow".into()))?;

        if is_final {
            seen_final = true;
        } else {
            chunk_index = chunk_index
                .checked_add(1)
                .ok_or_else(|| WilisError::InvalidFormat("chunk counter overflow".into()))?;
        }
    }

    if !seen_final {
        // Stream ended before an authenticated final chunk -> truncation attack!
        return Err(WilisError::AuthenticationFailed);
    }

    writer.flush()?;
    Ok(total_plain)
}

enum ReadOutcome {
    Eof,
    Truncated,
    Full,
}

fn read_exact_or_clean_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<ReadOutcome> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = match reader.read(&mut buf[filled..]) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            return Ok(if filled == 0 {
                ReadOutcome::Eof
            } else {
                ReadOutcome::Truncated
            });
        }
        filled += n;
    }
    Ok(ReadOutcome::Full)
}
