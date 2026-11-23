//! Constant-memory chunked streaming file encryption (`WILS` v2).

use std::io::{Read, Write};

use crate::aead::seal;
use crate::core::constants::{HASH_BYTES, KEY_BYTES};
use crate::error::{Result, WilisError};
use crate::format::header::{ContainerHeader, KeyMode, FORMAT_VERSION_V2};
use crate::hash::hash;
use crate::kdf::{derive_key_with_keyfile, KdfParams};
use crate::stream::chunk_nonce::{
    build_chunk_aad, derive_chunk_nonce, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
};
use crate::utils::random::{generate_nonce, generate_salt};
use crate::utils::zeroize::zeroize_bytes;

/// Encrypts an arbitrary byte stream with a raw 256-bit key into a `WILS` v2 stream.
///
/// Returns `(plaintext_bytes_read, total_ciphertext_bytes_written)`.
pub fn encrypt_stream_with_key<R: Read, W: Write>(
    key: &[u8; KEY_BYTES],
    reader: &mut R,
    writer: &mut W,
    user_aad: &[u8],
    chunk_size: u32,
) -> Result<(u64, u64)> {
    validate_chunk_size(chunk_size)?;
    let nonce = generate_nonce()?;
    let header = ContainerHeader {
        version: FORMAT_VERSION_V2,
        mode: KeyMode::RawKey,
        nonce,
        chunk_size: Some(chunk_size),
    };
    encrypt_stream_core(key, &header, reader, writer, user_aad, chunk_size)
}

/// Encrypts an arbitrary byte stream with a passphrase (+ optional 2FA keyfile hash)
/// into a `WILS` v2 stream.
pub fn encrypt_stream_with_passphrase<R: Read, W: Write>(
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    reader: &mut R,
    writer: &mut W,
    user_aad: &[u8],
    params: KdfParams,
    chunk_size: u32,
) -> Result<(u64, u64)> {
    validate_chunk_size(chunk_size)?;
    let salt = generate_salt()?;
    let nonce = generate_nonce()?;
    let derived_key = derive_key_with_keyfile(passphrase, keyfile_hash, &salt, params)?;
    let header = ContainerHeader {
        version: FORMAT_VERSION_V2,
        mode: KeyMode::Passphrase { params, salt },
        nonce,
        chunk_size: Some(chunk_size),
    };
    encrypt_stream_core(
        derived_key.as_bytes(),
        &header,
        reader,
        writer,
        user_aad,
        chunk_size,
    )
}

fn validate_chunk_size(chunk_size: u32) -> Result<()> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(WilisError::InvalidParameters(format!(
            "chunk_size {chunk_size} out of range [{MIN_CHUNK_SIZE}..={MAX_CHUNK_SIZE}] (default {DEFAULT_CHUNK_SIZE})"
        )));
    }
    Ok(())
}

/// Reads up to `buf.len()` bytes, retrying short reads until EOF or buffer full.
fn read_full_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

fn encrypt_stream_core<R: Read, W: Write>(
    key: &[u8; KEY_BYTES],
    header: &ContainerHeader,
    reader: &mut R,
    writer: &mut W,
    user_aad: &[u8],
    chunk_size: u32,
) -> Result<(u64, u64)> {
    let header_bytes = header.to_bytes();
    let header_digest = hash(&header_bytes);
    writer.write_all(&header_bytes)?;

    let mut total_in: u64 = 0;
    let mut total_out: u64 = header_bytes.len() as u64;
    let cs = chunk_size as usize;

    // Lookahead buffer lets us know with certainty when the current chunk is the final one
    let mut cur_buf = vec![0u8; cs];
    let mut next_buf = vec![0u8; cs];

    let mut cur_len = read_full_or_eof(reader, &mut cur_buf)?;
    let mut chunk_index: u64 = 0;

    loop {
        let next_len = if cur_len == cs {
            read_full_or_eof(reader, &mut next_buf)?
        } else {
            0
        };
        let is_final = next_len == 0;

        let chunk_nonce = derive_chunk_nonce(&header.nonce, chunk_index, is_final);
        let chunk_aad = build_chunk_aad(&header_digest, chunk_index, is_final, user_aad);
        let (ct, tag) = seal(key, &chunk_nonce, &chunk_aad, &cur_buf[..cur_len]);

        // Frame format per chunk: [chunk_pt_len: u32 LE][is_final: u8][ciphertext][tag: 32B]
        let frame_len = (cur_len as u32).to_le_bytes();
        let final_flag = [if is_final { 1u8 } else { 0u8 }];
        writer.write_all(&frame_len)?;
        writer.write_all(&final_flag)?;
        writer.write_all(&ct)?;
        writer.write_all(&tag)?;

        total_in += cur_len as u64;
        total_out += (4 + 1 + ct.len() + tag.len()) as u64;

        if is_final {
            break;
        }

        std::mem::swap(&mut cur_buf, &mut next_buf);
        cur_len = next_len;
        chunk_index = chunk_index
            .checked_add(1)
            .ok_or_else(|| WilisError::InvalidFormat("chunk counter overflow".into()))?;
    }

    zeroize_bytes(&mut cur_buf);
    zeroize_bytes(&mut next_buf);
    writer.flush()?;
    Ok((total_in, total_out))
}
