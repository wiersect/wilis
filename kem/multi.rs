//! Multi-Recipient Streaming Post-Quantum Public-Key Encryption (`WPKE` v2).
//!
//! Encrypts arbitrary multi-GB streams in constant memory (`O(chunk_size)` RAM) for up to
//! 64 post-quantum recipients simultaneously (`WilisKEM` Module-LWE 768 IND-CCA2 + `WilisAEAD`).
//!
//! Security properties:
//! - **Anonymous Recipient Slots:** No plaintext key fingerprint is stored per slot; each slot
//!   contains only a random-looking `WKC1` ciphertext + AEAD-wrapped File Encryption Key (FEK).
//! - **Full Header Binding:** `WilisHash-256` of the entire `WPKE` v2 header (including every
//!   recipient slot, count, chunk size, and base nonce) is bound into EVERY chunk's AAD, blocking
//!   recipient stripping, slot swapping, or header tampering.
//! - **Constant-Slot Decapsulation:** Decryption evaluates every recipient slot without early
//!   exit so timing does not leak which slot index matched the recipient's secret key.
//! - **Canonical Chunk Framing:** Identical anti-truncation, anti-reordering, trailing-garbage,
//!   and `ct_len == chunk_size` non-final invariants as `WILS` v2.

use std::collections::HashSet;
use std::io::{self, Cursor, Read, Write};

use crate::aead::{open, seal};
use crate::core::constants::{KEY_BYTES, NONCE_BYTES, TAG_BYTES};
use crate::error::{Result, WilisError};
use crate::hash::hash;
use crate::kem::hybrid::pub_decrypt;
use crate::kem::mlwe::{
    decapsulate, encapsulate, KemCiphertext, KemPublicKey, KemSecretKey, KEM_CT_BYTES,
};
use crate::stream::chunk_nonce::{
    build_chunk_aad, derive_chunk_nonce, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
};
use crate::utils::random::{generate_key, generate_nonce};
use crate::utils::zeroize::{zeroize_bytes, SecretKey};

/// Magic prefix shared by `WPKE` v1 and `WPKE` v2 containers.
pub const WPKE_MAGIC: [u8; 4] = *b"WPKE";

/// `WPKE` v2 multi-recipient streaming container version.
pub const WPKE_VERSION_V2: u8 = 2;

/// Maximum post-quantum recipients per `WPKE` v2 container.
pub const MAX_WPKE_RECIPIENTS: usize = 64;

/// Fixed prefix size before recipient slots: magic(4) + ver(1) + count(1) + chunk_size(4) + nonce(24).
const WPKE_V2_PREFIX_BYTES: usize = 4 + 1 + 1 + 4 + NONCE_BYTES;

/// Exact serialized size of one anonymous recipient slot:
/// `[ kem_ct: 1668B ][ wrap_nonce: 24B ][ wrapped_fek: 32B ][ wrap_tag: 32B ] = 1756 bytes`.
pub const WPKE_SLOT_BYTES: usize = KEM_CT_BYTES + NONCE_BYTES + KEY_BYTES + TAG_BYTES;

fn build_slot_wrap_aad(
    slot_idx: u8,
    recipient_count: u8,
    chunk_size: u32,
    stream_base_nonce: &[u8; NONCE_BYTES],
) -> [u8; 12 + 1 + 1 + 4 + NONCE_BYTES] {
    let mut aad = [0u8; 12 + 1 + 1 + 4 + NONCE_BYTES];
    aad[0..12].copy_from_slice(b"WPKE_WRAP_V2");
    aad[12] = slot_idx;
    aad[13] = recipient_count;
    aad[14..18].copy_from_slice(&chunk_size.to_le_bytes());
    aad[18..18 + NONCE_BYTES].copy_from_slice(stream_base_nonce);
    aad
}

fn read_full_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = match reader.read(&mut buf[filled..]) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
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
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
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

/// Stream-encrypts `reader` to `1..=64` post-quantum recipients into a `WPKE` v2 container.
///
/// Returns `(plaintext_bytes_read, total_ciphertext_bytes_written)`.
pub fn pub_encrypt_multi_stream<R: Read, W: Write>(
    recipients: &[&KemPublicKey],
    reader: &mut R,
    writer: &mut W,
    user_aad: &[u8],
    chunk_size: u32,
) -> Result<(u64, u64)> {
    if recipients.is_empty() || recipients.len() > MAX_WPKE_RECIPIENTS {
        return Err(WilisError::InvalidParameters(format!(
            "WPKE v2 recipient count {} out of range [1..={MAX_WPKE_RECIPIENTS}]",
            recipients.len()
        )));
    }
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(WilisError::InvalidParameters(format!(
            "chunk_size {chunk_size} out of range [{MIN_CHUNK_SIZE}..={MAX_CHUNK_SIZE}]"
        )));
    }

    // Reject duplicate recipient public keys to prevent redundant slots
    let mut seen_pks: HashSet<[u8; 32]> = HashSet::with_capacity(recipients.len());
    for pk in recipients {
        let pk_id = hash(&pk.to_bytes());
        if !seen_pks.insert(pk_id) {
            return Err(WilisError::InvalidParameters(
                "duplicate recipient public key in WPKE v2 recipient list".into(),
            ));
        }
    }

    let fek = generate_key()?;
    let stream_base_nonce = generate_nonce()?;
    let count_u8 = recipients.len() as u8;

    let header_len = WPKE_V2_PREFIX_BYTES + recipients.len() * WPKE_SLOT_BYTES;
    let mut header = Vec::with_capacity(header_len);
    header.extend_from_slice(&WPKE_MAGIC);
    header.push(WPKE_VERSION_V2);
    header.push(count_u8);
    header.extend_from_slice(&chunk_size.to_le_bytes());
    header.extend_from_slice(&stream_base_nonce);

    for (slot_idx, pk) in recipients.iter().enumerate() {
        let (kem_ct, kem_ss) = encapsulate(pk)?;
        let wrap_nonce = generate_nonce()?;
        let wrap_aad = build_slot_wrap_aad(slot_idx as u8, count_u8, chunk_size, &stream_base_nonce);
        let (wrapped_fek, wrap_tag) = seal(kem_ss.as_bytes(), &wrap_nonce, &wrap_aad, fek.as_bytes());
        header.extend_from_slice(&kem_ct.to_bytes());
        header.extend_from_slice(&wrap_nonce);
        header.extend_from_slice(&wrapped_fek);
        header.extend_from_slice(&wrap_tag);
    }

    let header_digest = hash(&header);
    writer.write_all(&header)?;

    let cs = chunk_size as usize;
    let mut cur_buf = vec![0u8; cs];
    let mut next_buf = vec![0u8; cs];

    let stream_res = (|| -> Result<(u64, u64)> {
        let mut total_in: u64 = 0;
        let mut total_out: u64 = header.len() as u64;
        let mut cur_len = read_full_or_eof(reader, &mut cur_buf)?;
        let mut chunk_index: u64 = 0;

        loop {
            let next_len = if cur_len == cs {
                read_full_or_eof(reader, &mut next_buf)?
            } else {
                0
            };
            let is_final = next_len == 0;

            let chunk_nonce = derive_chunk_nonce(&stream_base_nonce, chunk_index, is_final);
            let chunk_aad = build_chunk_aad(&header_digest, chunk_index, is_final, user_aad);
            let (ct, tag) = seal(fek.as_bytes(), &chunk_nonce, &chunk_aad, &cur_buf[..cur_len]);

            writer.write_all(&(cur_len as u32).to_le_bytes())?;
            writer.write_all(&[if is_final { 1u8 } else { 0u8 }])?;
            writer.write_all(&ct)?;
            writer.write_all(&tag)?;

            total_in = total_in
                .checked_add(cur_len as u64)
                .ok_or_else(|| WilisError::InvalidFormat("WPKE stream byte counter overflow".into()))?;
            total_out = total_out
                .checked_add((4 + 1 + ct.len() + tag.len()) as u64)
                .ok_or_else(|| WilisError::InvalidFormat("WPKE stream output counter overflow".into()))?;

            if is_final {
                break;
            }

            std::mem::swap(&mut cur_buf, &mut next_buf);
            cur_len = next_len;
            chunk_index = chunk_index
                .checked_add(1)
                .ok_or_else(|| WilisError::InvalidFormat("WPKE chunk counter overflow".into()))?;
        }

        writer.flush()?;
        Ok((total_in, total_out))
    })();

    zeroize_bytes(&mut cur_buf);
    zeroize_bytes(&mut next_buf);
    stream_res
}

/// Authenticates and stream-decrypts a `WPKE` v2 multi-recipient container using `recipient_sk`.
///
/// Returns total verified plaintext bytes written.
pub fn pub_decrypt_multi_stream<R: Read, W: Write>(
    recipient_sk: &KemSecretKey,
    reader: &mut R,
    writer: &mut W,
    user_aad: &[u8],
) -> Result<u64> {
    let mut prefix = [0u8; WPKE_V2_PREFIX_BYTES];
    reader.read_exact(&mut prefix).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            WilisError::InvalidFormat("truncated WPKE v2 header prefix".into())
        } else {
            WilisError::Io(e)
        }
    })?;

    if prefix[0..4] != WPKE_MAGIC {
        return Err(WilisError::InvalidFormat(
            "invalid magic bytes (expected 'WPKE')".into(),
        ));
    }
    if prefix[4] != WPKE_VERSION_V2 {
        return Err(WilisError::InvalidFormat(format!(
            "expected WPKE version {WPKE_VERSION_V2}, got {}",
            prefix[4]
        )));
    }

    let count = prefix[5] as usize;
    if count == 0 || count > MAX_WPKE_RECIPIENTS {
        return Err(WilisError::InvalidFormat(format!(
            "invalid WPKE v2 recipient count: {count}"
        )));
    }

    let chunk_size = u32::from_le_bytes(prefix[6..10].try_into().expect("4 bytes"));
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(WilisError::InvalidFormat(format!(
            "WPKE v2 chunk_size {chunk_size} out of safe range [{MIN_CHUNK_SIZE}..={MAX_CHUNK_SIZE}]"
        )));
    }

    let mut stream_base_nonce = [0u8; NONCE_BYTES];
    stream_base_nonce.copy_from_slice(&prefix[10..WPKE_V2_PREFIX_BYTES]);

    let slots_bytes_len = count * WPKE_SLOT_BYTES;
    let mut header = vec![0u8; WPKE_V2_PREFIX_BYTES + slots_bytes_len];
    header[..WPKE_V2_PREFIX_BYTES].copy_from_slice(&prefix);
    reader
        .read_exact(&mut header[WPKE_V2_PREFIX_BYTES..])
        .map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                WilisError::InvalidFormat("truncated WPKE v2 recipient slots".into())
            } else {
                WilisError::Io(e)
            }
        })?;

    // Evaluate EVERY recipient slot without early exit to avoid leaking slot index via timing
    let mut recovered_fek: Option<SecretKey> = None;
    for slot_idx in 0..count {
        let base = WPKE_V2_PREFIX_BYTES + slot_idx * WPKE_SLOT_BYTES;
        let kem_ct = match KemCiphertext::from_bytes(&header[base..base + KEM_CT_BYTES]) {
            Ok(ct) => ct,
            Err(_) => return Err(WilisError::InvalidFormat("corrupted KEM ciphertext in WPKE v2 slot".into())),
        };
        let wrap_nonce_start = base + KEM_CT_BYTES;
        let wrapped_start = wrap_nonce_start + NONCE_BYTES;
        let tag_start = wrapped_start + KEY_BYTES;

        let wrap_nonce: &[u8; NONCE_BYTES] = header[wrap_nonce_start..wrapped_start]
            .try_into()
            .expect("24 bytes");
        let wrapped_fek = &header[wrapped_start..tag_start];
        let wrap_tag: &[u8; TAG_BYTES] = header[tag_start..tag_start + TAG_BYTES]
            .try_into()
            .expect("32 bytes");

        let kem_ss = decapsulate(recipient_sk, &kem_ct);
        let wrap_aad = build_slot_wrap_aad(slot_idx as u8, count as u8, chunk_size, &stream_base_nonce);
        if let Ok(mut unwrapped) = open(kem_ss.as_bytes(), wrap_nonce, &wrap_aad, wrapped_fek, wrap_tag) {
            if unwrapped.len() == KEY_BYTES && recovered_fek.is_none() {
                let mut fek_arr = [0u8; KEY_BYTES];
                fek_arr.copy_from_slice(&unwrapped);
                recovered_fek = Some(SecretKey::from_bytes(fek_arr));
                zeroize_bytes(&mut fek_arr);
            }
            zeroize_bytes(&mut unwrapped);
        }
    }

    let fek = recovered_fek.ok_or(WilisError::AuthenticationFailed)?;
    let header_digest = hash(&header);

    let mut chunk_index: u64 = 0;
    let mut total_plain: u64 = 0;
    let mut ct_buf = Vec::new();
    let mut seen_final = false;

    loop {
        let mut frame_hdr = [0u8; 5];
        match read_exact_or_clean_eof(reader, &mut frame_hdr)? {
            ReadOutcome::Eof => break,
            ReadOutcome::Truncated => return Err(WilisError::AuthenticationFailed),
            ReadOutcome::Full => {}
        }

        if seen_final {
            return Err(WilisError::AuthenticationFailed);
        }

        let ct_len = u32::from_le_bytes(frame_hdr[0..4].try_into().expect("4 bytes"));
        let is_final = match frame_hdr[4] {
            0 => false,
            1 => true,
            _ => return Err(WilisError::AuthenticationFailed),
        };

        if (!is_final && ct_len != chunk_size) || ct_len > chunk_size {
            return Err(WilisError::AuthenticationFailed);
        }

        ct_buf.resize(ct_len as usize, 0);
        if let Err(e) = reader.read_exact(&mut ct_buf) {
            return Err(if e.kind() == io::ErrorKind::UnexpectedEof {
                WilisError::AuthenticationFailed
            } else {
                WilisError::Io(e)
            });
        }

        let mut tag = [0u8; TAG_BYTES];
        if let Err(e) = reader.read_exact(&mut tag) {
            return Err(if e.kind() == io::ErrorKind::UnexpectedEof {
                WilisError::AuthenticationFailed
            } else {
                WilisError::Io(e)
            });
        }

        let chunk_nonce = derive_chunk_nonce(&stream_base_nonce, chunk_index, is_final);
        let chunk_aad = build_chunk_aad(&header_digest, chunk_index, is_final, user_aad);
        let mut pt = open(fek.as_bytes(), &chunk_nonce, &chunk_aad, &ct_buf, &tag)?;

        let write_res = writer.write_all(&pt);
        let pt_len = pt.len() as u64;
        zeroize_bytes(&mut pt);
        write_res?;

        total_plain = total_plain
            .checked_add(pt_len)
            .ok_or_else(|| WilisError::InvalidFormat("WPKE stream plaintext counter overflow".into()))?;

        if is_final {
            seen_final = true;
        } else {
            chunk_index = chunk_index
                .checked_add(1)
                .ok_or_else(|| WilisError::InvalidFormat("WPKE chunk counter overflow".into()))?;
        }
    }

    if !seen_final {
        return Err(WilisError::AuthenticationFailed);
    }

    writer.flush()?;
    Ok(total_plain)
}

/// Convenience in-memory helper encrypting `plaintext` to multiple recipients (`WPKE` v2).
pub fn pub_encrypt_multi(
    recipients: &[&KemPublicKey],
    plaintext: &[u8],
    user_aad: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    pub_encrypt_multi_stream(
        recipients,
        &mut Cursor::new(plaintext),
        &mut out,
        user_aad,
        DEFAULT_CHUNK_SIZE,
    )?;
    Ok(out)
}

/// Convenience in-memory helper authenticating and decrypting either `WPKE` v1 or `WPKE` v2.
pub fn pub_decrypt_multi(
    recipient_sk: &KemSecretKey,
    packet: &[u8],
    user_aad: &[u8],
) -> Result<Vec<u8>> {
    if packet.len() >= 5 && packet[0..4] == WPKE_MAGIC && packet[4] == 1 {
        return pub_decrypt(recipient_sk, packet, user_aad);
    }
    let mut out = Vec::new();
    if let Err(e) = pub_decrypt_multi_stream(recipient_sk, &mut Cursor::new(packet), &mut out, user_aad) {
        zeroize_bytes(&mut out);
        return Err(e);
    }
    Ok(out)
}
